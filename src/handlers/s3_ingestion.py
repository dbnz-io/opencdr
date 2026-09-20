"""S3 -> SQS -> bounded parser -> durable evaluated records -> signal write queue.

The conditional record write pins the winning evaluation before any send. A retry
resends that exact result. The signal writer owns idempotent storage and alert/outbox
commit. No claim of exactly-once parser invocation or external notification delivery.
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from urllib.parse import quote_plus, unquote_plus

import boto3
from botocore.exceptions import ClientError

from ..domain.detection_engine import run_detection
from ..domain.ingestion import (
    MAX_OBJECT_BYTES,
    MAX_RESULT_BYTES,
    InvalidRecord,
    bounded,
    decode_record,
    encode,
    frame,
    identity,
    normalize,
    stock_falco_rules,
)
from ..infra.aws_handler import AwsHandler
from ..infra.detection_rules_repository import load_detection_rules
from ..infra.logger import Logger
from ..infra.metrics import emit_metric
from ..infra.parser_runtime import parse_record


def safe_item(item):
    return json.loads(json.dumps(item, default=lambda v: float(v) if isinstance(v, Decimal) else str(v)), parse_float=Decimal)


def json_default(value):
    if isinstance(value, Decimal):
        return int(value) if value == int(value) else float(value)
    raise TypeError('unsupported_value')


def pinned(table, item):
    """Winner persists immutable work; concurrent workers read the same result."""
    bounded(json.loads(json.dumps(item, default=json_default)), MAX_RESULT_BYTES)
    try:
        table.put_item(Item=safe_item(item), ConditionExpression='attribute_not_exists(pk)')
        return item
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ConditionalCheckFailedException':
            raise
        return table.get_item(Key={'pk': item['pk'], 'sk': item['sk']}, ConsistentRead=True)['Item']


def process_object(notification, context=None, replay_run=None):
    if notification.get('eventSource') != 'aws:s3' or not notification.get('eventName', '').startswith('ObjectCreated:'):
        raise InvalidRecord('unsupported_s3_event')
    obj = notification['s3']['object']
    bucket = notification['s3']['bucket']['name']
    key = unquote_plus(obj['key'])
    version = obj.get('versionId')
    if bucket != os.environ['INGESTION_BUCKET'] or not version or version == 'null':
        raise InvalidRecord('unregistered_bucket_or_unversioned_object')
    parts = key.split('/')
    if len(parts) < 3 or parts[0] != 'ingest':
        raise InvalidRecord('invalid_integration_prefix')
    integration_id = parts[1]
    table = boto3.resource('dynamodb').Table(os.environ['INGESTION_TABLE_NAME'])
    pk = f'INTEGRATION#{integration_id}'
    object_id = identity(integration_id, bucket, key, version, replay_run)
    job_key = {'pk': pk, 'sk': f'JOB#{object_id}'}
    job = table.get_item(Key=job_key, ConsistentRead=True).get('Item')
    if job and job.get('status') in {'DISPATCHED', 'PARTIAL', 'QUARANTINED'}:
        emit_metric('IngestionDuplicateObjects')
        return
    logger = Logger(service='OPENCDR-INGESTION', source='s3-ingestion')
    if not job:
        config = table.get_item(Key={'pk': pk, 'sk': 'CONFIG'}, ConsistentRead=True).get('Item')
        if not config or not config['enabled']:
            # Preserve disabled/unregistered deliveries in SQS/DLQ for operator recovery.
            raise RuntimeError('integration_disabled_or_missing')
        if config['bucket'] != bucket or not key.startswith(config['prefix']):
            raise InvalidRecord('binding_mismatch')
        aws = AwsHandler(logger=logger)
        rules = load_detection_rules(aws, logger, rule_kind='signal', include_disabled=True)
        lists = {r['rule_id']: r.get('values', []) for r in load_detection_rules(aws, logger, rule_kind='list')}
        if config['kind'] == 'falco':
            by_id = {r['rule_id']: r for r in stock_falco_rules()}
            by_id.update({r['rule_id']: r for r in rules})
            rules = list(by_id.values())
        job = pinned(table, {**job_key, 'object_id': object_id, 'status': 'PROCESSING',
            'created_at': datetime.now(UTC).isoformat(), 'config': config,
            'rules_json': json.dumps(rules, default=json_default),
            'lists_json': json.dumps(lists, default=json_default),
            'bucket': bucket, 'key': key, 'version_id': version,
            'mode': 'analysis' if replay_run else 'live', 'replay_run': replay_run,
            'expires_at': int((datetime.now(UTC) + timedelta(days=90)).timestamp())})
    config = job['config']
    try:
        s3 = boto3.client('s3')
        response = s3.get_object(Bucket=bucket, Key=key, VersionId=version)
        stream = response['Body']
        try:
            data = stream.read(MAX_OBJECT_BYTES + 1)
        finally:
            stream.close()
        records = frame(data, config)
    except InvalidRecord as exc:
        table.update_item(Key=job_key, UpdateExpression='SET #s=:s, error_code=:e',
                          ExpressionAttributeNames={'#s': 'status'},
                          ExpressionAttributeValues={':s': 'QUARANTINED', ':e': str(exc)})
        emit_metric('IngestionQuarantinedObjects')
        return
    failures = drops = signals = 0
    for index, text in enumerate(records):
        if context and context.get_remaining_time_in_millis() < 18000:
            raise RuntimeError('ingestion_time_budget_exhausted')
        record_key = {'pk': pk, 'sk': f'RECORD#{object_id}#{index:06d}'}
        saved = table.get_item(Key=record_key, ConsistentRead=True).get('Item')
        if not saved:
            try:
                event_id = identity(object_id, index)
                record = decode_record(text, config)
                parser_context = {'integration_id': integration_id, 'event_id': event_id}
                result = parse_record(record, config, parser_context)
                provenance = {'bucket': bucket, 'key': key, 'version_id': version,
                              'record_index': index, 'object_id': object_id,
                              'parser': config['parser'], 'binding_revision': int(config['rev']),
                              'received_at': job['created_at'], 'mode': job['mode'], 'replay_run': job.get('replay_run')}
                normalized = normalize(result, config, event_id=event_id, provenance=provenance)
                detections = run_detection(normalized, json.loads(job['rules_json']),
                                           lists=json.loads(job['lists_json'])) if normalized else []
                for detection in detections:
                    detection['detection_id'] = identity(event_id, detection['rule_id'], job['rules_json'])
                    # Existing table keys are severity/day + ISO timestamp. Preserve
                    # receipt time and append deterministic fractional-second precision
                    # to avoid collisions without changing existing AWS signal keys.
                    base = datetime.fromisoformat(job['created_at'])
                    fraction = f"{base.microsecond:06d}{int(detection['detection_id'], 16):078d}"
                    detection['timestamp'] = base.strftime('%Y-%m-%dT%H:%M:%S.') + fraction + '+00:00'
                    detection['ingestion_managed'] = True
                    if job['mode'] == 'analysis':
                        detection['notify'] = False
                bounded(detections, MAX_RESULT_BYTES - 4096)
                saved = pinned(table, {**record_key, 'status': 'EVALUATED' if normalized else 'DROPPED',
                    'code': result.get('code', ''), 'detections_json': encode(detections),
                    'expires_at': job['expires_at']})
            except InvalidRecord as exc:
                saved = pinned(table, {**record_key, 'status': 'QUARANTINED', 'code': str(exc),
                                       'expires_at': job['expires_at']})
        if saved['status'] == 'QUARANTINED':
            failures += 1
            continue
        if saved['status'] == 'DROPPED':
            drops += 1
            continue
        for detection in json.loads(saved['detections_json']):
            boto3.client('sqs').send_message(QueueUrl=os.environ['SIGNALS_WRITE_QUEUE_URL'], MessageBody=encode(detection))
            signals += 1
    table.update_item(Key=job_key, UpdateExpression='SET #s=:s, record_count=:r, invalid_count=:i, dropped_count=:d, signal_count=:n',
        ExpressionAttributeNames={'#s': 'status'}, ExpressionAttributeValues={
            ':s': 'PARTIAL' if failures else 'DISPATCHED', ':r': len(records), ':i': failures, ':d': drops, ':n': signals})
    emit_metric('IngestionRecordsDispatched', signals)
    emit_metric('IngestionRecordsQuarantined', failures)


def lambda_handler(event, context):
    failures = []
    for message in event.get('Records', []):
        try:
            body = json.loads(message['body'])
            if 'replay' in body:
                replay = body['replay']
                table = boto3.resource('dynamodb').Table(os.environ['INGESTION_TABLE_NAME'])
                job = table.get_item(Key={'pk': 'INTEGRATION#' + replay['integration_id'],
                                          'sk': 'JOB#' + replay['object_id']}, ConsistentRead=True)['Item']
                notification = {'eventSource': 'aws:s3', 'eventName': 'ObjectCreated:Replay',
                                's3': {'bucket': {'name': job['bucket']},
                                       'object': {'key': quote_plus(job['key']), 'versionId': job['version_id']}}}
                process_object(notification, context, replay_run=replay['run_id'])
                continue
            if body.get('Event') == 's3:TestEvent':
                continue
            if not isinstance(body.get('Records'), list) or not body['Records']:
                raise InvalidRecord('invalid_s3_notification')
            for record in body['Records']:
                process_object(record, context)
        except Exception:
            # Do not log payloads, bucket keys or custom parser exception text.
            emit_metric('IngestionRetry')
            failures.append({'itemIdentifier': message['messageId']})
    return {'batchItemFailures': failures}
