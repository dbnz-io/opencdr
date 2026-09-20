"""Scoped integration management; immutable job snapshots survive configuration updates."""
import json
import os
import uuid

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from ..domain.ingestion import (
    InvalidRecord,
    bounded,
    builtin_catalog,
    identity,
    normalize,
    stock_falco_rules,
    validate_config,
)
from ..infra.parser_runtime import allowed_parser_arns, parse_record, verify_permission


def handle(method, path, body, qs):
    if not os.getenv('INGESTION_TABLE_NAME'):
        return 503, {'message': 'S3 ingestion is not configured'}
    table = boto3.resource('dynamodb').Table(os.environ['INGESTION_TABLE_NAME'])
    parts = path.strip('/').split('/')
    if len(parts) < 2:
        if method != 'GET':
            return 405, {'message': 'Method not allowed'}
        return 200, {'parsers': builtin_catalog() + [{'kind': 'lambda', 'contract_version': '1', 'allowed_versions': list(allowed_parser_arns())}],
                     'stock_falco_rules': stock_falco_rules(),
                     'bucket': os.environ['INGESTION_BUCKET'], 'prefix_template': 'ingest/{integration_id}/'}
    integration_id = parts[1]
    pk = f'INTEGRATION#{integration_id}'
    key = {'pk': pk, 'sk': 'CONFIG'}
    if len(parts) == 3 and parts[2] == 'preview' and method == 'POST':
        try:
            config = validate_config(body.get('config'), integration_id, os.environ['INGESTION_BUCKET'], allowed_parser_arns())
            sample = bounded(body.get('record'))
            result = parse_record(sample, config, {'integration_id': integration_id, 'event_id': identity('preview', integration_id)})
            normalized = normalize(result, config, event_id='preview', provenance={})
            return 200, {'status': result['status'], 'event': normalized.to_dict() if normalized else None, 'code': result.get('code')}
        except InvalidRecord as exc:
            return 400, {'message': str(exc)}
        except Exception:
            return 502, {'message': 'parser_invocation_failed'}
    if len(parts) == 5 and parts[2] == 'jobs' and parts[4] == 'replay' and method == 'POST':
        job = table.get_item(Key={'pk': pk, 'sk': 'JOB#' + parts[3]}, ConsistentRead=True).get('Item')
        if not job:
            return 404, {'message': 'Job not found'}
        run_id = str(uuid.uuid4())
        boto3.client('sqs').send_message(QueueUrl=os.environ['INGESTION_QUEUE_URL'], MessageBody=json.dumps({
            'replay': {'integration_id': integration_id, 'object_id': parts[3], 'run_id': run_id}}))
        return 202, {'run_id': run_id, 'mode': 'analysis',
                     'object_id': identity(integration_id, job['bucket'], job['key'], job['version_id'], run_id)}
    if len(parts) >= 3 and parts[2] == 'jobs' and method == 'GET':
        if len(parts) == 4:
            job = table.get_item(Key={'pk': pk, 'sk': 'JOB#' + parts[3]}, ConsistentRead=True).get('Item')
            if not job:
                return 404, {'message': 'Job not found'}
            records = []
            query = {'KeyConditionExpression': Key('pk').eq(pk) & Key('sk').begins_with('RECORD#' + parts[3] + '#'),
                     'ProjectionExpression': 'sk, #s, code', 'ExpressionAttributeNames': {'#s': 'status'}, 'Limit': 100}
            # DynamoDB's 1 MiB page budget applies before projection. Large pinned
            # result rows may require several pages even for <=100 records.
            for _ in range(100):
                page = table.query(**query)
                records.extend(page['Items'])
                if not page.get('LastEvaluatedKey'):
                    break
                query['ExclusiveStartKey'] = page['LastEvaluatedKey']
            return 200, {**public_job(job), 'records': records}
        if len(parts) != 3:
            return 404, {'message': 'Not found'}
        kwargs = {'KeyConditionExpression': Key('pk').eq(pk) & Key('sk').begins_with('JOB#'), 'Limit': 25}
        if qs.get('next_token'):
            try:
                token = json.loads(qs['next_token'])
                if token['pk'] != pk or not token['sk'].startswith('JOB#'):
                    raise ValueError()
                kwargs['ExclusiveStartKey'] = token
            except (ValueError, KeyError, TypeError):
                return 400, {'message': 'Invalid next_token'}
        result = table.query(**kwargs)
        return 200, {'items': [public_job(j) for j in result['Items']],
                     'next_token': json.dumps(result['LastEvaluatedKey']) if result.get('LastEvaluatedKey') else None}
    if len(parts) != 2:
        return 404, {'message': 'Not found'}
    if method == 'GET':
        config = table.get_item(Key=key, ConsistentRead=True).get('Item')
        return (200, {k: v for k, v in config.items() if k not in {'pk', 'sk'}}) if config else (404, {'message': 'Integration not found'})
    if method == 'PUT':
        try:
            config = validate_config(body, integration_id, os.environ['INGESTION_BUCKET'], allowed_parser_arns())
            rev = body.get('expected_rev')
            if type(rev) is not int or rev < 0:
                raise InvalidRecord('expected_rev_required')
            verify_permission(config)
            item = {**key, **config, 'rev': rev + 1}
            kwargs = {'Item': item, 'ConditionExpression': 'attribute_not_exists(pk)' if rev == 0 else 'rev=:r'}
            if rev:
                kwargs['ExpressionAttributeValues'] = {':r': rev}
            table.put_item(**kwargs)
            return 200, {k: v for k, v in item.items() if k not in {'pk', 'sk'}}
        except InvalidRecord as exc:
            return 400, {'message': str(exc)}
        except ClientError as exc:
            if exc.response['Error']['Code'] == 'ConditionalCheckFailedException':
                return 409, {'message': 'Integration revision conflict'}
            return 502, {'message': 'Integration registration failed; check parser invocation permissions'}
    return 405, {'message': 'Method not allowed'}


def public_job(job):
    return {k: v for k, v in job.items() if k not in {'pk', 'sk', 'rules_json', 'lists_json', 'config'}}
