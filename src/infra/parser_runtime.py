"""Invoke executable parsers with a bounded, versioned JSON contract."""
import json
import os

import boto3
from botocore.config import Config

from ..domain.ingestion import MAX_RECORD_BYTES, InvalidRecord, bounded, encode, parse_builtin


def allowed_parser_arns():
    return tuple(a.strip() for a in os.getenv('CUSTOM_PARSER_ARNS', '').split(',') if a.strip())


def lambda_client(arn):
    return boto3.client('lambda', region_name=arn.split(':')[3],
                        config=Config(connect_timeout=3, read_timeout=12, retries={'total_max_attempts': 1}))


def verify_permission(config):
    if config['parser']['kind'] == 'lambda':
        arn = config['parser']['version_arn']
        if arn not in allowed_parser_arns():
            raise InvalidRecord('parser_version_not_allowed')
        lambda_client(arn).invoke(FunctionName=arn, InvocationType='DryRun')


def parse_record(record, config, context):
    bounded(record)
    if config['parser']['kind'] == 'builtin':
        return parse_builtin(record, config)
    arn = config['parser']['version_arn']
    if arn not in allowed_parser_arns():
        raise InvalidRecord('parser_version_not_allowed')
    response = lambda_client(arn).invoke(
        FunctionName=arn, InvocationType='RequestResponse',
        Payload=encode({'contract_version': '1', 'record': record, 'context': context}).encode())
    stream = response['Payload']
    try:
        data = stream.read(MAX_RECORD_BYTES + 1)
    finally:
        stream.close()
    if response.get('FunctionError'):
        # Customer code may fail transiently. Retry via SQS, then DLQ, never log its body.
        raise RuntimeError('parser_execution_failed')
    if response.get('StatusCode') != 200:
        raise RuntimeError('parser_invoke_failed')
    if len(data) > MAX_RECORD_BYTES:
        raise InvalidRecord('parser_output_too_large')
    try:
        return bounded(json.loads(data))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidRecord('invalid_parser_json') from exc
