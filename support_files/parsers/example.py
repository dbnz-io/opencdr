"""Customer-owned Lambda: publish a numeric version before registering its ARN.

No boto3, OpenCDR credentials, side effects or network access are needed to parse.
Input: {contract_version: "1", record: <JSON or string>, context: {...}}.
"""

def lambda_handler(event, context):
    if event.get('contract_version') != '1':
        return {'status': 'invalid', 'code': 'unsupported_contract'}
    record = event['record']
    if not isinstance(record, dict) or not record.get('timestamp') or not record.get('message'):
        return {'status': 'invalid', 'code': 'missing_timestamp_or_message'}
    if record.get('debug') is True:
        return {'status': 'dropped', 'code': 'debug_record'}
    return {'status': 'parsed', 'event': {
        'time': record['timestamp'], 'category': 'application',
        'class_name': 'security_finding', 'activity_name': record['message'],
        'severity': 'HIGH' if record.get('level') == 'error' else 'INFO',
        'host': {'name': record.get('hostname')},
    }}
