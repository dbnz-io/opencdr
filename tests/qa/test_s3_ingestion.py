"""Upload-to-delivery journeys using real handlers and isolated AWS services."""
import gzip
import io
import json
from datetime import datetime
from unittest.mock import MagicMock
from urllib.parse import quote_plus

import boto3
import pytest

from src.domain.ingestion import InvalidRecord, falco, frame, normalize, validate_config
from src.handlers import s3_ingestion
from src.infra import parser_runtime

ARN = 'arn:aws:lambda:us-east-1:123456789012:function:customer-parser:7'
CONFIG = {'kind': 'falco', 'format': 'ndjson', 'compression': 'none', 'enabled': True,
          'parser': {'kind': 'builtin', 'id': 'falco.json', 'version': '1.0.0'}, 'expected_rev': 0}
FALCO = {'rule': 'Terminal shell in container', 'priority': 'Critical',
         'time': '2026-09-17T13:00:00.123456789Z', 'hostname': 'worker-1', 'source': 'syscall',
         'output_fields': {'user.name': 'root', 'proc.name': 'bash', 'proc.pid': 123,
                           'container.id': 'c123', 'k8s.ns.name': 'production'}}


@pytest.fixture
def ingestion(app, monkeypatch):
    table = boto3.resource('dynamodb').create_table(
        TableName='qa-ingestion', BillingMode='PAY_PER_REQUEST',
        AttributeDefinitions=[{'AttributeName': k, 'AttributeType': 'S'} for k in ('pk', 'sk')],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}])
    monkeypatch.setenv('INGESTION_TABLE_NAME', table.name)
    monkeypatch.setenv('INGESTION_BUCKET', 'qa-ingestion')
    s3 = boto3.client('s3')
    s3.create_bucket(Bucket='qa-ingestion')
    s3.put_bucket_versioning(Bucket='qa-ingestion', VersioningConfiguration={'Status': 'Enabled'})
    app.call('PUT', '/integrations/runtime-prod', CONFIG)
    return app, table, s3


def upload(s3, data, key='ingest/runtime-prod/log + event.json'):
    version = s3.put_object(Bucket='qa-ingestion', Key=key, Body=data)['VersionId']
    return {'Records': [{'messageId': 'message-1', 'body': json.dumps({'Records': [{
        'eventSource': 'aws:s3', 'eventName': 'ObjectCreated:Put',
        's3': {'bucket': {'name': 'qa-ingestion'}, 'object': {'key': quote_plus(key), 'versionId': version}}}]})}]}


def test_falco_upload_to_query_archive_and_notification(ingestion):
    app, table, s3 = ingestion
    event = upload(s3, json.dumps(FALCO))
    assert s3_ingestion.lambda_handler(event, None) == {'batchItemFailures': []}
    batch = app.consume('signals_write', app.signal_writer)
    signal = app.rows('signals')[0]
    assert signal['source'] == 'falco' and signal['actor']['namespace'] == 'runtime'
    assert signal['host']['name'] == 'worker-1' and signal['process']['name'] == 'bash'
    assert signal['cloud_account_id'] is None and signal['response_module'] is None
    datetime.fromisoformat(signal['timestamp'])
    assert len(app.call('GET', '/signals', query={'event_id': signal['event_id']})['items']) == 1
    assert s3_ingestion.lambda_handler(event, None) == {'batchItemFailures': []}
    assert not app.receive('signals_write')['Records']
    assert not app.signal_writer.lambda_handler(batch, None)['batchItemFailures']
    assert len(app.rows('signals')) == len(app.rows('alerts')) == len(app.rows('outbox')) == 1
    from src.handlers.archiver import flatten_signal
    assert json.loads(flatten_signal(signal)['raw_item'])['host']['name'] == 'worker-1'
    app.publish()
    app.consume('notifications', app.notifier)
    mail = app.receive('mailbox')['Records']
    assert len(mail) == 1 and 'worker-1' in json.loads(mail[0]['body'])['Message']
    assert not app.receive('responses')['Records']
    jobs = app.call('GET', '/integrations/runtime-prod/jobs')['items']
    assert jobs[0]['status'] == 'DISPATCHED'
    detail = app.call('GET', '/integrations/runtime-prod/jobs/' + jobs[0]['object_id'])
    assert len(detail['records']) == 1


def test_mixed_records_are_quarantined_without_losing_valid_records(ingestion):
    app, table, s3 = ingestion
    event = upload(s3, json.dumps(FALCO) + '\ninvalid\n' + json.dumps({**FALCO, 'priority': 'Warning'}))
    assert not s3_ingestion.lambda_handler(event, None)['batchItemFailures']
    app.consume('signals_write', app.signal_writer)
    assert len(app.rows('signals')) == 2
    job = app.call('GET', '/integrations/runtime-prod/jobs')['items'][0]
    assert job['status'] == 'PARTIAL' and job['invalid_count'] == 1


def test_retry_uses_persisted_result_after_configuration_and_rule_change(ingestion, monkeypatch):
    app, table, s3 = ingestion
    event = upload(s3, json.dumps(FALCO))
    original = boto3.client
    failing_queue = MagicMock()
    failing_queue.send_message.side_effect = RuntimeError('temporary')
    with monkeypatch.context() as patch:
        patch.setattr(s3_ingestion.boto3, 'client', lambda service, **kwargs: failing_queue if service == 'sqs' else original(service, **kwargs))
        assert s3_ingestion.lambda_handler(event, None)['batchItemFailures']
    app.call('PUT', '/integrations/runtime-prod', {**CONFIG, 'enabled': False, 'expected_rev': 1})
    with monkeypatch.context() as patch:
        patch.setattr(s3_ingestion, 'parse_record', lambda *args: pytest.fail('must reuse persisted result'))
        assert not s3_ingestion.lambda_handler(event, None)['batchItemFailures']
    app.consume('signals_write', app.signal_writer)
    assert len(app.rows('signals')) == 1
    assert app.rows('signals')[0]['provenance']['binding_revision'] == 1


def test_signal_retry_repairs_alert_outbox_transaction(ingestion, monkeypatch):
    app, table, s3 = ingestion
    s3_ingestion.lambda_handler(upload(s3, json.dumps(FALCO)), None)
    batch = app.receive('signals_write')
    from src.infra.aws_handler import AwsHandler
    with monkeypatch.context() as patch:
        patch.setattr(AwsHandler, 'put_alert_with_outbox', MagicMock(side_effect=RuntimeError('outage')))
        assert app.signal_writer.lambda_handler(batch, None)['batchItemFailures']
    assert len(app.rows('signals')) == 1 and not app.rows('alerts')
    assert not app.signal_writer.lambda_handler(batch, None)['batchItemFailures']
    assert len(app.rows('signals')) == len(app.rows('alerts')) == len(app.rows('outbox')) == 1


def test_executable_customer_parser_preview_and_ingestion(ingestion, monkeypatch):
    app, table, s3 = ingestion
    monkeypatch.setenv('CUSTOM_PARSER_ARNS', ARN)
    client = MagicMock()
    def invoke(**kwargs):
        assert kwargs['FunctionName'] == ARN
        if kwargs['InvocationType'] == 'DryRun':
            return {'StatusCode': 204}
        request = json.loads(kwargs['Payload'])
        assert request['contract_version'] == '1'
        assert 'bucket' not in request['context']
        return {'StatusCode': 200, 'Payload': io.BytesIO(json.dumps(falco(FALCO)).encode())}
    client.invoke.side_effect = invoke
    monkeypatch.setattr(parser_runtime, 'lambda_client', lambda arn: client)
    config = {**CONFIG, 'kind': 'custom', 'format': 'lines', 'expected_rev': 1,
              'parser': {'kind': 'lambda', 'version_arn': ARN, 'contract_version': '1'}}
    app.call('PUT', '/integrations/runtime-prod', config)
    preview = app.call('POST', '/integrations/runtime-prod/preview', {'config': config, 'record': 'custom log'})
    assert preview['event']['source'] == 'custom'
    app.rule(conditions=[{'field': 'source', 'op': 'equals', 'value': 'custom'}], response_module='')
    assert not s3_ingestion.lambda_handler(upload(s3, 'custom log'), None)['batchItemFailures']
    app.consume('signals_write', app.signal_writer)
    assert len(app.rows('signals')) == 1 and app.rows('signals')[0]['response_module'] is None
    assert client.invoke.call_count == 3


def test_versioned_overwrite_reads_exact_object(ingestion):
    app, table, s3 = ingestion
    first = upload(s3, json.dumps(FALCO))
    upload(s3, 'not the original object')
    assert not s3_ingestion.lambda_handler(first, None)['batchItemFailures']
    app.consume('signals_write', app.signal_writer)
    assert app.rows('signals')[0]['activity_name'] == FALCO['rule']


def test_config_validation_revision_and_scope(ingestion):
    app, _, _ = ingestion
    app.call('PUT', '/integrations/runtime-prod', CONFIG, status=409)
    app.call('PUT', '/integrations/runtime-prod', {**CONFIG, 'expected_rev': 1, 'enabled': 'yes'}, status=400)
    app.call('PUT', '/integrations/runtime-prod', CONFIG, key='unknown-key', status=403)
    app.call('GET', '/integrations/runtime-prod', key='unknown-key', status=403)
    app.call('PUT', '/integrations/runtime-prod', {**CONFIG, 'parser': {'kind': 'builtin', 'id': 'cloudtrail'}}, status=400)


def test_unversioned_and_missing_bindings_retry_to_dlq(ingestion):
    _, _, s3 = ingestion
    event = upload(s3, json.dumps(FALCO), key='ingest/unregistered/event.json')
    assert s3_ingestion.lambda_handler(event, None)['batchItemFailures']
    body = json.loads(event['Records'][0]['body'])
    body['Records'][0]['s3']['object']['versionId'] = 'null'
    event['Records'][0]['body'] = json.dumps(body)
    assert s3_ingestion.lambda_handler(event, None)['batchItemFailures']


@pytest.mark.parametrize('priority,severity', [('Emergency','CRITICAL'), ('Alert','CRITICAL'), ('Critical','CRITICAL'), ('Error','HIGH'), ('Warning','MEDIUM'), ('Notice','LOW'), ('Informational','INFO'), ('Debug','INFO'), ('unknown','UNKNOWN')])
def test_falco_priorities(priority, severity):
    result = falco({**FALCO, 'priority': priority})
    config = validate_config(CONFIG, 'runtime-prod', 'bucket')
    event = normalize(result, config, event_id='test', provenance={})
    assert event.severity == severity and event.finding['priority'] == priority


@pytest.mark.parametrize('field,value', [('source','cloudtrail'), ('resources', [{'type': 'AWS::IAM::User', 'id': 'admin'}]), ('response_module','disable_user'), ('cloud_account_id','123456789012')])
def test_parser_cannot_forge_privileged_fields(field, value):
    result = falco(FALCO)
    result['event'][field] = value
    with pytest.raises(InvalidRecord, match='forbidden_event_fields'):
        normalize(result, {'kind': 'custom', 'integration_id': 'custom'}, event_id='test', provenance={})


def test_decompression_and_object_limits():
    with pytest.raises(InvalidRecord, match='expanded_object_too_large'):
        frame(gzip.compress(b'x' * (1024 * 1024 + 1)), {'compression': 'gzip', 'format': 'ndjson'})
    with pytest.raises(InvalidRecord, match='invalid_record_count'):
        frame(b'{}\n' * 101, {'compression': 'none', 'format': 'ndjson'})


def test_analysis_replay_is_queryable_without_live_effects(ingestion, monkeypatch):
    app, _, s3 = ingestion
    queue = app.sqs.create_queue(QueueName='qa-ingestion-queue')['QueueUrl']
    monkeypatch.setenv('INGESTION_QUEUE_URL', queue)
    app.queues['ingestion'] = queue
    assert not s3_ingestion.lambda_handler(upload(s3, json.dumps(FALCO)), None)['batchItemFailures']
    app.consume('signals_write', app.signal_writer)
    original = app.call('GET', '/integrations/runtime-prod/jobs')['items'][0]
    replay = app.call('POST', '/integrations/runtime-prod/jobs/' + original['object_id'] + '/replay', {}, status=202)
    app.consume('ingestion', s3_ingestion)
    app.consume('signals_write', app.signal_writer)
    signals = app.call('GET', '/signals', query={'integration_id': 'runtime-prod'})['items']
    assert len(signals) == 2
    analysis = [s for s in signals if s['provenance']['mode'] == 'analysis'][0]
    assert analysis['provenance']['replay_run'] == replay['run_id']
    assert analysis['notify'] is False
    assert len(app.rows('alerts')) == len(app.rows('outbox')) == 1
    from src.domain.correlation_engine import CorrelationEngine
    repo = MagicMock()
    assert CorrelationEngine(repo=repo).correlate(new_signal=analysis, rules=[]) == []
    repo.query_signals.assert_not_called()


def test_all_notification_builders_preserve_context_without_iam_invention(ingestion):
    app, _, s3 = ingestion
    s3_ingestion.lambda_handler(upload(s3, json.dumps(FALCO)), None)
    app.consume('signals_write', app.signal_writer)
    item = app.rows('alerts')[0]
    notifier = app.notifier
    payloads = [notifier.build_slack_payload(item), notifier.build_discord_payload(item),
                notifier.build_email_message(item), notifier.build_jira_issue(item, project_key='TEST')]
    assert all('worker-1' in json.dumps(p) for p in payloads)
    finding = notifier.build_securityhub_finding(item, product_arn='arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default', account_id='123456789012')
    assert finding['Resources'][0]['Type'] == 'Other'
    assert 'arn:aws:iam' not in json.dumps(finding)
    assert len(finding['CreatedAt']) < 40


def test_aws_response_blocked_even_for_forged_legacy_rule(ingestion, monkeypatch):
    app, _, _ = ingestion
    logger = MagicMock()
    dredge = MagicMock()
    monkeypatch.setattr(app.responder, '_get_dredge', dredge)
    app.responder._process_record({'body': json.dumps({'source': 'falco', 'response_module': 'disable_user',
                                 'actor': {'user_name': 'root'}, 'cloud_account_id': '123456789012'})}, None, None, logger)
    dredge.assert_not_called()
    assert logger.warning.call_args.kwargs['event_name'] == 'IR_UNSUPPORTED_SOURCE'
    rule = {'rule_kind': 'signal', 'rule_id': 'test-falco-response', 'severity': 'HIGH',
            'response_module': 'disable_user', 'conditions': [{'field': 'source', 'op': 'equals', 'value': 'falco'}]}
    app.call('POST', '/rules', rule, status=400)


def test_disabled_stock_override_does_not_reenable_fallback(ingestion):
    app, _, s3 = ingestion
    rule = {'rule_kind': 'signal', 'rule_id': 'falco/finding-critical-v1', 'severity': 'CRITICAL',
            'enabled': False, 'conditions': [{'field': 'source', 'op': 'equals', 'value': 'falco'}]}
    app.call('POST', '/rules', rule, status=201)
    assert not s3_ingestion.lambda_handler(upload(s3, json.dumps(FALCO)), None)['batchItemFailures']
    assert not app.receive('signals_write')['Records']


def test_runtime_correlation_is_scoped_and_uses_integration_index(ingestion):
    app, _, s3 = ingestion
    app.rule('cloudtrail/021_correlation_iam_activity_burst.json',
             rule_id='runtime-burst', response_module='', threshold=2,
             group_by='runtime_entity', signal_conditions=[
                 {'field': 'integration_id', 'op': 'equals', 'value': 'runtime-prod'},
                 {'field': 'source', 'op': 'equals', 'value': 'falco'}])
    app.rule('cloudtrail/021_correlation_iam_activity_burst.json',
             rule_id='unsafe-generic-root-correlation', response_module='', threshold=2,
             signal_conditions=[{'field': 'source', 'op': 'equals', 'value': 'falco'}])
    records = [FALCO, {**FALCO, 'hostname': 'different-worker'}, FALCO]
    assert not s3_ingestion.lambda_handler(upload(s3, '\n'.join(json.dumps(r) for r in records)), None)['batchItemFailures']
    app.consume('signals_write', app.signal_writer)
    result = app.alerter.lambda_handler(app.stream('signals'), None)
    assert result['alerts_stored'] == 1
    correlations = [a['payload'] for a in app.rows('alerts') if a.get('payload', {}).get('type') == 'correlation']
    assert len(correlations) == 1 and correlations[0]['rule_id'] == 'runtime-burst'
    assert correlations[0]['match_count'] == 2
    assert correlations[0]['primary_signal']['host']['name'] == 'worker-1'
