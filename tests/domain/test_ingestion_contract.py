import io
import json
from unittest.mock import MagicMock

import pytest

from src.domain.ingestion import InvalidRecord, normalize, validate_config
from src.infra import parser_runtime

ARN = 'arn:aws:lambda:us-east-1:123456789012:function:parser:7'
CONFIG = {'kind': 'custom', 'format': 'json', 'parser': {'kind': 'lambda', 'version_arn': ARN, 'contract_version': '1'}}


@pytest.mark.parametrize('arn', [ARN.rsplit(':', 1)[0], ARN.rsplit(':', 1)[0]+':latest', ARN.rsplit(':', 1)[0]+':$LATEST'])
def test_mutable_parsers_are_rejected_even_when_allowlisted(arn):
    with pytest.raises(InvalidRecord, match='parser_version_not_allowed'):
        validate_config({**CONFIG, 'parser': {**CONFIG['parser'], 'version_arn': arn}}, 'custom', 'bucket', [arn])


@pytest.mark.parametrize('response,exception', [
    ({'FunctionError': 'Unhandled', 'body': b'private exception details'}, RuntimeError),
    ({'body': b'[]'}, None),
    ({'body': b'invalid'}, InvalidRecord),
    ({'body': b'x'*17000}, InvalidRecord),
])
def test_lambda_execution_errors_and_bounded_output(monkeypatch, response, exception):
    monkeypatch.setenv('CUSTOM_PARSER_ARNS', ARN)
    client = MagicMock()
    client.invoke.return_value = {'StatusCode': 200, **response, 'Payload': io.BytesIO(response['body'])}
    monkeypatch.setattr(parser_runtime, 'lambda_client', lambda arn: client)
    if exception:
        with pytest.raises(exception):
            parser_runtime.parse_record({}, CONFIG, {})
    else:
        result = parser_runtime.parse_record({}, CONFIG, {})
        with pytest.raises(InvalidRecord):
            normalize(result, CONFIG, event_id='test', provenance={})
    assert client.invoke.return_value['Payload'].closed


def test_dropped_and_invalid_are_distinct():
    assert normalize({'status': 'dropped', 'code': 'known_noise'}, CONFIG, event_id='x', provenance={}) is None
    with pytest.raises(InvalidRecord, match='missing_field'):
        normalize({'status': 'invalid', 'code': 'missing_field'}, CONFIG, event_id='x', provenance={})
    with pytest.raises(InvalidRecord, match='invalid_diagnostic'):
        normalize({'status': 'invalid', 'code': 'private raw data!'}, CONFIG, event_id='x', provenance={})


def test_customer_example_matches_real_contract():
    from support_files.parsers.example import lambda_handler
    config = {**CONFIG, 'integration_id': 'example'}
    result = lambda_handler({'contract_version': '1', 'record': {'timestamp': '2026-09-17T12:00:00Z', 'message': 'Login', 'level': 'error'}}, None)
    event = normalize(result, config, event_id='test', provenance={})
    assert event.severity == 'HIGH' and event.cloud_provider is None
    assert 'credentials' not in json.dumps(event.to_dict())
