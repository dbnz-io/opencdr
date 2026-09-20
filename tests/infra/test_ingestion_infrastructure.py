"""Deployment contract checks without AWS credentials."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def template():
    return yaml.load((ROOT / 'serverless.yml').read_text(), Loader=yaml.BaseLoader)


def test_bucket_versions_private_delivery_and_bounded_queue():
    t = template()
    resources = t['resources']['Resources']
    bucket = resources['IngestionBucket']['Properties']
    assert bucket['VersioningConfiguration']['Status'] == 'Enabled'
    assert all(v == 'true' for v in bucket['PublicAccessBlockConfiguration'].values())
    assert resources['IngestionBucket']['DependsOn'] == 'IngestionQueuePolicy'
    policy = resources['IngestionQueuePolicy']['Properties']['PolicyDocument']['Statement'][0]
    assert policy['Principal'] == {'Service': 's3.amazonaws.com'}
    assert set(policy['Condition']) == {'StringEquals', 'ArnEquals'}
    worker = t['functions']['s3Ingestion']
    assert worker['events'][0]['sqs']['functionResponseType'] == 'ReportBatchItemFailures'
    assert int(resources['IngestionQueue']['Properties']['VisibilityTimeout']) >= 6 * int(worker['timeout'])
    assert resources['CustomParserInvokePolicy']['Condition'] == 'HasCustomParsers'


def test_api_routes_are_private_and_documented():
    t = template()
    routes = {(e['http']['path'], e['http']['method']) for e in t['functions']['api']['events'] if 'http' in e and e['http']['path'].startswith('integrations')}
    spec = yaml.safe_load((ROOT / 'openapi.yml').read_text())
    assert len(routes) == 7
    for path, method in routes:
        assert method in spec['paths']['/' + path]
    assert all(e['http']['private'] == 'true' for e in t['functions']['api']['events'] if 'http' in e and e['http']['path'].startswith('integrations'))


def test_all_new_explicit_cloudformation_references_resolve():
    # Includes Serverless-generated API role; existing refs were already packaged.
    t = template()
    text = (ROOT / 'serverless.yml').read_text()
    import re
    names = set(t['resources']['Resources']) | {'ApiIamRoleLambdaExecution'}
    for ref in re.findall(r'!(?:Ref|GetAtt) (Ingestion[A-Za-z]+|ApiIamRoleLambdaExecution)', text):
        assert ref in names
