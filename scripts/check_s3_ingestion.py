#!/usr/bin/env python3
"""Staging canary: upload a synthetic non-notifying Falco finding and verify storage.

Uses the configured OpenCDR API and current AWS profile. Does not configure IAM,
activate integrations or alter detection rules. Use a dedicated staging binding.
"""
import argparse
import json
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import boto3
import opencdr

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.domain.ingestion import identity  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('integration_id')
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    url, key = opencdr._require_api(opencdr._load_config())
    def request(path):
        status, body = opencdr._request('GET', path, url, key)
        opencdr._die_on_error(status, body, 'S3 canary')
        return body
    config = request('/integrations/' + args.integration_id)
    if config['kind'] != 'falco' or not config['enabled'] or config['compression'] != 'none':
        raise SystemExit('Canary requires an enabled Falco integration with compression=none')
    record = {'time': datetime.now(UTC).isoformat(), 'rule': 'OpenCDR staging canary',
              'priority': 'Informational', 'source': 'syscall', 'hostname': 'opencdr-canary', 'output_fields': {}}
    object_key = config['prefix'] + 'canary-' + str(uuid.uuid4()) + '.json'
    result = boto3.client('s3').put_object(Bucket=config['bucket'], Key=object_key, Body=json.dumps(record).encode())
    job_id = identity(args.integration_id, config['bucket'], object_key, result['VersionId'], None)
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        status, job = opencdr._request('GET', f'/integrations/{args.integration_id}/jobs/{job_id}', url, key)
        if status == 200 and job['status'] == 'DISPATCHED':
            event_id = identity(job_id, 0)
            signals = request('/signals?event_id=' + event_id)['items']
            if signals:
                if not all(s['source'] == 'falco' and s['provenance']['version_id'] == result['VersionId'] for s in signals):
                    raise SystemExit('Canary provenance mismatch')
                print(json.dumps({'status': 'passed', 'object_id': job_id, 'signals': len(signals)}))
                return
        elif status == 200 and job['status'] in {'QUARANTINED', 'PARTIAL'}:
            raise SystemExit('Canary quarantined; inspect the ingestion job')
        elif status not in {200, 404}:
            opencdr._die_on_error(status, job, 'S3 canary')
        time.sleep(3)
    raise SystemExit('Canary timed out; inspect queue/DLQ and job status')


if __name__ == '__main__':
    main()
