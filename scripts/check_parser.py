#!/usr/bin/env python3
"""Run a trusted local customer parser against OpenCDR's real v1 validator."""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.domain.ingestion import bounded, normalize  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('module', type=Path, help='Trusted local Python module with lambda_handler')
    parser.add_argument('sample', type=Path, help='JSON record fixture')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('customer_parser', args.module)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.lambda_handler({'contract_version': '1', 'record': bounded(json.loads(args.sample.read_text())),
                                   'context': {'integration_id': 'local-test', 'event_id': 'local-test'}}, None)
    event = normalize(result, {'kind': 'custom', 'integration_id': 'local-test'}, event_id='local-test', provenance={})
    print(json.dumps({'status': result['status'], 'event': event.to_dict() if event else None}, indent=2))


if __name__ == '__main__':
    main()
