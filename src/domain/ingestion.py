"""Versioned, bounded parser contract. No AWS credentials or routing in parser output."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import zlib
from datetime import datetime

from .ocsf_min_parser import Actor, Network, NormalizedEvent

MAX_OBJECT_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024
MAX_RECORDS = 100
MAX_RESULT_BYTES = 128 * 1024
SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'}
CONTEXT_FIELDS = ('host', 'process', 'container', 'kubernetes', 'finding', 'vendor')
PRIORITIES = dict(zip(
    ('Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Informational', 'Debug'),
    ('CRITICAL', 'CRITICAL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'INFO'), strict=True))


class InvalidRecord(ValueError):
    """Permanent, safe-to-display diagnostic code (never raw input)."""


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def identity(*parts):
    return hashlib.sha256(encode(parts).encode()).hexdigest()


def bounded(value, limit=MAX_RECORD_BYTES):
    try:
        if len(encode(value).encode()) > limit:
            raise InvalidRecord('payload_too_large')
    except (TypeError, ValueError, RecursionError) as exc:
        raise InvalidRecord('invalid_or_oversized_json') from exc
    return value


def validate_config(value, integration_id, bucket, allowed_arns=()):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', integration_id):
        raise InvalidRecord('invalid_integration_id')
    if not isinstance(value, dict) or set(value) - {'kind', 'format', 'compression', 'parser', 'enabled', 'expected_rev'}:
        raise InvalidRecord('invalid_configuration_fields')
    kind = value.get('kind')
    parser = value.get('parser', {})
    if not isinstance(parser, dict):
        raise InvalidRecord('invalid_parser')
    if kind != 'custom':
        if (set(parser) != {'kind', 'id', 'version'} or parser.get('kind') != 'builtin'
                or not all(isinstance(parser.get(k), str) for k in ('id', 'version'))):
            raise InvalidRecord('unsupported_builtin_parser')
        entry = BUILTIN_PARSERS.get((parser['id'], parser['version']))
        if not entry or entry['source'] != kind:
            raise InvalidRecord('unsupported_builtin_parser')
    elif kind == 'custom':
        arn = parser.get('version_arn', '')
        if (set(parser) != {'kind', 'version_arn', 'contract_version'}
                or parser.get('kind') != 'lambda' or parser.get('contract_version') != '1'
                or not isinstance(arn, str)
                or not re.fullmatch(r'arn:aws[a-z-]*:lambda:[a-z0-9-]+:\d{12}:function:[A-Za-z0-9_-]+:[1-9][0-9]*', arn)
                or arn not in allowed_arns):
            raise InvalidRecord('parser_version_not_allowed')
    if not isinstance(value.get('format'), str) or value.get('format') not in {'json', 'ndjson', 'lines'} or (kind == 'falco' and value['format'] == 'lines'):
        raise InvalidRecord('unsupported_format')
    if not isinstance(value.get('compression', 'none'), str) or value.get('compression', 'none') not in {'none', 'gzip'}:
        raise InvalidRecord('unsupported_compression')
    if type(value.get('enabled', False)) is not bool:
        raise InvalidRecord('invalid_enabled')
    return {'integration_id': integration_id, 'kind': kind, 'parser': parser,
            'format': value['format'], 'compression': value.get('compression', 'none'),
            'enabled': value.get('enabled', False), 'bucket': bucket,
            'prefix': f'ingest/{integration_id}/'}


def frame(data, config):
    if len(data) > MAX_OBJECT_BYTES:
        raise InvalidRecord('object_too_large')
    try:
        if config['compression'] == 'gzip':
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                data = stream.read(MAX_OBJECT_BYTES + 1)
        if len(data) > MAX_OBJECT_BYTES:
            raise InvalidRecord('expanded_object_too_large')
        text = data.decode('utf-8')
    except (OSError, EOFError, UnicodeError, zlib.error) as exc:
        raise InvalidRecord('invalid_encoding_or_compression') from exc
    records = [text] if config['format'] == 'json' else text.splitlines()
    if not records or len(records) > MAX_RECORDS:
        raise InvalidRecord('invalid_record_count')
    return records


def decode_record(text, config):
    if len(text.encode()) > MAX_RECORD_BYTES:
        raise InvalidRecord('record_too_large')
    if config['format'] == 'lines':
        return text
    try:
        return bounded(json.loads(text))
    except (ValueError, RecursionError) as exc:
        raise InvalidRecord('invalid_record_json') from exc


def falco(record):
    if not isinstance(record, dict) or not isinstance(record.get('output_fields'), dict):
        raise InvalidRecord('invalid_falco_record')
    if not isinstance(record.get('priority'), str):
        raise InvalidRecord('invalid_falco_priority')
    f = record['output_fields']
    def fields(mapping):
        return {dest: f[key] for key, dest in mapping.items() if f.get(key) is not None}
    return {'status': 'parsed', 'event': {
        'time': record.get('time'), 'category': 'runtime', 'class_name': 'security_finding',
        'activity_name': record.get('rule'), 'severity': PRIORITIES.get(record.get('priority'), 'UNKNOWN'),
        'actor': {'user_name': f.get('user.name'), 'user_id': str(f['user.uid']) if 'user.uid' in f else None},
        'host': {'name': record.get('hostname') or f.get('host.name')},
        'process': fields({'proc.name': 'name', 'proc.pid': 'pid', 'proc.cmdline': 'command_line', 'proc.pname': 'parent_name'}),
        'container': fields({'container.id': 'id', 'container.name': 'name', 'container.image.repository': 'image'}),
        'kubernetes': fields({'k8s.ns.name': 'namespace', 'k8s.pod.name': 'pod', 'k8s.node.name': 'node', 'k8s.cluster.name': 'cluster'}),
        'finding': {'rule_name': record.get('rule'), 'priority': record.get('priority')},
        'vendor': {'event_source': record.get('source'), 'tags': record.get('tags', [])},
    }}


# Adding a maintained parser requires an immutable registry entry plus fixtures,
# schema/catalog documentation and publication review; transport stays unchanged.
BUILTIN_PARSERS = {('falco.json', '1.0.0'): {'source': 'falco', 'parse': falco}}


def builtin_catalog():
    return [{'kind': 'builtin', 'id': name, 'version': version}
            for name, version in BUILTIN_PARSERS]


def parse_builtin(record, config):
    parser = config['parser']
    entry = BUILTIN_PARSERS.get((parser.get('id'), parser.get('version')))
    if not entry or entry['source'] != config['kind']:
        raise InvalidRecord('unsupported_builtin_parser')
    return entry['parse'](record)


def normalize(result, config, *, event_id, provenance):
    bounded(result)
    if not isinstance(result, dict):
        raise InvalidRecord('invalid_parser_response')
    status = result.get('status')
    if status in {'dropped', 'invalid'}:
        if set(result) != {'status', 'code'} or not re.fullmatch(r'[a-z0-9_]{1,64}', str(result.get('code', ''))):
            raise InvalidRecord('invalid_diagnostic')
        if status == 'invalid':
            raise InvalidRecord(result['code'])
        return None
    if status != 'parsed' or set(result) != {'status', 'event'} or not isinstance(result['event'], dict):
        raise InvalidRecord('invalid_parser_response')
    e = result['event']
    allowed = {'time', 'category', 'class_name', 'activity_name', 'severity', 'actor', 'network', *CONTEXT_FIELDS}
    if set(e) - allowed:
        raise InvalidRecord('forbidden_event_fields')
    for key in ('time', 'category', 'class_name', 'activity_name', 'severity'):
        if not isinstance(e.get(key), str) or not 0 < len(e[key]) <= 512:
            raise InvalidRecord('missing_or_invalid_event_field')
    try:
        if datetime.fromisoformat(e['time'].replace('Z', '+00:00')).tzinfo is None:
            raise ValueError()
    except ValueError as exc:
        raise InvalidRecord('invalid_event_time') from exc
    if e['severity'] not in SEVERITIES:
        raise InvalidRecord('invalid_severity')
    for key in CONTEXT_FIELDS:
        if not isinstance(e.get(key, {}), dict):
            raise InvalidRecord('invalid_context')
    context_keys = {
        'host': {'id', 'name'}, 'process': {'name', 'pid', 'command_line', 'parent_name'},
        'container': {'id', 'name', 'image'}, 'kubernetes': {'cluster', 'namespace', 'pod', 'node', 'workload', 'service_account'},
        'finding': {'rule_name', 'priority'}, 'vendor': {'event_source', 'tags'},
    }
    for context_key, allowed_keys in context_keys.items():
        values = e.get(context_key, {})
        if set(values) - allowed_keys:
            raise InvalidRecord('unknown_context_field')
        for key, value in values.items():
            if value is None:
                continue
            if context_key == 'process' and key == 'pid':
                if type(value) is not int or value < 0:
                    raise InvalidRecord('invalid_process_pid')
            elif context_key == 'vendor' and key == 'tags':
                if not isinstance(value, list) or len(value) > 32 or any(not isinstance(v, str) or len(v) > 128 for v in value):
                    raise InvalidRecord('invalid_vendor_tags')
            elif not isinstance(value, str) or len(value) > (2048 if key == 'command_line' else 512):
                raise InvalidRecord('invalid_context_value')
    for key, keys in [('actor', {'user_name', 'user_id'}), ('network', {'source_ip', 'user_agent'})]:
        fields = e.get(key, {})
        if not isinstance(fields, dict) or set(fields) - keys or any(v is not None and (not isinstance(v, str) or len(v) > 1024) for v in fields.values()):
            raise InvalidRecord('invalid_identity_or_network')
    entity = e.get('container', {}).get('id') or e.get('host', {}).get('id') or e.get('host', {}).get('name')
    runtime_entity = config['integration_id'] + ':' + identity(e.get('host', {}).get('name'), entity) if entity else None
    return NormalizedEvent(
        event_id=event_id, source=config['kind'] if config.get('parser', {}).get('kind') == 'builtin' else 'custom',
        time=e['time'], category=e['category'], class_name=e['class_name'],
        activity_name=e['activity_name'], severity=e['severity'], cloud_provider=None,
        actor=Actor(**e.get('actor', {}), namespace='runtime' if config['kind'] == 'falco' else 'custom'),
        network=Network(**e.get('network', {})), integration_id=config['integration_id'], runtime_entity=runtime_entity,
        provenance=provenance, **{key: e.get(key, {}) for key in CONTEXT_FIELDS})


def stock_falco_rules():
    """One non-overlapping finding rule per severity; customer rules remain additive."""
    return [{'rule_id': f'falco/finding-{severity.lower()}-v1', 'severity': severity,
             'notify': severity in {'CRITICAL', 'HIGH', 'MEDIUM'}, 'enabled': True,
             'conditions': [{'field': 'source', 'op': 'equals', 'value': 'falco'},
                            {'field': 'severity', 'op': 'equals', 'value': severity}]}
            for severity in sorted(SEVERITIES)]
