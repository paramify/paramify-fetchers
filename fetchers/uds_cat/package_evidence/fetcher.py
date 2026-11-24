#!/usr/bin/env python3
"""Retain the complete evidence graph of explicitly pinned CAT attestations."""

import base64
import binascii
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote, urlsplit

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / '_lib'))
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger('uds_cat_package_evidence')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
PREDICATES = {'chainloop.dev/attestation/v0.1.2', 'chainloop.dev/attestation/v0.2'}
MAX_STATEMENT_BYTES = 16 * 1024 * 1024
CODES = {401: 'auth_failed', 403: 'not_authorized', 429: 'rate_limited'}


class FetchError(Exception):
    def __init__(self, message, code='partial_failure'):
        super().__init__(message)
        self.code = code


def required(name):
    value = os.environ.get(name, '').strip()
    if not value:
        raise FetchError(f'{name} is not set', 'bad_config')
    return value


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FetchError('CAT JSON contains duplicate keys')
        result[key] = value
    return result


def decode_json(content):
    try:
        return json.loads(content, object_pairs_hook=unique_keys,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise FetchError('CAT object is not supported JSON') from exc


def one_alias(obj, names, default=None):
    present = [obj[n] for n in names if n in obj]
    if len(present) > 1:
        raise FetchError('CAT JSON contains ambiguous field aliases')
    return present[0] if present else default


def configuration():
    url = required('CAT_URL')
    try:
        p = urlsplit(url)
        valid = (p.scheme == 'https' and p.hostname and p.path in ('', '/')
                 and not p.username and not p.password and not p.query and not p.fragment and p.port != 0)
    except ValueError:
        valid = False
    if not valid:
        raise FetchError('CAT_URL must be an HTTPS origin without userinfo, path, query or fragment', 'bad_config')
    org = required('CAT_ORGANIZATION')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', org):
        raise FetchError('CAT_ORGANIZATION must be one organization name', 'bad_config')
    roots = decode_json(required('CAT_ATTESTATION_DIGESTS'))
    expected = decode_json(os.environ.get('CAT_EXPECTED_MATERIALS', '[]'))
    subject, token = required('CAT_SUBJECT_DIGEST'), required('CAT_API_TOKEN')
    if (not isinstance(roots, list) or not roots or len(roots) > 32
            or any(not isinstance(x, str) or not DIGEST.fullmatch(x) for x in roots)
            or len(roots) != len(set(roots)) or not DIGEST.fullmatch(subject)):
        raise FetchError('Supply unique SHA256 attestation roots and a SHA256 subject', 'bad_config')
    if not isinstance(expected, list) or any(not isinstance(x, str) or not x.strip() for x in expected):
        raise FetchError('CAT_EXPECTED_MATERIALS must be a JSON array of exact material names', 'bad_config')
    if '\n' in token or '\r' in token:
        raise FetchError('CAT_API_TOKEN must be a single line', 'bad_config')
    ca = os.environ.get('CAT_CA_BUNDLE', '').strip()
    if ca and not Path(ca).is_file():
        raise FetchError('CAT_CA_BUNDLE must name an existing PEM trust bundle', 'bad_config')
    limits = {}
    for field, env, default in [('max_object_bytes', 'CAT_MAX_OBJECT_BYTES', 200 * 1024 * 1024),
                                ('max_total_bytes', 'CAT_MAX_TOTAL_BYTES', 1024 * 1024 * 1024),
                                ('max_objects', 'CAT_MAX_OBJECTS', 1000)]:
        try:
            limits[field] = int(os.environ.get(env, str(default)))
        except ValueError as exc:
            raise FetchError(f'{env} must be a positive integer', 'bad_config') from exc
        if limits[field] <= 0:
            raise FetchError(f'{env} must be a positive integer', 'bad_config')
    return {'url': url.rstrip('/'), 'organization': org, 'roots': roots, 'subject': subject,
            'package_ref': required('CAT_PACKAGE_REF'), 'expected': expected, 'token': token,
            'ca': ca or True, **limits}


def statement(content):
    if len(content) > MAX_STATEMENT_BYTES:
        raise FetchError('CAT statement exceeds the JSON parsing limit')
    obj = decode_json(content)
    if not isinstance(obj, dict):
        raise FetchError('CAT attestation must be an object')
    container = 'unsigned_statement'
    if 'dsseEnvelope' in obj or 'payloadType' in obj:
        envelope = obj.get('dsseEnvelope', obj)
        if (not isinstance(envelope, dict) or envelope.get('payloadType') != 'application/vnd.in-toto+json'
                or not isinstance(envelope.get('payload'), str) or not envelope.get('signatures')):
            raise FetchError('CAT DSSE envelope is malformed')
        try:
            obj = decode_json(base64.b64decode(envelope['payload'], validate=True))
        except (ValueError, binascii.Error) as exc:
            raise FetchError('CAT DSSE payload is not base64') from exc
        container = 'dsse_present_unverified'
    if (not isinstance(obj, dict)
            or one_alias(obj, ('_type', 'type')) not in ('https://in-toto.io/Statement/v0.1', 'https://in-toto.io/Statement/v1')
            or one_alias(obj, ('predicateType', 'predicate_type')) not in PREDICATES
            or not isinstance(obj.get('subject'), list) or not isinstance(obj.get('predicate'), dict)
            or not isinstance(obj['predicate'].get('materials'), list)):
        raise FetchError('CAT statement or Chainloop predicate is unsupported')
    return obj, container


def sha256_of(item):
    hashes = item.get('digest')
    value = 'sha256:' + str(hashes.get('sha256', '')) if isinstance(hashes, dict) else ''
    if not DIGEST.fullmatch(value):
        raise FetchError('CAT material has no supported SHA256 content digest')
    return value


def flag(annotations, name):
    value = annotations.get(name, False)
    if type(value) is not bool and value not in ('true', 'false'):
        raise FetchError('CAT material has an invalid storage annotation')
    return value is True or value == 'true'


def output_name(cfg):
    identity = [cfg[k] for k in ('url', 'organization', 'package_ref', 'roots', 'subject', 'expected')]
    return 'uds_cat_package_evidence_' + hashlib.sha256(json.dumps(identity).encode()).hexdigest() + '.json'


def atomic_write(path, content):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, suffix='.part', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def collect(session, cfg, output):
    identity = Path(output_name(cfg)).stem
    directory = output / '_attachments' / identity
    try:
        if (output / '_attachments').is_symlink():
            raise OSError('attachment directory is a symlink')
        directory.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise FetchError('CAT output already exists or is not writable; use a new run directory', 'bad_config') from exc
    record = {'source': {'url': cfg['url'], 'organization': cfg['organization'], 'attestation_roots': cfg['roots']},
              'configured_package_ref': cfg['package_ref'], 'requested_subject_digest': cfg['subject'],
              'signature_verification': 'not_performed', 'statements': [], 'materials': [], 'attachments': [],
              'metadata': {'partial_failure': False, 'api_failures': []}}
    retained, errors, visited, adjacency, bindings = {}, [], set(), {}, set()
    downloaded = 0

    def failure(operation, exc):
        errors.append({'operation': operation, 'type': exc.code if isinstance(exc, FetchError) else 'partial_failure',
                       'message': str(exc) if isinstance(exc, FetchError) else 'CAT local evidence operation failed'})

    def retain(digest, filename, inline=None):
        nonlocal downloaded
        if digest in retained:
            return retained[digest]
        if not DIGEST.fullmatch(digest) or len(retained) >= cfg['max_objects']:
            raise FetchError('CAT content digest or object-count limit is invalid')
        suffix = Path(str(filename)).suffix.lower()
        if not re.fullmatch(r'\.[a-z0-9]{1,10}', suffix):
            suffix = '.bin'
        path = directory / (digest[7:] + suffix)
        response, temporary = None, None
        try:
            if inline is None:
                url = cfg['url'] + '/api/v1/artifacts/' + quote(cfg['organization'], safe='') + '/' + quote(digest, safe='')
                response = session.get(url, headers={'Authorization': 'Bearer ' + cfg['token'],
                                       'Accept': 'application/octet-stream', 'Accept-Encoding': 'identity'},
                                       timeout=(10, 120), stream=True, allow_redirects=False, verify=cfg['ca'])
                if response.status_code != 200:
                    raise FetchError(f'CAT artifact read failed (HTTP {response.status_code})', CODES.get(response.status_code, 'partial_failure'))
                if response.headers.get('Content-Encoding', 'identity').lower() not in ('', 'identity'):
                    raise FetchError('CAT encoded transfer would change original bytes')
            hasher, size = hashlib.sha256(), 0
            with tempfile.NamedTemporaryFile(dir=directory, suffix='.part', delete=False) as handle:
                temporary = Path(handle.name)
                chunks = response.iter_content(chunk_size=1024 * 1024) if response is not None else [inline]
                for chunk in chunks:
                    size += len(chunk)
                    downloaded += len(chunk)
                    if size > cfg['max_object_bytes'] or downloaded > cfg['max_total_bytes']:
                        raise FetchError('CAT original exceeds configured object or total byte limit')
                    handle.write(chunk)
                    hasher.update(chunk)
            length = response.headers.get('Content-Length') if response is not None else None
            if length is not None and (not length.isdecimal() or int(length) != size):
                raise FetchError('CAT artifact content length is invalid or truncated')
            if 'sha256:' + hasher.hexdigest() != digest:
                raise FetchError('CAT artifact bytes do not match the declared digest')
            os.link(temporary, path)
            descriptor = {'path': path.relative_to(output).as_posix(), 'sha256': digest[7:], 'bytes': size}
            record['attachments'].append(descriptor)
            retained[digest] = descriptor
            return descriptor
        except requests.RequestException as exc:
            raise FetchError('CAT artifact connection failed', 'target_unreachable') from exc
        finally:
            if response is not None:
                response.close()
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    queue = list(cfg['roots'])
    names = set()
    while queue:
        root = queue.pop(0)
        if root in visited:
            continue
        visited.add(root)
        adjacency[root] = []
        try:
            item = retain(root, 'attestation.json')
            parsed, container = statement((output / item['path']).read_bytes())
            record['statements'].append({'content_digest': root, 'container': container,
                                         'subject': parsed['subject'], 'predicate': parsed['predicate'],
                                         'statement_type': one_alias(parsed, ('_type', 'type')),
                                         'predicate_type': one_alias(parsed, ('predicateType', 'predicate_type'))})
            for subject in parsed['subject']:
                if not isinstance(subject, dict) or not isinstance(subject.get('digest'), dict):
                    raise FetchError('CAT statement subject is malformed')
                if subject['digest'].get('sha256') == cfg['subject'][7:]:
                    bindings.add(root)
            materials = list(parsed['predicate']['materials'])
            policy_ref = one_alias(parsed['predicate'], ('policyEvaluationsRef', 'policy_evaluations_ref'))
            if policy_ref is not None:
                if not isinstance(policy_ref, dict):
                    raise FetchError('CAT policy-evaluation reference is malformed')
                if not isinstance(policy_ref.get('annotations', {}), dict):
                    raise FetchError('CAT policy-reference annotations are malformed')
                materials.append({**policy_ref, 'name': 'policy-evaluations.json', 'annotations': {
                    **(policy_ref.get('annotations') or {}), 'chainloop.material.type': 'POLICY_EVALUATIONS',
                    'chainloop.material.name': 'policy-evaluations', 'chainloop.material.cas': True}})
            for index, material in enumerate(materials):
                edge = {'attestation_digest': root, 'index': index, 'descriptor': material, 'status': 'failed'}
                record['materials'].append(edge)
                try:
                    if not isinstance(material, dict) or not isinstance(material.get('annotations', {}), dict):
                        raise FetchError('CAT material descriptor is malformed')
                    a = material.get('annotations', {})
                    kind = a.get('chainloop.material.type')
                    name = a.get('chainloop.material.name', material.get('name'))
                    edge.update(name=name, material_type=kind)
                    if not isinstance(name, str) or not name or not isinstance(kind, str) or not kind:
                        raise FetchError('CAT material name or type is missing')
                    if kind in ('CONTAINER_IMAGE', 'ZARF_PACKAGE') and sha256_of(material) == cfg['subject']:
                        bindings.add(root)
                    inline_cas = flag(a, 'chainloop.material.cas.inline')
                    in_cas = flag(a, 'chainloop.material.cas')
                    if inline_cas or in_cas:
                        content_digest = sha256_of(material)
                        inline = None
                        if inline_cas:
                            try:
                                inline = base64.b64decode(material['content'], validate=True)
                            except (ValueError, TypeError, KeyError, binascii.Error) as exc:
                                raise FetchError('CAT inline material content is not base64') from exc
                        stored = retain(content_digest, material.get('name', name), inline)
                        declared_size = a.get('chainloop.material.size')
                        if declared_size is not None and (not str(declared_size).isdecimal() or int(declared_size) != stored['bytes']):
                            raise FetchError('CAT material size differs from its original bytes')
                        edge.update(status='stored', content_digest=content_digest, original_path=stored['path'])
                        names.add(name)
                        if kind == 'ATTESTATION':
                            adjacency[root].append(content_digest)
                            queue.append(content_digest)
                    elif kind == 'STRING':
                        if not isinstance(material.get('content'), str):
                            raise FetchError('CAT inline STRING content is missing')
                        try:
                            base64.b64decode(material['content'], validate=True)
                        except (ValueError, binascii.Error) as exc:
                            raise FetchError('CAT inline STRING content is not base64') from exc
                        edge['status'] = 'inline'
                        names.add(name)
                    elif kind in ('CONTAINER_IMAGE', 'HELM_CHART', 'ZARF_PACKAGE'):
                        edge['status'] = 'reference_only'
                    else:
                        edge['status'] = 'not_retained'
                        raise FetchError('CAT declares a file material without stored or inline original bytes')
                except (FetchError, OSError) as exc:
                    edge['error'] = str(exc) if isinstance(exc, FetchError) else 'CAT original could not be retained'
                    failure(f'material:{root}:{index}', exc)
        except (FetchError, OSError) as exc:
            failure('attestation:' + root, exc)

    def bound(root):
        pending, seen = [root], set()
        while pending:
            current = pending.pop()
            if current in bindings:
                return True
            if current not in seen:
                seen.add(current)
                pending.extend(adjacency.get(current, []))
        return False

    for root in cfg['roots']:
        if not bound(root):
            failure('subject:' + root, FetchError('CAT root graph does not bind the requested subject'))
    missing = sorted(set(cfg['expected']) - names)
    if missing:
        failure('expected_materials', FetchError('CAT graph is missing configured expected materials'))
    record['metadata'] = {'partial_failure': bool(errors), 'api_failures': errors}
    record['summary'] = {'graph_complete': not errors, 'unique_originals': len(retained),
                         'original_bytes': sum(a['bytes'] for a in retained.values()),
                         'material_references': len(record['materials']),
                         'missing_expected_materials': missing,
                         'expected_population': 'checked' if cfg['expected'] else 'not_configured',
                         'unsupported_outcomes': sum(m.get('descriptor', {}).get('annotations', {}).get('cat.scan.outcome') == 'unsupported'
                                                     for m in record['materials'] if isinstance(m.get('descriptor'), dict)
                                                     and isinstance(m['descriptor'].get('annotations', {}), dict)),
                         'scan_acceptance': 'not_evaluated'}
    return record, bool(errors)


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(name)s %(message)s')
    output = Path(os.environ.get('EVIDENCE_DIR', './evidence'))
    cfg = None
    try:
        cfg = configuration()
        output.mkdir(parents=True, exist_ok=True)
        path = output / output_name(cfg)
        if path.exists():
            raise FetchError('CAT output already exists; use a new run directory', 'bad_config')
        with requests.Session() as session:
            session.trust_env = False
            record, failed = collect(session, cfg, output)
        atomic_write(path, json.dumps(record, indent=2, allow_nan=False).encode())
        logger.info('Evidence saved to %s', path)
        if failed:
            report_failure('CAT package evidence is incomplete; inspect the evidence record', 'partial_failure')
            return 1
        return 0
    except (FetchError, OSError) as exc:
        message = str(exc) if isinstance(exc, FetchError) else 'CAT evidence output is unavailable'
        report_failure(message, exc.code if isinstance(exc, FetchError) else 'internal_error')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
