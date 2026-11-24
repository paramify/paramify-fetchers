"""Whole pinned CAT graph, exact originals, and visible incomplete evidence."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from urllib.parse import unquote

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / 'fetchers/uds_cat/package_evidence/fetcher.py'
SUBJECT = 'sha256:' + '1' * 64


def digest(content):
    return 'sha256:' + hashlib.sha256(content).hexdigest()


def material(name, content, kind='EVIDENCE', **annotations):
    return {'name': name, 'digest': {'sha256': digest(content)[7:]}, 'annotations': {
        'chainloop.material.name': name, 'chainloop.material.type': kind,
        'chainloop.material.cas': True, 'chainloop.material.size': str(len(content)), **annotations}}


def attestation(materials, *, subjects=None, signed=True, **predicate):
    obj = {'_type': 'https://in-toto.io/Statement/v1', 'predicateType': 'chainloop.dev/attestation/v0.2',
           'subject': subjects if subjects is not None else [{'name': 'selected package', 'digest': {'sha256': SUBJECT[7:]}}],
           'predicate': {'materials': materials, **predicate}}
    body = json.dumps(obj).encode()
    if signed:
        body = json.dumps({'dsseEnvelope': {'payloadType': 'application/vnd.in-toto+json',
                          'payload': base64.b64encode(body).decode(),
                          'signatures': [{'sig': 'c3ludGhldGlj', 'keyid': 'test-only'}]}}).encode()
    return body


class Response:
    def __init__(self, body=b'', status=200, headers=None, interrupted=False):
        self.body, self.status_code = body, status
        self.headers = headers or {}
        self.interrupted = interrupted

    def iter_content(self, chunk_size):
        yield self.body[:3]
        if self.interrupted:
            raise requests.ConnectionError('secret-token-in-error')
        yield self.body[3:]

    def close(self):
        pass


class Session:
    def __init__(self, objects):
        self.objects, self.calls = objects, []

    def get(self, url, **kwargs):
        assert url.startswith('https://cat.example.test/api/v1/artifacts/acme/')
        assert kwargs['allow_redirects'] is False and kwargs['verify'] is True
        self.calls.append(url)
        v = self.objects.get(unquote(url.rsplit('/', 1)[1]))
        return v if isinstance(v, Response) else Response(v) if v is not None else Response(status=404)


@pytest.fixture
def mod():
    assert ENTRY.is_file(), 'full CAT package collector is missing'
    spec = importlib.util.spec_from_file_location('cat_package_test', ENTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def graph(tmp_path):
    sbom = b'{ "bomFormat":"CycloneDX", "components": [] }\r\n'
    report = b'{"rules":{"R-1":{"result":"fail"}}}\n'
    unsupported = b'{"outcome":"unsupported","reason":"No matching benchmark"}\n'
    unknown = b'opaque new scanner format\x00\xff'
    policies = b'{"evaluations":[{"violations":[{"message":"failed"}]}]}'
    customer = attestation([material('sbom', sbom, 'SBOM_CYCLONEDX_JSON'), material('future-scan.bin', unknown)], signed=False,
                           metadata={'finishedOn': '2026-11-01T02:00:00Z'})
    root = attestation([material('customer-attestation', customer, 'ATTESTATION'),
                        material('openscap', report, **{'chainloop.evidence.type': 'STIG'}),
                        material('trivy', report, 'SARIF'),
                        material('unsupported', unsupported, **{'chainloop.evidence.type': 'SCAN_OUTCOME', 'cat.scan.outcome': 'unsupported'}),
                        {'name': 'image', 'digest': {'sha256': SUBJECT[7:]}, 'annotations': {'chainloop.material.type': 'CONTAINER_IMAGE'}},
                        {'name': 'version', 'content': base64.b64encode(b'0.1.0').decode(),
                         'annotations': {'chainloop.material.type': 'STRING'}}], subjects=[],
                        policyEvaluationsRef={'digest': {'sha256': digest(policies)[7:]}, 'size': len(policies)},
                        policyHasViolations=True, env={'scanner_version': 'synthetic-1'})
    objects = {digest(x): x for x in [root, customer, sbom, report, unsupported, unknown, policies]}
    cfg = {'url': 'https://cat.example.test', 'organization': 'acme', 'roots': [digest(root)],
           'subject': SUBJECT, 'package_ref': 'acme/demo:0.1.0-amd64', 'expected': ['sbom', 'openscap', 'unsupported'],
           'token': 'fake', 'ca': True, 'max_object_bytes': 1000000, 'max_total_bytes': 10000000,
           'max_objects': 1000}
    out = tmp_path / 'evidence'
    out.mkdir()
    return cfg, objects, out


def run_collect(mod, graph):
    cfg, objects, out = graph
    session = Session(objects)
    return mod.collect(session, cfg, out), session


def test_full_graph_keeps_every_original_and_unknown_format(mod, graph):
    (record, failed), session = run_collect(mod, graph)
    cfg, objects, out = graph
    assert not failed
    assert record['summary']['graph_complete'] is True
    assert record['summary']['unique_originals'] == len(objects)
    assert len(session.calls) == len(objects)
    assert record['summary']['unsupported_outcomes'] == 1
    assert record['summary']['scan_acceptance'] == 'not_evaluated'
    assert record['summary']['missing_expected_materials'] == []
    assert {a['sha256'] for a in record['attachments']} == {d[7:] for d in objects}
    for a in record['attachments']:
        assert (out / a['path']).read_bytes() == objects['sha256:' + a['sha256']]
    assert len(record['statements']) == 2
    assert any(s['container'] == 'unsigned_statement' for s in record['statements'])
    assert record['signature_verification'] == 'not_performed'
    assert len([m for m in record['materials'] if m['status'] == 'reference_only']) == 1
    assert len([m for m in record['materials'] if m['status'] == 'inline']) == 1
    assert any(s['predicate'].get('policyHasViolations') is True for s in record['statements'])


@pytest.mark.parametrize('damage', ['missing', 'digest', 'encoded', 'truncated', 'interrupted', 'oversized', 'total', 'count', 'subject', 'expected'])
def test_failure_keeps_record_and_verified_partial_originals(mod, graph, damage):
    cfg, objects, out = graph
    candidate = next(k for k, v in objects.items() if b'bomFormat' in v)
    original = objects[candidate]
    if damage == 'missing':
        del objects[candidate]
    elif damage == 'digest':
        objects[candidate] = original.replace(b'CycloneDX', b'CycloneDY')
    elif damage == 'encoded':
        objects[candidate] = Response(original, headers={'Content-Encoding': 'gzip'})
    elif damage == 'truncated':
        objects[candidate] = Response(original, headers={'Content-Length': '9999'})
    elif damage == 'interrupted':
        objects[candidate] = Response(original, interrupted=True)
    elif damage == 'oversized':
        cfg['max_object_bytes'] = 10
    elif damage == 'total':
        cfg['max_total_bytes'] = 10
    elif damage == 'count':
        cfg['max_objects'] = 1
    elif damage == 'subject':
        cfg['subject'] = 'sha256:' + '2' * 64
    else:
        cfg['expected'].append('scan-never-ran')
    (record, failed), _ = run_collect(mod, graph)
    assert failed and record['summary']['graph_complete'] is False
    assert record['metadata']['partial_failure'] is True
    assert record['metadata']['api_failures']
    assert 'secret-token-in-error' not in json.dumps(record)
    for a in record['attachments']:
        assert hashlib.sha256((out / a['path']).read_bytes()).hexdigest() == a['sha256']
    assert not list(out.rglob('*.part'))


def test_no_expectation_is_not_claimed_complete_scanner_coverage(mod, graph):
    graph[0]['expected'] = []
    (record, failed), _ = run_collect(mod, graph)
    assert not failed and record['summary']['expected_population'] == 'not_configured'


def test_output_is_never_overwritten(mod, graph):
    run_collect(mod, graph)
    with pytest.raises(mod.FetchError):
        run_collect(mod, graph)


def test_summary_documented(mod, graph, assert_summary_documented):
    (record, _), _ = run_collect(mod, graph)
    assert_summary_documented('uds_cat/package_evidence', record['summary'])


@pytest.mark.parametrize('variant', ['inline', 'no_cas', 'malformed', 'bad_alias', 'bad_size', 'policy_annotations', 'legacy_aliases', 'bad_flag'])
def test_native_material_variants_and_malformed_graphs(mod, graph, variant):
    cfg, objects, _ = graph
    body = b'inline original'
    item = material('scan', body)
    predicate = {}
    if variant == 'inline':
        item['annotations']['chainloop.material.cas.inline'] = True
        item['content'] = base64.b64encode(body).decode()
    elif variant == 'no_cas':
        item['annotations']['chainloop.material.cas'] = False
    elif variant == 'malformed':
        item['annotations'] = None
    elif variant == 'bad_size':
        item['annotations']['chainloop.material.size'] = '999'
    elif variant == 'bad_flag':
        item['annotations']['chainloop.material.cas'] = 1
    elif variant == 'policy_annotations':
        predicate['policyEvaluationsRef'] = {'digest': {'sha256': digest(body)[7:]}, 'annotations': 'invalid'}
    new_root = attestation([item], **predicate)
    if variant == 'bad_alias':
        obj = json.loads(attestation([item], signed=False))
        obj['type'] = obj['_type']
        new_root = json.dumps(obj).encode()
    elif variant == 'legacy_aliases':
        obj = json.loads(attestation([item], signed=False))
        obj['type'] = obj.pop('_type')
        obj['predicate_type'] = 'chainloop.dev/attestation/v0.1.2'
        del obj['predicateType']
        new_root = json.dumps(obj).encode()
    cfg.update(roots=[digest(new_root)], expected=[])
    objects[digest(new_root)] = new_root
    objects[digest(body)] = body
    (record, failed), session = run_collect(mod, graph)
    assert failed is (variant not in ('inline', 'legacy_aliases'))
    if variant == 'inline':
        assert len(session.calls) == 1
        assert record['summary']['unique_originals'] == 2


@pytest.mark.parametrize('url', ['http://cat.example.test', 'https://user:password@cat.example.test',
                                'https://cat.example.test/path', 'https://cat.example.test?q=token',
                                'https://cat.example.test/#fragment'])
def test_invalid_origin_is_refused_before_network(mod, monkeypatch, url):
    monkeypatch.setenv('CAT_URL', url)
    with pytest.raises(mod.FetchError, match='HTTPS origin'):
        mod.configuration()


@pytest.mark.parametrize('status', [301, 302, 401, 403, 429, 500])
def test_http_failure_retains_diagnostic_not_an_empty_success(mod, graph, status):
    cfg, objects, _ = graph
    objects[cfg['roots'][0]] = Response(b'private server detail', status=status)
    (record, failed), _ = run_collect(mod, graph)
    assert failed and not record['attachments']
    assert 'private server detail' not in json.dumps(record)
    assert any(f'HTTP {status}' in e['message'] for e in record['metadata']['api_failures'])


def test_main_reports_failure_and_keeps_native_record(mod, graph, monkeypatch, tmp_path):
    cfg, _, _ = graph
    values = {'CAT_URL': cfg['url'], 'CAT_ORGANIZATION': cfg['organization'], 'CAT_PACKAGE_REF': cfg['package_ref'],
              'CAT_ATTESTATION_DIGESTS': json.dumps(cfg['roots']), 'CAT_SUBJECT_DIGEST': cfg['subject'],
              'CAT_API_TOKEN': 'synthetic-token', 'CAT_EXPECTED_MATERIALS': '[]',
              'EVIDENCE_DIR': str(tmp_path / 'main'), 'FETCHER_STATUS_FILE': str(tmp_path / 'status.json')}
    for k, v in values.items():
        monkeypatch.setenv(k, v)
    def get(session, *args, **kwargs):
        assert session.trust_env is False
        return Response(status=403)
    monkeypatch.setattr(requests.Session, 'get', get)
    assert mod.main() == 1
    assert json.loads((tmp_path / 'status.json').read_text())['code'] == 'partial_failure'
    record = json.loads(next((tmp_path / 'main').glob('*.json')).read_text())
    assert record['metadata']['partial_failure'] is True


def test_attachment_directory_symlink_is_refused(mod, graph, tmp_path):
    _, _, out = graph
    (out / '_attachments').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(mod.FetchError):
        run_collect(mod, graph)


def test_native_runner_two_packages_and_native_delivery(tmp_path, monkeypatch, graph):
    import datetime
    import ipaddress
    import ssl
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    import yaml
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from framework import api
    from tests.test_provider_delivery_apply import FakeParamify, Harness

    cfg, objects, _ = graph
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    pem, private = tmp_path / 'ca.pem', tmp_path / 'key.pem'
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append((self.path, self.headers.get('Authorization')))
            prefix = '/api/v1/artifacts/acme/'
            body = objects.get(unquote(self.path[len(prefix):])) if self.path.startswith(prefix) else None
            self.send_response(200 if body is not None else 404)
            self.end_headers()
            if body is not None:
                self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pem, private)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        manifest = yaml.safe_load((ROOT / 'examples/uds_cat_package_evidence.yaml').read_text())
        monkeypatch.setenv('PYTHON_DOTENV_DISABLED', '1')
        monkeypatch.setenv('CAT_API_TOKEN', 'synthetic-token')
        manifest['run']['platforms']['uds_cat']['config'].update(url=f'https://127.0.0.1:{server.server_port}',
                                                        ca_bundle=str(pem), expected_materials=json.dumps(cfg['expected']))
        target = {'organization': 'acme', 'package_ref': 'demo:1.0-amd64',
                  'attestation_digests': json.dumps(cfg['roots']), 'subject_digest': SUBJECT}
        manifest['run']['output_dir'] = str(tmp_path / 'run')
        manifest['run']['fetchers'][0]['targets'] = [target, {**target, 'package_ref': 'demo:1.0-arm64'}]
        collected = api.run(manifest, ROOT)
        assert collected['ok'], collected
        run_dir = Path(collected['run_dir'])
        records = list(run_dir.glob('uds_cat_package_evidence_*.json'))
        assert len(records) == 2
        for p in records:
            document = json.loads(p.read_text())
            assert document['metadata']['attachments'] == document['payload']['attachments']
            assert document['metadata']['status'] == 'success'
        assert len(calls) == 2 * len(objects)
        assert all(token == 'Bearer synthetic-token' for _, token in calls)
        h = Harness(FakeParamify(), run_dir)
        h.run()
        assert len(h.sent) == 2 * (1 + len(objects))
        sent = [part['file'][1] for part in h.sent]
        for original in objects.values():
            assert sent.count(original) == 2
        h.run()
        assert len(h.sent) == len(sent)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
