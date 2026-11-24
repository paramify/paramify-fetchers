"""Original companion files use native delivery without JSON rewriting."""

import hashlib
import json
from dataclasses import replace

import pytest

from framework.envelope import wrap_outputs
from framework.sync.providers.desired import desired_from_run
from tests.test_envelope import make_fetcher, make_result
from tests.test_provider_delivery_apply import FakeParamify, Harness, with_request
from tests.test_sync_desired import env, build, inv

RAW = b'{ "schema_version":"vendor", "metadata":{}, "payload":{"failed":true} }\r\n'


def prepared(tmp_path, body=RAW):
    p = tmp_path / '_attachments' / 'one' / 'report.json'
    p.parent.mkdir(parents=True)
    p.write_bytes(body)
    item = {'path': '_attachments/one/report.json', 'bytes': len(body),
            'sha256': hashlib.sha256(body).hexdigest()}
    document = env()
    document['metadata']['attachments'] = [item]
    build(tmp_path, {'record.json': document}, [inv('x', ['record.json'])])
    return p, item


def test_opt_in_promotes_attachment_descriptors(tmp_path):
    p, item = prepared(tmp_path)
    (tmp_path / 'ev.json').write_text(json.dumps({'attachments': [item]}))
    fetcher = replace(make_fetcher(tmp_path), output_attachments=True)
    wrap_outputs(make_result(), fetcher, 'R', tmp_path)
    assert json.loads((tmp_path / 'ev.json').read_text())['metadata']['attachments'] == [item]
    assert p.read_bytes() == RAW


def test_non_opted_in_payload_is_ordinary_evidence(tmp_path):
    item = {'path': 'not-a-file'}
    (tmp_path / 'ev.json').write_text(json.dumps({'attachments': [item]}))
    wrap_outputs(make_result(), make_fetcher(tmp_path), 'R', tmp_path)
    assert 'attachments' not in json.loads((tmp_path / 'ev.json').read_text())['metadata']


@pytest.mark.parametrize('cfg', [{}, {'artifact_payload': 'payload'}])
def test_native_upload_preserves_envelope_shaped_original_and_rerun_deduplicates(tmp_path, cfg):
    prepared(tmp_path)
    h = Harness(FakeParamify(), tmp_path, upload_cfg=cfg)
    h.run()
    assert len(h.sent) == 2
    assert RAW in [part['file'][1] for part in h.sent]
    h.run()
    assert len(h.sent) == 2


@pytest.mark.parametrize('damage', ['missing', 'hash', 'size', 'traversal', 'absolute', 'symlink', 'directory', 'duplicate'])
def test_bad_attachment_refuses_the_whole_record(tmp_path, damage):
    p, item = prepared(tmp_path)
    if damage == 'missing':
        p.unlink()
    elif damage == 'hash':
        p.write_bytes(RAW.replace(b'true', b'TRUE'))
    elif damage == 'size':
        item['bytes'] += 1
    elif damage == 'traversal':
        item['path'] = '_attachments/one/../../record.json'
    elif damage == 'absolute':
        item['path'] = str(p)
    elif damage == 'symlink':
        p.rename(p.with_suffix('.saved'))
        p.symlink_to(p.with_suffix('.saved'))
    elif damage == 'directory':
        item['path'] = '_attachments/one'
    document = json.loads((tmp_path / 'record.json').read_text())
    document['metadata']['attachments'] = [item, item] if damage == 'duplicate' else [item]
    (tmp_path / 'record.json').write_text(json.dumps(document))
    [entry] = desired_from_run(tmp_path, {})
    assert entry.files and all(f.skip_reason for f in entry.files)
    h = Harness(FakeParamify(), tmp_path)
    h.run()
    assert not h.sent


def test_changed_original_after_plan_is_never_sent(tmp_path):
    p, _ = prepared(tmp_path)
    h = Harness(FakeParamify(), tmp_path)
    plan = h.plan()
    p.write_bytes(b'changed after plan')
    outcomes = h.apply(plan)
    assert all(part['file'][1] != b'changed after plan' for part in h.sent)
    assert any(o.status == 'failed' for o in outcomes.values())


def test_different_paths_cannot_collide_in_hosted_artifact_names(tmp_path):
    p, item = prepared(tmp_path)
    other = p.parent.parent / 'two' / p.name
    other.parent.mkdir()
    other.write_bytes(RAW)
    document = json.loads((tmp_path / 'record.json').read_text())
    document['metadata']['attachments'].append({**item, 'path': '_attachments/two/report.json'})
    (tmp_path / 'record.json').write_text(json.dumps(document))
    [entry] = desired_from_run(tmp_path, {})
    assert all(f.skip_reason for f in entry.files)


def test_remote_original_refusal_holds_batch_instead_of_approving_partial_evidence(tmp_path):
    prepared(tmp_path)
    fake = FakeParamify()
    fake.fail_upload('record__report.json', 413, 'Payload Too Large')
    with_request(fake)
    h = Harness(fake, tmp_path)
    result = h.run()['delivery/x']
    assert result.status == 'failed'
    assert result.result['state'] == 'held' and 'record__report.json' in result.message
    assert fake._batches[0]['status'] == 'OPEN'
    assert not h.submits()


def test_pipeline_entry_refuses_original_companions(tmp_path):
    prepared(tmp_path)
    document = json.loads((tmp_path / 'record.json').read_text())
    document['metadata']['pipeline'] = {'type': 'inventory', 'id_scheme': 'example'}
    (tmp_path / 'record.json').write_text(json.dumps(document))
    [entry] = desired_from_run(tmp_path, {})
    assert all(f.skip_reason for f in entry.files)
