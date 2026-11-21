"""The existing telemetry read boundary, applied by the public native helper."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import sys

import pytest

SHARED = Path(__file__).parents[1] / 'fetchers/azure/_shared'
sys.path.insert(0, str(SHARED))
from azure_rest import ArmError, AzureRestClient

SUB = '00000000-0000-0000-0000-000000000001'
BASE = f'/subscriptions/{SUB}/providers/Microsoft.Network/azureFirewalls'


def response(body=None, status=200):
    return SimpleNamespace(status_code=status, json=lambda: body or {})


def client(monkeypatch, scoped=True):
    monkeypatch.setenv('AZURE_AUTHORITY_HOST', 'https://login.microsoftonline.us')
    cred = Mock()
    cred.get_token.return_value = SimpleNamespace(token='synthetic-token', expires_on=9999999999)
    session = Mock()
    session.get.return_value = response({'value': []})
    session.post.return_value = response({'value': []})
    result = AzureRestClient(cred, session)
    if scoped:
        result.arm_subscription_scope = SUB
    return result, cred, session


@pytest.mark.parametrize('url', [
    'https://untrusted.example/subscriptions/{s}/items',
    'http://management.usgovcloudapi.net/subscriptions/{s}/items',
    'https://management.usgovcloudapi.net/subscriptions/foreign/items',
    'https://management.usgovcloudapi.net/subscriptions/{s}/../foreign/items',
    'https://management.usgovcloudapi.net/subscriptions/{s}/%2e%2e/foreign/items',
    'https://management.usgovcloudapi.net/subscriptions/{s}/%252e%252e/foreign/items',
    'https://management.usgovcloudapi.net/subscriptions/{s}/items#fragment',
    'https://user@management.usgovcloudapi.net/subscriptions/{s}/items',
    'https://management.usgovcloudapi.net/subscriptions/{s}/items\\foreign',
])
def test_rejects_scope_before_token_or_send(monkeypatch, url):
    native, cred, session = client(monkeypatch)
    with pytest.raises(ValueError):
        native._get(url.format(s=SUB))
    cred.get_token.assert_not_called()
    session.get.assert_not_called()


def test_selected_government_reads_and_nextlink_stay_in_scope(monkeypatch):
    native, cred, session = client(monkeypatch)
    session.get.side_effect = [response({'value':[1], 'nextLink':native.arm+BASE+'?page=2'}), response({'value':[2]})]
    assert native.list(BASE, '2024-05-01') == [1,2]
    assert all(c.kwargs['allow_redirects'] is False for c in session.get.call_args_list)
    cred.get_token.assert_called_once_with('https://management.usgovcloudapi.net/.default')


@pytest.mark.parametrize('method', ['get', 'post', 'query', 'search'])
def test_redirects_not_followed_for_scoped_reads(monkeypatch, method):
    native, _, session = client(monkeypatch)
    session.get.return_value = session.post.return_value = response(status=302)
    with pytest.raises(ArmError, match='Redirect'):
        if method in ('get','post'): getattr(native, method)(BASE, '2024-05-01')
        else: getattr(native, method)('workspace', 'Heartbeat | count', 'P1D')
    getattr(session, 'get' if method == 'get' else 'post').assert_called_once()
    assert getattr(session, 'get' if method == 'get' else 'post').call_args.kwargs['allow_redirects'] is False


def test_foreign_read_action_and_nextlink_never_get_token(monkeypatch):
    native, cred, session = client(monkeypatch)
    with pytest.raises(ValueError): native.post('/subscriptions/foreign/events/fetchEventDetails', '2025-04-01')
    cred.get_token.assert_not_called()
    session.get.return_value = response({'value':[], 'nextLink': 'https://untrusted.example/steal'})
    with pytest.raises(ValueError): native.list(BASE, '2024-05-01')
    assert session.get.call_count == 1


def test_arm_and_graph_cycles_and_graph_origin_reject(monkeypatch):
    native, _, session = client(monkeypatch)
    session.get.return_value = response({'value':[], 'nextLink': native.arm+BASE})
    with pytest.raises(ValueError, match='paging'): native.list(BASE, '2024-05-01')
    native, cred, session = client(monkeypatch, scoped=False)
    session.get.return_value = response({'value':[], '@odata.nextLink': 'https://untrusted.example/steal'})
    with pytest.raises(ValueError): native.graph_list('/users')
    assert session.get.call_count == 1
    session.get.return_value = response({'value':[], '@odata.nextLink': native.graph+'/v1.0/users'})
    with pytest.raises(ValueError, match='paging'): native.graph_list('/users')
    session.get.return_value = response(status=307)
    with pytest.raises(ArmError, match='Redirect'): native.graph_get('/users')
    assert session.get.call_args.kwargs['allow_redirects'] is False


def test_default_arm_callers_preserve_existing_behavior(monkeypatch):
    native, _, session = client(monkeypatch, scoped=False)
    native.get(BASE, '2024-05-01')
    assert 'allow_redirects' not in session.get.call_args.kwargs


def load(name):
    spec = spec_from_file_location('boundary_'+name, SHARED.parent/name/'fetcher.py')
    result = module_from_spec(spec);spec.loader.exec_module(result)
    return result






@pytest.mark.parametrize('value', ['TRUEE','1','yes'])
def test_bad_scope_configuration_rejects_before_credentials(monkeypatch,value):
    from azure_rest import target_subscription_scope
    monkeypatch.setenv('AZURE_TARGET_SUBSCRIPTION_ONLY',value)
    with pytest.raises(ValueError): target_subscription_scope()


def test_scope_requires_explicit_target_and_propagates_to_direct_clients(monkeypatch):
    from azure_rest import target_subscription_scope
    monkeypatch.setenv('AZURE_TARGET_SUBSCRIPTION_ONLY','true')
    monkeypatch.delenv('AZURE_SUBSCRIPTION_ID',raising=False)
    with pytest.raises(ValueError): target_subscription_scope()
    monkeypatch.setenv('AZURE_SUBSCRIPTION_ID',SUB)
    assert AzureRestClient(Mock(),Mock()).arm_subscription_scope == SUB


def test_firewall_referenced_policy_cannot_cross_selected_subscription(monkeypatch):
    import logging
    from azure_common import Collector
    native, _, session = client(monkeypatch)
    foreign='/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/synthetic/providers/Microsoft.Network/firewallPolicies/foreign'
    session.get.side_effect=[response({'value':[{'id':BASE+'/synthetic','properties':{'firewallPolicy':{'id':foreign}}}]}),response({'value':[]}),response({'value':[]})]
    collector=Collector(logging.getLogger('boundary-firewall'))
    results,summary=load('firewall_configuration').collect(native,SUB,collector)
    assert collector.ok is False
    assert results['foreign_firewall_policies']==[]
    assert summary['firewalls_with_rules_unread']==1
    assert all('/subscriptions/00000000-0000-0000-0000-000000000002/' not in call.args[0] for call in session.get.call_args_list)


def test_scoped_rest_rejects_resource_graph_root_before_token(monkeypatch):
    native,cred,session=client(monkeypatch)
    with pytest.raises(ValueError,match='subscription'):
        native.post('/providers/Microsoft.ResourceGraph/resources','2022-10-01')
    cred.get_token.assert_not_called();session.post.assert_not_called()
