"""Synthetic credentials/HTTP only: native SDK cannot leave its Graph source."""
import asyncio
import importlib.util
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

P = Path(__file__).resolve().parents[1] / 'fetchers/azure/_shared/entra_graph.py'
spec = importlib.util.spec_from_file_location('boundary_graph', P)
graph = importlib.util.module_from_spec(spec)
spec.loader.exec_module(graph)


def test_native_sdk_refuses_foreign_token_and_redirect(monkeypatch):
    pytest.importorskip('msgraph')
    import httpx
    from azure.core.credentials import AccessToken
    monkeypatch.setenv('AZURE_AUTHORITY_HOST', 'https://login.microsoftonline.us')
    tokens, requests = [], []
    from msgraph_core import GraphClientFactory
    original_factory = GraphClientFactory.create_with_default_middleware
    async def handler(request):
        requests.append(str(request.url))
        return httpx.Response(302, headers={'Location':'https://foreign.invalid/page'}, request=request)
    def factory(**kwargs):
        client = httpx.AsyncClient(base_url='https://graph.microsoft.us/v1.0',
                                  transport=httpx.MockTransport(handler), follow_redirects=False)
        return original_factory(client=client, **kwargs)
    monkeypatch.setattr(GraphClientFactory, 'create_with_default_middleware', factory)
    class Credential:
        def get_token(self, *scopes, **kwargs):
            tokens.append(scopes)
            return AccessToken('synthetic-only', 9999999999)
    async def run():
        async with graph.graph_service_client(Credential()) as client:
            provider = client.request_adapter._authentication_provider.access_token_provider
            assert await provider.get_authorization_token('https://foreign.invalid/page') == ''
            assert tokens == []
            assert await provider.get_authorization_token('https://graph.microsoft.us/v1.0/organization') == 'synthetic-only'
            assert tokens == [('https://graph.microsoft.us/.default',)]
            http = client.request_adapter._http_client
            response = await http.get('https://graph.microsoft.us/v1.0/organization')
            assert response.status_code == 302 and len(requests) == 1
            assert http.follow_redirects is False
    asyncio.run(run())


@pytest.mark.parametrize('link', ['https://foreign.invalid/x','https://graph.microsoft.com/x',
    'http://graph.microsoft.us/x','https://user@graph.microsoft.us/x','https://graph.microsoft.us:444/x'])
def test_sdk_pagination_rejects_source_expansion_before_next_read(monkeypatch, link):
    monkeypatch.setenv('AZURE_AUTHORITY_HOST', 'https://login.microsoftonline.us')
    calls = []
    class Builder:
        async def get(self, request_configuration=None):
            calls.append('get')
            return NS(value=[1], odata_next_link=link)
        def with_url(self, url):
            calls.append(url)
            return self
    class Collector:
        def record(self, *args): calls.append('failure')
    with pytest.raises(ValueError, match='Graph continuation'):
        asyncio.run(graph.paginate(Collector(),'test',Builder(),raise_on_error=True))
    assert calls == ['get']
