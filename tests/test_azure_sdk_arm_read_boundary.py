"""Synthetic SDK requests preserve the same opt-in boundary as native REST."""

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

pytest.importorskip("azure.core", reason="real Azure SDK transport checks run in azure-sdk CI")

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / "fetchers/azure/_shared/arm_rest.py"
sys.path.insert(0, str(P.parent))
spec = importlib.util.spec_from_file_location("sdk_arm_boundary", P)
arm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arm)
SUB = "11111111-1111-4111-8111-111111111111"
HOST = "https://management.usgovcloudapi.net"


def client(body=None, status=200):
    response = SimpleNamespace(status_code=status, json=lambda: body or {"value": []})
    return SimpleNamespace(
        format_url=lambda path: HOST + path if path.startswith("/") else path,
        send_request=Mock(return_value=response),
    )


@pytest.fixture
def scoped(monkeypatch):
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.us")
    monkeypatch.setenv("AZURE_TARGET_SUBSCRIPTION_ONLY", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    return client()


@pytest.mark.parametrize(
    "path",
    [
        "/subscriptions/other/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id/federatedIdentityCredentials",
        "/providers/Microsoft.Authorization/roleDefinitions/id",
        f"/subscriptions/{SUB}/../other/items",
        f"/subscriptions/{SUB}/%2e%2e/other/items",
        f"/subscriptions/{SUB}/%252e%252e/other/items",
        f"/subscriptions/{SUB}/providers/a\\b",
        f"https://management.azure.com/subscriptions/{SUB}/items",
        f"http://management.usgovcloudapi.net/subscriptions/{SUB}/items",
        f"https://user@management.usgovcloudapi.net/subscriptions/{SUB}/items",
        f"{HOST}:444/subscriptions/{SUB}/items",
    ],
)
def test_scoped_sdk_rejects_outside_target_before_sdk_send(scoped, path):
    with pytest.raises(ValueError):
        arm.get_json(scoped, path)
    scoped.send_request.assert_not_called()


def test_scoped_sdk_follows_valid_selected_subscription_page(monkeypatch, scoped):
    first = f"/subscriptions/{SUB}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id/federatedIdentityCredentials"
    second = f"{HOST}{first}?api-version=x&skip=next"
    responses = [
        SimpleNamespace(
            status_code=200, json=lambda: {"value": [{"id": "a"}], "nextLink": second}
        ),
        SimpleNamespace(status_code=200, json=lambda: {"value": [{"id": "b"}]}),
    ]
    scoped.send_request.side_effect = responses
    result = arm.list_all(scoped, first, "x")
    assert result == {"items": [{"id": "a"}, {"id": "b"}], "pages": 2}
    assert [call.args[0].url for call in scoped.send_request.call_args_list] == [
        f"{HOST}{first}?api-version=x",
        second,
    ]


def test_cross_subscription_sdk_continuation_fails_before_second_send(scoped):
    scoped.send_request.return_value = SimpleNamespace(
        status_code=200,
        json=lambda: {
            "value": [{"id": "a"}],
            "nextLink": HOST + "/subscriptions/other/items?skip=next",
        },
    )
    with pytest.raises(ValueError):
        arm.list_all(scoped, f"/subscriptions/{SUB}/items", "x")
    assert scoped.send_request.call_count == 1


def test_scoped_sdk_redirect_is_failure_without_following(scoped):
    scoped.send_request.return_value = SimpleNamespace(
        status_code=302, json=lambda: {"value": []}
    )
    with pytest.raises(ValueError, match="redirect"):
        arm.get_json(scoped, f"/subscriptions/{SUB}/items")
    assert scoped.send_request.call_count == 1


def test_unscoped_sdk_keeps_original_same_origin_behavior(monkeypatch):
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.us")
    monkeypatch.delenv("AZURE_TARGET_SUBSCRIPTION_ONLY", raising=False)
    api = client()
    assert arm.get_json(
        api, "/providers/Microsoft.Authorization/roleDefinitions/id"
    ) == {"value": []}
    api.send_request.assert_called_once()


def test_generated_sdk_options_enable_pre_auth_policy_and_disable_redirects(scoped):
    import azure_common

    options = azure_common.arm_client_kwargs()
    assert options["redirect_policy"].allow is False
    assert len(options["per_call_policies"]) == 1
    request = SimpleNamespace(
        http_request=SimpleNamespace(
            method="GET", url=HOST + "/subscriptions/other/items", body=None
        )
    )
    with pytest.raises(ValueError):
        options["per_call_policies"][0].on_request(request)


@pytest.mark.parametrize(
    "body",
    [
        {"subscriptions": ["other"], "query": "resources"},
        {"subscriptions": [SUB, "other"], "query": "resources"},
        {"query": "resources"},
        {"subscriptions": [SUB], "managementGroups": ["parent"], "query": "resources"},
    ],
)
def test_generated_resource_graph_posts_require_exact_target_in_body(scoped, body):
    import json

    import azure_common

    options = azure_common.arm_client_kwargs()
    request = SimpleNamespace(
        http_request=SimpleNamespace(
            method="POST",
            url=HOST
            + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01",
            body=json.dumps(body),
        )
    )
    with pytest.raises(ValueError):
        options["per_call_policies"][0].on_request(request)


def test_generated_resource_graph_accepts_only_exact_selected_subscription(scoped):
    import json

    import azure_common

    options = azure_common.arm_client_kwargs()
    request = SimpleNamespace(
        http_request=SimpleNamespace(
            method="POST",
            url=HOST
            + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01",
            body=json.dumps(
                {
                    "subscriptions": [SUB],
                    "query": "resources",
                    "options": {"$skipToken": "next"},
                }
            ),
        )
    )
    options["per_call_policies"][0].on_request(request)


def test_generated_sdk_rejects_redirect_response_without_following(scoped):
    import azure_common

    options = azure_common.arm_client_kwargs()
    response = SimpleNamespace(http_response=SimpleNamespace(status_code=302))
    with pytest.raises(ValueError, match="redirect"):
        options["per_call_policies"][0].on_response(None, response)


def recording_transport(pages):
    import json

    import requests
    from azure.core.credentials import AccessToken
    from azure.core.pipeline.transport import RequestsTransport

    calls, tokens = [], []
    session = requests.Session()

    def send(method, url, **kwargs):
        calls.append((method, url, kwargs))
        status, body = pages[len(calls) - 1]
        response = requests.Response()
        response.status_code = status
        response.headers["content-type"] = "application/json"
        response._content = json.dumps(body).encode()
        response._content_consumed = True
        response.raw = SimpleNamespace(enforce_content_length=True)
        return response

    session.request = send

    class Credential:
        def get_token(self, *scopes, **kwargs):
            tokens.append(scopes)
            return AccessToken("synthetic-only", 9999999999)

    return (
        RequestsTransport(session=session, session_owner=False),
        Credential(),
        calls,
        tokens,
    )


@pytest.mark.parametrize("sdk", ["msi", "authorization"])
def test_actual_sdk_paging_cannot_expand_subscription(scoped, sdk):
    import azure_common
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.msi import ManagedServiceIdentityClient

    transport, cred, calls, tokens = recording_transport(
        [
            (
                200,
                {
                    "value": [],
                    "nextLink": HOST + "/subscriptions/other/resources?api-version=x",
                },
            )
        ]
    )
    kwargs = {
        "credential": cred,
        "subscription_id": SUB,
        "transport": transport,
        **azure_common.arm_client_kwargs(),
    }
    if sdk == "msi":
        api = ManagedServiceIdentityClient(**kwargs)
        rows = api.user_assigned_identities.list_by_subscription()
    else:
        api = AuthorizationManagementClient(**kwargs)
        rows = api.role_definitions.list(scope="/subscriptions/" + SUB)
    with pytest.raises(ValueError, match="scope"):
        list(rows)
    assert len(calls) == 1
    assert tokens == [(HOST + "/.default",)]


def test_actual_resource_graph_sdk_keeps_explicit_subscription_on_every_page(scoped):
    import json

    import azure_common
    import resource_graph
    from azure.mgmt.resourcegraph import ResourceGraphClient

    transport, cred, calls, tokens = recording_transport(
        [
            (
                200,
                {
                    "data": [{"id": "one"}],
                    "totalRecords": 2,
                    "count": 1,
                    "resultTruncated": "false",
                    "$skipToken": "next",
                },
            ),
            (
                200,
                {
                    "data": [{"id": "two"}],
                    "totalRecords": 2,
                    "count": 1,
                    "resultTruncated": "false",
                },
            ),
        ]
    )
    api = ResourceGraphClient(
        credential=cred, transport=transport, **azure_common.arm_client_kwargs()
    )
    result = resource_graph.query_all(
        api, SUB, "resources | project id | order by id asc"
    )
    assert len(calls) == 2 and result["rows"] == [{"id": "one"}, {"id": "two"}]
    assert all(json.loads(call[2]["data"])["subscriptions"] == [SUB] for call in calls)
    assert json.loads(calls[1][2]["data"])["options"]["$skipToken"] == "next"
    assert tokens == [(HOST + "/.default",)]


def test_actual_resource_graph_sdk_rejects_unscoped_body_before_token(scoped):
    import azure_common
    import resource_graph
    from azure.mgmt.resourcegraph import ResourceGraphClient

    transport, cred, calls, tokens = recording_transport([])
    api = ResourceGraphClient(
        credential=cred, transport=transport, **azure_common.arm_client_kwargs()
    )
    with pytest.raises(ValueError, match="scope"):
        resource_graph.query_all(api, None, "resources")
    assert calls == [] and tokens == []


def test_one_backslash_cannot_change_scoped_path_interpretation(scoped):
    path = "/subscriptions/" + SUB + "/providers/a" + chr(92) + "b"
    with pytest.raises(ValueError):
        arm.get_json(scoped, path)
    scoped.send_request.assert_not_called()


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE", "POST"])
def test_generated_sdk_blocks_source_writes_before_token_or_transport(scoped, method):
    import azure_common
    from azure.core.rest import HttpRequest
    from azure.mgmt.msi import ManagedServiceIdentityClient

    transport, cred, calls, tokens = recording_transport([(200, {})])
    api = ManagedServiceIdentityClient(
        credential=cred,
        subscription_id=SUB,
        transport=transport,
        **azure_common.arm_client_kwargs(),
    )
    with pytest.raises(ValueError, match="read"):
        api._client.send_request(
            HttpRequest(
                method, HOST + "/subscriptions/" + SUB + "/providers/example/items"
            )
        )
    assert calls == [] and tokens == []
