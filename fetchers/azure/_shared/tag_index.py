"""Tag index: every resource's own tags and region, read once per subscription from Resource Graph when a tag: pattern
or an inclusion list needs them."""

from __future__ import annotations

import json
import re
from typing import Callable, Dict, List, Optional, Tuple

from azure_common import subscription_of

# Resources and their containers (resource groups and the subscription), each with only its own tags.
QUERY = "Resources | union ResourceContainers | project id = tolower(id), tags, location | order by id asc"

# A resource group, a subscription or a management group, and a record attached to one or to the tenant root (a lock,
# a policy or role assignment, a deployment): extension types only, so a resource the index missed is never taken for one.
SCOPES = r"/subscriptions/[^/]+(?:/resourcegroups/[^/]+)?|/providers/microsoft\.management/managementgroups/[^/]+"
CONTAINER = re.compile(rf"^(?:{SCOPES})$")
ATTACHED = re.compile(
    rf"^({SCOPES}|)/providers/(?:microsoft\.authorization|microsoft\.security"
    r"|microsoft\.policyinsights|microsoft\.resourcehealth|microsoft\.advisor|microsoft\.alertsmanagement"
    r"|microsoft\.insights/diagnosticsettings|microsoft\.resources/deployments)(?:/[^/]+)*$")
OPERATION = "resourcegraph.resources (tags in subscription {})"

Entry = Tuple[dict, Optional[str]]
_clients: list = []


def key(resource_id: Optional[str]) -> str:
    return str(resource_id or "").strip().lower().rstrip("/")


def load_subscription(subscription_id: str) -> Dict[str, Entry]:
    """{lowercased id: (its own tags, names lowercased; its region)} for every resource and container in it."""
    from azure_common import credential
    from resource_exclusions import own_tags
    from resource_graph import query_all, resource_graph_client

    if not _clients:
        _clients.append(resource_graph_client(credential()))
    held = {}
    for row in query_all(_clients[0], subscription_id, QUERY)["rows"]:
        tags = row.get("tags")
        if isinstance(tags, str):
            tags = json.loads(tags) if tags.strip() else None
        tags = own_tags(tags) if isinstance(tags, (dict, type(None))) else {}
        held[key(row.get("id"))] = (tags, row.get("location") or None)
    # A subscription the credential can't read comes back as no rows, not an error; its own row proves the read.
    if key(f"/subscriptions/{subscription_id}") not in held:
        raise LookupError(f"Resource Graph returned no row for subscription {subscription_id}, so it couldn't be read")
    return held


def _lookup_keys(resource_id: str) -> List[str]:
    """The id, then each parent resource's id; never a resource group or subscription, whose tags don't pass down."""
    parts = key(resource_id).split("/")
    parents = ["/".join(parts[:end]) for end in range(len(parts) - 2, 4, -2)]
    return ["/".join(parts)] + [p for p in parents if "/providers/" in p and p.rsplit("/", 2)[-2] != "providers"]


def container_of(resource_id: Optional[str]) -> Optional[str]:
    """The resource group, subscription or management group an id is, or that a record shaped
    <container>/providers/<ns>/<type>/<name> is attached to ("" for the tenant root); None for anything else."""
    k = key(resource_id)
    if CONTAINER.match(k):
        return k
    m = ATTACHED.match(k)
    return m.group(1) if m else None


def above_subscription(container: str) -> bool:
    return not container.startswith("/subscriptions/")


def failed_read(evidence: dict) -> Optional[str]:
    """The first failed index read the evidence records, else None."""
    failures = (evidence.get("metadata") or {}).get("api_failures") if isinstance(evidence, dict) else None
    prefix = OPERATION.split("{")[0]
    return next((f["operation"] for f in failures or [] if isinstance(f, dict)
                 and str(f.get("operation") or "").startswith(prefix)), None)


def group_of(resource_id: str) -> Optional[str]:
    parts = key(resource_id).split("/")
    return "/".join(parts[:5]) if len(parts) > 4 and parts[3] == "resourcegroups" else None


class TagIndex:
    """Answers "what are this id's own tags?", reading each subscription the first time one of its ids is asked about.
    An id the index doesn't hold, such as a key vault key or a storage container, takes its nearest parent resource's
    tags; None when neither is held or the subscription couldn't be read (its failure is kept in `failures`)."""

    def __init__(self, loader: Optional[Callable[[str], Dict[str, Entry]]] = None):
        self._loader = loader or load_subscription
        self._subscriptions: Dict[str, Optional[Dict[str, Entry]]] = {}
        self.failures: List[Tuple[str, BaseException]] = []

    def entries(self, subscription_id: Optional[str]) -> Optional[Dict[str, Entry]]:
        if not subscription_id:
            return None
        if subscription_id not in self._subscriptions:
            try:
                self._subscriptions[subscription_id] = self._loader(subscription_id)
            except Exception as exc:  # noqa: BLE001 — recorded; every resource it holds is then of unknown scope
                self._subscriptions[subscription_id] = None
                self.failures.append((OPERATION.format(subscription_id), exc))
        return self._subscriptions[subscription_id]

    def held(self, resource_id: Optional[str]) -> Optional[bool]:
        """Whether the index holds this id itself; None when its subscription couldn't be read."""
        entries = self.entries(subscription_of(resource_id))
        return None if entries is None else key(resource_id) in entries

    def tags_of(self, resource_id: Optional[str]) -> Optional[dict]:
        entries = self.entries(subscription_of(resource_id))
        if entries is None:
            return None
        return next((entries[k][0] for k in _lookup_keys(resource_id) if k in entries), None)
