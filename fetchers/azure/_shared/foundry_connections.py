"""Foundry and Azure ML connection auth types, shared by the AI services and AI hub fetchers."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

# Connection auth types that keep a credential in the connection, and those that keep none.
STORED_SECRET_AUTH = {
    "apikey",
    "customkeys",
    "pat",
    "usernamepassword",
    "accesskey",
    "sas",
    "accountkey",
    "serviceprincipal",
    "oauth2",
}
KEYLESS_AUTH = {"aad", "managedidentity", "projectmanagedidentity", "agenticidentity", "useridentity"}


def compact(name) -> str:
    return "".join(ch for ch in str(name or "").lower() if ch.isalnum())


def stored_secret(auth_type) -> Optional[bool]:
    """True for auth types that keep a credential in the connection, False for keyless, None if unrecognised."""
    kind = compact(auth_type)
    if kind in STORED_SECRET_AUTH:
        return True
    if kind in KEYLESS_AUTH or kind == "none":
        return False
    return None


# Connection-string keys whose values are safe to keep; every other key's value is redacted.
SAFE_CONNECTION_STRING_KEYS = {
    "server",
    "datasource",
    "host",
    "hostname",
    "address",
    "addr",
    "networkaddress",
    "endpoint",
    "port",
    "database",
    "initialcatalog",
    "accountname",
    "defaultendpointsprotocol",
    "endpointsuffix",
    "blobendpoint",
    "queueendpoint",
    "tableendpoint",
    "fileendpoint",
    "encrypt",
    "trustservercertificate",
    "authentication",
}
REDACTED = "<redacted>"


def strip_query(target) -> str:
    """A connection target safe to write into evidence: no credentials, query string or fragment.

    URLs lose their userinfo (``user:password@``) and query/fragment (SAS tokens).
    Connection strings (``Key=Value;...``) keep only the values of known non-secret
    keys. A bare ``user:password@host`` loses everything before the last ``@``.
    """
    text = str(target or "").strip()
    if not text:
        return ""
    if "://" in text:
        parts = urlsplit(text)
        host = parts.netloc.rpartition("@")[2]
        return urlunsplit((parts.scheme, host, parts.path, "", ""))
    if "=" in text and ";" in text:
        pairs = []
        for item in text.split(";"):
            if not item.strip():
                continue
            key, sep, value = item.partition("=")
            keep = sep and compact(key) in SAFE_CONNECTION_STRING_KEYS
            pairs.append(f"{key.strip()}={value.strip() if keep else REDACTED}" if sep else REDACTED)
        return ";".join(pairs)
    if "@" in text:
        return text.rpartition("@")[2]
    return text


def connection_fields(raw: Dict[str, Any]) -> Dict[str, Any]:
    """One connection from wire JSON; credentials are never read (the list does not return them)."""
    props = raw.get("properties") or {}
    auth = props.get("authType")
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "category": props.get("category"),
        "auth_type": auth,
        "uses_stored_secret": stored_secret(auth),
        "unauthenticated": compact(auth) == "none",
        "target": strip_query(props.get("target")),
        "is_shared_to_all": props.get("isSharedToAll"),
    }
