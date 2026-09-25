#!/usr/bin/env python3
"""
Record and replay OCI HTTP traffic, so the fetchers can be tested without a tenancy.

WHY AT THE HTTP LAYER. A hand-written double is built from the same assumptions
as the fetcher, so the two agree with each other and both disagree with the API —
this project has re-learned that four times. Recording raw responses and
replaying them through the real `oci` SDK keeps every layer below the fetcher
real: deserialization into the generated models, enum validation, the
`opc-next-page` pagination the SDK follows on its own, and the error classes it
raises. The only thing faked is the socket.

WHAT A CASSETTE IS. A JSON file of interactions, keyed by HTTP method and the
request path with its query string (minus the volatile bits). Each carries the
status, the response body and the headers pagination depends on. Cassettes are
recorded against the live trial tenancy by `tools/oci_capture.py` and redacted on
the way out: tenancy and user OCIDs become fixed placeholders, and the account
email becomes user@example.com.

AN UNMATCHED REQUEST IS AN ERROR, NOT AN EMPTY RESPONSE. If a fetcher asks for
something the cassette does not hold, replay raises. A mock that answers
everything with `{}` would let a fetcher silently collect nothing and still exit
0, which is the failure mode this whole category is built to avoid.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit

# Env vars the subprocess bootstrap reads (see tests/oci_replay_bootstrap).
CASSETTE_ENV = "OCI_CASSETTE"
MODE_ENV = "OCI_CASSETTE_MODE"

# Headers worth keeping: the SDK's paginator reads opc-next-page, and
# content-type decides how it deserializes.
KEPT_HEADERS = ("opc-next-page", "content-type", "opc-total-items")

# Query parameters excluded from the key. `page` is deliberately NOT here: the
# SDK follows `opc-next-page` on its own, so dropping it from the key replays
# page one forever against its own next-page header — an infinite loop, which is
# exactly how this was found.
#
# `timeStart`/`timeEnd` are a window computed from the clock at run time
# (oci_operator_access_control), so no replay could ever match them. Sending the
# window at all is asserted by that fetcher's unit tests instead.
VOLATILE_PARAMS: tuple = ("timeStart", "timeEnd")

# Identifier patterns replaced on the way into a cassette. Each distinct match
# gets its own deterministic stand-in, never one shared placeholder.
#
# ONE PLACEHOLDER PER TYPE IS A BUG, and a subtle one. Per-user calls address the
# user in the path (`/users/{id}/apiKeys`), so collapsing every user OCID to the
# same string made two users' requests share a cassette key: the first recording
# answered both, and the admin's API keys were served as the other user's empty
# list. Caught by the Cloud Guard cross-check, by no fetcher test.
REDACTIONS = (
    (re.compile(r"ocid1\.tenancy\.oc1\.\.[a-z0-9]+"), "ocid1.tenancy.oc1..aaaaaaaatenancy"),
    (re.compile(r"ocid1\.user\.oc1\.\.[a-z0-9]+"), "ocid1.user.oc1..aaaaaaaauser{}"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "user{}@example.com"),
    # An identity domain's host is the tenancy's login endpoint: an account
    # identifier like the tenancy OCID, and in every SCIM request URL.
    (re.compile(r"idcs-[0-9a-f]{32}"), "idcs-00000000000000000000000000{}"),
    # The account's own API key fingerprint appears in IAM evidence.
    (re.compile(r"\b(?:[0-9a-f]{2}:){15}[0-9a-f]{2}\b"), "00:11:22:33:44:55:66:77:88:99:aa:bb:{}"),
)


# Longest list kept in a recorded body. Oracle's managed Cloud Guard recipe alone
# carries 126 detector rules and 80 security policies, which is 400 KB of
# cassette for a shape three records already prove. The review of PR #42 cut a
# fixture for being 59% of the diff, so the cap is deliberate.
MAX_LIST_ITEMS = 3

# Kept whole: the compartment listing IS the fanout shape. Trimmed to three, the
# replay walked whichever three came first and silently lost the nested
# compartments that the cross-compartment joins are tested against. Cloud
# Guard's problem list likewise: it is the cross-check's independent evidence,
# and trimmed, which problem types survived depended on Oracle's ordering.
UNTRIMMED = re.compile(r"^GET (identity/\d+/compartments|cloudguard-cp-api/\d+/problems)\?")


def trim(body: str) -> str:
    """Shorten every list in a JSON body, keeping the shape and the first items.

    A trimmed cassette still exercises the full path — deserialization,
    pagination, per-item calls — but a summary count taken from it is the count
    of the TRIMMED data, which is why the subprocess tests assert wiring and
    field presence rather than the live tenancy's numbers.
    """
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError):
        return body

    def shrink(node):
        if isinstance(node, list):
            return [shrink(item) for item in node[:MAX_LIST_ITEMS]]
        if isinstance(node, dict):
            return {key: shrink(value) for key, value in node.items()}
        return node

    return json.dumps(shrink(redact_people(parsed)))


# Cloud Guard's ACTIVITY problems (INTERNET_GATEWAY_CREATED and the like) name
# the person who acted: resourceType "User", resourceName their display name. A
# display name has no pattern a regex could catch, so it is replaced by field.
# Configuration problems on a User (NO_MFA_ENABLED_FOR_USER) name the username
# instead, which the email redaction already covers and the cross-check matches
# on, so only the activity detector is touched.
PERSON_STAND_IN = "Example User"
ACTIVITY_DETECTOR = "IAAS_ACTIVITY_DETECTOR"


def _people_redacted(body: str) -> str:
    """redact_people on a raw body; trim() applies it itself on the trimmed path."""
    try:
        return json.dumps(redact_people(json.loads(body)))
    except (TypeError, ValueError):
        return body


def redact_people(node):
    if isinstance(node, list):
        return [redact_people(item) for item in node]
    if isinstance(node, dict):
        out = {key: redact_people(value) for key, value in node.items()}
        if (out.get("resourceType") == "User" and out.get("detectorId") == ACTIVITY_DETECTOR
                and "resourceName" in out):
            out["resourceName"] = PERSON_STAND_IN
        return out
    return node


def _stand_in(template: str, original: str) -> str:
    """A stable, collision-free replacement for one identifier.

    IDEMPOTENT ON PURPOSE. Recording redacts the URL and the body together, so a
    replayed body hands the fetcher a stand-in, which it then puts back into the
    next request's URL. Hashing that a second time would produce a different key
    than the one recorded, and every per-user call would miss.
    """
    if "{}" not in template:
        return template
    if re.fullmatch(re.escape(template).replace(r"\{\}", "[0-9a-f]{6}"), original):
        return original
    return template.format(hashlib.sha256(original.encode()).hexdigest()[:6])


def redact(text: str) -> str:
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(functools.partial(_substitute, replacement), text)
    return text


def _substitute(replacement: str, match: "re.Match[str]") -> str:
    return _stand_in(replacement, match.group(0))


def request_key(method: str, url: str, params=None) -> str:
    """Method + path + stable query, which is what identifies a call."""
    split = urlsplit(url)
    pairs = []
    for key, value in sorted((params or {}).items()):
        if key in VOLATILE_PARAMS or value is None:
            continue
        pairs.append(f"{key}={value}")
    query = "&".join(pairs)
    # The service is in the host; keep it so two services' /20160918/ paths differ.
    service = split.netloc.split(".")[0]
    return redact(f"{method.upper()} {service}{split.path}" + (f"?{query}" if query else ""))


class Cassette:
    """The recorded interactions for one fetcher."""

    def __init__(self, interactions: List[Dict[str, Any]] | None = None):
        self.interactions = interactions or []

    @classmethod
    def load(cls, path) -> "Cassette":
        return cls(json.loads(Path(path).read_text())["interactions"])

    def save(self, path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({"interactions": self.interactions}, indent=1) + "\n")

    def record(self, key: str, status: int, headers: Dict[str, str], body: str) -> None:  # noqa: D401
        # Repeated identical calls (the same list from two compartments) record
        # once; replay serves the same answer, which is what the API does.
        if any(i["key"] == key for i in self.interactions):
            return
        self.interactions.append({
            "key": key,
            "status": status,
            "headers": {k: v for k, v in headers.items() if k.lower() in KEPT_HEADERS},
            "body": _people_redacted(redact(body)) if UNTRIMMED.match(key) else trim(redact(body)),
        })

    def match(self, key: str) -> Dict[str, Any] | None:
        return next((i for i in self.interactions if i["key"] == key), None)

    def size_kb(self) -> float:
        return round(len(json.dumps({"interactions": self.interactions})) / 1024, 1)


class CassetteUnmatched(RuntimeError):
    """A request the cassette does not hold. Never answered with an empty body."""


def _requests_module():
    """The `requests` the OCI SDK actually uses.

    THE SDK VENDORS ITS OWN COPY at `oci._vendor.requests`, so patching the
    installed `requests` intercepts nothing — and neither would responses,
    requests-mock or vcrpy, which all patch the public package. Cost an hour to
    find: the patch applied cleanly and recorded zero interactions.
    """
    try:
        from oci._vendor import requests as vendored
        return vendored
    except ImportError:  # a future SDK that stops vendoring
        import requests
        return requests


def install(cassette: Cassette, mode: str = "replay"):
    """Patch Session.request under the OCI SDK. Returns an uninstall fn.

    `record` calls the real session and stores the response; `replay` serves the
    cassette and never touches the network.
    """
    requests = _requests_module()

    original = requests.Session.request

    def recording(self, method, url, *args, **kwargs):
        response = original(self, method, url, *args, **kwargs)
        cassette.record(
            request_key(method, url, kwargs.get("params")),
            response.status_code, dict(response.headers), response.text,
        )
        return response

    def replaying(self, method, url, *args, **kwargs):  # noqa: ARG001
        key = request_key(method, url, kwargs.get("params"))
        found = cassette.match(key)
        if found is None:
            raise CassetteUnmatched(f"no recorded response for {key}")
        response = requests.Response()
        response.status_code = found["status"]
        response._content = found["body"].encode()
        response.headers.update(found["headers"])
        response.url = url
        response.request = requests.Request(method=method, url=url).prepare()
        return response

    requests.Session.request = recording if mode == "record" else replaying
    return lambda: setattr(requests.Session, "request", original)


# Fault injection, driven by tools/oci_fault_sweep.py: replay one recorded call as
# a failure and see whether the fetcher notices.
FAULT_KEY_ENV = "OCI_FAULT_KEY"
FAULT_KIND_ENV = "OCI_FAULT_KIND"
FAULT_HITS_ENV = "OCI_FAULT_HITS"
FAULT_BODIES = {
    "401": ("NotAuthenticated", "The required information to complete authentication was not provided."),
    "404": ("NotAuthorizedOrNotFound", "Authorization failed or requested resource not found."),
    "429": ("TooManyRequests", "Too many requests for the tenant."),
    "500": ("InternalServerError", "Internal error."),
}
FAULT_KINDS = (*FAULT_BODIES, "timeout")


def inject_fault(cassette: Cassette, key: str, kind: str, hits_path: str | None = None):
    """Serve `key` as a failure of `kind`. Returns an uninstall fn; call after install().

    The SDK's retry backoff is disabled, or each 429/500/timeout would sleep
    through eight attempts for real.
    """
    import oci.retry.retry as sdk_retry

    if kind not in FAULT_KINDS:
        raise ValueError(f"unknown fault kind {kind!r}; expected one of {FAULT_KINDS}")
    if kind in FAULT_BODIES:
        code, message = FAULT_BODIES[kind]
        for interaction in cassette.interactions:
            if interaction["key"] == key:
                interaction.update(status=int(kind), headers={"content-type": "application/json"},
                                   body=json.dumps({"code": code, "message": message}))

    real_time = sdk_retry.time

    class _NoSleep:
        def __getattr__(self, name):
            return getattr(real_time, name)

        @staticmethod
        def sleep(_seconds):
            return None

    sdk_retry.time = _NoSleep()
    requests = _requests_module()
    inner = requests.Session.request

    def faulting(self, method, url, *args, **kwargs):
        if request_key(method, url, kwargs.get("params")) == key:
            if hits_path:
                with open(hits_path, "a") as hits:
                    hits.write("x")
            if kind == "timeout":
                raise requests.exceptions.ConnectTimeout("injected timeout")
        return inner(self, method, url, *args, **kwargs)

    requests.Session.request = faulting

    def uninstall():
        requests.Session.request = inner
        sdk_retry.time = real_time
    return uninstall


def install_from_env():
    """Used by the subprocess bootstrap; a no-op when no cassette is named."""
    path = os.environ.get(CASSETTE_ENV)
    if not path:
        return None
    cassette = Cassette.load(path)
    uninstall = install(cassette, os.environ.get(MODE_ENV, "replay"))
    if os.environ.get(FAULT_KEY_ENV):
        inject_fault(cassette, os.environ[FAULT_KEY_ENV], os.environ.get(FAULT_KIND_ENV, "404"),
                     os.environ.get(FAULT_HITS_ENV))
    return uninstall
