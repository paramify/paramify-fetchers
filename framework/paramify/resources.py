"""Typed reads and writes over the Paramify REST API (0.14.0 shapes).

`Resources` wraps a `Client` and returns frozen dataclasses. `Reader` is the
read-only, memoizing view the planner uses, so a plan never asks twice.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from framework.paramify.client import ApiError, Client, ErrorKind
from framework.paramify_responses import already_present

_PAGE_SIZE = 100
# File names per artifacts read: the names go in the URL, so a big entry is
# read in several requests rather than one URL the server may refuse.
NAMES_PER_READ = 50


@dataclass(frozen=True)
class Stack:
    id: str
    name: str


@dataclass(frozen=True)
class Channel:
    id: str
    reference_id: str
    stack_id: str


@dataclass(frozen=True)
class EvidenceSet:
    id: str
    reference_id: str
    name: str
    approval: str
    channels: Tuple[Channel, ...]


@dataclass(frozen=True)
class ArtifactRequest:
    id: str
    reference_id: str
    channel_id: str
    evidence_id: str
    requested_date: date
    due_date: date


@dataclass(frozen=True)
class Batch:
    id: str
    reference_id: str
    status: str
    evidence_id: str
    artifact_request_id: Optional[str]
    artifact_count: int
    when_to_approve: str


@dataclass(frozen=True)
class Artifact:
    id: str
    original_file_name: str
    note: str
    batch_id: Optional[str]
    created_at: str
    validators: Tuple[Tuple[str, str], ...]  # (name, result)


def _channel(d: Dict[str, Any]) -> Channel:
    return Channel(id=d["id"], reference_id=d.get("referenceId") or "", stack_id=d.get("stackId") or "")


def _evidence(d: Dict[str, Any]) -> EvidenceSet:
    return EvidenceSet(
        id=d["id"],
        reference_id=d["referenceId"],
        name=d.get("name") or "",
        approval=d.get("whenToApproveArtifactRequest") or "",
        channels=tuple(_channel(c) for c in d.get("channels") or ()),
    )


def _request(d: Dict[str, Any]) -> ArtifactRequest:
    return ArtifactRequest(
        id=d["id"],
        reference_id=d.get("referenceId") or "",
        channel_id=d.get("channelId") or "",
        evidence_id=d.get("evidenceId") or "",
        requested_date=date.fromisoformat(d["requestedDate"][:10]),
        due_date=date.fromisoformat(d["dueDate"][:10]),
    )


def _batch(d: Dict[str, Any]) -> Batch:
    return Batch(
        id=d["id"],
        reference_id=d.get("referenceId") or "",
        status=d.get("status") or "",
        evidence_id=d.get("evidenceId") or "",
        artifact_request_id=d.get("artifactRequestId"),
        artifact_count=int(d.get("artifactCount") or 0),
        when_to_approve=d.get("whenToApprove") or "",
    )


def _artifact(d: Dict[str, Any]) -> Artifact:
    return Artifact(
        id=d["id"],
        original_file_name=d.get("originalFileName") or "",
        note=d.get("note") or "",
        batch_id=d.get("batchId"),
        created_at=d.get("createdAt") or "",
        validators=tuple((v.get("name") or "", v.get("result") or "") for v in d.get("validators") or ()),
    )


class Resources:
    def __init__(self, client: Client) -> None:
        self._client = client

    def _paged(self, path: str, key: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Walk page=1..totalPages; an empty page also ends the walk."""
        out: List[Dict[str, Any]] = []
        page = 1
        while True:
            body = self._client.get(path, {**params, "page": page, "pageSize": _PAGE_SIZE}) or {}
            rows = body.get(key) or []
            out.extend(rows)
            total_pages = int((body.get("pagination") or {}).get("totalPages") or 1)
            if not rows or page >= total_pages:
                return out
            page += 1

    def stacks(self) -> List[Stack]:
        return [Stack(id=s["id"], name=s["name"]) for s in self._client.get("/stacks") or []]

    def evidence_by_reference(self, refs: Sequence[str]) -> Dict[str, EvidenceSet]:
        found: Dict[str, EvidenceSet] = {}
        for ref in refs:
            body = self._client.get("/evidence", {"referenceId": ref}) or {}
            for row in body.get("evidences") or []:
                if row.get("referenceId") == ref:
                    found[ref] = _evidence(row)
                    break
        return found

    def artifact_requests(self, evidence_id: str, *, current: Optional[bool] = None) -> List[ArtifactRequest]:
        params: Dict[str, Any] = {"evidenceId": evidence_id}
        if current is not None:
            params["current"] = "true" if current else "false"
        return [_request(r) for r in self._paged("/artifact-requests", "artifactRequests", params)]

    def batches(
        self,
        *,
        evidence_id: Optional[str] = None,
        artifact_request_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Batch]:
        params = {
            k: v
            for k, v in (("evidenceId", evidence_id), ("artifactRequestId", artifact_request_id), ("status", status))
            if v is not None
        }
        return [_batch(b) for b in self._paged("/batches", "batches", params)]

    def batch(self, batch_id: str) -> Batch:
        return _batch(self._client.get(f"/batches/{batch_id}"))

    def artifacts(
        self,
        evidence_id: str,
        *,
        batch_id: Optional[str] = None,
        original_file_names: Optional[Sequence[str]] = None,
        created_on: Optional[Sequence[date]] = None,
    ) -> List[Artifact]:
        """Artifacts of an evidence set.

        `original_file_names` and `created_on` are repeated parameters
        (`originalFileName`, `createdAt` as YYYY-MM-DD; any listed value
        matches). The names go out `NAMES_PER_READ` to a request.
        """
        params: Dict[str, Any] = {}
        if batch_id:
            params["batchId"] = batch_id
        if created_on:
            params["createdAt"] = [d.isoformat() for d in created_on]
        names = list(original_file_names or [])
        chunks = [names[i:i + NAMES_PER_READ] for i in range(0, len(names), NAMES_PER_READ)] or [[]]
        out: List[Artifact] = []
        seen: set = set()
        for chunk in chunks:
            query = {**params, "originalFileName": chunk} if chunk else params
            body = self._client.get(f"/evidence/{evidence_id}/artifacts", query or None) or {}
            for row in body.get("artifacts") or []:
                a = _artifact(row)
                if a.id not in seen:
                    seen.add(a.id)
                    out.append(a)
        return out

    def create_evidence(self, body: Dict[str, Any]) -> EvidenceSet:
        ref = body["referenceId"]
        try:
            return _evidence(self._client.post_json("/evidence", body))
        except ApiError as exc:
            if exc.status is None or not already_present(exc.status, exc.message):
                raise
        existing = self.evidence_by_reference([ref]).get(ref)
        if existing is None:
            raise ApiError(
                f"evidence {ref} was reported as already present but could not be read back",
                status=None, kind=ErrorKind.CONFLICT, method="POST", path="/evidence",
            )
        return existing

    def create_batch(
        self, *, artifact_request_id: Optional[str] = None, evidence_id: Optional[str] = None
    ) -> Batch:
        if artifact_request_id:
            body = {"type": "ARTIFACT_REQUEST", "artifactRequestId": artifact_request_id}
        elif evidence_id:
            body = {"type": "EVIDENCE", "evidenceId": evidence_id}
        else:
            raise ValueError("create_batch needs an artifact_request_id or an evidence_id")
        return _batch(self._client.post_json("/batches", body))

    def upload_to_batch(self, batch_id: str, filename: str, content: bytes, meta: Dict[str, Any]) -> Artifact:
        return _artifact(self._client.post_file(f"/batches/{batch_id}/artifacts/upload", filename, content, meta))

    def submit_batch(self, batch_id: str) -> Batch:
        return _batch(self._client.post_json(f"/batches/{batch_id}/submit", {}))

    def add_tags(self, entity: str, entity_id: str, tags: List[str]) -> None:
        self._client.post_json(f"/custom-tags/{entity}/{entity_id}", {"names": list(tags)})


def _freeze(value: Any) -> Any:
    if isinstance(value, (list, tuple, set)):
        return tuple(_freeze(v) for v in value)
    return value


class Reader:
    """Read-only view of `Resources`; identical calls hit the API once."""

    def __init__(self, resources: Resources) -> None:
        self._resources = resources
        self._memo: Dict[Any, Any] = {}

    def _cached(self, name: str, *args: Any, **kwargs: Any) -> Any:
        key = (name, _freeze(args), tuple(sorted((k, _freeze(v)) for k, v in kwargs.items())))
        if key not in self._memo:
            fn: Callable[..., Any] = getattr(self._resources, name)
            self._memo[key] = fn(*args, **kwargs)
        return self._memo[key]

    def stacks(self) -> List[Stack]:
        return list(self._cached("stacks"))

    def evidence_by_reference(self, refs: Sequence[str]) -> Dict[str, EvidenceSet]:
        return dict(self._cached("evidence_by_reference", refs))

    def artifact_requests(self, evidence_id: str, *, current: Optional[bool] = None) -> List[ArtifactRequest]:
        return list(self._cached("artifact_requests", evidence_id, current=current))

    def batches(
        self,
        *,
        evidence_id: Optional[str] = None,
        artifact_request_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Batch]:
        return list(
            self._cached("batches", evidence_id=evidence_id, artifact_request_id=artifact_request_id, status=status)
        )

    def batch(self, batch_id: str) -> Batch:
        return self._cached("batch", batch_id)  # type: ignore[no-any-return]

    def artifacts(
        self,
        evidence_id: str,
        *,
        batch_id: Optional[str] = None,
        original_file_names: Optional[Sequence[str]] = None,
        created_on: Optional[Sequence[date]] = None,
    ) -> List[Artifact]:
        return list(self._cached(
            "artifacts", evidence_id, batch_id=batch_id,
            original_file_names=list(original_file_names) if original_file_names else None,
            created_on=list(created_on) if created_on else None,
        ))
