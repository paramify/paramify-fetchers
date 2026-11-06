"""An in-process fake of the Paramify 0.14.0 API for the sync engine's tests.

`FakeParamify.session` stands in for a `requests.Session`: pass it to
`Client(..., session=fake.session)`. State helpers build the workspace.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from framework.paramify.resources import ArtifactRequest, Channel, EvidenceSet, Stack

_EVIDENCE_POST_KEYS = frozenset({
    "referenceId", "name", "description", "instructions", "remarks", "frequency", "startDate",
    "whenToApproveArtifactRequest", "whenToCreateAndUpdateProcessArtifactRequest",
})

_DIRECT_META_KEYS = frozenset({"title", "note", "effectiveDate", "channelId"})


def _public(row: Dict[str, Any]) -> Dict[str, Any]:
    """An artifact as the API shows it: the fake's private keys (leading underscore) are dropped."""
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _matches(wanted: Any, value: str) -> bool:
    """A query filter: absent matches all; a list (a repeated parameter) matches any of its values."""
    if wanted is None:
        return True
    return value in wanted if isinstance(wanted, (list, tuple)) else value == wanted


class FakeResponse:
    def __init__(self, status_code: int, payload: Any = None, text: Optional[str] = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else ("" if payload is None else json.dumps(payload))
        self.headers: Dict[str, str] = {}

    def json(self) -> Any:
        return json.loads(self.text)


@dataclass
class _Session:
    fake: "FakeParamify"
    headers: Dict[str, str] = field(default_factory=dict)

    def request(self, method: str, url: str, params: Any = None, json: Any = None,
                files: Any = None, timeout: Any = None) -> FakeResponse:
        path = urlparse(url).path
        self.fake.calls.append((method, path, dict(params or {})))
        return self.fake._route(method, path, dict(params or {}), json, files)


class FakeParamify:
    def __init__(self) -> None:
        self.session = _Session(self)
        self.calls: List[Tuple[str, str, Dict[str, Any]]] = []
        self.today = date(2026, 11, 1)
        self.tags: Dict[Tuple[str, str], List[str]] = {}
        self._stacks: List[Dict[str, Any]] = []
        self._evidence: List[Dict[str, Any]] = []
        self._requests: List[Dict[str, Any]] = []
        self._batches: List[Dict[str, Any]] = []
        self._artifacts: List[Dict[str, Any]] = []
        self._fail_all: Dict[str, Tuple[int, str]] = {}
        self._fail_once: Dict[str, int] = {}
        self._fail_routes: List[Tuple[str, str, int, str, Dict[str, Any]]] = []
        self._batches_enabled = True
        self._batches_flag_off = False
        self._n: Dict[str, int] = {}
        self.duplicate_evidence_body = "Evidence already exists"

    # ----- state helpers -------------------------------------------------
    def _next(self, kind: str) -> int:
        self._n[kind] = self._n.get(kind, 0) + 1
        return self._n[kind]

    def add_stack(self, name: str) -> Stack:
        row = {"id": f"st-{self._next('st')}", "name": name}
        self._stacks.append(row)
        return Stack(**row)

    def _make_evidence(self, ref: str, channels: Any, approval: str, name: Optional[str] = None) -> Dict[str, Any]:
        row = {
            "id": f"ev-{self._next('ev')}", "referenceId": ref, "name": name or ref,
            "whenToApproveArtifactRequest": approval,
            "channels": [
                {"id": f"ch-{self._next('ch')}", "referenceId": f"CH-{self._n['ch']}",
                 "owner": None, "stackId": s}
                for s in channels
            ],
        }
        self._evidence.append(row)
        return row

    def add_evidence(self, ref: str, *, channels: Any = (), approval: str = "SUBMISSION") -> EvidenceSet:
        row = self._make_evidence(ref, channels, approval)
        return EvidenceSet(
            id=row["id"], reference_id=ref, name=row["name"], approval=approval,
            channels=tuple(Channel(c["id"], c["referenceId"], c["stackId"]) for c in row["channels"]),
        )

    def add_request(self, evidence_id: str, channel_id: str, requested: date, due: date) -> ArtifactRequest:
        row = {
            "id": f"ar-{self._next('ar')}", "referenceId": f"AR-{self._n['ar']}",
            "requestedDate": requested.isoformat(), "dueDate": due.isoformat(),
            "channelId": channel_id, "evidenceId": evidence_id, "batchCount": 0,
        }
        self._requests.append(row)
        return ArtifactRequest(row["id"], row["referenceId"], channel_id, evidence_id, requested, due)

    def set_today(self, d: date) -> None:
        self.today = d

    def fail_upload(self, filename: str, status: int, body: str = "") -> None:
        self._fail_all[filename] = (status, body)

    def fail_upload_once(self, filename: str, status: int) -> None:
        self._fail_once[filename] = status

    def without_batches(self) -> None:
        self._batches_enabled = False

    def batches_flag_off(self, off: bool = True) -> None:
        """A workspace whose batches flag is off: /batches and /artifact-requests answer 403."""
        self._batches_flag_off = off

    def fail_route(self, method: str, path_regex: str, status: int, text: str = "",
                   when: Optional[Dict[str, Any]] = None) -> None:
        """Answer `status` to every `method` call on a path matching `path_regex`.

        `when` limits it to JSON bodies that hold these key/value pairs.
        """
        self._fail_routes.append((method, path_regex, status, text, dict(when or {})))

    def add_legacy_artifact(self, evidence_id: str, filename: str, note: str) -> Dict[str, Any]:
        """An artifact the pre-batch uploader made (POST /evidence/{id}/artifacts/upload): no batch."""
        row = {
            "id": f"af-{self._next('af')}", "title": filename, "originalFileName": filename,
            "pathname": f"/artifacts/{filename}", "note": note, "isUrl": False, "fileType": "json",
            "createdAt": f"{self.today.isoformat()}T00:00:00Z", "createdBy": {},
            "effectiveDate": self.today.isoformat(), "batchId": None, "validators": [],
            "_evidenceId": evidence_id,
        }
        self._artifacts.append(row)
        return row

    # ----- routing -------------------------------------------------------
    def _route(self, method: str, path: str, params: Dict[str, Any], body: Any, files: Any) -> FakeResponse:
        for f_method, f_path, f_status, f_text, f_when in self._fail_routes:
            if (f_method == method and re.fullmatch(f_path, path)
                    and all((body or {}).get(k) == v for k, v in f_when.items())):
                return FakeResponse(f_status, text=f_text)
        if self._batches_flag_off and path.startswith(("/batches", "/artifact-requests")):
            return FakeResponse(403, text=json.dumps({
                "requestId": "r-1", "statusMessage": "Forbidden",
                "error": {"message": "Artifact requests are not enabled for this workspace.", "path": path},
            }))
        if path.startswith("/batches") and not self._batches_enabled:
            return FakeResponse(404, text="Not Found")
        if method == "GET" and path == "/stacks":
            return FakeResponse(200, self._stacks)
        if path == "/evidence":
            if method == "GET":
                ref = params.get("referenceId")
                rows = [e for e in self._evidence if ref in (None, e["referenceId"])]
                return FakeResponse(200, {"evidences": rows})
            extra = sorted(set(body) - _EVIDENCE_POST_KEYS)
            if extra:
                return FakeResponse(400, text=f"Unrecognized keys: {', '.join(extra)}")
            if not body.get("name"):
                return FakeResponse(400, text="name is required")
            if any(e["referenceId"] == body.get("referenceId") for e in self._evidence):
                # The spec gives no body text for this refusal; the wording is assumed.
                return FakeResponse(409, text=self.duplicate_evidence_body)
            row = self._make_evidence(
                body.get("referenceId") or f"EVD-{self._next('ev') + 1000}", (),
                body.get("whenToApproveArtifactRequest", "SUBMISSION"), body["name"],
            )
            row["whenToCreateAndUpdateProcessArtifactRequest"] = body.get(
                "whenToCreateAndUpdateProcessArtifactRequest", "MANUAL")
            return FakeResponse(201, row)
        if method == "GET" and path == "/artifact-requests":
            rows = [r for r in self._requests if r["evidenceId"] == params.get("evidenceId")]
            if str(params.get("current")).lower() == "true":
                rows = [r for r in rows
                        if date.fromisoformat(r["requestedDate"]) <= self.today <= date.fromisoformat(r["dueDate"])]
            return self._page(rows, "artifactRequests", params)
        if path == "/batches":
            if method == "GET":
                rows = [b for b in self._batches
                        if all(params.get(q) in (None, b[k]) for q, k in
                               (("evidenceId", "evidenceId"), ("artifactRequestId", "artifactRequestId"),
                                ("status", "status")))]
                return self._page(rows, "batches", params)
            return self._create_batch(body)
        m = re.fullmatch(r"/batches/([^/]+)(?:/(submit|artifacts/upload))?", path)
        if m:
            batch = next((b for b in self._batches if b["id"] == m.group(1)), None)
            if batch is None:
                return FakeResponse(404, text="Not Found")
            if m.group(2) is None and method == "GET":
                return FakeResponse(200, batch)
            if m.group(2) == "submit":
                return self._submit(batch)
            if m.group(2):
                return self._upload(batch, files)
        m = re.fullmatch(r"/evidence/([^/]+)/artifacts/upload", path)
        if method == "POST" and m:
            if not any(e["id"] == m.group(1) for e in self._evidence):
                return FakeResponse(404, text="Not Found")
            return self._upload_direct(m.group(1), files)
        m = re.fullmatch(r"/evidence/([^/]+)/artifacts", path)
        if method == "GET" and m:
            rows = [a for a in self._artifacts
                    if a["_evidenceId"] == m.group(1)
                    and params.get("batchId") in (None, a["batchId"])
                    and _matches(params.get("originalFileName"), a["originalFileName"])
                    and _matches(params.get("createdAt"), a["createdAt"][:10])]
            return FakeResponse(200, {"artifacts": [_public(a) for a in rows]})
        m = re.fullmatch(r"/custom-tags/([^/]+)/([^/]+)", path)
        if method == "POST" and m:
            have = self.tags.setdefault((m.group(1), m.group(2)), [])
            have.extend(n for n in body["names"] if n not in have)
            return FakeResponse(200, {"customTags": have})
        return FakeResponse(404, text="Not Found")

    def _page(self, rows: List[Dict[str, Any]], key: str, params: Dict[str, Any]) -> FakeResponse:
        size = int(params.get("pageSize", 100))
        page = int(params.get("page", 1))
        total_pages = max(1, -(-len(rows) // size))
        return FakeResponse(200, {
            key: rows[(page - 1) * size: page * size],
            "pagination": {"page": page, "pageSize": size, "totalCount": len(rows), "totalPages": total_pages},
        })

    def _create_batch(self, body: Dict[str, Any]) -> FakeResponse:
        request_id = None
        if body["type"] == "ARTIFACT_REQUEST":
            request = next((r for r in self._requests if r["id"] == body["artifactRequestId"]), None)
            if request is None:
                return FakeResponse(404, text="Not Found")
            request_id, evidence_id = request["id"], request["evidenceId"]
            request["batchCount"] += 1
        else:
            evidence_id = body["evidenceId"]
        evidence = next((e for e in self._evidence if e["id"] == evidence_id), None)
        if evidence is None:
            return FakeResponse(404, text="Not Found")
        row = {
            "id": f"bt-{self._next('bt')}", "referenceId": f"BCH-{self._n['bt']}", "status": "OPEN",
            "evidenceId": evidence_id, "artifactRequestId": request_id, "artifactCount": 0,
            "whenToApprove": evidence["whenToApproveArtifactRequest"], "whenToCreateAndUpdateProcess": "NEVER",
        }
        self._batches.append(row)
        return FakeResponse(201, row)

    def _upload(self, batch: Dict[str, Any], files: Any) -> FakeResponse:
        filename = files["file"][0]
        if batch["status"] not in ("OPEN", "REJECTED"):
            return FakeResponse(409, text="Batch is not open")
        if filename in self._fail_once:
            return FakeResponse(self._fail_once.pop(filename), text="injected failure")
        if filename in self._fail_all:
            status, text = self._fail_all[filename]
            return FakeResponse(status, text=text)
        meta = json.loads(files["artifact"][1])
        row = {
            "id": f"af-{self._next('af')}", "title": meta.get("title") or filename,
            "originalFileName": filename, "pathname": f"/artifacts/{filename}", "note": meta.get("note"),
            "isUrl": False, "fileType": "json", "createdAt": f"{self.today.isoformat()}T00:00:00Z",
            "createdBy": {}, "effectiveDate": meta.get("effectiveDate") or self.today.isoformat(),
            "batchId": batch["id"], "validators": [], "_evidenceId": batch["evidenceId"],
        }
        self._artifacts.append(row)
        batch["artifactCount"] += 1
        return FakeResponse(201, _public(row))

    def _upload_direct(self, evidence_id: str, files: Any) -> FakeResponse:
        """POST /evidence/{id}/artifacts/upload: no batch, so the artifact has batchId None."""
        filename = files["file"][0]
        meta = json.loads(files["artifact"][1])
        extra = sorted(set(meta) - _DIRECT_META_KEYS)
        if extra:
            return FakeResponse(400, text=f"Unrecognized keys: {', '.join(extra)}")
        if filename in self._fail_once:
            return FakeResponse(self._fail_once.pop(filename), text="injected failure")
        if filename in self._fail_all:
            status, text = self._fail_all[filename]
            return FakeResponse(status, text=text)
        row = {
            "id": f"af-{self._next('af')}", "title": meta.get("title") or filename,
            "originalFileName": filename, "pathname": f"/artifacts/{filename}", "note": meta.get("note"),
            "isUrl": False, "fileType": "json", "createdAt": f"{self.today.isoformat()}T00:00:00Z",
            "createdBy": {}, "effectiveDate": meta.get("effectiveDate") or self.today.isoformat(),
            "batchId": None, "validators": [], "_evidenceId": evidence_id, "_channelId": meta.get("channelId"),
        }
        self._artifacts.append(row)
        return FakeResponse(200, _public(row))

    def _submit(self, batch: Dict[str, Any]) -> FakeResponse:
        if batch["status"] not in ("OPEN", "REJECTED"):
            return FakeResponse(409, text="Batch is not open")
        if batch["artifactCount"] == 0:
            return FakeResponse(409, text="Batch has no artifacts")
        batch["status"] = "SUBMITTED" if batch["whenToApprove"] == "MANUAL" else "APPROVED"
        return FakeResponse(200, batch)
