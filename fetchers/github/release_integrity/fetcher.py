#!/usr/bin/env python3
"""Whether released software can be verified and cannot be swapped: build provenance on release assets, immutable
releases, and tag rulesets that stop a release tag being moved or deleted.

Each asset's sha256 digest (GitHub computes it on upload) is looked up in the repository's build provenance
attestations, filtered by GitHub (predicate_type=provenance). Where GitHub returns the Sigstore bundle inline, its
in-toto statement is checked to name the digest; a large bundle is served from blob storage instead and is not
fetched. Signatures are not verified: GitHub stores the bundles, `gh attestation verify` checks them.
"""

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import ruleset_targets_ref, run  # noqa: E402

NAME = "github_release_integrity"
CONFIG = {"releases_per_repository": ("GITHUB_RELEASES_PER_REPOSITORY", 10)}
# A tag is fixed in place only when both are refused: deleting it, and pointing it at another commit.
TAG_LOCKS = ("deletion", "update")


def statement(bundle):
    """The in-toto statement inside a Sigstore bundle's DSSE envelope, or None."""
    try:
        payload = ((bundle or {}).get("dsseEnvelope") or {}).get("payload")
        return json.loads(base64.b64decode(payload)) if payload else None
    except (ValueError, TypeError):
        return None


def attestation_summary(found, digest):
    """What the provenance attestations for one digest say, without the bundles."""
    inline = [statement(a.get("bundle")) for a in found if a.get("bundle")]
    hex_digest = digest.split(":", 1)[1] if ":" in digest else digest
    return {
        "count": len(found),
        "initiators": sorted({a.get("initiator") for a in found if a.get("initiator")}),
        "predicate_types": sorted({s.get("predicateType") for s in inline if s and s.get("predicateType")}),
        # The digest GitHub matched on must be a subject of each statement it returned inline; None when none was.
        "subject_matches": None if not inline else all(s is not None and any(
            (subj.get("digest") or {}).get("sha256") == hex_digest for subj in s.get("subject") or []) for s in inline),
        "bundles_not_inline": sum(1 for a in found if not a.get("bundle")),
    }


def asset_record(client, base, asset):
    digest = asset.get("digest")
    row = {"name": asset.get("name"), "size": asset.get("size"), "digest": digest,
           "uploader": (asset.get("uploader") or {}).get("login"), "build_provenance": None, "provenance": None}
    if not digest:
        return row  # assets uploaded before GitHub computed digests have none; unknown, not unattested
    failures = len(client.failures)
    # An immutable release also carries GitHub's own release attestation (initiator "github", measured), which says
    # what was released, not how it was built; the filter leaves it out.
    _, body = client.lookup(f"{base}/attestations/{digest}", {"predicate_type": "provenance"})  # 404: none
    if len(client.failures) > failures:
        return {**row, "collected": False}
    summary = attestation_summary((body or {}).get("attestations") or [], digest)
    return {**row, "build_provenance": summary["count"] > 0 and summary["subject_matches"] is not False,
            "provenance": summary}


def tag_rules(rulesets, repo_name, tag, default_branch):
    """The tag-lock rules active rulesets enforce on refs/tags/<tag>, and whether any ruleset's reach is unknown."""
    locks, unknown, always_bypass = set(), False, []
    for rs in rulesets:
        applies = ruleset_targets_ref(rs, repo_name, f"refs/tags/{tag}", default_branch, target="tag")
        if rs.get("enforcement") != "active" or applies is False:
            continue
        types = {r.get("type") for r in rs.get("rules") or []}
        if applies is None:
            unknown = unknown or bool(types & set(TAG_LOCKS))
            continue
        locks |= types & set(TAG_LOCKS)
        if any(a.get("bypass_mode") == "always" for a in rs.get("bypass_actors") or []):
            always_bypass.append(rs.get("name"))
    full = set(TAG_LOCKS) <= locks
    return {"locked": True if full else None if unknown else False, "rules": sorted(locks),
            "always_bypass": sorted(always_bypass)}


def repo_record(client, org, repo, config, details):
    name = repo["name"]
    base = f"repos/{org}/{name}"
    seen = []
    releases = client.paginate_required(f"{base}/releases", until=lambda r: seen.append(r) or
                                        len(seen) > config["releases_per_repository"])
    immutable = client.get(f"{base}/immutable-releases")
    summaries = client.paginate_required(f"{base}/rulesets", {"includes_parents": "true"})
    if releases is None or immutable is None or summaries is None:
        return {"repository": name, "collected": False}
    rulesets = []
    for s in summaries:
        if s.get("target") == "tag":
            if s["id"] not in details:
                details[s["id"]] = client.get(f"{base}/rulesets/{s['id']}")
            rulesets.append(details[s["id"]] or s)
    rows = []
    for rel in releases:
        assets = [asset_record(client, base, a) for a in rel.get("assets") or []]
        rows.append({
            "tag": rel.get("tag_name"),
            "name": rel.get("name"),
            "draft": rel.get("draft"),
            "prerelease": rel.get("prerelease"),
            "published_at": rel.get("published_at"),
            "author": (rel.get("author") or {}).get("login"),
            "immutable": rel.get("immutable"),
            "tag_protection": tag_rules(rulesets, name, rel.get("tag_name") or "", repo.get("default_branch")),
            "assets": assets,
        })
    if any(a.get("collected") is False for r in rows for a in r["assets"]):
        return {"repository": name, "collected": False}
    return {
        "repository": name,
        "collected": True,
        "immutable_releases_enabled": immutable.get("enabled"),
        "immutable_releases_enforced_by_owner": immutable.get("enforced_by_owner"),
        "tag_rulesets": [{"name": r.get("name"), "enforcement": r.get("enforcement"),
                          "rule_types": sorted({x.get("type") for x in r.get("rules") or [] if x.get("type")})}
                         for r in rulesets],
        "releases": rows,
    }


def collect(client, org, repos, config):
    login = org["login"]
    policy = client.get(f"orgs/{login}/settings/immutable-releases")
    details = {}
    records = [repo_record(client, login, r, config, details) for r in repos]
    done = [r for r in records if r["collected"]]
    published = [(r["repository"], rel) for r in done for rel in r["releases"] if not rel["draft"]]
    assets = [(repo, rel, a) for repo, rel in published for a in rel["assets"]]

    def label(repo, rel):
        return f"{repo}@{rel['tag']}"
    return {
        "summary": {
            "organization_immutable_releases": (policy or {}).get("enforced_repositories"),
            "repositories_with_releases": len({repo for repo, _ in published}),
            "repositories_with_immutable_releases": sorted(r["repository"] for r in done
                                                           if r["immutable_releases_enabled"]),
            "releases_checked": len(published),
            "releases_not_immutable": sorted(label(repo, rel) for repo, rel in published if rel["immutable"] is False),
            "releases_immutability_unknown": sorted(label(repo, rel) for repo, rel in published
                                                    if rel["immutable"] is None),
            "release_assets": len(assets),
            "release_assets_with_build_provenance": sum(1 for *_, a in assets if a["build_provenance"]),
            "release_assets_without_build_provenance": sorted(f"{label(repo, rel)}:{a['name']}"
                                                              for repo, rel, a in assets
                                                              if a["build_provenance"] is False),
            "release_assets_without_digest": sorted(f"{label(repo, rel)}:{a['name']}" for repo, rel, a in assets
                                                    if not a["digest"]),
            # Locked by an active tag ruleset or by the release being immutable; a ruleset GitHub resolves by
            # repository property is unknown, never unlocked.
            "release_tags_not_locked": sorted(label(repo, rel) for repo, rel in published
                                              if rel["tag_protection"]["locked"] is False and not rel["immutable"]),
            "release_tags_lock_unknown": sorted(label(repo, rel) for repo, rel in published
                                                if rel["tag_protection"]["locked"] is None and not rel["immutable"]),
            "not_collected": [r["repository"] for r in records if not r["collected"]],
        },
        "organization": {"immutable_releases": policy},
        "repositories": records,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
