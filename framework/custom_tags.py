"""Default custom tags on everything the uploaders create in Paramify.

Every evidence set, script and validator the fetchers project puts into a
workspace carries two tags by default, so a user who has the fetchers create
resources sees tagging working out of the box and can filter the fetchers' work
from the hand-made rest:

- a **provenance** tag, "Automated by Paramify Fetchers" unless renamed, and
- a **service** tag, the category's `display_name` (`AWS`, `Okta`), spelled out
  on `fetchers/_categories/<category>.yaml` because no rule turns a slug like
  `aws` into its brand name.

Both are project-wide knobs in the uploader config (`upload.yaml`), not
per-fetcher settings, and both can be renamed or switched off:

    tags:
      provenance: Automated by Paramify Fetchers   # a string, or false to drop it
      service: true                                 # false to drop the category tag

    tags: false                                     # no default tags at all

To switch the whole feature off without touching a file, set
`PARAMIFY_CUSTOM_TAGS=off` wherever the stage runs (a shell, CI, a container);
it wins over the config. `--no-tags` on `paramify upload`, `paramify scripts
sync` and `paramify validators sync` does the same for one invocation.

Writes are **additive and re-asserted on every run**: `POST
/custom-tags/{entity}/{id}` adds names and auto-creates unknown ones; it never
replaces the entity's tag set, so a user's own tags survive, and a run reaches
resources an earlier run created before this existed. The cost is that a
renamed or disabled default leaves its old tag behind once — additive writes
cannot remove it. PATCH, which could, would clobber user tags; it is never used.

Tagging can never fail an upload. A key without the custom-tags permission gets
one warning and the rest of the run proceeds untagged; any other error is logged
per entity and counted. See docs/uploader_design.md.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

logger = logging.getLogger("paramify_custom_tags")

DEFAULT_PROVENANCE_TAG = "Automated by Paramify Fetchers"
CONFIG_KEY = "tags"
#: The kill switch: set to off / false / no / 0 and no stage writes a tag,
#: whatever the config says. Any other value leaves the config in charge.
ENV_SWITCH = "PARAMIFY_CUSTOM_TAGS"
_OFF_VALUES = {"0", "false", "no", "off"}

#: The `entity` path segment of `/custom-tags/{entity}/{entityId}` for each
#: resource type the uploaders create.
ENTITY_EVIDENCE = "evidence"
ENTITY_SCRIPT = "scripts"
ENTITY_VALIDATOR = "validators"

_TAG_MAX_LEN = 255
_KNOWN_KEYS = {"provenance", "service"}


@dataclass(frozen=True)
class TagPolicy:
    """Which default tags a run applies. `provenance` None means no provenance tag."""

    provenance: Optional[str] = DEFAULT_PROVENANCE_TAG
    service: bool = True
    #: Why the feature is off, when it is — the switch that turned it off, so
    #: the Done block can say so. None while tags are on.
    off_reason: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return bool(self.provenance) or self.service


def _off(reason: str) -> TagPolicy:
    return TagPolicy(provenance=None, service=False, off_reason=reason)


def _clean_tag(value: Any, *, where: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{where} must be a string, got {type(value).__name__}")
    name = value.strip()
    if not name:
        raise ValueError(f"{where} must not be empty (use false to turn the tag off)")
    if len(name) > _TAG_MAX_LEN:
        raise ValueError(f"{where} must be at most {_TAG_MAX_LEN} characters")
    return name


def resolve_tag_policy(
    config: Optional[Mapping[str, Any]],
    env: Optional[Mapping[str, str]] = None,
    *,
    override_off: Optional[str] = None,
) -> TagPolicy:
    """The tag policy for one run: the switches first, then the config block.

    Precedence: `override_off` (a caller's reason, e.g. `--no-tags`), then the
    `PARAMIFY_CUSTOM_TAGS` env var when it says off, then the config's `tags:`
    block. Absent block -> the defaults. `tags: false` -> everything off.
    Inside the block, `provenance` is a string or false/null (off) and
    `service` a bool. Raises ValueError for a shape it does not understand,
    like the uploaders do for any other config mistake — a typo must not
    silently fall back to the defaults. A switch that says off wins before the
    block is looked at, so a broken block cannot keep the feature on.
    """
    if override_off:
        return _off(override_off)
    src = env if env is not None else os.environ
    raw_switch = (src.get(ENV_SWITCH) or "").strip()
    if raw_switch.lower() in _OFF_VALUES:
        return _off(f"{ENV_SWITCH}={raw_switch}")

    block = (config or {}).get(CONFIG_KEY)
    if block is None or block is True:
        return TagPolicy()
    if block is False:
        return _off(f"`{CONFIG_KEY}: false` in the uploader config")
    if not isinstance(block, Mapping):
        raise ValueError(f"`{CONFIG_KEY}` must be a mapping or false, got {type(block).__name__}")
    unknown = sorted(set(block) - _KNOWN_KEYS)
    if unknown:
        raise ValueError(
            f"`{CONFIG_KEY}` has unknown key(s) {unknown}; expected {sorted(_KNOWN_KEYS)}"
        )

    provenance: Optional[str] = DEFAULT_PROVENANCE_TAG
    if "provenance" in block:
        raw = block["provenance"]
        if raw is None or raw is False:
            provenance = None
        elif raw is True:
            provenance = DEFAULT_PROVENANCE_TAG
        else:
            provenance = _clean_tag(raw, where=f"`{CONFIG_KEY}.provenance`")

    service = True
    if "service" in block:
        raw = block["service"]
        if not isinstance(raw, bool):
            raise ValueError(f"`{CONFIG_KEY}.service` must be true or false, got {raw!r}")
        service = raw

    return TagPolicy(provenance=provenance, service=service)


def category_display_names(root: Path) -> Dict[str, str]:
    """{category: display_name} for every category file that declares one.

    A category without a `display_name` is simply absent, and its resources get
    the provenance tag only. An unreadable categories tree is a warning, not a
    failure: tags never block an upload.
    """
    try:
        from framework.config_loader import discover_platforms

        platforms = discover_platforms(Path(root))
    except Exception as exc:  # noqa: BLE001 — tagging must never break an upload
        logger.warning(
            "could not read category display names from %s (%s); "
            "service tags are off for this run",
            root, exc,
        )
        return {}
    return {name: spec.display_name for name, spec in platforms.items() if spec.display_name}


class Tagger:
    """Applies the default tags to entities through one authenticated session.

    `plan(category)` is the names a resource of that category gets; `tag(...)`
    POSTs them. Each (entity, id) is posted at most once per run — an evidence
    set that several files land on is tagged once. After a 403 the tagger
    switches itself off for the rest of the run, with a single warning.
    """

    def __init__(
        self,
        session: Any,
        base_url: str,
        *,
        policy: TagPolicy,
        display_names: Optional[Mapping[str, str]] = None,
        timeout: int = 30,
    ):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.policy = policy
        self.display_names: Dict[str, str] = dict(display_names or {})
        self.timeout = timeout
        #: Why tagging stopped for this run (a 403), or None while it is on.
        self.disabled: Optional[str] = None
        self.applied = 0
        self.failed = 0
        self.skipped = 0
        self._done: Set[Tuple[str, str]] = set()
        self._no_display_name: Set[str] = set()

    # -- what ------------------------------------------------------------- #
    def plan(self, category: Optional[str]) -> List[str]:
        """The tag names a resource of `category` receives under this policy."""
        names: List[str] = []
        if not self.policy.enabled:
            return names
        if self.policy.provenance:
            names.append(self.policy.provenance)
        if self.policy.service and category:
            display = self.display_names.get(category)
            if display:
                names.append(display)
            elif category not in self._no_display_name:
                self._no_display_name.add(category)
                logger.info(
                    "category %r declares no display_name; its resources get no service tag",
                    category,
                )
        return names

    # -- do --------------------------------------------------------------- #
    def tag(self, entity: str, entity_id: str, category: Optional[str] = None) -> Dict[str, Any]:
        """Add the default tags to one entity. Never raises.

        Returns {"outcome": ..., "tags": [...]} where outcome is `applied`,
        `already` (this run already tagged it), `off` (the feature is switched
        off), `skipped` (nothing to apply), `forbidden` (the key lacks the
        permission; the run goes on untagged), `dry_run` (no session) or
        `error` (logged and counted).
        """
        if not self.policy.enabled:
            return {"outcome": "off", "tags": []}
        names = self.plan(category)
        if not names:
            return {"outcome": "skipped", "tags": []}
        key = (entity, entity_id)
        if key in self._done:
            return {"outcome": "already", "tags": names}
        if self.session is None:
            return {"outcome": "dry_run", "tags": names}
        if self.disabled:
            self.skipped += 1
            return {"outcome": "forbidden", "tags": names}

        url = f"{self.base_url}/custom-tags/{entity}/{entity_id}"
        try:
            r = self.session.post(url, json={"names": names}, timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001 — network trouble must not fail the upload
            self.failed += 1
            logger.warning("custom tags: %s %s: %s", entity, entity_id, exc)
            return {"outcome": "error", "tags": names, "error": str(exc)[:300]}

        # 409 is tolerated the way the association endpoints' 409 is: the tag
        # is already on the entity, which is the state we wanted.
        if r.status_code in (200, 201, 409):
            self._done.add(key)
            self.applied += 1
            return {"outcome": "applied", "tags": names}
        if r.status_code == 403:
            self.disabled = (
                "the API key is not allowed to manage custom tags (HTTP 403); "
                "ask a workspace admin for the custom-tags permission"
            )
            self.skipped += 1
            logger.warning("custom tags: %s — the rest of this run proceeds untagged", self.disabled)
            return {"outcome": "forbidden", "tags": names}

        self.failed += 1
        detail = (getattr(r, "text", "") or "")[:200]
        logger.warning("custom tags: %s %s: HTTP %s %s", entity, entity_id, r.status_code, detail)
        return {"outcome": "error", "tags": names, "error": f"HTTP {r.status_code}: {detail}"}

    def summary(self) -> Dict[str, Any]:
        return {
            "enabled": self.policy.enabled,
            "reason": self.policy.off_reason,
            "provenance": self.policy.provenance,
            "service": self.policy.service,
            "applied": self.applied,
            "failed": self.failed,
            "skipped": self.skipped,
            "disabled": self.disabled,
        }


def build_tagger(
    session: Any,
    base_url: str,
    *,
    config: Optional[Mapping[str, Any]] = None,
    root: Optional[Path] = None,
    display_names: Optional[Mapping[str, str]] = None,
    timeout: int = 30,
    override_off: Optional[str] = None,
) -> Tagger:
    """The Tagger for one uploader run.

    `session` is the client's authenticated requests.Session; pass None for a
    dry run, where `plan()` still answers but `tag()` writes nothing. Display
    names come from `display_names`, or are read from `root`'s category files.
    `override_off` is a caller's reason to switch the feature off for this run
    (`--no-tags`). When tags are off — by that, by `PARAMIFY_CUSTOM_TAGS`, or
    by the config — the Tagger still exists but plans and writes nothing, and
    its summary says why. Raises ValueError for a malformed `tags:` block (a
    setup error).
    """
    policy = resolve_tag_policy(config, override_off=override_off)
    if not policy.enabled:
        return Tagger(None, base_url, policy=policy, timeout=timeout)
    names = dict(display_names) if display_names is not None else (
        category_display_names(root) if root is not None else {}
    )
    return Tagger(session, base_url, policy=policy, display_names=names, timeout=timeout)
