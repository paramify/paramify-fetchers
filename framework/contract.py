"""Dataclasses for the runner's internal representation of fetchers, manifests, and run results.

These are the in-memory shapes the runner uses; the on-disk yaml/json shapes are
documented in framework/schemas/*.json and parsed by config_loader / manifest_loader.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Secret:
    name: str
    env: str
    per_target: bool = False


@dataclass
class TargetField:
    name: str
    type: str
    required: bool = True
    env: Optional[str] = None
    default: Any = None
    description: Optional[str] = None


@dataclass
class SchemaBinding:
    """A fetcher's claim that its payload conforms to a vendored JSON Schema.

    Declared under evidence_set.schema_binding in fetcher.yaml. The pair must
    match an entry in framework/schemas/vendored/index.yaml; the runner verifies
    each JSON artifact against that schema and records the result in envelope
    metadata.validation. Absent binding = no verification (the common case).
    """
    schema_id: str
    pinned_version: str


@dataclass
class EvidenceSet:
    """Paramify evidence-set identity for a fetcher (1 fetcher = 1 evidence set).

    Shipped default declared in fetcher.yaml; the runner carries it into the
    envelope and the uploader get-or-creates the set by reference_id. Customers
    override reference_id per program in the uploader config, not here.

    The optional package_group field in fetcher.yaml is reserved for future
    package-completeness logic and deliberately NOT parsed here — nothing may
    read it yet.
    """
    reference_id: str
    name: str
    instructions: Optional[str] = None
    description: Optional[str] = None
    schema_binding: Optional[SchemaBinding] = None


@dataclass
class ConfigField:
    """A non-secret config knob a fetcher (or platform) accepts.

    Mirrors TargetField: declared in fetcher.yaml `config_schema` (per-fetcher)
    or in fetchers/_categories/<category>.yaml `config_schema` (platform-wide).
    The runner resolves a value and, when `env` is set, injects it as that env
    var for the invocation.
    """
    name: str
    type: str = "string"
    required: bool = False
    env: Optional[str] = None
    default: Any = None
    description: Optional[str] = None


@dataclass
class Fetcher:
    name: str
    version: str
    description: str
    category: Optional[str]
    runtime_type: str
    runtime_entry: str
    runtime_timeout: Optional[int]
    output_type: str
    output_path: str
    output_aggregation: Optional[str]
    secrets: List[Secret]
    supports_targets: bool
    target_schema: Dict[str, TargetField]
    path: Path
    config_schema: Dict[str, ConfigField] = field(default_factory=dict)
    evidence_set: Optional["EvidenceSet"] = None
    ksis: List[str] = field(default_factory=list)

    @property
    def entry_path(self) -> Path:
        return self.path / self.runtime_entry


@dataclass
class PlatformSpec:
    """Code-side declaration for a category, from fetchers/_categories/<name>.yaml.

    Holds config shared across every fetcher in the category plus the default
    auth passthrough list. Empty/absent category files yield an empty spec.
    """
    category: str
    config_schema: Dict[str, ConfigField] = field(default_factory=dict)
    passthrough_env: List[str] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class PlatformConfig:
    """Customer-side values for a category, from a manifest `platforms:` block."""
    config: Dict[str, Any] = field(default_factory=dict)
    passthrough_env: List[str] = field(default_factory=list)


@dataclass
class TargetInstance:
    """A single target from a manifest entry — values for one fanout iteration."""
    values: Dict[str, Any]
    secrets: Dict[str, str]


@dataclass
class ManifestEntry:
    use: str
    config: Dict[str, Any] = field(default_factory=dict)
    secrets: Dict[str, str] = field(default_factory=dict)
    targets: List[TargetInstance] = field(default_factory=list)


@dataclass
class Manifest:
    output_dir: Path
    entries: List[ManifestEntry]
    platforms: Dict[str, PlatformConfig] = field(default_factory=dict)


@dataclass
class InvocationResult:
    """Result of a single fetcher invocation (one target if fanout, else just one)."""
    fetcher_name: str
    fetcher_version: str
    target: Optional[Dict[str, Any]]
    started_at: str
    completed_at: str
    duration_sec: float
    exit_code: int
    stdout: str
    stderr: str
    outputs: List[str]
