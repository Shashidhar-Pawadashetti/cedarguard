"""Internal Resource Representation (IRR) data models.

The IRR is the provider-agnostic shape every parser normalizes into,
and the only shape the Cedar policy engine ever evaluates.
Reference: docs/04-data-model-api.md §1
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Resource:
    """Provider-agnostic representation of an infrastructure resource."""

    resource_id: str
    resource_type: str
    source_file: str
    source_line: int
    attributes: dict[str, Any] = field(default_factory=dict)
    raw_snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert resource to a dictionary representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Resource:
        """Construct Resource from dictionary data."""
        return cls(
            resource_id=data["resource_id"],
            resource_type=data["resource_type"],
            source_file=data["source_file"],
            source_line=data.get("source_line", 1),
            attributes=data.get("attributes", {}),
            raw_snippet=data.get("raw_snippet", ""),
        )


@dataclass
class Violation:
    """Representation of a policy violation discovered by CedarGuard."""

    rule_id: str
    severity: str
    resource_id: str
    resource_type: str
    file: str
    line: int
    explanation: str
    suggested_fix: str
    fix_snippet: str = ""
    detected_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert violation to a dictionary representation."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ScanResult:
    """Top-level result container for a scan execution."""

    scan_id: str
    target: str
    summary: dict[str, int]
    violations: list[Violation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "summary": self.summary,
            "violations": [v.to_dict() for v in self.violations],
        }
