"""Cedar execution engine abstraction.

Decouples the Cedar authorization execution mechanism (local CLI binary,
Lambda runtime / layer binary, or mock/in-process engine) from policy logic.
Crucially, all implementations evaluate the EXACT SAME Cedar policies
(policies/*.cedar) and schema (schema.cedarschema.json).

Reference: docs/03-architecture.md §2.2 and docs/06-engineering-rules.md §2.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class CedarEngine(ABC):
    """Abstract Cedar policy evaluation engine."""

    @abstractmethod
    def authorize(
        self,
        principal: str,
        action: str,
        resource: str,
        entities: list[dict[str, Any]],
        schema_path: str,
        policy_content: str,
    ) -> str:
        """Run Cedar authorization and return decision string: 'ALLOW' or 'DENY'."""


class SubprocessCedarEngine(CedarEngine):
    """Executes Cedar authorization via the official cedar-policy-cli binary.

    Works locally and in CI where cedar/cedar.exe is installed or on PATH.
    """

    def __init__(self, cedar_bin: str | None = None):
        self._cedar_bin = cedar_bin

    def _resolve_binary(self) -> str:
        if self._cedar_bin and Path(self._cedar_bin).exists():
            return self._cedar_bin

        # Check environment variable
        env_bin = os.environ.get("CEDAR_BIN")
        if env_bin and Path(env_bin).exists():
            return env_bin

        # Check local bin/ directory
        root = Path(__file__).resolve().parent.parent
        bin_name = "cedar.exe" if sys.platform == "win32" else "cedar"
        local_bin = root / "bin" / bin_name
        if local_bin.exists():
            return str(local_bin)

        # Check PATH
        path_bin = shutil.which("cedar")
        if path_bin:
            return path_bin

        # Windows fallback without .exe in which()
        if sys.platform == "win32":
            path_bin = shutil.which("cedar.exe")
            if path_bin:
                return path_bin

        raise FileNotFoundError(
            "Cedar CLI binary not found. Please install via cargo: "
            "cargo install cedar-policy-cli, or set CEDAR_BIN environment variable."
        )

    def authorize(
        self,
        principal: str,
        action: str,
        resource: str,
        entities: list[dict[str, Any]],
        schema_path: str,
        policy_content: str,
    ) -> str:
        cedar_exec = self._resolve_binary()

        entity_path = None
        policy_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8"
            ) as ef:
                json.dump(entities, ef)
                entity_path = ef.name

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".cedar", delete=False, encoding="utf-8"
            ) as pf:
                pf.write(policy_content)
                policy_path = pf.name

            cmd = [
                cedar_exec,
                "authorize",
                "--schema",
                schema_path,
                "--schema-format",
                "json",
                "--policies",
                policy_path,
                "--entities",
                entity_path,
                "--principal",
                principal,
                "--action",
                action,
                "--resource",
                resource,
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            return proc.stdout.strip()
        finally:
            if entity_path and os.path.exists(entity_path):
                os.unlink(entity_path)
            if policy_path and os.path.exists(policy_path):
                os.unlink(policy_path)


class LambdaCedarEngine(CedarEngine):
    """Executes Cedar authorization in AWS Lambda environments.

    Looks for cedar in:
    1. /opt/bin/cedar (standard Lambda Layer location for custom binaries)
    2. CEDAR_BIN environment variable
    3. Bundled binary or PATH
    """

    def __init__(self, layer_bin_path: str = "/opt/bin/cedar"):
        self.layer_bin_path = layer_bin_path
        self._subprocess_engine: SubprocessCedarEngine | None = None

    def _get_engine(self) -> SubprocessCedarEngine:
        if self._subprocess_engine is None:
            bin_path = None
            if Path(self.layer_bin_path).exists():
                bin_path = self.layer_bin_path
            elif os.environ.get("CEDAR_BIN"):
                bin_path = os.environ.get("CEDAR_BIN")
            self._subprocess_engine = SubprocessCedarEngine(bin_path)
        return self._subprocess_engine

    def authorize(
        self,
        principal: str,
        action: str,
        resource: str,
        entities: list[dict[str, Any]],
        schema_path: str,
        policy_content: str,
    ) -> str:
        return self._get_engine().authorize(
            principal=principal,
            action=action,
            resource=resource,
            entities=entities,
            schema_path=schema_path,
            policy_content=policy_content,
        )


_default_engine: CedarEngine | None = None


def get_cedar_engine(engine: CedarEngine | None = None) -> CedarEngine:
    """Get the active CedarEngine instance, defaulting to SubprocessCedarEngine."""
    if engine is not None:
        return engine
    global _default_engine
    if _default_engine is None:
        if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
            _default_engine = LambdaCedarEngine()
        else:
            _default_engine = SubprocessCedarEngine()
    return _default_engine
