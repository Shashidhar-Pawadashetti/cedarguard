"""Smoke test asserting Cedar engine authorization."""

import subprocess
import sys
from pathlib import Path


def test_cedar_smoke_script_execution():
    """Verify cedar-smoke-test/smoke_test.py passes end-to-end."""
    root_dir = Path(__file__).resolve().parent.parent
    smoke_script = root_dir / "cedar-smoke-test" / "smoke_test.py"

    res = subprocess.run(
        [sys.executable, str(smoke_script)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert res.returncode == 0, f"Smoke test failed with output:\n{res.stdout}\n{res.stderr}"
    assert "SMOKE TEST SUCCESSFUL: Cedar policy engine is ready!" in res.stdout
