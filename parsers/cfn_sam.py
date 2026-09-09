"""CloudFormation / SAM template parser for CedarGuard.

Parses YAML/JSON CloudFormation and SAM templates into Internal Resource
Representation (IRR) objects.
Reference: docs/03-architecture.md §2.1 and docs/04-data-model-api.md §1
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cfn_flip import load_yaml

from engine.irr import Resource


def parse_cfn_file(file_path: Path) -> list[Resource]:
    """Parse a single CloudFormation or SAM template into IRR resources."""
    content = file_path.read_text(encoding="utf-8")
    data = load_yaml(content)

    if not isinstance(data, dict):
        return []

    resources_dict: dict[str, Any] = data.get("Resources", {})
    parsed_resources: list[Resource] = []

    for res_id, res_body in resources_dict.items():
        if not isinstance(res_body, dict):
            continue

        res_type = res_body.get("Type", "Unknown")
        props = res_body.get("Properties", {})

        parsed_resources.append(
            Resource(
                resource_id=res_id,
                resource_type=res_type,
                source_file=str(file_path),
                source_line=1,  # Line mapping will be enhanced
                attributes=props,
                raw_snippet=str(res_body),
            )
        )

    return parsed_resources
