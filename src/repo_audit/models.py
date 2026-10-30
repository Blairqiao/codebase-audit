"""Versioned JSON interchange validation."""

from __future__ import annotations

import json
from typing import Any

from jsonschema import Draft202012Validator

from .config import resource_dir

SCHEMA_VERSION = 1
CATEGORIES = (
    "correctness",
    "security",
    "concurrency",
    "maintenance",
    "architecture",
    "style",
    "testing",
)


def load_schema(kind: str) -> dict[str, Any]:
    if kind not in {"agent-output", "report", "coverage", "evidence", "policy"}:
        raise ValueError(f"Unknown schema {kind}")
    result: dict[str, Any] = json.loads(
        (resource_dir("schemas") / f"{kind}.schema.json").read_text()
    )
    return result


def validate_document(kind: str, data: dict[str, Any]) -> None:
    schema = load_schema(kind)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(data)
