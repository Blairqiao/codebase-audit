import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

from repo_audit.models import validate_document


def output():
    return {
        "schema_version": 1,
        "repo_id": "one",
        "snapshot": "a" * 40,
        "candidates": [],
        "scope_ledger": [],
    }


def test_agent_output_rejects_unknown_version_and_nested_properties():
    valid = output()
    validate_document("agent-output", valid)
    with pytest.raises(ValidationError):
        validate_document("agent-output", {**valid, "schema_version": 2})
    with pytest.raises(ValidationError):
        validate_document(
            "agent-output",
            {**valid, "scope_ledger": [{"scope_id": "x", "assessed": True, "allow_network": True}]},
        )


def test_rules_have_complete_pinned_provenance():
    for pack in (Path(__file__).parents[1] / "policies").glob("*.json"):
        validate_document("policy", json.loads(pack.read_text()))
    with pytest.raises(ValidationError):
        validate_document(
            "policy",
            {"schema_version": 1, "id": "empty", "version": "1.0.0", "rules": [{"id": "bad"}]},
        )
