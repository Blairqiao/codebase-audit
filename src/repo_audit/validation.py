"""Deterministic checks for claims about a filtered commit snapshot."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from .models import load_schema, validate_document
from .snapshot import Snapshot


@dataclass
class ValidationResult:
    accepted: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"accepted": self.accepted, "rejected": self.rejected, "errors": self.errors}


@dataclass(frozen=True)
class ReproductionEvidence:
    """Caller-supplied observed execution; agent JSON cannot instantiate this record."""

    repo_id: str
    snapshot: str
    problem_key: str
    artifact_path: Path
    artifact_sha256: str
    observation: str


def fingerprint(repo_id: str, rule_id: str, problem_key: str, path: str, symbol: str = "") -> str:
    parts = [
        repo_id,
        rule_id,
        " ".join(problem_key.lower().split()),
        str(PurePosixPath(path)),
        symbol,
    ]
    digest = hashlib.sha256(
        json.dumps(parts, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()
    return f"item-{digest}"


def _location_lines(
    location: dict[str, Any], snapshot: Snapshot, inventory: dict[str, Any]
) -> list[str]:
    path: str = location["path"]
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts or "\\" in path or path not in inventory:
        raise ValueError("Location is not in eligible snapshot inventory")
    target = snapshot.root / path
    if target.is_symlink() or any(
        parent.is_symlink() for parent in target.parents if parent.is_relative_to(snapshot.root)
    ):
        raise ValueError("Location traverses symlink")
    if not target.resolve().is_relative_to(snapshot.root.resolve()):
        raise ValueError("Location escapes snapshot")
    data = target.read_bytes()
    if hashlib.sha256(data).hexdigest() != inventory[path].sha256:
        raise ValueError("Snapshot file digest does not match inventory")
    lines = data.decode("utf-8").splitlines()
    start: int = location["line"]
    end: int = location.get("end_line", start)
    if not 1 <= start <= end <= len(lines):
        raise ValueError("Location line range is outside snapshot file")
    return lines[start - 1 : end]


def validate_candidates(
    output: dict[str, Any],
    snapshot: Snapshot,
    rules: list[dict[str, Any]],
    *,
    reproductions: list[ReproductionEvidence] | None = None,
) -> ValidationResult:
    result = ValidationResult()
    inventory = {item.path: item for item in snapshot.files}
    try:
        envelope = {**output, "candidates": []}
        validate_document("agent-output", envelope)
        if output.get("repo_id") != snapshot.repo_id or output.get("snapshot") != snapshot.commit:
            raise ValueError("Agent output repository/snapshot identity mismatch")
        for ledger in output["scope_ledger"]:
            if any(path not in inventory for path in ledger.get("paths", [])):
                raise ValueError("Scope ledger path is outside eligible inventory")
            for claimed in ledger.get("ranges", []):
                _location_lines(
                    {
                        "path": claimed["path"],
                        "line": claimed["start_line"],
                        "end_line": claimed["end_line"],
                    },
                    snapshot,
                    inventory,
                )
        if not isinstance(output.get("candidates"), list):
            raise TypeError("Candidates must be array")
    except (ValidationError, ValueError, TypeError, OSError, UnicodeDecodeError) as exc:
        result.errors.append(
            f"Invalid agent output: {exc.message if isinstance(exc, ValidationError) else exc}"
        )
        return result
    rule_index = {rule["id"]: rule for rule in rules if rule.get("mode") != "disabled"}
    candidate_validator = Draft202012Validator(
        load_schema("agent-output")["properties"]["candidates"]["items"]
    )
    seen: set[str] = set()
    now = datetime.now(UTC).isoformat()
    for index, original in enumerate(output["candidates"]):
        try:
            candidate_validator.validate(original)
            candidate = copy.deepcopy(original)
            for field in ["title", "problem_key", "mechanism", "impact", "next_action"]:
                if not candidate[field].strip():
                    raise ValueError(f"Candidate {field} must contain a concrete statement")
            if (
                candidate["kind"] == "finding"
                and not candidate.get("trigger_conditions", "").strip()
            ):
                raise ValueError("Finding must state concrete trigger conditions")
            rule = rule_index.get(candidate["rule_id"])
            if not rule:
                raise ValueError("Unknown, disabled or inapplicable rule")
            if candidate["category"] != rule["category"]:
                raise ValueError("Candidate category differs from rule")
            if (
                candidate["kind"] == "investigation"
                and not candidate.get("uncertainty", "").strip()
            ):
                raise ValueError("Investigation task must explain uncertainty")
            location = candidate["primary_location"]
            _location_lines(location, snapshot, inventory)
            for related in candidate.get("related_locations", []):
                _location_lines(related, snapshot, inventory)
            canonical_source = rule["source"]["url"]
            allowed_sources = {canonical_source, rule["source"]["url"], rule["source"]["section"]}
            if any(ref not in allowed_sources for ref in candidate.get("source_refs", [])):
                raise ValueError("Unknown rule source reference")
            evidence = []
            primary_supported = False
            for citation in candidate["evidence"]:
                actual = "\n".join(_location_lines(citation, snapshot, inventory))
                if citation["snippet"] != actual:
                    raise ValueError("Evidence snippet does not match cited lines")
                evidence.append(
                    {
                        **{k: v for k, v in citation.items() if k != "snippet"},
                        "snippet_sha256": hashlib.sha256(actual.encode()).hexdigest(),
                    }
                )
                if citation["path"] == location["path"] and citation["line"] <= location[
                    "line"
                ] <= citation.get("end_line", citation["line"]):
                    primary_supported = True
            if not primary_supported:
                raise ValueError("Primary location requires matching concrete evidence")
            item_id = fingerprint(
                snapshot.repo_id,
                candidate["rule_id"],
                candidate["problem_key"],
                location["path"],
                location.get("symbol", ""),
            )
            if item_id in seen:
                raise ValueError("Duplicate candidate identity within output")
            seen.add(item_id)
            item = {
                **candidate,
                "id": item_id,
                "repo_id": snapshot.repo_id,
                "snapshot": snapshot.commit,
                "evidence": evidence,
                "source_refs": [canonical_source],
                "related_locations": candidate.get("related_locations", []),
                "trigger_conditions": candidate.get("trigger_conditions", ""),
                "uncertainty": candidate.get("uncertainty", ""),
                "verification_level": "supported",
                "first_observed": now,
                "last_observed": now,
                "state": "open",
                "triage_history": [],
                "observation_status": "new",
            }
            for reproduction in reproductions or []:
                if not isinstance(reproduction, ReproductionEvidence):
                    continue
                if (reproduction.repo_id, reproduction.snapshot, reproduction.problem_key) != (
                    snapshot.repo_id,
                    snapshot.commit,
                    candidate["problem_key"],
                ):
                    continue
                if not reproduction.observation.strip() or not reproduction.artifact_path.is_file():
                    continue
                if (
                    hashlib.sha256(reproduction.artifact_path.read_bytes()).hexdigest()
                    != reproduction.artifact_sha256
                ):
                    continue
                item["verification_level"] = "reproduced"
                item["execution_evidence"] = [
                    {
                        "artifact_sha256": reproduction.artifact_sha256,
                        "observation": reproduction.observation,
                    }
                ]
            result.accepted.append(item)
        except (ValidationError, ValueError, OSError, UnicodeDecodeError, KeyError) as exc:
            reason = exc.message if isinstance(exc, ValidationError) else str(exc)
            result.rejected.append({"index": index, "reason": reason})
    return result
