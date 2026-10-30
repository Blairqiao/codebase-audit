"""Write local JSON and Markdown artifacts without raw source or transcripts."""

from __future__ import annotations

import copy
import hashlib
import html
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .models import validate_document

METADATA_KEYS = {
    "run_id",
    "created_at",
    "backend",
    "model",
    "usage",
    "platform",
    "versions",
    "stages",
    "warnings",
    "history_complete",
    "hydration_complete",
    "cache_freshness",
    "launches",
    "publication_enabled",
    "allowed_destination",
    "github_repository",
}
ITEM_KEYS = {
    "id",
    "repo_id",
    "snapshot",
    "kind",
    "title",
    "category",
    "rule_id",
    "problem_key",
    "primary_location",
    "related_locations",
    "evidence",
    "source_refs",
    "trigger_conditions",
    "mechanism",
    "impact",
    "severity",
    "confidence",
    "verification_level",
    "next_action",
    "uncertainty",
    "first_observed",
    "last_observed",
    "state",
    "triage_history",
    "observation_status",
    "github_issue",
    "execution_evidence",
    "identity_match",
}
DROP_KEYS = re.compile(
    r"password|secret|api.?key|(?:^|_)(?:access|auth|refresh|bearer)_?token$|^token$|^raw$|raw_(?:output|text|source)|transcript|snippet$|stdout|stderr|prompt|source_content",
    re.IGNORECASE,
)


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: sanitize(item) for key, item in value.items() if not DROP_KEYS.search(key)}
    if isinstance(value, list):
        result = []
        redact_next = False
        for item in value:
            if redact_next:
                result.append("[redacted]")
                redact_next = False
            elif isinstance(item, str) and re.search(
                r"^--?(?:password|secret|token|api-key)(?:=|$)", item, re.IGNORECASE
            ):
                result.append(item.split("=")[0] + "=[redacted]" if "=" in item else item)
                redact_next = "=" not in item
            else:
                result.append(sanitize(item))
        return result
    if isinstance(value, str):
        value = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[redacted]@", value)
        value = re.sub(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,})\b",
            "[redacted]",
            value,
        )
        value = re.sub(
            r"(?i)\b(password|secret|token|api[_-]?key)\s*[=:]\s*[^\s,;]+", r"\1=[redacted]", value
        )
        return value
    return value


def _safe_item(original: dict[str, Any]) -> dict[str, Any]:
    item = {key: copy.deepcopy(value) for key, value in original.items() if key in ITEM_KEYS}
    item["evidence"] = [
        {
            **{
                key: value
                for key, value in citation.items()
                if key in {"path", "line", "end_line", "snippet_sha256"}
            },
            **(
                {"snippet_sha256": hashlib.sha256(citation["snippet"].encode()).hexdigest()}
                if "snippet" in citation
                else {}
            ),
        }
        for citation in item.get("evidence", [])
    ]
    # Evidence digests are metadata, even though their key contains the word snippet.
    evidence = item.pop("evidence")
    result: dict[str, Any] = sanitize(item)
    result["evidence"] = evidence
    return result


def _atomic(path: Path, data: str) -> None:
    if path.is_symlink():
        raise ValueError(f"Report artifact may not be symlink: {path.name}")
    descriptor, temporary = tempfile.mkstemp(prefix=".repo-audit-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _markdown(report: dict[str, Any]) -> str:
    def text(value: Any) -> str:
        return html.escape(str(value)).replace("\r", "").replace("\n", " ")

    lines = [
        f"# Audit report for {text(report['repo_id'])}",
        "",
        f"Outcome: {report['outcome']}. Snapshot: `{report['snapshot']}`.",
        "",
        "Coverage records assigned assessments, observable reads, and inventory separately. A complete run does not establish exhaustive correctness.",
        "",
        f"Inventoried files: {len(report['coverage']['inventoried'])}. Assessed scopes: {len(report['coverage']['assessed'])}. Observed reads: {len(report['coverage']['observed_reads'])}.",
        "",
    ]
    for limitation in report["coverage"]["limitations"]:
        lines.extend([f"- {text(limitation)}"])
    if report["coverage"]["limitations"]:
        lines.append("")
    for item in report["items"]:
        location = item["primary_location"]
        lines.extend(
            [
                f"## {text(item['title'])}",
                "",
                f"ID: `{item['id']}`. State: {text(item['state'])}. Observation: {text(item['observation_status'])}.",
                "",
                f"Location: {text(location['path'])}:{location['line']}. Severity: {item['severity']}. Confidence: {item['confidence']}. Verification: {item['verification_level']}.",
                "",
                f"Trigger: {text(item['trigger_conditions'])}",
                "",
                f"Mechanism: {text(item['mechanism'])}",
                "",
                f"Impact: {text(item['impact'])}",
                "",
                f"Next action: {text(item['next_action'])}",
                "",
            ]
        )
        if item["uncertainty"]:
            lines.extend([f"Uncertainty: {text(item['uncertainty'])}", ""])
        lines.extend([f"Guidance: {', '.join(text(source) for source in item['source_refs'])}", ""])
    if not report["items"]:
        lines.extend(
            [
                "No accepted backlog items were produced. Coverage and execution limits still apply.",
                "",
            ]
        )
    if report.get("errors"):
        lines.extend(["## Execution errors", ""])
        lines.extend(f"- {text(error)}" for error in report["errors"])
        lines.append("")
    return "\n".join(lines)


def write_reports(
    run_dir: Path,
    *,
    repo_id: str,
    snapshot: str | None,
    outcome: str,
    items: list[dict[str, Any]],
    coverage: dict[str, Any],
    analyzers: list[dict[str, Any]] | None = None,
    policy: list[dict[str, Any]] | None = None,
    errors: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = metadata or {}
    report = {
        "schema_version": 1,
        "repo_id": repo_id,
        "snapshot": snapshot,
        "outcome": outcome,
        "items": [_safe_item(item) for item in items],
        "coverage": sanitize(coverage),
        "analyzers": sanitize(analyzers or []),
        "policy": sanitize(policy or []),
        "errors": sanitize(errors or []),
        "metadata": sanitize(
            {key: value for key, value in metadata.items() if key in METADATA_KEYS}
        ),
    }
    if any(item["repo_id"] != repo_id for item in report["items"]):
        raise ValueError("Report items belong to another repository")
    if (
        report["coverage"].get("repo_id") != repo_id
        or report["coverage"].get("snapshot") != snapshot
    ):
        raise ValueError("Coverage identity differs from report")
    validate_document("report", report)
    validate_document("coverage", report["coverage"])
    run_dir = Path(run_dir)
    if run_dir.is_symlink():
        raise ValueError("Run directory must not be symlink")
    run_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "report.json": json.dumps(report, indent=2, sort_keys=True) + "\n",
        "report.md": _markdown(report),
        "coverage.json": json.dumps(report["coverage"], indent=2, sort_keys=True) + "\n",
        "execution.json": json.dumps(
            {
                "schema_version": 1,
                "repo_id": repo_id,
                "snapshot": snapshot,
                "outcome": outcome,
                "errors": report["errors"],
                "metadata": report["metadata"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    }
    for filename, content in artifacts.items():
        _atomic(run_dir / filename, content)
    return report
