"""Hydrate complete issue history and publish only tool-owned issue sections."""
import copy
import fcntl
import hashlib
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .render import PublicationError, evidence_digest, managed_section, parse_managed, sanitize
from .transport import GhTransport

DEFAULT_LABEL = "repo-audit:managed"
DESTINATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


def _destination(value: Any) -> str:
    if not isinstance(value, str) or not DESTINATION.fullmatch(value) or any(p in {".", ".."} for p in value.split("/")):
        raise PublicationError("GitHub destination must be explicit owner/repository")
    return value


def _label(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,49}", value):
        raise PublicationError("managed label must be a simple explicit name")
    return value


def _inventory(destination: str, repo_id: str, transport: Any, label: str) -> list[dict[str, Any]]:
    inventory = []
    seen_numbers: set[int] = set()
    seen_items: set[str] = set()
    for page in range(1, 10001):
        response = transport.request("GET", f"repos/{destination}/issues?state=all&per_page=100&page={page}")
        if not isinstance(response, list) or len(response) > 100:
            raise PublicationError("incomplete issue inventory: expected paginated issue array")
        for issue in response:
            if not isinstance(issue, dict) or type(issue.get("number")) is not int:
                raise PublicationError("incomplete issue inventory: malformed issue")
            number = issue["number"]
            if number in seen_numbers:
                raise PublicationError("incomplete issue inventory: repeated pagination result")
            seen_numbers.add(number)
            if "pull_request" in issue:
                continue
            labels = issue.get("labels", [])
            if not isinstance(labels, list):
                raise PublicationError("incomplete issue inventory: malformed labels")
            names = {label_value.get("name") if isinstance(label_value, dict) else label_value for label_value in labels}
            managed = parse_managed(issue.get("body"))
            if managed is None:
                if label in names:
                    raise PublicationError("conflict: managed label exists without identity marker")
                continue
            metadata = managed["metadata"]
            if metadata["repo_id"] != repo_id:
                continue
            if label not in names:
                raise PublicationError("conflict: managed identity exists without managed label")
            if metadata["item_id"] in seen_items:
                raise PublicationError("conflict: duplicate managed item identity")
            seen_items.add(metadata["item_id"])
            if issue.get("state") not in {"open", "closed"}:
                raise PublicationError("incomplete issue inventory: missing lifecycle state")
            inventory.append({"issue": issue, **managed})
        if len(response) < 100:
            return inventory
    raise PublicationError("incomplete issue inventory: pagination limit reached")


def hydrate(destination: str, repo_id: str, transport: Any = None, *, label: str = DEFAULT_LABEL) -> dict[str, Any]:
    """Return shared decisions only after a complete open-and-closed issue scan."""
    try:
        destination, label = _destination(destination), _label(label)
        inventory = _inventory(destination, repo_id, transport or GhTransport(), label)
        items = []
        for entry in inventory:
            metadata, issue = entry["metadata"], entry["issue"]
            history = copy.deepcopy(metadata.get("triage_history", []))
            closed = issue["state"] == "closed"
            state = metadata["state"]
            if closed and state not in {"dismissed", "accepted-risk"}:
                state = "resolved"
                if not history or history[-1].get("state") != "resolved":
                    history.append({"state": "resolved", "reason": "Human closed GitHub issue",
                                    "at": issue.get("closed_at") or issue.get("updated_at") or datetime.now(UTC).isoformat()})
            items.append({"id": metadata["item_id"], "repo_id": repo_id, "state": state,
                          "triage_history": history,
                          "github_issue": {"number": issue["number"],
                                           "url": f"https://github.com/{destination}/issues/{issue['number']}",
                                           "closed": closed},
                          "snapshot": metadata.get("snapshot", ""),
                          "first_observed": metadata.get("first_observed") or issue.get("created_at", ""),
                          "last_observed": metadata.get("last_observed", "")})
        return {"complete": True, "items": items, "errors": []}
    except (PublicationError, RuntimeError, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return {"complete": False, "items": [], "errors": [sanitize(str(exc), 500)]}


@contextmanager
def _lock(destination: str, lock_dir: Path | None) -> Iterator[None]:
    directory = Path(lock_dir) if lock_dir is not None else Path(tempfile.gettempdir()) / "repo-audit-publish-locks"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = hashlib.sha256(destination.lower().encode()).hexdigest()
    with (directory / f"{key}.lock").open("a") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise PublicationError("another publisher holds the destination lock") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _eligible(item: dict[str, Any]) -> str | None:
    if item.get("confidence") not in {"medium", "high"}:
        return "confidence is below publication threshold"
    if item.get("verification_level") not in {"supported", "reproduced"}:
        return "claim lacks supported evidence"
    if item.get("kind") not in {"finding", "investigation"}:
        return "unknown backlog item kind"
    if item.get("state") in {"dismissed", "accepted-risk", "resolved"}:
        return "human decision retained locally"
    if not str(item.get("next_action", "")).strip():
        return "next action is missing"
    location = item.get("primary_location", {})
    if not item.get("evidence") or not location.get("path") or not location.get("line"):
        return "concrete source evidence is missing"
    if item.get("kind") == "investigation" and not str(item.get("uncertainty", "")).strip():
        return "investigation question is missing"
    return None


def _plan(report: dict[str, Any], inventory: list[dict[str, Any]], maximum: int, label: str) -> dict[str, Any]:
    existing = {entry["metadata"]["item_id"]: entry for entry in inventory}
    actions, overflow, skipped = [], [], []
    new_count = 0
    seen = set()
    partial = report.get("outcome") != "complete"
    for original in report.get("items", []):
        if not isinstance(original, dict) or original.get("repo_id") != report["repo_id"]:
            raise PublicationError("item belongs to a different repository")
        item = copy.deepcopy(original)
        item_id = item.get("id")
        if item_id in seen:
            raise PublicationError("report repeats an item identity")
        seen.add(item_id)
        reason = _eligible(item)
        if reason:
            skipped.append({"item_id": item_id, "reason": reason})
            continue
        entry = existing.get(item_id)
        if entry is None:
            if new_count >= maximum:
                overflow.append(item_id)
                continue
            section = managed_section(item, partial=partial)
            actions.append({"type": "create", "item_id": item_id,
                            "payload": {"title": sanitize(item.get("title"), 240).replace("\n", " "),
                                        "body": section, "labels": [label]}, "applied": False})
            new_count += 1
            continue
        if entry["metadata"].get("evidence_digest") == evidence_digest(item, partial):
            continue
        if entry["issue"]["state"] == "closed":
            item["state"] = "needs-revalidation"
        # Repeated observations and unrelated commit changes are not material updates.
        if entry["metadata"].get("evidence_digest") == evidence_digest(item, partial):
            continue
        section = managed_section(item, partial=partial)
        actions.append({"type": "update", "item_id": item_id, "number": entry["issue"]["number"],
                        "payload": {"body": entry["prefix"] + section + entry["suffix"]},
                        "expected_body_sha256": entry["body_sha256"],
                        "expected_updated_at": entry["issue"].get("updated_at"),
                        "expected_state": entry["issue"]["state"], "applied": False})
    return {"actions": actions, "overflow": overflow, "skipped": skipped}


def publish(report: dict[str, Any], github: dict[str, Any], transport: Any = None, *,
            apply: bool = False, lock_dir: Path | None = None) -> dict[str, Any]:
    """Plan exact issue requests; apply only under enrollment and complete history.

    The host lock serializes publishers sharing a filesystem. Distributed runs also
    require the documented per-destination GitHub Actions concurrency group.
    """
    result: dict[str, Any] = {"destination": github.get("repository"), "actions": [],
                              "overflow": [], "skipped": [], "outcome": "failed", "errors": []}
    try:
        destination = _destination(github.get("repository"))
        label = _label(github.get("label", DEFAULT_LABEL))
        if github.get("enabled") is not True or github.get("allow_publish") is not True:
            raise PublicationError("destination is not explicitly enrolled for publication")
        if report.get("metadata", {}).get("github_repository") != destination:
            raise PublicationError("report destination does not match enrolled repository")
        if report.get("schema_version") != 1 or not isinstance(report.get("repo_id"), str) or not isinstance(report.get("items"), list):
            raise PublicationError("invalid report publication envelope")
        if report.get("outcome") not in {"complete", "partial", "failed"}:
            raise PublicationError("invalid source run outcome")
        maximum = github.get("max_new_issues", 5)
        if type(maximum) is not int or maximum < 0:
            raise PublicationError("max_new_issues must be a nonnegative integer")
        transport = transport or GhTransport()
        with _lock(destination, lock_dir):
            label_response = transport.request("GET", f"repos/{destination}/labels/{quote(label, safe='')}")
            if not isinstance(label_response, dict) or label_response.get("name") != label:
                raise PublicationError("managed label is missing; create the configured label during enrollment")
            inventory = _inventory(destination, report["repo_id"], transport, label)
            result.update(_plan(report, inventory, maximum, label))
            if apply:
                for action in result["actions"]:
                    # A complete second inventory check also catches new duplicate markers.
                    latest = _inventory(destination, report["repo_id"], transport, label)
                    present = {entry["metadata"]["item_id"]: entry for entry in latest}
                    if action["type"] == "create":
                        if action["item_id"] in present:
                            raise PublicationError("conflict: item appeared before create; replan required")
                        created = transport.request("POST", f"repos/{destination}/issues", action["payload"])
                        if not isinstance(created, dict) or type(created.get("number")) is not int:
                            raise PublicationError("create response incomplete; rehydrate before retry")
                        action["number"] = created["number"]
                        action["applied"] = True
                        created_managed = parse_managed(created.get("body"))
                        created_labels = {entry.get("name") if isinstance(entry, dict) else entry for entry in created.get("labels", [])}
                        if created_managed is None or created_managed["metadata"].get("item_id") != action["item_id"] or label not in created_labels:
                            raise PublicationError("created issue lacks its managed marker or label; repair enrollment before retry")
                    else:
                        current = transport.request("GET", f"repos/{destination}/issues/{action['number']}")
                        if not isinstance(current, dict) or "pull_request" in current:
                            raise PublicationError("conflict: issue became unavailable before update")
                        digest = hashlib.sha256(str(current.get("body") or "").encode()).hexdigest()
                        if digest != action["expected_body_sha256"] or current.get("updated_at") != action["expected_updated_at"] or current.get("state") != action["expected_state"]:
                            raise PublicationError("conflict: issue changed before update; replan required")
                        transport.request("PATCH", f"repos/{destination}/issues/{action['number']}", action["payload"])
                    action["applied"] = True
            result["outcome"] = "complete"
    except (PublicationError, RuntimeError, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        result["errors"].append(sanitize(str(exc), 500))
    return result
