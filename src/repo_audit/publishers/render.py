"""A bounded, sanitized body section with stable machine-readable identity."""
import copy
import hashlib
import html
import json
import re
from typing import Any

START = "<!-- repo-audit:managed:start -->"
END = "<!-- repo-audit:managed:end -->"
META = "<!-- repo-audit:meta "
ID = re.compile(r"item-[0-9a-f]{64}\Z")
STATES = {"open", "dismissed", "accepted-risk", "resolved", "needs-revalidation"}


class PublicationError(RuntimeError):
    """Publication cannot proceed safely under the current inventory or configuration."""


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def sanitize(value: Any, limit: int = 2000) -> str:
    text = html.unescape(str(value or ""))[:limit]
    text = re.sub(r"\\([\\`*_[\]#!|~])", r"\1", text)
    text = re.sub(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@", r"\1[redacted]@", text)
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*", "[redacted private key]", text)
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16})\b", "[redacted credential]", text)
    text = re.sub(r"(?i)\b(?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)[A-Z0-9_]*)\s*[:=]\s*[^\s,;]+", "[redacted credential]", text)
    text = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._~-]+", "[redacted credential]", text)
    text = re.sub(r"!?\[([^\]]*)\]\([^\n]*?\)", r"\1 [link removed]", text)
    text = re.sub(r"(?i)(javascript|vbscript|data):", "[unsafe link removed]", text)
    text = re.sub(r"([a-zA-Z][a-zA-Z0-9+.-]*):/{2}", r"\1[:]//", text)
    text = text.replace("@", "＠")
    text = html.escape(text, quote=False)
    text = re.sub(r"([\\`*_[\]#!|~])", r"\\\1", text)
    return text.replace("\r", "")


def evidence_digest(item: dict[str, Any], partial: bool = False) -> str:
    fields = ("kind", "title", "category", "rule_id", "primary_location", "related_locations",
              "evidence", "source_refs", "trigger_conditions", "mechanism", "impact", "severity",
              "confidence", "verification_level", "next_action", "uncertainty", "state", "triage_history")
    # Hash only bounded published content. Source snippets never enter the public section.
    def canonical(value: Any) -> Any:
        if isinstance(value, str):
            return sanitize(value, 16000)
        if isinstance(value, dict):
            return {key: canonical(value[key]) for key in sorted(value)}
        if isinstance(value, list):
            return [canonical(entry) for entry in value]
        return value
    safe = {key: canonical(item.get(key)) for key in fields}
    safe["partial"] = str(partial)
    return _digest(safe)


def _triage(history: Any) -> list[dict[str, str]]:
    if not isinstance(history, list):
        raise PublicationError("triage history must be an array")
    result = []
    for decision in history[-50:]:
        if not isinstance(decision, dict) or decision.get("state") not in STATES:
            raise PublicationError("invalid shared triage state")
        reason = str(decision.get("reason", "")).strip()
        if not reason:
            raise PublicationError("shared triage decisions require a reason")
        entry = {"state": decision["state"], "reason": sanitize(reason), "at": sanitize(decision.get("at", ""), 64)}
        if decision.get("expires_at"):
            entry["expires_at"] = sanitize(decision["expires_at"], 64)
        result.append(entry)
    return result


def managed_section(item: dict[str, Any], *, partial: bool = False) -> str:
    item_id, repo_id = item.get("id"), item.get("repo_id")
    if not isinstance(item_id, str) or not ID.fullmatch(item_id) or not isinstance(repo_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", repo_id):
        raise PublicationError("invalid managed repository or item identity")
    if item.get("state", "open") not in STATES:
        raise PublicationError("invalid item state")
    if not re.fullmatch(r"[0-9a-f]{40,64}", str(item.get("snapshot", ""))):
        raise PublicationError("invalid item snapshot identity")
    history = _triage(item.get("triage_history", []))
    if item.get("state") in {"dismissed", "accepted-risk"} and not any(d["state"] == item["state"] for d in history):
        raise PublicationError("shared dismissal or accepted risk requires a reason")
    metadata = {"schema_version": 1, "repo_id": repo_id, "item_id": item_id,
                "snapshot": str(item.get("snapshot", "")), "state": item.get("state", "open"),
                "triage_history": history,
                "first_observed": sanitize(item.get("first_observed", ""), 64),
                "last_observed": sanitize(item.get("last_observed", ""), 64),
                "evidence_digest": evidence_digest(item, partial)}
    location = item.get("primary_location", {})
    lines = [f"## {sanitize(item.get('title'), 240)}", "",
             f"Kind: {sanitize(item.get('kind'))}. Severity: {sanitize(item.get('severity'))}. Confidence: {sanitize(item.get('confidence'))}.",
             f"Verification: {sanitize(item.get('verification_level'))}. State: {sanitize(item.get('state', 'open'))}.",
             f"Location: {sanitize(location.get('path'))}, line {sanitize(location.get('line'))}.", "",
             "### Evidence and mechanism", "", sanitize(item.get("mechanism")), "",
             "### Impact", "", sanitize(item.get("impact")), "",
             "### Next action", "", sanitize(item.get("next_action")), "",
             "### Uncertainty", "", sanitize(item.get("uncertainty")), "",
             f"Snapshot: {sanitize(item.get('snapshot'), 64)}", ""]
    if partial:
        lines.extend(["This audit has partial coverage. Unreviewed or failed scopes remain unresolved.", ""])
    for evidence in item.get("evidence", [])[:20]:
        lines.append(f"- Evidence: {sanitize(evidence.get('path'))}, line {sanitize(evidence.get('line'))}; snippet SHA-256 {sanitize(evidence.get('snippet_sha256'), 64)}")
    for source in item.get("source_refs", [])[:10]:
        lines.append(f"- Guidance: {sanitize(source, 1000)}")
    content = "\n".join(lines).strip()
    metadata["body_digest"] = hashlib.sha256(content.encode()).hexdigest()
    encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{START}\n{META}{encoded} -->\n{content}\n{END}"


def parse_managed(body: Any) -> dict[str, Any] | None:
    if not isinstance(body, str):
        body = ""
    if START not in body and META not in body and END not in body:
        return None
    if body.count(START) != 1 or body.count(END) != 1 or body.count(META) != 1:
        raise PublicationError("conflict: malformed or repeated managed section")
    start, end = body.index(START), body.index(END)
    if end < start:
        raise PublicationError("conflict: invalid managed section ordering")
    section = body[start + len(START):end].strip()
    if not section.startswith(META) or " -->\n" not in section:
        raise PublicationError("conflict: managed metadata is missing")
    encoded, content = section[len(META):].split(" -->\n", 1)
    try:
        metadata = json.loads(encoded)
    except ValueError as exc:
        raise PublicationError("conflict: malformed managed metadata") from exc
    required = {"schema_version", "repo_id", "item_id", "snapshot", "state", "triage_history",
                "first_observed", "last_observed", "evidence_digest", "body_digest"}
    if (not isinstance(metadata, dict) or set(metadata) != required
            or type(metadata.get("schema_version")) is not int or metadata["schema_version"] != 1
            or not ID.fullmatch(str(metadata.get("item_id", "")))
            or not re.fullmatch(r"[0-9a-f]{40,64}", str(metadata.get("snapshot", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(metadata.get("evidence_digest", "")))):
        raise PublicationError("conflict: unsupported managed identity")
    if metadata.get("state") not in STATES or not isinstance(metadata.get("repo_id"), str):
        raise PublicationError("conflict: invalid managed state or repository")
    if metadata.get("body_digest") != hashlib.sha256(content.strip().encode()).hexdigest():
        raise PublicationError("conflict: human changed tool-owned content")
    metadata["triage_history"] = _triage(metadata.get("triage_history", []))
    if metadata["state"] in {"dismissed", "accepted-risk"} and not any(d["state"] == metadata["state"] for d in metadata["triage_history"]):
        raise PublicationError("shared dismissal or accepted risk requires a reason")
    return {"metadata": copy.deepcopy(metadata), "prefix": body[:start],
            "suffix": body[end + len(END):], "body_sha256": hashlib.sha256(body.encode()).hexdigest()}
