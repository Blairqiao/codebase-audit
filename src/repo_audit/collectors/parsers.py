"""Parse documented analyzer subsets without executing report content."""
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree


@dataclass
class ParseResult:
    status: str
    diagnostics: list[dict[str, Any]]
    error: str | None = None


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError("expected an object")
    return value


def _array(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise TypeError("expected an array")
    return value


def _string(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("expected a nonempty string")
    return value


def _position(value: Any) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("source positions must be positive integers")
    return value


def _path(value: Any, root: Path, cwd: Path) -> str | None:
    if value is None:
        return None
    value = _string(value)
    if "\x00" in value or "\\" in value:
        raise ValueError("invalid source path")
    target = Path(value)
    if not target.is_absolute():
        target = cwd / target
    try:
        return target.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        raise ValueError("source path is outside execution root") from None


def _diagnostic(path: Any, message: Any, rule: Any, severity: str, root: Path,
                cwd: Path, line: Any = None, column: Any = None,
                end_line: Any = None, end_column: Any = None) -> dict[str, Any]:
    return {"path": _path(path, root, cwd), "message": _string(message),
            "rule_id": _string(rule) if rule is not None else None,
            "severity": severity, "line": _position(line), "column": _position(column),
            "end_line": _position(end_line), "end_column": _position(end_column)}


def _native(format: str, data: Any, root: Path, cwd: Path) -> list[dict[str, Any]]:
    diagnostics = []
    for entry in _array(data):
        entry = _object(entry)
        if format == "eslint":
            path = _string(entry.get("filePath"))
            for msg in _array(entry.get("messages")):
                msg = _object(msg)
                severity = msg.get("severity")
                if severity not in (0, 1, 2) or isinstance(severity, bool):
                    raise ValueError("invalid ESLint severity")
                diagnostics.append(_diagnostic(path, msg.get("message"), msg.get("ruleId"),
                    {0: "note", 1: "warning", 2: "error"}[severity], root, cwd,
                    msg.get("line"), msg.get("column"), msg.get("endLine"), msg.get("endColumn")))
        else:
            loc = _object(entry.get("location") or {})
            end = _object(entry.get("end_location") or {})
            diagnostics.append(_diagnostic(entry.get("filename"), entry.get("message"),
                entry.get("code"), "warning", root, cwd, loc.get("row"), loc.get("column"),
                end.get("row"), end.get("column")))
    return diagnostics


_KNIP_TYPES = {"files", "dependencies", "devDependencies", "optionalPeerDependencies",
               "unlisted", "binaries", "unresolved", "exports", "types", "nsExports",
               "nsTypes", "duplicates", "enumMembers", "classMembers", "namespaceMembers",
               "catalog", "catalogReferences", "cycles"}


def _knip(data: Any, root: Path, cwd: Path) -> list[dict[str, Any]]:
    data = _object(data)
    diagnostics = [_diagnostic(path, "Unused file", "files", "warning", root, cwd)
                   for path in _array(data.get("files", []))]
    for row in _array(data.get("issues")):
        row = _object(row)
        path = _string(row.get("file"))
        for kind in _KNIP_TYPES.intersection(row):
            items = row[kind]
            if kind in {"enumMembers", "classMembers"} and isinstance(items, dict):
                items = [item for group in items.values() for item in _array(group)]
            items = _array(items)
            if kind in {"duplicates", "cycles"}:
                items = [item for group in items for item in _array(group)]
            for item in items:
                item = _object(item)
                name = _string(item.get("name"))
                diagnostics.append(_diagnostic(path, f"{kind}: {name}", kind, "warning", root,
                                               cwd, item.get("line"), item.get("col")))
    return diagnostics


def _sarif(data: Any, root: Path, cwd: Path) -> list[dict[str, Any]]:
    data = _object(data)
    if data.get("version") != "2.1.0":
        raise ValueError("only SARIF 2.1.0 is supported")
    diagnostics = []
    for run in _array(data.get("runs")):
        run = _object(run)
        if run.get("externalPropertyFileReferences"):
            raise ValueError("external SARIF properties are unsupported")
        for result in _array(run.get("results", [])):
            result = _object(result)
            message = _object(result.get("message")).get("text")
            level = result.get("level", "warning")
            if level not in {"none", "note", "warning", "error"}:
                raise ValueError("invalid SARIF level")
            locations = _array(result.get("locations", []))
            if not locations:
                diagnostics.append(_diagnostic(None, message, result.get("ruleId"), level, root, cwd))
            for location in locations:
                physical = _object(_object(location).get("physicalLocation"))
                artifact = _object(physical.get("artifactLocation"))
                if "uriBaseId" in artifact or "uri" not in artifact:
                    raise ValueError("SARIF subset needs an explicit URI without uriBaseId")
                uri = urlsplit(_string(artifact["uri"]))
                if uri.scheme not in {"", "file"} or uri.netloc or uri.query or uri.fragment:
                    raise ValueError("unsupported SARIF artifact URI")
                region = _object(physical.get("region", {}))
                diagnostics.append(_diagnostic(unquote(uri.path), message, result.get("ruleId"),
                    level, root, cwd, region.get("startLine"), region.get("startColumn"),
                    region.get("endLine"), region.get("endColumn")))
    return diagnostics


def _junit(raw: bytes, root: Path, cwd: Path) -> list[dict[str, Any]]:
    # Decode before checking declarations so UTF-16 cannot bypass the entity rejection.
    text = raw.decode("utf-8-sig")
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("XML declarations and entities are forbidden")
    tree = ElementTree.fromstring(text)
    if tree.tag not in {"testsuite", "testsuites"}:
        raise ValueError("expected JUnit testsuite or testsuites")
    diagnostics = []
    for case in tree.iter("testcase"):
        for result in case:
            if result.tag not in {"failure", "error"}:
                continue
            message = result.get("message") or (result.text or "").strip() or case.get("name")
            line = case.get("line")
            diagnostics.append(_diagnostic(case.get("file"), message, result.get("type"),
                "error", root, cwd, int(line) if line is not None else None))
    return diagnostics


def parse_report(format: str, raw: bytes, root: Path, cwd: Path | None = None) -> ParseResult:
    """Return atomic diagnostics or an explicit parse failure; never fetch report URIs."""
    cwd = cwd or root
    try:
        if format == "text":
            return ParseResult("unstructured", [])
        if format == "junit":
            diagnostics = _junit(raw, root, cwd)
        else:
            data = json.loads(raw)
            if format == "json":
                return ParseResult("unstructured", [])
            if format in {"eslint", "ruff"}:
                diagnostics = _native(format, data, root, cwd)
            elif format == "knip":
                diagnostics = _knip(data, root, cwd)
            elif format == "sarif":
                diagnostics = _sarif(data, root, cwd)
            else:
                return ParseResult("error", [], f"unsupported report format: {format}")
        return ParseResult("parsed", diagnostics)
    except (ValueError, TypeError, ElementTree.ParseError, UnicodeError) as exc:
        return ParseResult("error", [], str(exc))
