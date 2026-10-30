import json
from pathlib import Path

import pytest

from repo_audit.collectors.parsers import parse_report

FIXTURES = Path(__file__).parent / "fixtures" / "analyzers"


@pytest.mark.parametrize("format,filename,rule,line", [
    ("eslint", "eslint-v9.22.0.json", "no-unused-vars", 2),
    ("ruff", "ruff-0.9.10.json", "F401", 1),
    ("knip", "knip-5.46.0.json", "exports", 3),
    ("sarif", "sarif-2.1.0.json", "TEST001", 4),
    ("junit", "junit.xml", "AssertionError", 5),
])
def test_pinned_formats_normalize_evidence(tmp_path, format, filename, rule, line):
    result = parse_report(format, (FIXTURES / filename).read_bytes(), tmp_path)
    assert result.status == "parsed"
    diagnostic = next(d for d in result.diagnostics if d["rule_id"] == rule)
    assert diagnostic["path"] == "src/sample.py"
    assert diagnostic["line"] == line
    assert diagnostic["message"]


@pytest.mark.parametrize("format,raw", [
    ("eslint", b'{'), ("eslint", b'{}'), ("ruff", b'[{}]'),
    ("knip", b'{"issues":[{"file":"a","exports":"bad"}]}'),
    ("sarif", b'{"version":"1.0","runs":[]}'),
    ("junit", b'<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><testsuite>&x;</testsuite>'),
    ("junit", b'<other/>'),
])
def test_malformed_is_not_clean(format, raw, tmp_path):
    result = parse_report(format, raw, tmp_path)
    assert result.status == "error"
    assert result.error
    assert result.diagnostics == []


def test_unknown_json_and_text_are_unstructured(tmp_path):
    assert parse_report("json", b'{"findings":42}', tmp_path).status == "unstructured"
    assert parse_report("text", b'failed somehow', tmp_path).status == "unstructured"
    assert parse_report("json", b'{', tmp_path).status == "error"


def test_rejects_outside_paths_and_does_not_invent_source_locations(tmp_path):
    raw = json.dumps([{"filePath":"../secret", "messages":[{"message":"bad", "severity":2}]}]).encode()
    assert parse_report("eslint", raw, tmp_path).status == "error"
    raw = b'<testsuite><testcase name="unlocated"><failure message="bad"/></testcase><testcase name="skip"><skipped/></testcase></testsuite>'
    result = parse_report("junit", raw, tmp_path)
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0]["path"] is None
    assert result.diagnostics[0]["line"] is None


def test_knip_file_duplicate_member_variants(tmp_path):
    raw = b'{"files":["old.ts"],"issues":[{"file":"a.ts","duplicates":[[{"name":"a","line":1},{"name":"b","line":2}]],"enumMembers":{"Enum":[{"name":"A","line":3}]}}]}'
    result = parse_report("knip", raw, tmp_path)
    assert result.status == "parsed"
    assert len(result.diagnostics) == 4
    assert result.diagnostics[0]["rule_id"] == "files"


def test_sarif_subset_rejects_unresolved_locations(tmp_path):
    raw = b'{"version":"2.1.0","runs":[{"results":[{"message":{"text":"bad"},"locations":[{"physicalLocation":{"artifactLocation":{"index":0}}}]}]}]}'
    assert parse_report("sarif", raw, tmp_path).status == "error"
