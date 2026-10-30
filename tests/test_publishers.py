import copy
import json

import pytest

from repo_audit.publishers import hydrate, managed_section, publish

DEST = "owner/repository"
BASE = f"repos/{DEST}/issues"
GITHUB = {"repository": DEST, "enabled": True, "allow_publish": True}


def item(index=0, **changes):
    value = {"id": f"item-{index:064x}", "repo_id": "test", "snapshot": "a" * 40,
             "kind": "finding", "title": "Missing validation", "category": "correctness",
             "rule_id": "general.correctness", "problem_key": f"missing-validation-{index}",
             "primary_location": {"path": "src/main.py", "line": 2}, "related_locations": [],
             "evidence": [{"path": "src/main.py", "line": 2, "snippet_sha256": "b" * 64}],
             "source_refs": ["https://example.org/primary"], "trigger_conditions": "an empty input",
             "mechanism": "Input reaches an unchecked operation", "impact": "Invalid result",
             "severity": "medium", "confidence": "high", "verification_level": "supported",
             "next_action": "Validate input before the operation", "uncertainty": "No execution proof",
             "state": "open", "triage_history": [], "first_observed": "2026-10-30T12:00:00+00:00",
             "last_observed": "2026-10-30T12:00:00+00:00", "observation_status": "new"}
    value.update(changes)
    return value


def report(items, outcome="complete"):
    return {"schema_version": 1, "repo_id": "test", "snapshot": "a" * 40,
            "outcome": outcome, "items": items, "metadata": {"github_repository": DEST}}


def issue(number, data=None, **changes):
    body = managed_section(data or item())
    value = {"number": number, "body": body, "title": "Human title", "state": "open",
             "labels": [{"name": "repo-audit:managed"}, {"name": "human-label"}],
             "updated_at": "2026-10-30T12:00:00Z", "created_at": "2026-10-29T12:00:00Z"}
    value.update(changes)
    return value


class MemoryTransport:
    def __init__(self, issues=None, fail_page=None):
        self.issues = copy.deepcopy(issues or [])
        self.calls = []
        self.fail_page = fail_page
        self.fail_after_create = False
        self.before_request = None
        self.managed_label_exists = True
        self.drop_label_on_create = False

    def request(self, method, path, payload=None):
        self.calls.append((method, path, copy.deepcopy(payload)))
        if self.before_request:
            self.before_request(method, path)
        if method == "GET" and "/labels/" in path:
            if not self.managed_label_exists:
                raise RuntimeError("managed label is not configured")
            return {"name": "repo-audit:managed"}
        if method == "GET" and "?" in path:
            page = int(path.rsplit("page=", 1)[1])
            if page == self.fail_page:
                raise RuntimeError("inventory outage")
            return copy.deepcopy(self.issues[(page - 1) * 100: page * 100])
        if method == "GET":
            number = int(path.rsplit("/", 1)[1])
            return copy.deepcopy(next(i for i in self.issues if i["number"] == number))
        if method == "POST":
            created = issue(max([i["number"] for i in self.issues] or [0]) + 1, body=payload["body"], title=payload["title"])
            if self.drop_label_on_create:
                created["labels"] = []
            self.issues.append(created)
            if self.fail_after_create:
                self.fail_after_create = False
                raise RuntimeError("connection lost after remote commit")
            return copy.deepcopy(created)
        if method == "PATCH":
            current = next(i for i in self.issues if i["number"] == int(path.rsplit("/", 1)[1]))
            current.update(payload)
            return copy.deepcopy(current)
        raise AssertionError((method, path))


def test_dry_run_exact_actions_no_writes_and_create_limit(tmp_path):
    transport = MemoryTransport()
    result = publish(report([item(i) for i in range(7)]), GITHUB, transport, lock_dir=tmp_path)
    assert result["outcome"] == "complete"
    assert len(result["actions"]) == 5
    assert len(result["overflow"]) == 2
    action = result["actions"][0]
    assert action["type"] == "create"
    assert action["payload"]["labels"] == ["repo-audit:managed"]
    assert "repo-audit:managed:start" in action["payload"]["body"]
    assert all(method == "GET" for method, _, _ in transport.calls)


def test_apply_twice_creates_once_and_same_result_no_update(tmp_path):
    transport = MemoryTransport()
    first = publish(report([item()]), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert first["outcome"] == "complete"
    assert len(transport.issues) == 1
    second = publish(report([item()]), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert second["actions"] == []
    assert len([c for c in transport.calls if c[0] == "POST"]) == 1
    assert not any(c[0] == "PATCH" for c in transport.calls)


def test_update_managed_section_preserves_human_body_fields_and_closure(tmp_path):
    old = issue(1, state="closed")
    old["body"] = "Human introduction\n\n" + old["body"] + "\n\nHuman notes @friend"
    transport = MemoryTransport([old])
    changed = item(snapshot="c" * 40, impact="New contradictory evidence", state="needs-revalidation")
    result = publish(report([changed], "partial"), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert result["outcome"] == "complete"
    assert len(result["actions"]) == 1
    patch = next(c for c in transport.calls if c[0] == "PATCH")
    assert set(patch[2]) == {"body"}
    current = transport.issues[0]
    assert current["body"].startswith("Human introduction\n\n")
    assert current["body"].endswith("\n\nHuman notes @friend")
    assert "partial" in current["body"].lower()
    assert current["title"] == "Human title"
    assert current["state"] == "closed"
    assert current["labels"] == old["labels"]


def test_inventory_pagination_closed_issues_and_pull_request_exclusion():
    ordinary = [{"number": n, "body": "human", "labels": []} for n in range(1, 101)]
    target = issue(101, state="closed")
    pr = issue(102, item(1), pull_request={"url": "ignored"})
    transport = MemoryTransport(ordinary + [target, pr])
    history = hydrate(DEST, "test", transport)
    assert history["complete"]
    assert len(history["items"]) == 1
    assert history["items"][0]["state"] == "resolved"
    assert history["items"][0]["triage_history"][-1]["reason"]
    assert len(transport.calls) == 2
    assert "state=all" in transport.calls[0][1]


def test_incomplete_inventory_fails_closed(tmp_path):
    ordinary = [{"number": n, "body": "human", "labels": []} for n in range(1, 101)]
    transport = MemoryTransport(ordinary, fail_page=2)
    result = publish(report([item()]), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert result["outcome"] == "failed"
    assert result["errors"]
    assert all(c[0] == "GET" for c in transport.calls)


def test_partial_write_retry_rehydrates_marker_without_duplicate(tmp_path):
    transport = MemoryTransport()
    transport.fail_after_create = True
    first = publish(report([item()]), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert first["outcome"] == "failed"
    second = publish(report([item()]), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert second["outcome"] == "complete"
    assert len(transport.issues) == 1
    assert len([c for c in transport.calls if c[0] == "POST"]) == 1


def test_conflicting_human_edit_before_update_stops_without_write(tmp_path):
    transport = MemoryTransport([issue(1)])
    def race(method, path):
        if method == "GET" and path == f"{BASE}/1":
            transport.issues[0]["body"] += "\nHuman raced edit"
    transport.before_request = race
    result = publish(report([item(impact="changed")]), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert result["outcome"] == "failed"
    assert any("conflict" in e.lower() for e in result["errors"])
    assert not any(c[0] == "PATCH" for c in transport.calls)


def test_duplicate_markers_fail_closed(tmp_path):
    transport = MemoryTransport([issue(1), issue(2)])
    result = publish(report([item()]), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert result["outcome"] == "failed"
    assert all(c[0] == "GET" for c in transport.calls)


@pytest.mark.parametrize("config,binding", [
    ({"repository": DEST}, DEST), ({**GITHUB, "allow_publish": False}, DEST),
    (GITHUB, "different/repository"), ({**GITHUB,"repository":"../escape"}, DEST),
])
def test_requires_explicit_enrollment(tmp_path, config, binding):
    transport = MemoryTransport()
    data = report([item()])
    data["metadata"]["github_repository"] = binding
    result = publish(data, config, transport, apply=True, lock_dir=tmp_path)
    assert result["outcome"] == "failed"
    assert transport.calls == []


def test_low_confidence_unsupported_unactionable_and_dismissed_stay_local(tmp_path):
    values = [item(0, confidence="low"), item(1, verification_level="unverified"),
              item(2, next_action=""), item(3, state="dismissed"),
              item(4, kind="investigation", uncertainty="what invokes this?", next_action="Trace dynamic entry points")]
    result = publish(report(values), GITHUB, MemoryTransport(), lock_dir=tmp_path)
    assert [a["item_id"] for a in result["actions"]] == [values[-1]["id"]]
    assert len(result["skipped"]) == 4


def test_publish_sanitizes_mentions_links_embeds_and_secrets(tmp_path):
    dangerous = "@team ![image](https://evil.example/a) [run](javascript:alert(1)) <iframe src=x> sk-abcdefghijklmnopqrstuvwxyz1234567890 GH_TOKEN=abcdef1234567890"
    result = publish(report([item(title=dangerous, mechanism=dangerous)]), GITHUB, MemoryTransport(), lock_dir=tmp_path)
    payload = result["actions"][0]["payload"]
    assert "@team" not in payload["body"]
    assert "![image]" not in payload["body"]
    assert "javascript:" not in payload["body"]
    assert "<iframe" not in payload["body"]
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in json.dumps(payload)
    assert "abcdef1234567890" not in json.dumps(payload)


def test_managed_tampering_or_missing_label_cannot_create_duplicate(tmp_path):
    current = issue(1)
    current["body"] = current["body"].replace("Missing validation", "Edited managed content")
    transport = MemoryTransport([current])
    result = publish(report([item()]), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert result["outcome"] == "failed"
    assert all(c[0] == "GET" for c in transport.calls)
    transport = MemoryTransport([issue(1, labels=[])])
    assert publish(report([item()]), GITHUB, transport, apply=True, lock_dir=tmp_path)["outcome"] == "failed"


def test_missing_managed_label_preflight_stops_issue_writes(tmp_path):
    transport = MemoryTransport()
    transport.managed_label_exists = False
    result = publish(report([item()]), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert result["outcome"] == "failed"
    assert not any(c[0] != "GET" for c in transport.calls)
    assert any("label" in error.lower() for error in result["errors"])


def test_dropped_managed_label_is_failure_and_retry_never_duplicates(tmp_path):
    transport = MemoryTransport()
    transport.drop_label_on_create = True
    first = publish(report([item()]), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert first["outcome"] == "failed"
    assert first["actions"][0]["applied"]
    second = publish(report([item()]), GITHUB, transport, apply=True, lock_dir=tmp_path)
    assert second["outcome"] == "failed"
    assert len(transport.issues) == 1
    assert len([c for c in transport.calls if c[0] == "POST"]) == 1


def test_snapshot_only_change_is_not_material_and_shared_triage_is_stable(tmp_path):
    decision = {"state": "needs-revalidation", "reason": "check @operator [evidence]", "at": "2026-10-30T12:00:00Z"}
    data = item(state="needs-revalidation", triage_history=[decision])
    transport = MemoryTransport([issue(1, data)])
    hydrated = hydrate(DEST, "test", transport)["items"][0]
    data["triage_history"] = hydrated["triage_history"]
    data["snapshot"] = "f" * 40
    result = publish(report([data]), GITHUB, transport, lock_dir=tmp_path)
    assert result["actions"] == []


def test_metadata_cannot_inject_a_second_section(tmp_path):
    result = publish(report([item(snapshot="a" * 40 + " -->\n@team")]), GITHUB, MemoryTransport(), lock_dir=tmp_path)
    assert result["outcome"] == "failed"


def test_t4_validated_report_passes_to_publisher(tmp_path):
    from repo_audit.models import validate_document
    from repo_audit.reports import write_reports

    coverage = {"schema_version": 1, "repo_id": "test", "snapshot": "a" * 40,
                "inventoried": ["src/main.py"], "assessed": [], "observed_reads": [],
                "deferred": [], "limitations": ["Synthetic report fixture"]}
    validated = write_reports(tmp_path / "reports", repo_id="test", snapshot="a" * 40,
                              outcome="complete", items=[item()], coverage=coverage,
                              metadata={"github_repository": DEST})
    validate_document("report", validated)
    result = publish(validated, GITHUB, MemoryTransport(), lock_dir=tmp_path / "locks")
    assert result["outcome"] == "complete"
    assert len(result["actions"]) == 1
    assert result["actions"][0]["item_id"] == item()["id"]


def test_url_credentials_are_redacted_and_static_fixture_hydrates(tmp_path):
    from pathlib import Path

    current = json.loads((Path(__file__).parent / "fixtures/issues/managed-issue.json").read_text())
    history = hydrate(DEST, "test", MemoryTransport([current]))
    assert history["complete"]
    assert history["items"][0]["id"] == item()["id"]
    result = publish(report([item(mechanism="Fetch https://user:private-password@example.org/repo")]), GITHUB, MemoryTransport(), lock_dir=tmp_path)
    assert "private-password" not in json.dumps(result["actions"])


def test_managed_metadata_schema_rejects_boolean_version_and_unknown_fields():
    body = issue(1)["body"]
    for invalid in [body.replace('"schema_version":1', '"schema_version":true'),
                    body.replace('"schema_version":1', '"schema_version":1,"unknown":true')]:
        history = hydrate(DEST, "test", MemoryTransport([issue(1, body=invalid)]))
        assert history["complete"] is False
        assert history["items"] == []


def test_malformed_network_shapes_fail_closed_instead_of_raising(tmp_path):
    body = issue(1)["body"].replace('"state":"open"', '"state":[]')
    for current in [issue(1, body=body), issue(1, labels=[{"name": []}])]:
        result = publish(report([item()]), GITHUB, MemoryTransport([current]), apply=True, lock_dir=tmp_path)
        assert result["outcome"] == "failed"
        assert result["errors"]
