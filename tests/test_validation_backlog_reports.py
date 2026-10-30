import copy
import hashlib
import json

import pytest

from repo_audit.backlog import Backlog
from repo_audit.models import validate_document
from repo_audit.reports import write_reports
from repo_audit.snapshot import InventoryFile, Snapshot
from repo_audit.validation import validate_candidates


def fixture(tmp_path):
    root = tmp_path / "snapshot"
    root.mkdir()
    content = "def check(value):\n    return value[0]\n"
    (root / "main.py").write_text(content)
    snap = Snapshot(
        "one",
        "a" * 40,
        root,
        [InventoryFile("main.py", hashlib.sha256(content.encode()).hexdigest(), len(content), 2)],
        [],
        False,
    )
    rules = [
        {
            "id": "general.correctness",
            "category": "correctness",
            "source": {"url": "https://primary.invalid/guidance", "section": "Functionality"},
            "mode": "advisory",
        }
    ]
    candidate = {
        "kind": "finding",
        "title": "Empty input fails",
        "category": "correctness",
        "rule_id": "general.correctness",
        "primary_location": {"path": "main.py", "line": 2, "symbol": "check"},
        "evidence": [{"path": "main.py", "line": 2, "snippet": "    return value[0]"}],
        "mechanism": "Empty input has no first element",
        "impact": "Request fails with IndexError",
        "next_action": "Handle empty input before indexing",
        "severity": "medium",
        "confidence": "high",
        "problem_key": "empty-index",
        "trigger_conditions": "Empty input",
        "uncertainty": "Caller validation may preclude empty input",
        "verification_level": "reproduced",
    }
    output = {
        "schema_version": 1,
        "repo_id": "one",
        "snapshot": snap.commit,
        "candidates": [candidate],
        "scope_ledger": [],
    }
    return snap, rules, output


def accepted(tmp_path):
    snap, rules, output = fixture(tmp_path)
    result = validate_candidates(output, snap, rules)
    assert len(result.accepted) == 1
    return snap, result.accepted[0]


def test_accept_evidence_without_trusting_model_reproduction(tmp_path):
    snap, rules, output = fixture(tmp_path)
    result = validate_candidates(output, snap, rules)
    assert len(result.accepted) == 1
    item = result.accepted[0]
    assert item["verification_level"] == "supported"
    assert item["repo_id"] == snap.repo_id
    assert "snippet" not in item["evidence"][0]
    assert (
        item["evidence"][0]["snippet_sha256"] == hashlib.sha256(b"    return value[0]").hexdigest()
    )


@pytest.mark.parametrize("field,value", [("snapshot", "b" * 40), ("repo_id", "other")])
def test_wrong_envelope_identity_rejected(tmp_path, field, value):
    snap, rules, output = fixture(tmp_path)
    output[field] = value
    result = validate_candidates(output, snap, rules)
    assert result.accepted == []
    assert result.errors


@pytest.mark.parametrize(
    "mutation",
    [
        "nonexistent",
        "outside",
        "wrong_snippet",
        "out_of_bounds",
        "unknown_rule",
        "wrong_source",
        "wrong_category",
        "investigation_without_uncertainty",
        "tampered_file",
    ],
)
def test_forged_or_incomplete_evidence_rejected(tmp_path, mutation):
    snap, rules, output = fixture(tmp_path)
    candidate = output["candidates"][0]
    if mutation in {"nonexistent", "outside"}:
        candidate["primary_location"]["path"] = (
            "missing.py" if mutation == "nonexistent" else "../secret"
        )
    elif mutation == "wrong_snippet":
        candidate["evidence"][0]["snippet"] = "invented code"
    elif mutation == "out_of_bounds":
        candidate["evidence"][0]["line"] = 999
    elif mutation == "unknown_rule":
        candidate["rule_id"] = "made-up"
    elif mutation == "wrong_source":
        candidate["source_refs"] = ["https://invented.invalid/"]
    elif mutation == "wrong_category":
        candidate["category"] = "security"
    elif mutation == "investigation_without_uncertainty":
        candidate.update(kind="investigation", uncertainty="")
    elif mutation == "tampered_file":
        (snap.root / "main.py").write_text("changed")
    result = validate_candidates(output, snap, rules)
    assert not result.accepted
    assert result.rejected or result.errors


def test_line_insertions_and_confident_rename_preserve_id_and_human_triage(tmp_path):
    snap, item = accepted(tmp_path)
    with Backlog(tmp_path / "one.db", "one") as store:
        first = store.reconcile([item], outcome="complete", snapshot=snap.commit)
        assert len(first) == 1
        first_id = first[0]["id"]
        store.triage(first_id, "dismissed", "Caller guarantees nonempty")
        moved = copy.deepcopy(item)
        moved["primary_location"]["line"] += 5
        moved["title"] = "Changed wording"
        again = store.reconcile([moved], outcome="complete", snapshot="b" * 40)
        assert again[0]["id"] == first_id
        assert again[0]["state"] == "dismissed"
        moved["primary_location"]["path"] = "new.py"
        renamed = store.reconcile(
            [moved], outcome="complete", snapshot="c" * 40, renames={"main.py": "new.py"}
        )
        assert len(renamed) == 1
        assert renamed[0]["id"] == first_id
        assert renamed[0]["state"] == "dismissed"
        assert renamed[0]["first_observed"] == first[0]["first_observed"]


def test_partial_or_missing_history_preserves_decisions_and_absence_never_resolves(tmp_path):
    snap, item = accepted(tmp_path)
    with Backlog(tmp_path / "one.db", "one") as store:
        rows = store.reconcile([item], outcome="complete", snapshot=snap.commit)
        assert rows
        store.triage(rows[0]["id"], "accepted-risk", "Temporary owner decision")
        assert (
            store.reconcile([], outcome="partial", snapshot="b" * 40)[0]["state"] == "accepted-risk"
        )
        assert (
            store.reconcile([], outcome="complete", snapshot="c" * 40, history_complete=False)[0][
                "state"
            ]
            == "accepted-risk"
        )
        store.triage(rows[0]["id"], "open", "Recheck requested")
        absent = store.reconcile([], outcome="complete", snapshot="d" * 40)
        assert absent[0]["state"] == "needs-revalidation"
        assert absent[0]["state"] != "resolved"


def test_repo_isolation_and_lock_and_triage_reason(tmp_path):
    snap, item = accepted(tmp_path)
    path = tmp_path / "one.db"
    with Backlog(path, "one") as store:
        assert store.reconcile([item], outcome="complete", snapshot=snap.commit)
        with pytest.raises((ValueError, RuntimeError)), Backlog(path, "one"):
            pass
        with pytest.raises(ValueError):
            store.triage(item["id"], "dismissed", "")
    with pytest.raises(ValueError), Backlog(path, "two"):
        pass
    other = copy.deepcopy(item)
    other["repo_id"] = "two"
    with Backlog(tmp_path / "two.db", "two") as store:
        result = store.reconcile([other], outcome="complete", snapshot=snap.commit)
        assert result[0]["id"] != item["id"]


@pytest.mark.parametrize("outcome", ["complete", "partial", "failed"])
def test_reports_every_outcome_schema_and_sanitization(tmp_path, outcome):
    snap, item = accepted(tmp_path)
    coverage = {
        "schema_version": 1,
        "repo_id": "one",
        "snapshot": snap.commit,
        "inventoried": ["main.py"],
        "assessed": [],
        "observed_reads": [],
        "deferred": [],
        "limitations": ["No assessed coverage declared"],
    }
    report = write_reports(
        tmp_path / "run",
        repo_id="one",
        snapshot=snap.commit,
        outcome=outcome,
        items=[item],
        coverage=coverage,
        errors=["limited"],
        metadata={"token": "sensitive", "raw_transcript": "source dump", "backend": "fixture"},
    )
    validate_document("report", report)
    for filename in ["report.json", "report.md", "coverage.json", "execution.json"]:
        assert (tmp_path / "run" / filename).exists()
    text = (tmp_path / "run" / "report.json").read_text()
    assert "sensitive" not in text and "source dump" not in text
    assert "return value[0]" not in text
    assert json.loads(text)["outcome"] == outcome
    assert report["coverage"]["inventoried"] == ["main.py"]
    assert report["coverage"]["assessed"] == []


def test_observed_execution_artifact_required_for_reproduced_level(tmp_path):
    from repo_audit.validation import ReproductionEvidence

    snap, rules, output = fixture(tmp_path)
    artifact = tmp_path / "observed.txt"
    artifact.write_text("Observed empty input raises IndexError")
    proof = ReproductionEvidence(
        "one",
        snap.commit,
        "empty-index",
        artifact,
        hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "Configured reproduction observed IndexError",
    )
    result = validate_candidates(output, snap, rules, reproductions=[proof])
    assert result.accepted[0]["verification_level"] == "reproduced"
    artifact.write_text("changed")
    result = validate_candidates(output, snap, rules, reproductions=[proof])
    assert result.accepted[0]["verification_level"] == "supported"


def test_expiring_decisions_need_complete_history_and_do_not_reopen(tmp_path):
    snap, item = accepted(tmp_path)
    with Backlog(tmp_path / "one.db", "one") as store:
        store.reconcile([item], outcome="complete", snapshot=snap.commit)
        store.triage(
            item["id"],
            "dismissed",
            "Review next month",
            expires_at="2026-11-01T00:00:00Z",
            now="2026-10-01T00:00:00Z",
        )
        partial = store.reconcile(
            [item], outcome="partial", snapshot=snap.commit, now="2026-11-02T00:00:00Z"
        )
        assert partial[0]["state"] == "dismissed"
        complete = store.reconcile(
            [item], outcome="complete", snapshot=snap.commit, now="2026-11-02T00:00:00Z"
        )
        assert complete[0]["state"] == "needs-revalidation"
        assert len(complete[0]["triage_history"]) == 1


def test_shared_closure_and_incomplete_hydration_preserve_decisions(tmp_path):
    snap, item = accepted(tmp_path)
    with Backlog(tmp_path / "one.db", "one") as store:
        store.reconcile([item], outcome="complete", snapshot=snap.commit)
        store.triage(item["id"], "dismissed", "Local reason", now="2026-10-01T00:00:00Z")
        store.apply_shared_decisions(
            [{"id": item["id"], "state": "open", "triage_history": []}], complete=True
        )
        assert store.items()[0]["state"] == "dismissed"
        closure = {
            "id": item["id"],
            "state": "resolved",
            "triage_history": [
                {
                    "state": "resolved",
                    "reason": "Human closed GitHub issue",
                    "at": "2026-10-03T00:00:00Z",
                }
            ],
            "github_issue": {"number": 4, "url": "https://github.com/o/r/issues/4", "closed": True},
        }
        store.apply_shared_decisions([closure], complete=True)
        assert store.items()[0]["state"] == "resolved"
        assert len(store.items()[0]["triage_history"]) == 2
        store.apply_shared_decisions([{"id": item["id"], "state": "open"}], complete=False)
        again = store.reconcile([item], outcome="complete", snapshot="b" * 40)
        assert again[0]["state"] == "resolved"
        assert len(again[0]["triage_history"]) == 2


def test_failed_transaction_and_unknown_schema_leave_cache_unchanged(tmp_path):
    import sqlite3

    snap, item = accepted(tmp_path)
    path = tmp_path / "one.db"
    with Backlog(path, "one") as store:
        wrong = copy.deepcopy(item)
        wrong["repo_id"] = "other"
        with pytest.raises(ValueError):
            store.reconcile([item, wrong], outcome="complete", snapshot=snap.commit)
        assert store.items() == []
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError), Backlog(path, "one"):
        pass
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 99


def test_report_keeps_usage_counts_and_artifact_digests_without_stream_content(tmp_path):
    snap, item = accepted(tmp_path)
    coverage = {
        "schema_version": 1,
        "repo_id": "one",
        "snapshot": snap.commit,
        "inventoried": ["main.py"],
        "assessed": [],
        "observed_reads": [],
        "deferred": [],
        "limitations": [],
    }
    report = write_reports(
        tmp_path / "run",
        repo_id="one",
        snapshot=snap.commit,
        outcome="complete",
        items=[item],
        coverage=coverage,
        metadata={
            "usage": {
                "input_tokens": 50,
                "output_tokens": 20,
                "total_tokens": 70,
                "access_token": "secret",
            }
        },
        analyzers=[
            {
                "id": "a",
                "raw_artifacts": [{"path": "a.bin", "sha256": "f" * 64}],
                "stdout": "raw source",
            }
        ],
    )
    assert report["metadata"]["usage"]["total_tokens"] == 70
    assert report["analyzers"][0]["raw_artifacts"][0]["sha256"] == "f" * 64
    assert "stdout" not in report["analyzers"][0]
    assert "access_token" not in report["metadata"]["usage"]


def test_agreeing_model_outputs_remain_supported_and_ambiguous_rename_requires_triage(tmp_path):
    snap, rules, output = fixture(tmp_path)
    first = validate_candidates(output, snap, rules)
    second = validate_candidates(copy.deepcopy(output), snap, rules)
    assert (
        first.accepted[0]["verification_level"]
        == second.accepted[0]["verification_level"]
        == "supported"
    )
    one = first.accepted[0]
    two = copy.deepcopy(one)
    two["primary_location"]["path"] = "other.py"
    with Backlog(tmp_path / "one.db", "one") as store:
        assert len(store.reconcile([one, two], outcome="complete", snapshot=snap.commit)) == 2
        moved = copy.deepcopy(one)
        moved["primary_location"]["path"] = "new.py"
        rows = store.reconcile(
            [moved],
            outcome="complete",
            snapshot="b" * 40,
            renames={"main.py": "new.py", "other.py": "new.py"},
        )
        current = next(item for item in rows if item["primary_location"]["path"] == "new.py")
        assert current["identity_match"]["status"] == "ambiguous"
        assert len(current["identity_match"]["candidates"]) == 2
        assert len(rows) == 3


def test_pre_snapshot_failure_has_explicit_null_snapshot(tmp_path):
    coverage = {
        "schema_version": 1,
        "repo_id": "one",
        "snapshot": None,
        "inventoried": [],
        "assessed": [],
        "observed_reads": [],
        "deferred": [],
        "limitations": ["No committed snapshot available"],
    }
    result = write_reports(
        tmp_path / "failed",
        repo_id="one",
        snapshot=None,
        outcome="failed",
        items=[],
        coverage=coverage,
        errors=["Repository has no commit"],
    )
    assert result["snapshot"] is None
    assert result["outcome"] == "failed"
    validate_document("report", result)


@pytest.mark.parametrize(
    "ledger",
    [
        [{"scope_id": "a", "assessed": True, "paths": ["../outside"]}],
        [
            {
                "scope_id": "a",
                "assessed": True,
                "ranges": [{"path": "main.py", "start_line": 1, "end_line": 99}],
            }
        ],
    ],
)
def test_claimed_coverage_rejects_paths_or_ranges_outside_snapshot(tmp_path, ledger):
    snap, rules, output = fixture(tmp_path)
    output["scope_ledger"] = ledger
    result = validate_candidates(output, snap, rules)
    assert result.errors
    assert result.accepted == []


def test_shared_history_preserves_first_observation_in_a_fresh_cache(tmp_path):
    _snap, item = accepted(tmp_path)
    with Backlog(tmp_path / "fresh.db", "one") as store:
        store.apply_shared_decisions(
            [
                {
                    "id": item["id"],
                    "repo_id": "one",
                    "state": "dismissed",
                    "first_observed": "2026-01-01T00:00:00Z",
                    "last_observed": "2026-01-02T00:00:00Z",
                    "triage_history": [
                        {
                            "state": "dismissed",
                            "reason": "Owner decision",
                            "at": "2026-01-02T00:00:00Z",
                        }
                    ],
                }
            ],
            complete=True,
        )
        result = store.reconcile(
            [item], outcome="complete", snapshot="b" * 40, now="2026-10-30T00:00:00Z"
        )
        assert result[0]["first_observed"] == "2026-01-01T00:00:00Z"
        assert result[0]["last_observed"] == "2026-10-30T00:00:00Z"
        assert result[0]["snapshot"] == "b" * 40


@pytest.mark.parametrize(
    "field", ["title", "problem_key", "mechanism", "impact", "next_action", "trigger_conditions"]
)
def test_whitespace_only_claim_fields_cannot_be_findings(tmp_path, field):
    snap, rules, output = fixture(tmp_path)
    output["candidates"][0][field] = "   \n "
    result = validate_candidates(output, snap, rules)
    assert result.accepted == []
    assert result.rejected


def test_missing_trigger_cannot_be_finding_and_sources_are_real_urls(tmp_path):
    snap, rules, output = fixture(tmp_path)
    valid = validate_candidates(output, snap, rules)
    assert valid.accepted[0]["source_refs"] == [rules[0]["source"]["url"]]
    del output["candidates"][0]["trigger_conditions"]
    result = validate_candidates(output, snap, rules)
    assert result.accepted == []
    assert result.rejected
