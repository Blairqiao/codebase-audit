import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from repo_audit.collectors import runner
from repo_audit.models import validate_document


def setup(tmp_path, commands):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "source.py").write_text("original\n")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "source.py").write_text("original\n")
    profile = SimpleNamespace(root=checkout, analyzers=commands)
    snap = SimpleNamespace(root=snapshot, commit="a" * 40, repo_id="test")
    return profile, snap, tmp_path / "run"


def command(id, code, **kwargs):
    return {"id":id, "category":"testing", "command":[sys.executable, "-c", code], **kwargs}


def test_disposable_mutation_minimal_environment_and_digest(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "model-secret")
    monkeypatch.setenv("GH_TOKEN", "publish-secret")
    monkeypatch.setenv("ARBITRARY_SECRET", "secret")
    code = "import os,pathlib,json; pathlib.Path('source.py').write_text('changed'); print(json.dumps(dict(os.environ)))"
    profile, snap, run_dir = setup(tmp_path, [command("writer", code, format="json")])
    checks = runner.collect_analyzers(profile, snap, run_dir)
    check = next(c for c in checks if c["id"] == "writer")
    assert check["status"] == "passed"
    assert check["parser_status"] == "unstructured"
    assert (profile.root / "source.py").read_text() == "original\n"
    assert (snap.root / "source.py").read_text() == "original\n"
    raw = next(a for a in check["raw_artifacts"] if a["kind"] == "stdout")
    body = (run_dir / raw["path"]).read_bytes()
    assert hashlib.sha256(body).hexdigest() == raw["sha256"]
    env = json.loads(body)
    assert not {"OPENAI_API_KEY", "GH_TOKEN", "ARBITRARY_SECRET"}.intersection(env)
    assert Path(env["HOME"]) != Path.home()
    assert check["started_at"] <= check["finished_at"]


def test_execution_outcomes_and_missing_categories(tmp_path):
    commands = [command("pass", "print('[]')", format="ruff"),
                command("finding", "print('[]'); raise SystemExit(1)", format="ruff", finding_exit_codes=[1]),
                command("fail", "raise SystemExit(2)"), command("parse", "print('{')", format="ruff"),
                {"id":"missing", "command":["/definitely/missing"], "category":"maintenance"}]
    profile, snap, run_dir = setup(tmp_path, commands)
    checks = {c["id"]:c for c in runner.collect_analyzers(profile, snap, run_dir)}
    assert checks["pass"]["status"] == "passed"
    assert checks["finding"]["status"] == "findings"
    assert checks["fail"]["status"] == "failed"
    assert checks["parse"]["status"] == "passed"
    assert checks["parse"]["parser_status"] == "error"
    assert checks["missing"]["status"] == "unavailable"
    assert any(c["status"] == "not_configured" for c in checks.values())


def test_timeout_terminates_children(tmp_path):
    marker = tmp_path / "child-survived"
    child_code = f"import time,pathlib; time.sleep(1); pathlib.Path({str(marker)!r}).touch()"
    code = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child_code!r}]); time.sleep(10)"
    profile, snap, run_dir = setup(tmp_path, [command("timeout", code, timeout_seconds=.1)])
    checks = runner.collect_analyzers(profile, snap, run_dir)
    assert checks[0]["status"] == "timeout"
    import time
    time.sleep(1.1)
    assert not marker.exists()


def test_bounds_stream_output_and_file_artifact(tmp_path):
    commands = [command("flood", "import os; os.write(1,b'x'*1000000)", max_output_bytes=128),
                command("artifact", "from pathlib import Path; Path('report.json').write_text('x'*1000)",
                        artifact="report.json", format="json", max_output_bytes=128)]
    profile, snap, run_dir = setup(tmp_path, commands)
    checks = runner.collect_analyzers(profile, snap, run_dir)
    assert len(checks) >= 2
    for check in checks[:2]:
        assert check["status"] == "output_limit"
        assert check["parser_status"] == "not_parsed"
        assert any(a["truncated"] for a in check["raw_artifacts"])
        assert all(a["size_bytes"] <= 128 for a in check["raw_artifacts"])


def test_artifact_and_cwd_escape_are_rejected(tmp_path):
    commands = [command("cwd", "print('never')", cwd="../outside"),
                command("symlink", "import os; os.symlink('/etc/passwd','report')", artifact="report", format="text")]
    profile, snap, run_dir = setup(tmp_path, commands)
    checks = runner.collect_analyzers(profile, snap, run_dir)
    assert checks[0]["status"] == "invalid_config"
    assert checks[1]["parser_status"] == "error"
    assert not any(a["kind"] == "report" for a in checks[1]["raw_artifacts"])


def test_version_only_runs_when_explicit_and_keeps_status(tmp_path):
    profile, snap, run_dir = setup(tmp_path, [command("version", "print('clean')", version_command=[sys.executable,"-c","print('tool 1.2.3')"])])
    check = runner.collect_analyzers(profile, snap, run_dir)[0]
    assert check["version"]["text"].strip() == "tool 1.2.3"
    assert check["version"]["status"] == "passed"
    validate_document("evidence", {"schema_version": 1, "repo_id": "test", "snapshot": snap.commit, "checks": [check]})
    assert check["pass_exit_codes"] == [0]
    assert check["finding_exit_codes"] == [1]


def test_each_check_has_fresh_copy_and_checkout_run_dir_rejected(tmp_path):
    commands = [command("first", "from pathlib import Path; Path('new').touch()"),
                command("second", "from pathlib import Path; assert not Path('new').exists()")]
    profile, snap, run_dir = setup(tmp_path, commands)
    checks = runner.collect_analyzers(profile, snap, run_dir)
    assert all(c["status"] == "passed" for c in checks[:2])
    with pytest.raises(ValueError, match="outside"):
        runner.collect_analyzers(profile, snap, profile.root / "run")
