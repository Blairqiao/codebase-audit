import subprocess

import pytest

from repo_audit.config import ConfigError, effective_policy, load_profile, load_workspace
from repo_audit.snapshot import SnapshotError, create_snapshot


def git(root, *args):
    return (
        subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.STDOUT)
        .decode()
        .strip()
    )


def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "user.name", "Fixture")
    return root


def profile_file(tmp_path, root, extra=""):
    path = tmp_path / "audit.toml"
    path.write_text(f'schema_version = 1\nrepo_id = "one"\nroot = "{root}"\n{extra}')
    return path


def test_profile_relative_paths_workspace_precedence_and_provenance(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "audit.toml").write_text(
        'schema_version=1\nrepo_id="one"\nroot="."\n[budgets]\nmax_launches=2\n'
    )
    manifest = tmp_path / "workspace.toml"
    manifest.write_text(
        'schema_version=1\n[defaults]\nreport_dir="runs"\n[defaults.budgets]\nmax_launches=9\nwall_clock_seconds=30\n[[repositories]]\nid="one"\nprofile="project/audit.toml"\n'
    )
    profiles = load_workspace(manifest)
    assert len(profiles) == 1
    p = profiles[0]
    assert p.root == project
    assert p.report_dir == tmp_path / "runs"
    assert p.budgets["max_launches"] == 2
    assert p.budgets["wall_clock_seconds"] == 30
    assert p.provenance["budgets.max_launches"] == str(project / "audit.toml")
    assert p.provenance["budgets.wall_clock_seconds"] == str(manifest)


@pytest.mark.parametrize(
    "extra",
    [
        "typo=true",
        'decision_documents=["../secret"]',
        'decision_documents=["/tmp/secret"]',
        "[agent]\nallow_network=true",
        '[[analyzers]]\nid="a"\ncategory="testing"\ncommand="npm test"',
    ],
)
def test_strict_config_rejects_unknown_or_unsafe_config(tmp_path, extra):
    with pytest.raises(ConfigError):
        load_profile(profile_file(tmp_path, tmp_path, extra))


def test_policy_applicability_and_project_override(tmp_path):
    p = load_profile(
        profile_file(
            tmp_path,
            tmp_path,
            'policy_packs=["general","web-security"]\n[rule_overrides."general.complexity"]\nmode="required"\nreason="Project adopted"\n',
        )
    )
    rules = effective_policy(p)
    assert rules
    assert not any(r["id"].startswith("web.") for r in rules)
    complexity = next(r for r in rules if r["id"] == "general.complexity")
    assert complexity["mode"] == "required"
    assert complexity["provenance"] == str(tmp_path / "audit.toml")
    assert all(
        r["source"]["url"].startswith("https://")
        and r["source"].get("revision", r["source"].get("sha256"))
        for r in rules
    )


def test_snapshot_uses_commit_and_filters_trust_boundaries(tmp_path):
    root = repository(tmp_path)
    for path, content in {
        "main.py": "old\n",
        ".env": "SECRET=foo\n",
        "node_modules/a.js": "vendor",
        "generated.py": "# @generated\n",
        "image.bin": "\x00abc",
        ".gitignore": "decisions.md\n",
        "nested/code.py": "nested",
    }.items():
        dest = root / path
        dest.parent.mkdir(exist_ok=True, parents=True)
        dest.write_text(content)
    (root / "link").symlink_to("/etc/passwd")
    git(root, "add", ".")
    git(root, "commit", "-m", "fixture")
    (root / "main.py").write_text("dirty\n")
    (root / "decisions.md").write_text("Decision\n")
    (root / "nested" / ".git").mkdir()
    p = load_profile(profile_file(tmp_path, root, 'decision_documents=["decisions.md"]'))
    snap = create_snapshot(p, tmp_path / "snapshot")
    assert snap.dirty is True
    assert (snap.root / "main.py").read_text() == "old\n"
    assert (snap.root / "decisions.md").read_text() == "Decision\n"
    assert {f.path for f in snap.files} == {"main.py", ".gitignore", "decisions.md"}
    assert {x["path"] for x in snap.excluded} >= {
        ".env",
        "link",
        "nested/code.py",
        "generated.py",
        "image.bin",
        "node_modules/a.js",
    }
    assert snap.commit == git(root, "rev-parse", "HEAD")
    assert (root / "main.py").read_text() == "dirty\n"


def test_no_commit_and_symlink_decision_documents_fail(tmp_path):
    root = repository(tmp_path)
    p = load_profile(profile_file(tmp_path, root))
    with pytest.raises(SnapshotError):
        create_snapshot(p, tmp_path / "out")
    (root / "ok").write_text("ok")
    git(root, "add", ".")
    git(root, "commit", "-m", "fixture")
    (root / "doc").symlink_to("/etc/passwd")
    p = load_profile(profile_file(tmp_path, root, 'decision_documents=["doc"]'))
    with pytest.raises(SnapshotError):
        create_snapshot(p, tmp_path / "out2")


@pytest.mark.parametrize(
    "extra",
    [
        '[github]\nenabled="yes"',
        "[github]\nrepository=123",
        '[github]\nrepository="https://token@github.com/o/r"',
        '[[analyzers]]\nid="a"\ncategory="made-up"\ncommand=["echo"]',
        '[[analyzers]]\nid="a"\ncommand=["echo"]\npass_exit_codes=[0]\nfinding_exit_codes=[0]',
    ],
)
def test_invalid_typed_github_and_analyzer_fields(tmp_path, extra):
    with pytest.raises(ConfigError):
        load_profile(profile_file(tmp_path, tmp_path, extra))


def test_snapshot_refuses_checkout_destination_and_symlink_parent(tmp_path):
    root = repository(tmp_path)
    (root / "ok").write_text("ok")
    git(root, "add", ".")
    git(root, "commit", "-m", "fixture")
    p = load_profile(profile_file(tmp_path, root))
    with pytest.raises(SnapshotError):
        create_snapshot(p, root / "audit")
    (root / "real").mkdir()
    (root / "docs").symlink_to(root / "real", target_is_directory=True)
    (root / "real" / "doc.md").write_text("content")
    (root / ".gitignore").write_text("real/\ndocs/\n")
    p = load_profile(profile_file(tmp_path, root, 'decision_documents=["docs/doc.md"]'))
    with pytest.raises(SnapshotError):
        create_snapshot(p, tmp_path / "snapshot")


def test_cli_explains_two_profiles_with_isolated_policy_and_secret_redaction(tmp_path, capsys):
    import json

    from repo_audit.cli import main

    first = tmp_path / "first.toml"
    first.write_text(
        'schema_version=1\nrepo_id="first"\nroot="."\n[[analyzers]]\nid="lint"\ncategory="lint"\ncommand=["tool", "--token", "sensitive"]\n'
    )
    second = tmp_path / "second.toml"
    second.write_text(
        'schema_version=1\nrepo_id="second"\nroot="."\napplicability=["web"]\npolicy_packs=["general", "web-security"]\n'
    )
    assert main(["explain", "--config", str(first), "--json"]) == 0
    first_text = capsys.readouterr().out
    assert "sensitive" not in first_text
    first_result = json.loads(first_text)
    assert main(["explain", "--config", str(second), "--json"]) == 0
    second_result = json.loads(capsys.readouterr().out)
    assert first_result["profile"]["repo_id"] == "first"
    assert second_result["profile"]["repo_id"] == "second"
    assert len(second_result["policy"]) > len(first_result["policy"])
    assert main(["doctor", "--config", str(second)]) == 0
    assert json.loads(capsys.readouterr().out)["auth_probed"] is False


def test_general_pack_can_assess_every_advertised_default_scope_category(tmp_path):
    from repo_audit.scopes import plan_scopes
    from repo_audit.snapshot import InventoryFile, Snapshot

    profile = load_profile(profile_file(tmp_path, tmp_path))
    rules = effective_policy(profile)
    snap = Snapshot("one", "a" * 40, tmp_path, [InventoryFile("a.py", "b" * 64, 1, 1)], [], False)
    scopes = plan_scopes(snap)
    advertised = set().union(*(set(scope.categories) for scope in scopes))
    assert advertised <= {rule["category"] for rule in rules}
    assert all(rule["mode"] == "advisory" for rule in rules)
