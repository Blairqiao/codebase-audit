import json
import subprocess
from pathlib import Path

import pytest

from repo_audit.cli import main
from repo_audit.config import Profile
from repo_audit.orchestration import collect, finalize


def enrolled(tmp_path, name='alpha'):
    root = tmp_path / name
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    (root / 'code.py').write_text('def divide(a, b):\n    return a / b\n')
    subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], check=True)
    return Profile(name, root, report_dir=tmp_path / 'cache')


def output(bundle):
    scope = bundle['scopes'][0]
    return {'schema_version': 1, 'repo_id': bundle['repo_id'], 'snapshot': bundle['snapshot']['commit'],
            'candidates': [], 'scope_ledger': [{'scope_id': scope['scope_id'], 'assessed': True,
            'paths': scope['paths'], 'ranges': [{'path': scope['paths'][0], 'start_line': 1, 'end_line': 2}]}],
            'outcome': 'complete'}


def test_collect_finalize_portable_contract_and_tamper(tmp_path):
    profile = enrolled(tmp_path)
    run_dir = tmp_path / 'run'
    bundle = collect(profile, run_dir)
    assert (run_dir / 'review-prompt.md').exists()
    assert (run_dir / 'agent-output.schema.json').exists()
    assert not (profile.root / 'report.json').exists()
    agent = run_dir / 'answer.json'
    agent.write_text(json.dumps(output(bundle)))
    report = finalize(run_dir, agent)
    assert report['outcome'] == 'complete'
    assert report['coverage']['observed_reads'] == []
    assert report['coverage']['assessed']
    assert (run_dir/'report.md').exists()
    (run_dir / 'snapshot' / 'code.py').write_text('tampered\n')
    report = finalize(run_dir, agent)
    assert report['outcome'] == 'failed'
    assert any('digest' in x.lower() for x in report['errors'])
    assert not report['coverage']['assessed']


def test_finalize_malformed_and_unknown_scope_write_failed_reports(tmp_path):
    profile = enrolled(tmp_path)
    run_dir = tmp_path / 'run'
    bundle = collect(profile, run_dir)
    agent = run_dir / 'answer.json'
    final = output(bundle)
    final['scope_ledger'][0]['scope_id'] = 'forged'
    agent.write_text(json.dumps(final))
    report = finalize(run_dir, agent)
    assert report['outcome'] == 'failed'
    assert not report['coverage']['assessed']
    agent.write_text('{broken')
    assert finalize(run_dir, agent)['outcome'] == 'failed'
    assert (run_dir/'coverage.json').exists()
    assert (run_dir/'execution.json').exists()


def test_collect_cannot_write_inside_checkout(tmp_path):
    profile = enrolled(tmp_path)
    with pytest.raises(ValueError):
        collect(profile, profile.root / 'audit')


def test_workspace_continues_after_uncommitted_prerequisite(tmp_path, monkeypatch, capsys):
    good = enrolled(tmp_path)
    bad = tmp_path / 'bad'
    bad.mkdir()
    subprocess.run(['git', 'init', '-q', str(bad)], check=True)
    for name, root in [('alpha', good.root), ('bad', bad)]:
        (tmp_path/f'{name}.toml').write_text(f'schema_version=1\nrepo_id="{name}"\nroot="{root}"\nreport_dir="{tmp_path}/cache"\n[agent]\nmodel="fixture"\nexecutable="absent-codex"\n')
    workspace = tmp_path / 'workspace.toml'
    workspace.write_text('schema_version=1\nrepositories=[{id="bad",profile="bad.toml"},{id="alpha",profile="alpha.toml"}]\n')
    assert main(['run', '--workspace', str(workspace), '--run-dir', str(tmp_path/'runs')]) == 3
    assert (tmp_path/'runs'/'alpha'/'report.json').exists()
    summary = json.loads((tmp_path/'runs'/'workspace-report.json').read_text())
    assert {x['repo_id'] for x in summary['repositories']} == {'alpha', 'bad'}
    assert summary['outcome'] == 'partial'
