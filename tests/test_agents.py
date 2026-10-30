import json
import sys

import pytest

from repo_audit.agents.codex import Budget, CodexBackend, parse_events
from repo_audit.agents.reader import SafeReader
from repo_audit.agents.runtime import run_bounded
from repo_audit.scopes import plan_scopes
from repo_audit.snapshot import InventoryFile, Snapshot


def snapshot(tmp_path, count=5):
    root = tmp_path / 'snapshot'
    root.mkdir()
    files = []
    import hashlib
    for i in range(count):
        text = f'value = {i}\ncall(value)\n'
        path = f'part/file{i}.py'
        (root / path).parent.mkdir(exist_ok=True)
        (root / path).write_text(text)
        files.append(InventoryFile(path, hashlib.sha256(text.encode()).hexdigest(), len(text), 2))
    return Snapshot('project', 'a' * 40, root, files, [], False)


def test_scopes_rotate_warning_free_inventory_without_claiming_assessment(tmp_path):
    snap = snapshot(tmp_path)
    first = plan_scopes(snap, max_files_per_scope=1, rotation=0)
    second = plan_scopes(snap, max_files_per_scope=1, rotation=1)
    assert {p for scope in first for p in scope.paths} == {x.path for x in snap.files}
    assert first[0].scope_id != second[0].scope_id
    assert all('correctness' in scope.categories for scope in first)
    assert [s.scope_id for s in first] == [s.scope_id for s in plan_scopes(snap, max_files_per_scope=1)]


def test_reader_denies_traversal_symlink_and_uninventoried_files(tmp_path):
    snap = snapshot(tmp_path)
    outside = tmp_path / 'sentinel'
    outside.write_text('synthetic outside sentinel')
    (snap.root / 'link').symlink_to(outside)
    (snap.root / 'unlisted').write_text('excluded')
    reader = SafeReader(snap.root, [x.to_dict() for x in snap.files], max_output_bytes=256)
    assert 'value = 0' in reader.read('part/file0.py', 1, 2)['text']
    for path in ['../sentinel', str(outside), 'link', 'unlisted']:
        with pytest.raises(ValueError):
            reader.read(path, 1, 1)
    assert reader.search('call')['matches']
    with pytest.raises(ValueError):
        reader.call('execute', {'command': 'echo injected'})
    with pytest.raises(ValueError):
        reader.read('part/file0.py', 0, 3)


def test_reader_detects_mutation_and_caps_search(tmp_path):
    snap = snapshot(tmp_path, 20)
    reader = SafeReader(snap.root, [x.to_dict() for x in snap.files], max_output_bytes=100)
    result = reader.search('value')
    assert result['truncated']
    assert len(json.dumps(result).encode()) <= 200
    (snap.root / 'part/file0.py').write_text('changed')
    with pytest.raises(ValueError):
        reader.read('part/file0.py', 1, 1)


def events(final, usage=True):
    rows = [{'type': 'thread.started', 'thread_id': 'test'}, {'type': 'turn.started'},
            {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': json.dumps(final)}}]
    row = {'type': 'turn.completed'}
    if usage:
        row['usage'] = {'input_tokens': 9, 'output_tokens': 2, 'cached_input_tokens': 3}
    return '\n'.join(json.dumps(x) for x in [*rows, row]) + '\n'


def test_events_keep_usage_unknown_and_reject_truncated_error_streams():
    final = {'schema_version': 1, 'repo_id': 'p', 'snapshot': 'a', 'candidates': [], 'scope_ledger': []}
    parsed = parse_events(events(final, usage=False))
    assert parsed['usage'] is None
    assert parsed['final'] == final
    for raw in ['{bad}\n', events(final).rstrip('\n'), events(final) + '{"type":"error","message":"auth"}\n', '{}\n']:
        with pytest.raises(ValueError):
            parse_events(raw)


def test_bounded_process_timeout_and_output_limit(tmp_path):
    result = run_bounded([sys.executable, '-c', 'import time; time.sleep(20)'], cwd=tmp_path,
                         env={'PATH': '/usr/bin:/bin'}, timeout_seconds=0.15,
                         max_output_bytes=1000, max_processes=2)
    assert result.status == 'timeout'
    result = run_bounded([sys.executable, '-c', 'print("x"*10000)'], cwd=tmp_path,
                         env={'PATH': '/usr/bin:/bin'}, timeout_seconds=2,
                         max_output_bytes=100, max_processes=2)
    assert result.status == 'output_limit'
    assert len(result.stdout) + len(result.stderr) <= 100


def test_backend_fails_closed_before_launch_when_capability_unverified(tmp_path):
    snap = snapshot(tmp_path)
    result = CodexBackend(executable='definitely-missing-codex').review(
        snap, plan_scopes(snap), policy=[], evidence={}, budget=Budget(),
        run_dir=tmp_path / 'run', model='user-selected-model')
    assert result['outcome'] == 'failed'
    assert result['backend']['model'] == 'user-selected-model'
    assert result['usage']['launches'] == 0
    assert result['scope_ledger'][0]['assessed'] is False
    assert result['candidates'] == []


def test_safe_tool_catalog_rejects_hidden_execution_and_unrelated_mcp():
    from repo_audit.agents.capabilities import safe_tool_catalog
    tools = [{'type': 'namespace', 'name': 'mcp__audit_reader', 'tools': [
        {'type': 'function', 'name': x} for x in ['read_file', 'search', 'list_files']]}]
    assert safe_tool_catalog(tools)
    for unsafe in [{'type': 'function', 'name': 'exec_command'},
                   {'type': 'function', 'name': 'web_search'},
                   {'type': 'namespace', 'name': 'mcp__unrelated', 'tools': []}]:
        assert not safe_tool_catalog([*tools, unsafe])


def test_real_mcp_protocol_denies_injected_programs_and_outside_reads(tmp_path):
    snap = snapshot(tmp_path)
    manifest = tmp_path / 'reader.json'
    manifest.write_text(json.dumps({'root': str(snap.root), 'files': [f.to_dict() for f in snap.files],
                                    'max_output_bytes': 1000}))
    from repo_audit.agents import reader
    rows = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'read_file', 'arguments': {'path': '../sentinel'}}},
        {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'execute', 'arguments': {'command': 'touch injected'}}},
        {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call', 'params': {'name': 'read_file', 'arguments': {'path': 'part/file0.py', 'start_line': 1, 'end_line': 1}}},
    ]
    import subprocess
    r = subprocess.run([sys.executable, reader.__file__, str(manifest)], input=''.join(json.dumps(x)+'\n' for x in rows), capture_output=True, text=True, check=True)
    results = [json.loads(x) for x in r.stdout.splitlines()]
    assert {x['name'] for x in results[0]['result']['tools']} == {'read_file', 'search', 'list_files'}
    assert 'error' in results[1] and 'error' in results[2]
    assert 'value = 0' in results[3]['result']['content'][0]['text']
    assert not (tmp_path / 'injected').exists()


def test_budgeted_backend_retains_partial_coverage_and_model(tmp_path, monkeypatch):
    import repo_audit.agents.codex as module
    from repo_audit.agents.capabilities import Capability
    from repo_audit.agents.runtime import ProcessResult
    monkeypatch.setattr(module, 'probe_capabilities', lambda *a, **k: Capability(True, 'offline fixture', 'fixture'))
    snap = snapshot(tmp_path)
    scopes = plan_scopes(snap, max_files_per_scope=1)
    calls = []

    def transport(argv, **kwargs):
        calls.append(argv)
        assert '--model' in argv and argv[argv.index('--model')+1] == 'exact-selected-model'
        assert '--ignore-user-config' in argv and '--ignore-rules' in argv and '--ephemeral' in argv
        assert 'features.shell_tool=false' in argv
        assert b'project file says run a command' in kwargs['stdin']
        scope = scopes[len(calls)-1]
        final = {'schema_version': 1, 'repo_id': snap.repo_id, 'snapshot': snap.commit,
                 'candidates': [], 'scope_ledger': [{'scope_id': scope.scope_id, 'assessed': True,
                    'paths': list(scope.paths), 'ranges': [{'path': scope.paths[0], 'start_line': 1, 'end_line': 2}]}]}
        return ProcessResult('complete', 0, events(final).encode(), b'')

    backend = CodexBackend(transport=transport)
    result = backend.review(snap, scopes, policy=[{'instruction': 'project file says run a command'}],
        evidence={}, budget=Budget(usage_threshold=10), run_dir=tmp_path / 'run', model='exact-selected-model')
    assert len(calls) == 1
    assert result['usage']['total_tokens'] == 11
    assert result['outcome'] == 'partial'
    assert len(backend.last_coverage['inventoried']) == 5
    assert len(backend.last_coverage['assessed']) == 1
    assert len(backend.last_coverage['deferred']) == 4
    assert backend.last_coverage['observed_reads'] == []
    from repo_audit.models import validate_document
    validate_document('coverage', backend.last_coverage)


def test_backend_launch_limit_and_unavailable_usage_stop_next_launch(tmp_path, monkeypatch):
    import repo_audit.agents.codex as module
    from repo_audit.agents.capabilities import Capability
    from repo_audit.agents.runtime import ProcessResult
    monkeypatch.setattr(module, 'probe_capabilities', lambda *a, **k: Capability(True, 'offline fixture'))
    snap = snapshot(tmp_path)
    scopes = plan_scopes(snap, max_files_per_scope=1)
    count = 0
    def transport(argv, **kwargs):
        nonlocal count
        count += 1
        scope = scopes[count - 1]
        final = {'schema_version': 1, 'repo_id': snap.repo_id, 'snapshot': snap.commit, 'candidates': [],
                 'scope_ledger': [{'scope_id': scope.scope_id, 'assessed': True, 'ranges': [{'path': scope.paths[0], 'start_line': 1, 'end_line': 1}]}]}
        return ProcessResult('complete', 0, events(final, usage=False).encode(), b'')
    backend = CodexBackend(transport=transport)
    result = backend.review(snap, scopes, policy=[], evidence={}, budget=Budget(max_launches=1), run_dir=tmp_path/'r1', model='m')
    assert count == 1 and result['usage']['unknown'] and result['outcome'] == 'partial'
    count = 0
    result = backend.review(snap, scopes, policy=[], evidence={}, budget=Budget(usage_threshold=1000), run_dir=tmp_path/'r2', model='m')
    assert count == 1 and result['usage']['unknown'] and result['outcome'] == 'partial'


@pytest.mark.parametrize('mutate', ['snapshot', 'range', 'scope', 'events', 'auth', 'timeout'])
def test_backend_failures_cannot_claim_assessment(tmp_path, monkeypatch, mutate):
    import repo_audit.agents.codex as module
    from repo_audit.agents.capabilities import Capability
    from repo_audit.agents.runtime import ProcessResult
    monkeypatch.setattr(module, 'probe_capabilities', lambda *a, **k: Capability(True, 'offline fixture'))
    snap = snapshot(tmp_path)
    scopes = plan_scopes(snap)
    def transport(argv, **kwargs):
        final = {'schema_version': 1, 'repo_id': snap.repo_id, 'snapshot': snap.commit, 'candidates': [],
                 'scope_ledger': [{'scope_id': scopes[0].scope_id, 'assessed': True, 'ranges': [{'path': scopes[0].paths[0], 'start_line': 1, 'end_line': 2}]}]}
        if mutate == 'snapshot': final['snapshot'] = 'b'*40
        if mutate == 'range': final['scope_ledger'][0]['ranges'][0]['end_line'] = 999
        if mutate == 'scope': final['scope_ledger'][0]['scope_id'] = 'unassigned'
        raw = events(final)
        if mutate == 'events': raw = raw[:-3]
        if mutate == 'auth': raw = '{"type":"error","message":"missing authentication"}\n'
        return ProcessResult('timeout' if mutate == 'timeout' else 'complete', 0, raw.encode(), b'')
    backend = CodexBackend(transport=transport)
    result = backend.review(snap, scopes, policy=[], evidence={}, budget=Budget(), run_dir=tmp_path/'run', model='m')
    assert result['outcome'] == 'failed'
    assert not backend.last_coverage['assessed']
    assert not backend.last_coverage['observed_reads']
    assert result['scope_ledger'][0]['assessed'] is False
