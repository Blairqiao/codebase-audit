"""Collection and one shared finalization path for local and Actions review output."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import ValidationError

from .agents.codex import Budget, CodexBackend, build_coverage
from .agents.reader import SafeReader
from .backlog import Backlog
from .collectors import collect_analyzers
from .config import Profile, effective_policy
from .models import load_schema, validate_document
from .publishers.github import hydrate
from .reports import write_reports
from .scopes import Scope, plan_scopes
from .snapshot import Snapshot, create_snapshot
from .validation import validate_candidates


class BundleError(ValueError):
    """Prepared audit data failed integrity or boundary checks."""


def _json(path: Path, value: Any) -> None:
    if path.is_symlink():
        raise BundleError('Audit artifact must not be a symlink')
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cache_path(profile: Profile) -> Path:
    path = profile.report_dir.resolve() / profile.repo_id / 'backlog.sqlite3'
    if path.is_relative_to(profile.root.resolve()):
        raise BundleError('Cache/report location must be outside the target checkout')
    return path


def _outside(profile: Profile, run_dir: Path) -> None:
    if run_dir.resolve().is_relative_to(profile.root.resolve()):
        raise BundleError('Run directory must be outside the target checkout')
    cache_path(profile)


def collect(profile: Profile, run_dir: Path) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    _outside(profile, run_dir)
    if run_dir.exists() and any(run_dir.iterdir()):
        raise BundleError('Use a new or empty run directory; existing artifacts are never overwritten by collect')
    run_dir.mkdir(parents=True, exist_ok=True)
    snapshot = create_snapshot(profile, run_dir / 'snapshot')
    checks = collect_analyzers(profile, snapshot, run_dir)
    evidence = {'schema_version': 1, 'repo_id': profile.repo_id,
                'snapshot': snapshot.commit, 'checks': checks}
    validate_document('evidence', evidence)
    policy = effective_policy(profile)
    budget = Budget(**profile.budgets)
    risks = [d['path'] for check in checks for d in check.get('diagnostics', []) if d.get('path')]
    rotation = datetime.now(timezone.utc).date().toordinal() // 7
    scopes = plan_scopes(snapshot, component_roots=profile.component_roots, risk_paths=risks,
                        max_files_per_scope=budget.max_files_per_scope, rotation=rotation)
    _json(run_dir / 'evidence.json', evidence)
    _json(run_dir / 'policy.json', policy)
    _json(run_dir / 'agent-output.schema.json', load_schema('agent-output'))
    prompt = Path(__file__).with_name('agents').joinpath('audit_prompt.md').read_text()
    # The official Action makes a single bounded launch. Other scopes stay explicitly deferred.
    action_scopes = scopes[:1]
    action_data = {'repo_id': profile.repo_id, 'snapshot': snapshot.commit,
                   'assigned_scopes': [s.to_dict() for s in action_scopes], 'policy': policy,
                   'evidence': evidence,
                   'deferred_scope_ids': [s.scope_id for s in scopes[1:]]}
    (run_dir / 'review-prompt.md').write_text(prompt + '\n\nAudit inputs as data:\n' + json.dumps(action_data) + '\n')
    serialized = snapshot.to_dict()
    serialized['root'] = 'snapshot'
    bundle = {'schema_version': 1, 'repo_id': profile.repo_id, 'snapshot': serialized,
              'profile': profile.to_dict(), 'scopes': [s.to_dict() for s in scopes],
              'action_scope_ids': [s.scope_id for s in action_scopes],
              'artifacts': {p: _digest(run_dir / p) for p in
                            ['evidence.json', 'policy.json', 'agent-output.schema.json', 'review-prompt.md']}}
    _json(run_dir / 'manifest.json', bundle)
    (run_dir / 'manifest.sha256').write_text(_digest(run_dir / 'manifest.json') + '\n')
    return bundle


def _profile(data: dict[str, Any]) -> Profile:
    fields = dict(data)
    fields['root'] = Path(fields['root'])
    fields['report_dir'] = Path(fields['report_dir'])
    return Profile(**fields)


def load_bundle(run_dir: Path, *, verify: bool = True) -> tuple[dict[str, Any], Profile, Snapshot]:
    run_dir = run_dir.resolve()
    bundle = json.loads((run_dir / 'manifest.json').read_text())
    expected = {'schema_version', 'repo_id', 'snapshot', 'profile', 'scopes', 'action_scope_ids', 'artifacts'}
    if set(bundle) != expected or bundle['schema_version'] != 1:
        raise BundleError('Unknown or invalid prepared bundle fields')
    profile = _profile(bundle['profile'])
    _outside(profile, run_dir)
    snapshot_data = {**bundle['snapshot'], 'root': str(run_dir / 'snapshot')}
    if bundle['snapshot']['root'] != 'snapshot' or snapshot_data['repo_id'] != profile.repo_id or bundle['repo_id'] != profile.repo_id:
        raise BundleError('Prepared bundle identity or source root mismatch')
    snapshot = Snapshot.from_dict(snapshot_data)
    if verify:
        if (run_dir / 'manifest.json').is_symlink() or (run_dir / 'manifest.sha256').is_symlink():
            raise BundleError('Prepared manifest must not be a symlink')
        if _digest(run_dir / 'manifest.json') != (run_dir / 'manifest.sha256').read_text().strip():
            raise BundleError('Prepared manifest digest mismatch')
        if set(bundle['artifacts']) != {'evidence.json', 'policy.json', 'agent-output.schema.json', 'review-prompt.md'}:
            raise BundleError('Unexpected prepared artifacts')
        for path, digest in bundle['artifacts'].items():
            target = run_dir / path
            if target.is_symlink() or _digest(target) != digest:
                raise BundleError('Prepared artifact digest mismatch: ' + path)
        if snapshot.root.is_symlink():
            raise BundleError('Snapshot root must not be a symlink')
        reader = SafeReader(snapshot.root, [f.to_dict() for f in snapshot.files])
        for item in snapshot.files:
            reader._text(item.path)
    return bundle, profile, snapshot


def _scopes(bundle: dict[str, Any]) -> list[Scope]:
    scopes = [Scope(s['scope_id'], tuple(s['paths']), tuple(s['categories']), s['reason']) for s in bundle['scopes']]
    if len({s.scope_id for s in scopes}) != len(scopes):
        raise BundleError('Duplicate assigned scope identity')
    return scopes


def _ledger(output: dict[str, Any], scopes: list[Scope], snapshot: Snapshot) -> None:
    assigned = {s.scope_id: set(s.paths) for s in scopes}
    inventory = {f.path: f.line_count for f in snapshot.files}
    seen = set()
    for entry in output['scope_ledger']:
        key = entry['scope_id']
        if key not in assigned or key in seen:
            raise BundleError('Unknown or duplicate scope in agent coverage')
        seen.add(key)
        if any(p not in assigned[key] for p in entry.get('paths', [])):
            raise BundleError('Coverage path is outside its assigned scope')
        if entry['assessed'] and not entry.get('ranges'):
            raise BundleError('Assessment requires declared line ranges')
        for span in entry.get('ranges', []):
            if (span['path'] not in assigned[key] or span['path'] not in inventory
                    or not 1 <= span['start_line'] <= span['end_line'] <= inventory[span['path']]):
                raise BundleError('Coverage range is outside its assigned inventory')


def finalize(run_dir: Path, agent_output: Path, *, observed_reads: list[dict[str, Any]] | None = None,
             transport: Any = None) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    # Recover trusted identity for a useful failed report even when a source digest changed.
    bundle, profile, snapshot = load_bundle(run_dir, verify=False)
    errors: list[str] = []
    scopes = _scopes(bundle)
    output: dict[str, Any] = {'schema_version': 1, 'repo_id': snapshot.repo_id,
        'snapshot': snapshot.commit, 'candidates': [], 'scope_ledger': [], 'outcome': 'failed'}
    try:
        load_bundle(run_dir)
        if agent_output.stat().st_size > Budget(**profile.budgets).max_output_bytes:
            raise BundleError('Agent output exceeds configured byte budget')
        output = json.loads(agent_output.read_text())
        validate_document('agent-output', output)
        if output['repo_id'] != snapshot.repo_id or output['snapshot'] != snapshot.commit:
            raise BundleError('Agent output repository/snapshot mismatch')
        _ledger(output, scopes, snapshot)
    except (OSError, ValueError, KeyError, TypeError, ValidationError) as exc:
        errors.append(str(exc).splitlines()[0][:400])
        output = {'schema_version': 1, 'repo_id': snapshot.repo_id, 'snapshot': snapshot.commit,
                  'candidates': [], 'scope_ledger': [], 'outcome': 'failed'}
    policy = json.loads((run_dir / 'policy.json').read_text())
    evidence = json.loads((run_dir / 'evidence.json').read_text())
    validation = validate_candidates(output, snapshot, policy)
    errors.extend(validation.errors)
    errors.extend(output.get('errors', []))
    if validation.rejected:
        errors.extend('Rejected candidate: ' + str(item.get('reason', 'invalid evidence')) for item in validation.rejected)
    accounted = {x['scope_id'] for x in output['scope_ledger'] if x['assessed']}
    pending = {s.scope_id: s for s in scopes if s.scope_id not in accounted}
    reason = 'Agent did not assess this assigned scope, or review was incomplete'
    coverage = build_coverage(snapshot, output['scope_ledger'], observed_reads or [], pending, reason)
    checks = evidence['checks']
    check_errors = [c for c in checks if c['status'] in {'failed', 'timeout', 'output_limit', 'unavailable', 'invalid_config', 'unsupported'} or c['parser_status'] == 'error']
    if check_errors:
        errors.extend('Analyzer incomplete: ' + c['id'] + '/' + c['status'] for c in check_errors)
    outcome = output.get('outcome', 'complete')
    if outcome == 'complete' and (pending or errors):
        outcome = 'partial' if accounted else 'failed'
    if validation.errors:
        outcome = 'failed'
    warnings = ['Coverage is bounded; a complete run is not an exhaustive correctness claim.']
    if snapshot.dirty:
        warnings.append('Dirty checkout was ignored; the selected committed snapshot was audited.')
    shared_complete = not profile.github.get('enabled', False)
    with Backlog(cache_path(profile), profile.repo_id) as backlog:
        if profile.github.get('enabled', False):
            hydration = hydrate(profile.github['repository'], profile.repo_id, transport,
                                label=profile.github.get('label', 'repo-audit:managed'))
            shared_complete = hydration['complete']
            backlog.apply_shared_decisions(hydration['items'], complete=shared_complete)
            if not shared_complete:
                warnings.append('GitHub history unavailable; cached triage is retained with unknown freshness.')
                errors.extend(hydration['errors'])
                if outcome == 'complete':
                    outcome = 'partial'
        items = backlog.reconcile(validation.accepted, outcome=outcome, snapshot=snapshot.commit,
                                  history_complete=shared_complete)
    metadata = {'backend': output.get('backend', {}), 'usage': output.get('usage', {}),
        'model': output.get('backend', {}).get('model', profile.agent.get('model', 'unknown')),
        'warnings': warnings, 'history_complete': shared_complete, 'hydration_complete': shared_complete,
        'publication_enabled': bool(profile.github.get('enabled', False)),
        'github_repository': profile.github.get('repository'),
        'stages': {'collection': 'partial' if check_errors else 'complete', 'review': outcome}}
    report = write_reports(run_dir, repo_id=profile.repo_id, snapshot=snapshot.commit, outcome=outcome,
        items=items, coverage=coverage, analyzers=checks, policy=policy, errors=errors, metadata=metadata)
    return report


def run(profile: Profile, run_dir: Path) -> dict[str, Any]:
    bundle = collect(profile, run_dir)
    _, _, snapshot = load_bundle(run_dir)
    if not profile.agent.get('model'):
        output = {'schema_version': 1, 'repo_id': profile.repo_id, 'snapshot': snapshot.commit,
                  'candidates': [], 'scope_ledger': [], 'outcome': 'failed',
                  'errors': ['Configure an exact agent.model; no default model is selected']}
        reads = []
    else:
        backend = CodexBackend(profile.agent.get('executable', 'codex'))
        output = backend.review(snapshot, _scopes(bundle), policy=json.loads((run_dir/'policy.json').read_text()),
            evidence=json.loads((run_dir/'evidence.json').read_text()), budget=Budget(**profile.budgets),
            run_dir=run_dir, model=profile.agent['model'])
        reads = backend.last_coverage.get('observed_reads', [])
        _json(run_dir / 'capability.json', backend.last_capability)
    answer = run_dir / 'agent-output.json'
    _json(answer, output)
    return finalize(run_dir, answer, observed_reads=reads)


def prerequisite_report(profile: Profile, run_dir: Path, error: str) -> dict[str, Any]:
    _outside(profile, run_dir)
    coverage = {'schema_version': 1, 'repo_id': profile.repo_id, 'snapshot': None,
                'inventoried': [], 'assessed': [], 'observed_reads': [], 'deferred': [],
                'limitations': ['No committed snapshot was available; no source was assessed.']}
    return write_reports(run_dir, repo_id=profile.repo_id, snapshot=None, outcome='failed',
                         items=[], coverage=coverage, errors=[error])
