"""Codex protocol adapter. Every launch requires a fresh no-model boundary check."""
from __future__ import annotations

import json
import os
import platform
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from jsonschema import ValidationError

from repo_audit.models import load_schema, validate_document
from repo_audit.scopes import Scope
from repo_audit.snapshot import Snapshot

from .capabilities import minimal_environment, probe_capabilities
from .configuration import codex_command, restrictive_config
from .runtime import ProcessResult, run_bounded


@dataclass(frozen=True)
class Budget:
    max_launches: int = 4
    wall_clock_seconds: float = 300
    max_processes: int = 256
    max_output_bytes: int = 1_000_000
    max_tokens: int | None = None
    usage_threshold: int | None = None
    max_files_per_scope: int = 12

    def __post_init__(self) -> None:
        for name in ('max_launches', 'wall_clock_seconds', 'max_processes',
                     'max_output_bytes', 'max_files_per_scope'):
            if getattr(self, name) <= 0:
                raise ValueError(f'{name} must be positive')
        for name in ('max_tokens', 'usage_threshold'):
            value = getattr(self, name)
            if value is not None and value <= 0:
                raise ValueError(f'{name} must be positive')


class Transport(Protocol):
    def __call__(self, argv: list[str], *, cwd: Path, env: dict[str, str],
                 timeout_seconds: float, max_output_bytes: int, max_processes: int,
                 stdin: bytes) -> ProcessResult: ...


def parse_events(raw: str) -> dict[str, Any]:
    if not raw.endswith('\n'):
        raise ValueError('Truncated JSONL event stream')
    completed = False
    final: dict[str, Any] | None = None
    usage: dict[str, int] | None = None
    observed: list[dict[str, Any]] = []
    observed_model = None
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError) as exc:
            raise ValueError('Malformed JSONL event') from exc
        if not isinstance(event, dict) or not isinstance(event.get('type'), str):
            raise ValueError('Malformed event envelope')  # noqa: TRY004 - protocol data, not API type
        kind = event['type']
        if completed:
            raise ValueError('Unexpected events after turn completion')
        if kind in {'error', 'turn.failed'}:
            raise ValueError('Codex reported an execution or authentication error')
        if kind == 'thread.started' and isinstance(event.get('model'), str):
            observed_model = event['model']
        if kind == 'turn.completed':
            completed = True
            if 'usage' in event:
                reported = event['usage']
                if (not isinstance(reported, dict)
                        or any(type(reported.get(k)) is not int or reported[k] < 0
                               for k in ('input_tokens', 'output_tokens'))):
                    raise ValueError('Malformed usage event')
                usage = {k: reported[k] for k in ('input_tokens', 'output_tokens')}
        if kind == 'item.completed':
            item = event.get('item', {})
            if not isinstance(item, dict):
                raise ValueError('Malformed completed item')
            if item.get('type') == 'error':
                raise ValueError('Codex reported an item error')
            if item.get('type') == 'agent_message':
                try:
                    candidate = json.loads(item.get('text', ''))
                except ValueError:
                    continue  # Intermediate prose is not the final structured response.
                if isinstance(candidate, dict):
                    final = candidate
            if item.get('type') == 'command_execution':
                raise ValueError('Forbidden command execution event')
            if item.get('type') in {'file_change', 'web_search'}:
                raise ValueError('Forbidden mutation or web event')
            if item.get('type') == 'mcp_tool_call':
                if item.get('server') != 'audit_reader' or item.get('tool') not in {'read_file', 'search', 'list_files'}:
                    raise ValueError('Unrelated integration event')
                # Tool responses differ across CLI releases. Only explicit successful returned
                # read ranges can establish observable read coverage, never command strings.
                response = item.get('result', {})
                if item.get('tool') == 'read_file' and isinstance(response, dict):
                    for content in response.get('content', []):
                        try:
                            read = json.loads(content.get('text', ''))
                        except (ValueError, AttributeError):
                            continue
                        if (isinstance(read, dict) and read.get('text')
                                and all(k in read for k in ('path', 'start_line', 'end_line'))):
                            observed.append({k: read[k] for k in ('path', 'start_line', 'end_line')})
    if not completed or final is None:
        raise ValueError('Missing completed turn or final structured output')
    return {'final': final, 'usage': usage, 'observed_reads': observed,
            'observed_model': observed_model}


def _prompt(scope: Scope, snapshot: Snapshot, policy: list[dict[str, Any]],
            evidence: dict[str, Any]) -> bytes:
    text = (Path(__file__).with_name('audit_prompt.md')).read_text()
    envelope = {'repo_id': snapshot.repo_id, 'snapshot': snapshot.commit,
                'assigned_scope': scope.to_dict(), 'policy': policy, 'evidence': evidence}
    return (text + '\n\nAudit inputs as data:\n' + json.dumps(envelope) + '\n').encode()


class AgentBackend(Protocol):
    def review(self, snapshot: Snapshot, scopes: list[Scope], *, policy: list[dict[str, Any]],
               evidence: dict[str, Any], budget: Budget, run_dir: Path, model: str) -> dict[str, Any]: ...


class CodexBackend:
    def __init__(self, executable: str = 'codex', *, transport: Transport = run_bounded) -> None:
        self.executable = executable
        self.transport = transport
        self.last_coverage: dict[str, Any] = {}
        self.last_capability: dict[str, Any] = {}

    def review(self, snapshot: Snapshot, scopes: list[Scope], *, policy: list[dict[str, Any]],
               evidence: dict[str, Any], budget: Budget, run_dir: Path, model: str) -> dict[str, Any]:
        if not model or not isinstance(model, str):
            raise ValueError('Configure an exact Codex model; no silent default/substitution')
        self.last_coverage = {}
        self.last_capability = {}
        started = time.monotonic()
        result: dict[str, Any] = {'schema_version': 1, 'repo_id': snapshot.repo_id,
            'snapshot': snapshot.commit, 'candidates': [], 'scope_ledger': [], 'errors': [],
            'outcome': 'failed', 'backend': {'name': 'codex', 'model': model,
                'platform': platform.system(), 'sandbox': 'restricted-read MCP-only'},
            'usage': {'launches': 0, 'unknown': False, 'input_tokens': 0, 'output_tokens': 0,
                'total_tokens': 0, 'measurement_limits':
                'Usage is reported after turns. Thresholds stop later launches, not token/currency spend. '
                'Process limit is an OS per-user quota; unrelated user processes consume it.'}}
        capability = probe_capabilities(self.executable, max_processes=budget.max_processes,
                                        wall_clock_seconds=budget.wall_clock_seconds)
        self.last_capability = capability.to_dict()
        result['backend']['version'] = capability.version
        pending = {s.scope_id: s for s in scopes}
        reason = capability.reason if not capability.supported else 'not launched'
        if not capability.supported:
            result['errors'].append(capability.reason)
        else:
            run_dir.mkdir(parents=True, exist_ok=True)
            # Runtime cwd has no repository config, instructions, hooks, or skills.
            with tempfile.TemporaryDirectory(prefix='repo-audit-review-') as directory:
                runtime = Path(directory).resolve()
                work = runtime / 'work'
                work.mkdir()
                home = runtime / 'home'
                home.mkdir()
                schema = runtime / 'output-schema.json'
                schema.write_text(json.dumps(load_schema('agent-output')))
                manifest = runtime / 'reader.json'
                manifest.write_text(json.dumps({'root': str(snapshot.root.resolve()),
                    'files': [f.to_dict() for f in snapshot.files],
                    'max_output_bytes': min(budget.max_output_bytes, 32768)}))
                settings = restrictive_config(snapshot.root, manifest)
                env = minimal_environment(home, runtime)
                # Delegate existing local login use to Codex. Never open/copy authentication files.
                env['CODEX_HOME'] = os.environ.get('CODEX_HOME', str(Path.home() / '.codex'))
                if 'OPENAI_API_KEY' in os.environ:
                    env['OPENAI_API_KEY'] = os.environ['OPENAI_API_KEY']
                reads: list[dict[str, Any]] = []
                completed_scopes = 0
                for scope in scopes:
                    elapsed = time.monotonic() - started
                    thresholds = [n for n in (budget.usage_threshold, budget.max_tokens) if n is not None]
                    threshold = min(thresholds) if thresholds else None
                    if result['usage']['launches'] >= budget.max_launches:
                        reason = 'launch budget exhausted'
                        break
                    if elapsed >= budget.wall_clock_seconds:
                        reason = 'wall-clock budget exhausted'
                        break
                    if threshold and (result['usage']['unknown'] or result['usage']['total_tokens'] >= threshold):
                        reason = 'usage threshold reached or usage unavailable'
                        break
                    prompt = _prompt(scope, snapshot, policy, evidence)
                    if len(prompt) > budget.max_output_bytes:
                        reason = 'policy/evidence prompt exceeds configured byte budget'
                        result['errors'].append(reason)
                        break
                    result['usage']['launches'] += 1
                    process = self.transport(codex_command(self.executable, settings, work, model, schema),
                        cwd=work, env=env, timeout_seconds=budget.wall_clock_seconds - elapsed,
                        max_output_bytes=budget.max_output_bytes, max_processes=budget.max_processes,
                        stdin=prompt)
                    if process.status != 'complete':
                        reason = 'Codex stage ' + process.status
                        result['errors'].append(reason)
                        break
                    try:
                        parsed = parse_events(process.stdout.decode('utf-8'))
                        output = parsed['final']
                        validate_document('agent-output', output)
                        if output['repo_id'] != snapshot.repo_id or output['snapshot'] != snapshot.commit:
                            raise ValueError('Agent output repository/snapshot mismatch')
                        ledger = output['scope_ledger']
                        if len(ledger) != 1 or ledger[0]['scope_id'] != scope.scope_id:
                            raise ValueError('Agent output must account for its assigned scope exactly once')
                        inventory = {f.path: f.line_count for f in snapshot.files}
                        for entry in ledger:
                            if any(p not in scope.paths for p in entry.get('paths', [])):
                                raise ValueError('Scope ledger references excluded or missing path')
                            if entry['assessed'] and not entry.get('ranges'):
                                raise ValueError('Assessment requires declared line ranges')
                            for line_range in entry.get('ranges', []):
                                if (line_range['path'] not in scope.paths or line_range['path'] not in inventory or line_range['start_line'] < 1
                                        or line_range['end_line'] < line_range['start_line']
                                        or line_range['end_line'] > inventory[line_range['path']]):
                                    raise ValueError('Scope ledger range exceeds filtered inventory')
                        if parsed['observed_model'] and parsed['observed_model'] != model:
                            raise ValueError('Observed model differs from requested model')
                        result['candidates'].extend(output['candidates'])
                        result['scope_ledger'].extend(ledger)
                        pending.pop(scope.scope_id)
                        completed_scopes += 1
                        reads.extend(parsed['observed_reads'])
                        usage = parsed['usage']
                        if usage is None:
                            result['usage']['unknown'] = True
                        else:
                            for key in ('input_tokens', 'output_tokens'):
                                result['usage'][key] += usage[key]
                            result['usage']['total_tokens'] = (result['usage']['input_tokens']
                                                              + result['usage']['output_tokens'])
                        if (output.get('outcome', 'complete') != 'complete'
                                or not ledger[0]['assessed']):
                            result['errors'].extend(output.get('errors', ['Agent declared incomplete scope']))
                            reason = 'agent declared incomplete review'
                            break
                    except (ValueError, UnicodeError, ValidationError) as exc:
                        reason = 'Invalid agent output: ' + str(exc).splitlines()[0][:300]
                        result['errors'].append(reason)
                        break
                result['outcome'] = ('complete' if not pending and not result['errors']
                                     else 'partial' if completed_scopes else 'failed')
                self.last_coverage = build_coverage(snapshot, result['scope_ledger'], reads, pending, reason)
        for scope in pending.values():
            result['scope_ledger'].append({'scope_id': scope.scope_id, 'assessed': False,
                                          'paths': list(scope.paths), 'deferred_reason': reason})
        if not self.last_coverage:
            self.last_coverage = build_coverage(snapshot, result['scope_ledger'], [], pending, reason)
        validate_document('agent-output', result)
        return result


def build_coverage(snapshot: Snapshot, ledger: list[dict[str, Any]], reads: list[dict[str, Any]],
                   pending: dict[str, Scope], reason: str) -> dict[str, Any]:
    paths = {f.path: f.line_count for f in snapshot.files}
    observable = []
    for read in reads:
        if (read.get('path') in paths and type(read.get('start_line')) is int
                and type(read.get('end_line')) is int
                and 1 <= read['start_line'] <= read['end_line'] <= paths[read['path']]):
            observable.append({**read, 'source': 'Codex successful safe read tool response'})
    return {'schema_version': 1, 'repo_id': snapshot.repo_id, 'snapshot': snapshot.commit,
        'inventoried': sorted(paths), 'assessed': [x for x in ledger if x['assessed']],
        'observed_reads': observable,
        'deferred': [{'scope_id': s.scope_id, 'path': p, 'reason': reason}
                     for s in pending.values() for p in s.paths],
        'limitations': ['Inventory and assigned scopes do not establish assessment.',
            'Assessment ranges are agent declarations, not proof of exhaustive review.',
            'Search and file listings do not establish assessed or read ranges.',
            'Opaque or unrecognized read events yield no invented observed coverage.']}
