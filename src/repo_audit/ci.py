"""Trusted Actions preparation and bounded Codex executable interception."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

from .agents.capabilities import probe_capabilities
from .agents.codex import Budget, parse_events
from .agents.configuration import restrictive_config, toml_literal
from .agents.runtime import run_bounded
from .orchestration import load_bundle


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(run_dir: Path, runtime: Path, real_codex: Path, model: str) -> dict[str, str]:
    bundle, profile, snapshot = load_bundle(run_dir)
    if not model or profile.agent.get('model') != model:
        raise ValueError('Actions model must exactly match the enrolled profile agent.model')
    if profile.github.get('repository') != os.environ.get('GITHUB_REPOSITORY'):
        raise ValueError('Enrolled GitHub destination must equal the consumer repository')
    budget = Budget(**profile.budgets)
    runtime.mkdir(parents=True, exist_ok=True)
    for name in ['home', 'work', 'bin']:
        (runtime / name).mkdir(exist_ok=True)
    manifest = runtime / 'reader.json'
    manifest.write_text(json.dumps({'root': str(snapshot.root), 'files': [f.to_dict() for f in snapshot.files],
                                  'max_output_bytes': min(budget.max_output_bytes, 32768)}))
    settings = restrictive_config(snapshot.root, manifest)
    # The action must read its own proxy-provider configuration. This isolated home
    # contains only auditor settings, never an inherited user or target configuration.
    (runtime/'home'/'config.toml').write_text('\n'.join(k+' = '+toml_literal(v) for k,v in settings.items())+'\n')
    info = {'schema_version': 1, 'real_codex': str(real_codex.resolve()),
        'executable_sha256': _sha(real_codex.resolve()), 'model': model,
        'max_launches': 1, 'budget': profile.budgets, 'runtime': str(runtime.resolve()),
        'run_dir': str(run_dir.resolve()), 'scope_ids': bundle['action_scope_ids']}
    boundary = runtime / 'boundary.json'
    boundary.write_text(json.dumps(info))
    wrapper = runtime / 'bin' / 'codex'
    wrapper.write_text('#!'+sys.executable+'\nfrom repo_audit.ci import bounded_action_main\nbounded_action_main('+repr(str(boundary))+')\n')
    wrapper.chmod(0o755)
    return {'runtime': str(runtime.resolve()), 'codex_home': str((runtime/'home').resolve()),
            'working_directory': str((runtime/'work').resolve()),
            'path': str((runtime/'bin').resolve()) + os.pathsep + str(real_codex.parent) + os.pathsep + os.environ.get('PATH', '/usr/bin:/bin')}


def bounded_action_main(boundary_file: str) -> None:
    info = json.loads(Path(boundary_file).read_text())
    runtime = Path(info['runtime'])
    budget = Budget(**info['budget'])
    real = Path(info['real_codex'])
    if _sha(real) != info['executable_sha256']:
        raise SystemExit('Pinned Codex executable changed after the no-model setup')
    argv = sys.argv[1:]
    if not argv or argv[0] != 'exec' or '--model' not in argv:
        raise SystemExit('Unexpected official Action command')
    if argv[argv.index('--model') + 1] != info['model']:
        raise SystemExit('Official Action selected an unenrolled model')
    if '--cd' not in argv or Path(argv[argv.index('--cd')+1]).resolve() != runtime / 'work':
        raise SystemExit('Official Action runtime directory mismatch')
    stamp = runtime / 'launch.lock'
    try:
        descriptor = os.open(stamp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
    except FileExistsError:
        raise SystemExit('Actions launch count exhausted') from None
    # Only the proxy's isolated configuration is inherited. No GitHub/model key enters Codex/MCP.
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(runtime/'home'), 'CODEX_HOME': str(runtime/'home'),
           'TMPDIR': str(runtime), 'LANG': 'C.UTF-8'}
    # Run the same fresh no-model probe under the same dedicated UID/quota immediately before use.
    capability = probe_capabilities(str(real), max_processes=budget.max_processes,
                                    wall_clock_seconds=min(budget.wall_clock_seconds, 60))
    (runtime/'capability.json').write_text(json.dumps(capability.to_dict()))
    if not capability.supported:
        raise SystemExit('Actions boundary unsupported: '+capability.reason)
    result = run_bounded([str(real), '--no-daemon', *argv], cwd=runtime/'work', env=env,
        timeout_seconds=budget.wall_clock_seconds, max_output_bytes=budget.max_output_bytes,
        max_processes=budget.max_processes)
    state: dict[str, Any] = {'status': result.status, 'launches': 1, 'model': info['model']}
    if result.status == 'complete':
        try:
            parsed = parse_events(result.stdout.decode('utf-8'))
            state['usage'] = parsed['usage']
            state['observed_reads'] = parsed['observed_reads']
        except (ValueError, UnicodeError) as exc:
            state.update(status='failed', error=str(exc))
    (Path(info['run_dir'])/'action-execution.json').write_text(json.dumps(state))
    print(json.dumps({'repo_audit_stage': state['status'], 'launches': 1}))
    raise SystemExit(0 if state['status'] == 'complete' else 3)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-dir', required=True, type=Path)
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--real-codex', required=True, type=Path)
    parser.add_argument('--model', required=True)
    args = parser.parse_args()
    result = prepare(args.run_dir.resolve(), args.runtime.resolve(), args.real_codex, args.model)
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as target:
            for key,value in result.items():
                target.write(key+'='+value+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
