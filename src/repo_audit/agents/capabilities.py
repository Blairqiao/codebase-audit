"""No-model checks of the sandbox and actual model-facing tool catalog."""
from __future__ import annotations

import json
import platform
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from .configuration import PINNED_VERSION, codex_command, restrictive_config
from .runtime import run_bounded


@dataclass
class Capability:
    supported: bool
    reason: str
    version: str = ''
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {'supported': self.supported, 'reason': self.reason,
                'version': self.version, 'evidence': self.evidence}


def minimal_environment(home: Path, temp: Path) -> dict[str, str]:
    return {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'CODEX_HOME': str(home),
            'TMPDIR': str(temp), 'LANG': 'C.UTF-8'}


def safe_tool_catalog(tools: list[dict[str, Any]]) -> bool:
    generic = {'list_mcp_resources', 'list_mcp_resource_templates',
               'read_mcp_resource', 'request_user_input'}
    seen: set[str] = set()
    found_reader = False
    for tool in tools:
        name = tool.get('name', '')
        if name in seen:
            return False
        seen.add(name)
        if tool.get('type') == 'namespace' and name == 'mcp__audit_reader':
            nested = tool.get('tools', [])
            names = [item.get('name') for item in nested if item.get('type') == 'function']
            if sorted(names) != ['list_files', 'read_file', 'search'] or len(names) != len(nested):
                return False
            found_reader = True
        elif tool.get('type') != 'function' or name not in generic:
            return False
    return found_reader


def probe_capabilities(executable: str = 'codex', *, max_processes: int = 256,
                       wall_clock_seconds: float = 60) -> Capability:
    """No login check, no auth reads, no paid or remote model call.

    A successful probe is recomputed for this invocation, never accepted from profile prose.
    RLIMIT_NPROC is a hard per-user quota, so other work under this UID consumes the limit.
    """
    deadline = time.monotonic() + wall_clock_seconds
    if platform.system() not in {'Darwin', 'Linux'}:
        return Capability(False, 'Only macOS and Linux capability probes are supported')
    resolved = shutil.which(executable)
    if not resolved:
        return Capability(False, 'Codex executable unavailable')
    evidence: dict[str, Any] = {'model_calls': 0, 'remote_requests': 0,
        'process_quota': 'OS RLIMIT_NPROC counts all processes for this user'}
    with tempfile.TemporaryDirectory(prefix='repo-audit-probe-') as directory:
        root = Path(directory).resolve()
        home = root / 'home'
        home.mkdir()
        source = root / 'snapshot'
        source.mkdir()
        work = root / 'work'
        work.mkdir()
        sentinel = root / 'outside-sentinel.txt'
        sentinel.write_text('synthetic outside sentinel\n')
        allowed = source / 'allowed.txt'
        allowed.write_text('synthetic allowed source\n')
        env = minimal_environment(home, root)

        def execute(argv: list[str]) -> Any:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                from .runtime import ProcessResult
                return ProcessResult('timeout', None, b'', b'Capability wall-clock budget exhausted')
            return run_bounded(argv, cwd=work, env=env, timeout_seconds=min(20, remaining),
                               max_output_bytes=262144, max_processes=max_processes)

        version_run = execute([resolved, '--version'])
        version = version_run.stdout.decode(errors='replace').strip()
        if version_run.status != 'complete' or version != PINNED_VERSION:
            return Capability(False, 'Install the pinned/probed Codex version or revalidate a new version',
                              version, evidence)
        config = ('default_permissions = "audit"\n[permissions.audit.filesystem]\n'
                  '":root" = "deny"\n":minimal" = "read"\n' + json.dumps(str(source)) +
                  ' = "read"\n[permissions.audit.network]\nenabled = false\n')
        (home / 'config.toml').write_text(config)
        commands = {
            'allowed_read': ['/bin/cat', str(allowed)],
            'outside_read': ['/bin/cat', str(sentinel)],
            'source_write': ['/bin/sh', '-c', 'printf forbidden > "$1"',
                             'probe', str(source / 'written.txt')],
        }
        results = {}
        for name, command in commands.items():
            result = execute([resolved, 'sandbox', '-P', 'audit', '-C', str(source), *command])
            results[name] = {'status': result.status, 'exit_code': result.returncode,
                             'stdout': result.stdout.decode(errors='replace'),
                             'stderr': result.stderr.decode(errors='replace')}
        evidence['sandbox'] = results
        # Negative tests alone cannot distinguish denial from a broken sandbox.
        if (results['allowed_read']['status'] != 'complete'
                or results['allowed_read']['stdout'] != 'synthetic allowed source\n'
                or results['outside_read']['exit_code'] == 0
                or 'synthetic outside sentinel' in results['outside_read']['stdout']
                or results['source_write']['exit_code'] == 0 or (source / 'written.txt').exists()):
            return Capability(False, 'Restricted-read/write sandbox probe failed; use an enforceable host',
                              version, evidence)
        manifest = root / 'reader.json'
        manifest.write_text(json.dumps({'root': str(source), 'files': [], 'max_output_bytes': 2048}))
        requests: list[dict[str, Any]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                size = int(self.headers.get('Content-Length', '0'))
                if size > 2_000_000:
                    self.send_error(413)
                    return
                requests.append(json.loads(self.rfile.read(size)))
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"error":{"message":"offline tool probe complete"}}')

            def log_message(self, *_: Any) -> None:
                pass

        try:
            server = HTTPServer(('127.0.0.1', 0), Handler)
        except OSError as exc:
            return Capability(False, f'Cannot start local no-model capability probe: {exc}', version, evidence)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            settings = restrictive_config(source, manifest)
            settings.update({
                'model_provider': 'offline_probe',
                'model_providers.offline_probe.name': 'Offline capability probe',
                'model_providers.offline_probe.base_url': f'http://127.0.0.1:{server.server_port}/v1',
                'model_providers.offline_probe.wire_api': 'responses',
                'model_providers.offline_probe.requires_openai_auth': False,
                'model_providers.offline_probe.request_max_retries': 0,
                'model_providers.offline_probe.stream_max_retries': 0,
            })
            result = run_bounded(codex_command(resolved, settings, work, 'offline-probe-model'),
                cwd=work, env=env, timeout_seconds=max(0.001, min(20, deadline - time.monotonic())), max_output_bytes=262144,
                max_processes=max_processes, stdin=b'Offline tool exposure probe.\n')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        tools = requests[0].get('tools', []) if requests else []
        evidence['offered_tools'] = [{k: v for k, v in tool.items() if k in {'type', 'name', 'tools'}}
                                     for tool in tools]
        evidence['tool_probe_status'] = result.status
        if not tools or not safe_tool_catalog(tools):
            return Capability(False, 'Exact read/search tool isolation not verified; agent execution denied',
                              version, evidence)
        return Capability(True, 'Restricted reads, source write denial, and MCP-only tool catalog verified',
                          version, evidence)
