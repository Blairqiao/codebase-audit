"""Auditor-owned CLI settings for the pinned, probed Codex CLI."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PINNED_VERSION = 'codex-cli 0.163.0-alpha.11.2'
DISABLED_FEATURES = (
    'apps', 'plugins', 'hooks', 'shell_tool', 'shell_snapshot', 'multi_agent',
    'browser_use', 'computer_use', 'in_app_browser', 'image_generation', 'view_image',
    'memories', 'remote_plugin', 'skill_search', 'skill_mcp_dependency_install',
    'code_mode', 'code_mode_host', 'goals', 'sleep_tool', 'workspace_dependencies',
)


def toml_literal(value: Any) -> str:
    if isinstance(value, dict):
        return '{' + ', '.join(json.dumps(k) + ' = ' + toml_literal(v)
                               for k, v in value.items()) + '}'
    return json.dumps(value)


def restrictive_config(snapshot_root: Path, manifest: Path) -> dict[str, Any]:
    settings: dict[str, Any] = {
        'approval_policy': 'never', 'web_search': 'disabled', 'project_doc_max_bytes': 0,
        'default_permissions': 'audit',
        'permissions.audit.filesystem': {':root': 'deny', ':minimal': 'read',
                                        str(snapshot_root.resolve()): 'read'},
        'permissions.audit.network.enabled': False,
        'mcp_servers.audit_reader.command': sys.executable,
        'mcp_servers.audit_reader.args': [str(Path(__file__).with_name('reader.py')), str(manifest)],
        'mcp_servers.audit_reader.required': True,
        'mcp_servers.audit_reader.enabled_tools': ['read_file', 'search', 'list_files'],
        'shell_environment_policy.inherit': 'none',
        'features.skip_host_skill_discovery': True,
        'suppress_unstable_features_warning': True,
    }
    settings.update({f'features.{feature}': False for feature in DISABLED_FEATURES})
    return settings


def config_arguments(settings: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for key, value in settings.items():
        result.extend(['-c', key + '=' + toml_literal(value)])
    return result


def codex_command(executable: str, settings: dict[str, Any], cwd: Path, model: str,
                  schema: Path | None = None) -> list[str]:
    argv = [executable, '--no-daemon', 'exec', '--strict-config', '--ignore-user-config',
            '--ignore-rules', '--ephemeral', '--skip-git-repo-check', '--json',
            '-C', str(cwd), '--model', model, *config_arguments(settings)]
    if schema is not None:
        argv.extend(['--output-schema', str(schema)])
    return [*argv, '-']
