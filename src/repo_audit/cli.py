"""Command contracts for local audit stages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from typing import Any

from .agents.capabilities import probe_capabilities
from .backlog import Backlog
from .orchestration import cache_path, collect, finalize, load_bundle, prerequisite_report, run
from .publishers import publish
from .snapshot import SnapshotError
from .models import validate_document

from .config import ConfigError, effective_policy, load_profile, load_workspace


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[redacted]"
            if re.search(r"password|secret|api[_-]?key|access[_-]?token", key, re.IGNORECASE)
            else _sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        cleaned = []
        redact_next = False
        for item in value:
            if redact_next:
                cleaned.append("[redacted]")
                redact_next = False
            elif isinstance(item, str) and re.search(
                r"^--?(?:password|secret|token|api-key)(?:=|$)", item, re.IGNORECASE
            ):
                cleaned.append(item.split("=")[0] + "=[redacted]" if "=" in item else item)
                redact_next = "=" not in item
            else:
                cleaned.append(_sanitize(item))
        return cleaned
    if isinstance(value, str):
        return re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[redacted]@", value)
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repo-audit")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ["doctor", "explain", "collect", "run", "finalize", "publish", "triage"]:
        sub = commands.add_parser(name)
        if name in {"doctor", "explain", "collect", "triage"}:
            sub.add_argument("--config", required=True)
        if name == "run":
            source = sub.add_mutually_exclusive_group(required=True)
            source.add_argument("--config")
            source.add_argument("--workspace")
        if name in {"collect", "run", "finalize", "publish"}:
            sub.add_argument("--run-dir", required=True)
        if name == "doctor":
            sub.add_argument("--probe-auth", action="store_true")
        if name == "explain":
            sub.add_argument("--json", action="store_true")
        if name == "finalize":
            sub.add_argument("--agent-output", required=True)
        if name == "publish":
            mode = sub.add_mutually_exclusive_group(required=True)
            mode.add_argument("--dry-run", action="store_true")
            mode.add_argument("--apply", action="store_true")
        if name == "triage":
            sub.add_argument("--item", required=True)
            sub.add_argument(
                "--state",
                required=True,
                choices=["dismissed", "accepted-risk", "resolved", "open", "needs-revalidation"],
            )
            sub.add_argument("--reason", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profiles = (
            load_workspace(args.workspace)
            if getattr(args, "workspace", None)
            else [load_profile(args.config)]
            if getattr(args, "config", None)
            else []
        )
        if args.command == "explain":
            result: dict[str, Any] = {
                "schema_version": 1,
                "profile": profiles[0].to_dict(),
                "policy": effective_policy(profiles[0]),
                "execution_boundary": {
                    "agent_read_only": True,
                    "agent_network": False,
                    "agent_execution": False,
                    "publication_requires_apply": True,
                },
            }
            print(json.dumps(_sanitize(result), indent=2, sort_keys=True))
            return 0
        if args.command == "doctor":
            profile = profiles[0]
            git = shutil.which("git")
            capability = probe_capabilities(profile.agent.get("executable", "codex"),
                max_processes=profile.budgets["max_processes"],
                wall_clock_seconds=profile.budgets["wall_clock_seconds"])
            result = {"schema_version": 1, "platform": platform.system(),
                "python": platform.python_version(), "git": None,
                "auth_probed": args.probe_auth, "agent_capability": capability.to_dict()}
            if git:
                result["git"] = subprocess.check_output([git, "--version"], text=True).strip()
            if args.probe_auth:
                auth = subprocess.run([profile.agent.get("executable", "codex"), "login", "status"],
                                      capture_output=True, timeout=10)
                result["authentication_available"] = auth.returncode == 0
            print(json.dumps(_sanitize(result), indent=2))
            return 0 if git and capability.supported else 2
        if args.command == "collect":
            bundle = collect(profiles[0], Path(args.run_dir))
            checks = json.loads((Path(args.run_dir) / "evidence.json").read_text())["checks"]
            print(json.dumps({"repo_id": bundle["repo_id"], "snapshot": bundle["snapshot"]["commit"],
                              "run_dir": str(Path(args.run_dir).resolve())}))
            return 3 if any(c["status"] in {"failed", "timeout", "output_limit", "unavailable", "invalid_config", "unsupported"} or c["parser_status"] == "error" for c in checks) else 0
        if args.command == "run":
            outcomes = []
            for profile in profiles:
                destination = Path(args.run_dir) / profile.repo_id if getattr(args, "workspace", None) else Path(args.run_dir)
                try:
                    report = run(profile, destination)
                    code = 0 if report["outcome"] == "complete" else 3
                    outcomes.append({"repo_id": profile.repo_id, "outcome": report["outcome"],
                                     "exit_code": code, "report": str(destination / "report.json")})
                except (ConfigError, SnapshotError, OSError, ValueError, RuntimeError) as exc:
                    prerequisite_report(profile, destination, str(exc))
                    outcomes.append({"repo_id": profile.repo_id, "outcome": "failed",
                                     "exit_code": 2, "error": str(exc)})
            code = max((x["exit_code"] for x in outcomes), default=2)
            if getattr(args, "workspace", None):
                code = 0 if code == 0 else 3
                summary = {"schema_version": 1, "outcome": "complete" if code == 0 else "partial",
                           "repositories": outcomes}
                path = Path(args.run_dir) / "workspace-report.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(summary, indent=2) + "\n")
                print(json.dumps(summary))
            else:
                print(json.dumps(outcomes[0]))
            return code
        if args.command == "finalize":
            report = finalize(Path(args.run_dir), Path(args.agent_output))
            print(json.dumps({"repo_id": report["repo_id"], "outcome": report["outcome"]}))
            return 0 if report["outcome"] == "complete" else 3
        if args.command == "publish":
            _, profile, _ = load_bundle(Path(args.run_dir), verify=False)
            report = json.loads((Path(args.run_dir) / "report.json").read_text())
            validate_document('report', report)
            publication = publish(report, profile.github, apply=args.apply,
                                  lock_dir=cache_path(profile).parent)
            (Path(args.run_dir) / "publication.json").write_text(json.dumps(publication, indent=2) + "\n")
            print(json.dumps(publication, indent=2))
            return 0 if publication["outcome"] == "complete" else 3
        if args.command == "triage":
            with Backlog(cache_path(profiles[0]), profiles[0].repo_id) as backlog:
                backlog.triage(args.item, args.state, args.reason)
            print(json.dumps({"item": args.item, "state": args.state}))
            return 0
        return 2
    except (ConfigError, ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"repo-audit: {exc}", file=sys.stderr)
        return 2


def entrypoint() -> None:
    raise SystemExit(main())
