"""Execute explicitly enrolled trusted analyzers; this is not hostile-code isolation."""
import hashlib
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .parsers import parse_report

CHECK_CATEGORIES = ("lint", "typecheck", "tests", "dependencies", "unused")
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _inside(path: Path, root: Path) -> bool:
    return path.resolve().is_relative_to(root.resolve())


def _relative(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or Path(value).is_absolute() or ".." in Path(value).parts:
        raise ValueError("paths must be relative and stay inside execution root")
    target = root / value
    if not _inside(target, root):
        raise ValueError("path escapes execution root")
    return target


def _argv(value: Any) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(s, str) or not s or "\x00" in s for s in value):
        raise ValueError("command must be an explicit nonempty argv array")
    return value


def _kill(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _execute(argv: list[str], cwd: Path, env: dict[str, str], timeout: float,
             limit: int) -> dict[str, Any]:
    result: dict[str, Any] = {"command": argv, "status": "passed", "exit_code": None,
                              "started_at": _now(), "error": None}
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = False
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
    except FileNotFoundError as exc:
        result.update(status="unavailable", error=str(exc))
    except OSError as exc:
        result.update(status="failed", error=str(exc))
    else:
        started = time.monotonic()
        total = 0
        with selectors.DefaultSelector() as selector:
            assert process.stdout is not None and process.stderr is not None
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                if time.monotonic() - started >= timeout and result["status"] == "passed":
                    result.update(status="timeout", error=f"command exceeded {timeout:g} seconds")
                    _kill(process)
                for key, _ in selector.select(timeout=.025):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        pipe = process.stdout if key.data == "stdout" else process.stderr
                        pipe.close()
                        continue
                    remaining = max(0, limit - total)
                    streams[key.data].extend(chunk[:remaining])
                    total += len(chunk)
                    if total > limit:
                        truncated = True
                        if result["status"] == "passed":
                            result.update(status="output_limit", error=f"command output exceeded {limit} bytes")
                            _kill(process)
            remaining_time = max(.01, timeout - (time.monotonic() - started))
            try:
                process.wait(timeout=remaining_time)
            except subprocess.TimeoutExpired:
                result.update(status="timeout", error=f"command exceeded {timeout:g} seconds")
                _kill(process)
                process.wait()
        result["exit_code"] = process.returncode
        # Reap the group even if a detached pipe owner outlives its parent.
        _kill(process)
    result.update(stdout=bytes(streams["stdout"]), stderr=bytes(streams["stderr"]),
                  truncated=truncated, finished_at=_now())
    return result


def _artifact(raw: bytes, path: Path, run_dir: Path, kind: str,
              truncated: bool = False) -> dict[str, Any]:
    path.write_bytes(raw)
    return {"path": path.relative_to(run_dir).as_posix(), "kind": kind,
            "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw),
            "truncated": truncated}


def _record_streams(result: dict[str, Any], output_dir: Path,
                    run_dir: Path, prefix: str = "") -> list[dict[str, Any]]:
    return [_artifact(result[name], output_dir / f"{prefix}{name}.bin", run_dir,
                      f"{prefix}{name}", result["truncated"]) for name in ("stdout", "stderr")]


def _base(config: dict[str, Any]) -> dict[str, Any]:
    return {"id": config.get("id", "invalid"), "category": config.get("category", "other"),
            "format": config.get("format", "text"), "command": config.get("command", []),
            "cwd": config.get("cwd", "."), "version": None, "status": "failed",
            "parser_status": "not_parsed", "exit_code": None,
            "pass_exit_codes": config.get("pass_exit_codes", [0]),
            "finding_exit_codes": config.get("finding_exit_codes", [1]),
            "started_at": _now(), "finished_at": _now(), "raw_artifacts": [],
            "diagnostics": [], "error": None}


def _one(config: dict[str, Any], snapshot: Any, run_dir: Path, index: int) -> dict[str, Any]:
    check = _base(config)
    if sys.platform not in {"darwin", "linux"}:
        check.update(status="unsupported", error=f"unsupported analyzer platform: {sys.platform}")
        return check
    output_dir = run_dir / "analyzers" / f"{index:04d}"
    output_dir.mkdir(parents=True, exist_ok=False)
    try:
        argv = _argv(config.get("command"))
        timeout = config.get("timeout_seconds", 300)
        limit = config.get("max_output_bytes", 1024 * 1024)
        if type(timeout) not in (int, float) or not 0 < timeout <= 86400:
            raise ValueError("timeout_seconds must be positive and at most 86400")
        if type(limit) is not int or not 0 < limit <= MAX_OUTPUT_BYTES:
            raise ValueError(f"max_output_bytes must be a positive integer <= {MAX_OUTPUT_BYTES}")
        passing, findings = check["pass_exit_codes"], check["finding_exit_codes"]
        if not isinstance(passing, list) or not isinstance(findings, list) or any(type(x) is not int for x in passing + findings):
            raise ValueError("exit codes must be integer arrays")
        if set(passing).intersection(findings):
            raise ValueError("pass and finding exit codes must not overlap")
        with tempfile.TemporaryDirectory(prefix="repo-audit-analyzer-") as temporary:
            workspace = Path(temporary)
            execution = workspace / "source"
            shutil.copytree(snapshot.root, execution, symlinks=True)
            # No source symlinks are followed into the execution copy.
            if any(path.is_symlink() for path in execution.rglob("*")):
                raise ValueError("execution snapshot must not contain symlinks")
            home, temp = workspace / "home", workspace / "tmp"
            home.mkdir()
            temp.mkdir()
            env = {"PATH": os.defpath, "HOME": str(home), "TMPDIR": str(temp),
                   "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_COLOR": "1"}
            cwd = _relative(execution, config.get("cwd", "."))
            if not cwd.is_dir():
                raise ValueError("configured cwd does not exist in snapshot")
            artifact = None
            if "artifact" in config:
                artifact = _relative(cwd, config["artifact"])
                if not _inside(artifact, execution):
                    raise ValueError("artifact is outside execution root")
            if "version_command" in config:
                version = _execute(_argv(config["version_command"]), cwd, env, min(timeout, 10), limit)
                version_artifacts = _record_streams(version, output_dir, run_dir, "version-")
                check["version"] = {key: version[key] for key in ("command", "status", "exit_code", "started_at", "finished_at", "error")}
                if version["status"] == "passed" and version["exit_code"] != 0:
                    check["version"]["status"] = "failed"
                check["version"].update(text=version["stdout"].decode("utf-8", errors="replace"), raw_artifacts=version_artifacts)
            result = _execute(argv, cwd, env, timeout, limit)
            for key in ("status", "exit_code", "started_at", "finished_at", "error"):
                check[key] = result[key]
            check["raw_artifacts"] = _record_streams(result, output_dir, run_dir)
            if check["status"] == "passed":
                code = check["exit_code"]
                check["status"] = "passed" if code in passing else "findings" if code in findings else "failed"
                if check["status"] == "failed":
                    check["error"] = f"undeclared analyzer exit code: {code}"
            raw = result["stdout"]
            if artifact is not None and check["status"] not in {"timeout", "output_limit", "unavailable"}:
                # Revalidate after execution because the command can replace paths with symlinks.
                if not _inside(artifact, execution) or artifact.is_symlink() or not artifact.is_file():
                    check.update(parser_status="error", error="report artifact is missing or escapes execution root")
                    return check
                with artifact.open("rb") as stream:
                    raw = stream.read(limit + 1)
                truncated = len(raw) > limit
                raw = raw[:limit]
                check["raw_artifacts"].append(_artifact(raw, output_dir / "report.bin", run_dir, "report", truncated))
                if truncated:
                    check.update(status="output_limit", error=f"report artifact exceeded {limit} bytes")
            if check["status"] not in {"timeout", "output_limit", "unavailable"}:
                parsed = parse_report(check["format"], raw, execution, cwd)
                check.update(parser_status=parsed.status, diagnostics=parsed.diagnostics)
                if parsed.error:
                    check["error"] = parsed.error
    except (ValueError, OSError) as exc:
        check.update(status="invalid_config", error=str(exc))
    return check


def collect_analyzers(profile: Any, snapshot: Any, run_dir: Path) -> list[dict[str, Any]]:
    """Collect configured checks, retaining execution and parser outcomes separately.

    Every check starts from a fresh filtered snapshot. Executables and their installed
    dependencies must already be accessible. No scripts are discovered or installed.
    The configured command is trusted and can access the host as the current user.
    """
    run_dir = Path(run_dir).resolve()
    if _inside(run_dir, profile.root) or _inside(run_dir, snapshot.root):
        raise ValueError("run_dir must be outside checkout and snapshot")
    run_dir.mkdir(parents=True, exist_ok=True)
    checks = [_one(config, snapshot, run_dir, index) for index, config in enumerate(profile.analyzers)]
    configured = {config.get("category", "other") for config in profile.analyzers}
    for category in CHECK_CATEGORIES:
        if category not in configured:
            missing = _base({"id": f"not-configured:{category}", "category": category})
            missing.update(status="not_configured", command=[])
            checks.append(missing)
    return checks
