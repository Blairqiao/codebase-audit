"""Bounded GitHub REST calls through the installed gh credential adapter."""
import json
import os
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .render import PublicationError


class GhTransport:
    """No shell, repository scripts, issue search, or custom credential storage."""

    def __init__(self, executable: str | None = None, *, timeout: float = 30,
                 max_output_bytes: int = 16 * 1024 * 1024) -> None:
        self.executable = executable
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        if method not in {"GET", "POST", "PATCH"} or not path.startswith("repos/") or "\n" in path:
            raise PublicationError("unsupported GitHub REST request")
        executable = self.executable or shutil.which("gh")
        if not executable:
            raise PublicationError("gh executable is unavailable")
        args = [executable, "api", "--hostname", "github.com", "--method", method,
                "--header", "Accept: application/vnd.github+json",
                "--header", "X-GitHub-Api-Version: 2022-11-28", path]
        keep = {"PATH", "HOME", "XDG_CONFIG_HOME", "GH_CONFIG_DIR", "GH_TOKEN", "GITHUB_TOKEN",
                "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"}
        env = {key: value for key, value in os.environ.items() if key in keep}
        env.update(GH_PROMPT_DISABLED="1", GH_PAGER="cat", NO_COLOR="1")
        with tempfile.TemporaryDirectory(prefix="repo-audit-gh-") as temporary:
            if payload is not None:
                request_file = Path(temporary) / "request.json"
                request_file.write_text(json.dumps(payload), encoding="utf-8")
                request_file.chmod(0o600)
                args.extend(["--input", str(request_file)])
            try:
                process = subprocess.Popen(args, cwd=temporary, env=env, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=True)
            except OSError as exc:
                raise PublicationError("gh could not start") from exc
            output = bytearray()
            total = 0
            deadline = time.monotonic() + self.timeout
            failure = None
            with selectors.DefaultSelector() as selector:
                assert process.stdout is not None and process.stderr is not None
                for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, name)
                while selector.get_map():
                    if time.monotonic() > deadline and failure is None:
                        failure = "gh API request timed out"
                        self._kill(process)
                    for key, _ in selector.select(timeout=.025):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            pipe = process.stdout if key.data == "stdout" else process.stderr
                            pipe.close()
                            continue
                        total += len(chunk)
                        if total > self.max_output_bytes:
                            failure = "gh API response exceeded output limit"
                            self._kill(process)
                        elif key.data == "stdout":
                            output.extend(chunk)
                try:
                    process.wait(timeout=max(.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    failure = "gh API request timed out"
                    self._kill(process)
                    process.wait()
            self._kill(process)
            if failure:
                raise PublicationError(failure)
            if process.returncode != 0:
                # API error bodies and stderr can contain untrusted or sensitive text.
                raise PublicationError(f"gh API request failed with exit code {process.returncode}")
            try:
                return json.loads(output)
            except ValueError as exc:
                raise PublicationError("gh API response was not valid JSON") from exc

    @staticmethod
    def _kill(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
