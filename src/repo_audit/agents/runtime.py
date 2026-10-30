"""Bound local subprocess output, elapsed time, and OS per-user process quota."""
from __future__ import annotations

import os
import resource
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ProcessResult:
    status: str
    returncode: int | None
    stdout: bytes
    stderr: bytes


def run_bounded(argv: list[str], *, cwd: Path, env: dict[str, str], timeout_seconds: float,
                max_output_bytes: int, max_processes: int,
                stdin: bytes = b'') -> ProcessResult:
    if timeout_seconds <= 0 or max_output_bytes < 1 or max_processes < 1:
        raise ValueError('Subprocess budgets must be positive')
    if os.name != 'posix' or not hasattr(resource, 'RLIMIT_NPROC') or os.geteuid() == 0:
        return ProcessResult('unsupported', None, b'', b'Hard process quota needs non-root POSIX user')

    try:
        with __import__('tempfile').TemporaryFile() as input_file:
            input_file.write(stdin)
            input_file.seek(0)
            process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('limits.py')),
                                        str(max_processes), str(max_output_bytes), *argv], cwd=cwd, env=env, stdin=input_file,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return ProcessResult('unavailable', None, b'', str(exc).encode()[:max_output_bytes])
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic() + timeout_seconds
    status = 'complete'
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                status = 'timeout'
                break
            for key, _ in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, min(65536, max_output_bytes + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                remaining = max_output_bytes - sum(len(v) for v in output.values())
                output[key.data].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    status = 'output_limit'
                    break
            if status != 'complete':
                break
    finally:
        # Also terminate descendants that retained pipes after the primary process exited.
        try:
            if status != 'complete' or process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            if process.poll() is None:
                process.kill()
                status = 'unsupported'
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if status == 'complete' and process.returncode != 0:
        status = 'failed'
    return ProcessResult(status, process.returncode, bytes(output['stdout']), bytes(output['stderr']))
