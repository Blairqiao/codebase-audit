"""Filtered committed snapshots without checkout mutation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import Profile


class SnapshotError(ValueError):
    """The commit snapshot cannot be prepared safely."""


@dataclass
class InventoryFile:
    path: str
    sha256: str
    size_bytes: int
    line_count: int
    origin: str = "committed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Snapshot:
    repo_id: str
    commit: str
    root: Path
    files: list[InventoryFile]
    excluded: list[dict[str, str]]
    dirty: bool

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["root"] = str(self.root)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any], root: Path | None = None) -> Snapshot:
        return cls(
            repo_id=data["repo_id"],
            commit=data["commit"],
            root=root if root is not None else Path(data["root"]),
            files=[InventoryFile(**f) for f in data["files"]],
            excluded=data["excluded"],
            dirty=data["dirty"],
        )


import fnmatch
import hashlib
import os
import re
import subprocess
from pathlib import PurePosixPath

EXCLUDED_PARTS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "coverage",
    ".next",
    ".cache",
    ".pytest_cache",
    "target",
}
SECRET_NAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "secrets.json",
    "secrets.toml",
    "secrets.yaml",
    "secrets.yml",
    "id_rsa",
    "id_ed25519",
    ".git-credentials",
}


def _git(root: Path, *args: str) -> bytes:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, check=True, env=env, timeout=60
        )
        return result.stdout
    except (subprocess.SubprocessError, OSError) as exc:
        raise SnapshotError("Git snapshot prerequisite failed") from exc


def _path_reason(path: str, profile: Profile) -> str | None:
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts or "\\" in path or any(ord(c) < 32 for c in path):
        return "unsafe_path"
    if any(part in EXCLUDED_PARTS for part in p.parts):
        return "dependency_or_build_or_metadata"
    name = p.name.lower()
    if (
        name in SECRET_NAMES
        or name.startswith(".env.")
        or p.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".jks"}
        or name.endswith((".secrets", ".secret"))
    ):
        return "credential_path"
    if any(
        fnmatch.fnmatchcase(path, pattern) or p.match(pattern) for pattern in profile.exclusions
    ):
        return "configured_exclusion"
    return None


def _content_reason(data: bytes) -> str | None:
    if len(data) > 2_000_000:
        return "oversize"
    if b"\x00" in data:
        return "binary"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "non_utf8"
    if re.search(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}",
        text,
    ):
        return "credential_content"
    if re.search(
        r"@generated|Code generated .*DO NOT EDIT|automatically generated",
        text[:4096],
        re.IGNORECASE,
    ):
        return "generated"
    return None


def create_snapshot(profile: Profile, destination: Path, commit: str = "HEAD") -> Snapshot:
    """Copy eligible Git blobs plus explicitly named ignored decision documents."""
    root = profile.root.resolve()
    destination = Path(destination)
    if destination.is_symlink() or any(p.is_symlink() for p in destination.parents):
        raise SnapshotError("Snapshot destination may not traverse symlinks")
    destination = destination.resolve()
    if destination == root or root in destination.parents:
        raise SnapshotError("Snapshot destination must be outside audited checkout")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise SnapshotError("Snapshot destination must be new or empty")
    sha = _git(root, "rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", sha):
        raise SnapshotError("Invalid commit identity")
    if Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() != root:
        raise SnapshotError("Profile root must be repository top level")
    dirty = bool(_git(root, "status", "--porcelain", "--untracked-files=normal"))
    entries = _git(root, "ls-tree", "-rz", "--full-tree", sha).split(b"\x00")
    files: list[InventoryFile] = []
    excluded: list[dict[str, str]] = []
    payloads: dict[str, tuple[bytes, str]] = {}
    tracked: set[str] = set()
    for entry in entries:
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        path = raw_path.decode("utf-8", errors="surrogateescape")
        mode, kind, oid = metadata.decode().split()
        tracked.add(path)
        reason = _path_reason(path, profile)
        if any(0xD800 <= ord(c) <= 0xDFFF for c in path):
            reason = "non_utf8_path"
        if mode == "120000":
            reason = "symlink"
        elif mode == "160000" or kind != "blob":
            reason = "submodule"
        elif any(
            (root / parent / ".git").exists()
            for parent in PurePosixPath(path).parents
            if str(parent) != "."
        ):
            reason = "nested_repository"
        if reason:
            excluded.append({"path": path, "reason": reason})
            continue
        size = int(_git(root, "cat-file", "-s", oid))
        if size > 2_000_000:
            excluded.append({"path": path, "reason": "oversize"})
            continue
        data = _git(root, "cat-file", "blob", oid)
        if reason := _content_reason(data):
            excluded.append({"path": path, "reason": reason})
            continue
        payloads[path] = (data, "committed")
    for path in profile.decision_documents:
        if path in tracked:
            continue
        doc = root / path
        if doc.is_symlink() or any(
            parent.is_symlink()
            for parent in doc.parents
            if parent != root and root in parent.parents
        ):
            raise SnapshotError(f"Decision document may not traverse symlinks: {path}")
        if not doc.resolve().is_relative_to(root) or not doc.is_file():
            raise SnapshotError(f"Decision document must be an existing in-root file: {path}")
        try:
            _git(root, "check-ignore", "-q", "--", path)
        except SnapshotError as exc:
            raise SnapshotError(
                f"Uncommitted decision document must be explicitly Git ignored: {path}"
            ) from exc
        reason = _path_reason(path, profile)
        if any(
            (root / parent / ".git").exists()
            for parent in PurePosixPath(path).parents
            if str(parent) != "."
        ):
            reason = "nested_repository"
        if doc.stat().st_size > 2_000_000:
            reason = "oversize"
        if reason:
            excluded.append({"path": path, "reason": reason})
            continue
        data = doc.read_bytes()
        if reason := _content_reason(data):
            excluded.append({"path": path, "reason": reason})
            continue
        payloads[path] = (data, "decision_document")
    destination.mkdir(parents=True, exist_ok=True)
    for path, (data, origin) in sorted(payloads.items()):
        output = destination / path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        files.append(
            InventoryFile(
                path,
                hashlib.sha256(data).hexdigest(),
                len(data),
                len(data.decode("utf-8").splitlines()),
                origin,
            )
        )
    return Snapshot(
        profile.repo_id, sha, destination, files, sorted(excluded, key=lambda x: x["path"]), dirty
    )
