"""Deterministic bounded review assignments. An assignment is not assessment."""
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath

from repo_audit.snapshot import Snapshot


@dataclass(frozen=True)
class Scope:
    scope_id: str
    paths: tuple[str, ...]
    categories: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"scope_id": self.scope_id, "paths": list(self.paths),
                "categories": list(self.categories), "reason": self.reason}


def plan_scopes(snapshot: Snapshot, *, component_roots: Iterable[str] = (),
                risk_paths: Iterable[str] = (), max_files_per_scope: int = 12,
                rotation: int = 0) -> list[Scope]:
    if max_files_per_scope < 1 or rotation < 0:
        raise ValueError("Scope size must be positive and rotation nonnegative")
    roots = sorted(set(component_roots), key=lambda p: (-len(p), p))
    risks = set(risk_paths)
    groups: dict[str, list[str]] = {}
    for item in sorted(snapshot.files, key=lambda f: f.path):
        component = next((p for p in roots if item.path == p or item.path.startswith(p + '/')),
                         str(PurePosixPath(item.path).parent))
        groups.setdefault(component, []).append(item.path)
    categories = ('correctness', 'security', 'concurrency', 'maintenance', 'architecture')
    priority: list[Scope] = []
    rotating: list[Scope] = []
    for paths in groups.values():
        for start in range(0, len(paths), max_files_per_scope):
            chunk = tuple(paths[start:start + max_files_per_scope])
            scope_id = sha256((snapshot.repo_id + '\0' + '\0'.join(chunk)).encode()).hexdigest()[:16]
            risky = any(p in risks for p in chunk)
            scope = Scope(scope_id, chunk, categories,
                          'risk signal' if risky else 'rotating warning-independent review')
            (priority if risky else rotating).append(scope)
    if rotating:
        offset = rotation % len(rotating)
        rotating = rotating[offset:] + rotating[:offset]
    # Reserve opportunities for warning-independent work even with many risk scopes.
    result: list[Scope] = []
    for i in range(max(len(priority), len(rotating))):
        if i < len(priority):
            result.append(priority[i])
        if i < len(rotating):
            result.append(rotating[i])
    return result
