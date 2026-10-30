"""Transactional per-repository observation and triage storage."""

from __future__ import annotations

import copy
import fcntl
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from .validation import fingerprint

STATES = {"open", "dismissed", "accepted-risk", "resolved", "needs-revalidation"}
DB_SCHEMA_VERSION = 1


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _date(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include timezone")
    return parsed


def _key(item: dict[str, Any], path: str | None = None) -> str:
    primary = item["primary_location"]
    return fingerprint(
        item["repo_id"],
        item["rule_id"],
        item["problem_key"],
        path or primary["path"],
        primary.get("symbol", ""),
    )


class Backlog:
    """One repository per database. A nonblocking local lock protects each session."""

    def __init__(self, path: Path, repo_id: str):
        self.path = Path(path)
        self.repo_id = repo_id
        self.connection: sqlite3.Connection | None = None
        self._lock: int | None = None
        self.shared_history_complete = True

    def __enter__(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        if self.path.is_symlink() or lock_path.is_symlink():
            raise ValueError("Backlog and lock must not be symlinks")
        self._lock = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("Repository audit cache is locked by another run") from exc
            self.connection = sqlite3.connect(self.path)
            self.connection.row_factory = sqlite3.Row
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, DB_SCHEMA_VERSION}:
                raise ValueError(
                    "Unsupported backlog schema version; backup and reviewed migration required"
                )
            tables = {
                r[0]
                for r in self.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if version == 0 and tables:
                raise ValueError("Unversioned nonempty database is not an audit cache")
            with self.connection:
                self.connection.execute(
                    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                existing = self.connection.execute(
                    "SELECT value FROM meta WHERE key='repo_id'"
                ).fetchone()
                if existing and existing[0] != self.repo_id:
                    raise ValueError("Repository ID does not match cache owner")
                self.connection.execute(
                    "INSERT OR IGNORE INTO meta VALUES ('repo_id', ?)", (self.repo_id,)
                )
                self.connection.execute(
                    "CREATE TABLE IF NOT EXISTS items (id TEXT PRIMARY KEY, data TEXT NOT NULL)"
                )
                self.connection.execute(
                    "CREATE TABLE IF NOT EXISTS aliases (fingerprint TEXT PRIMARY KEY, item_id TEXT NOT NULL)"
                )
                self.connection.execute(
                    "CREATE TABLE IF NOT EXISTS observations (item_id TEXT NOT NULL, snapshot TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(item_id, snapshot))"
                )
                self.connection.execute(
                    "CREATE TABLE IF NOT EXISTS shared_decisions (item_id TEXT PRIMARY KEY, data TEXT NOT NULL)"
                )
                self.connection.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args: object) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self._lock is not None:
            os.close(self._lock)
            self._lock = None

    def _db(self) -> sqlite3.Connection:
        if self.connection is None:
            raise RuntimeError("Open Backlog with a context manager")
        return self.connection

    def items(self) -> list[dict[str, Any]]:
        return [
            json.loads(row[0]) for row in self._db().execute("SELECT data FROM items ORDER BY id")
        ]

    def _save(self, item: dict[str, Any]) -> None:
        self._db().execute(
            "INSERT INTO items(id,data) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
            (item["id"], json.dumps(item, sort_keys=True)),
        )

    def apply_shared_decisions(self, items: list[dict[str, Any]], *, complete: bool) -> None:
        """Import only a complete publisher inventory, retaining closure and human triage."""
        self.shared_history_complete = complete
        if not complete:
            return
        db = self._db()
        with db:
            current = {item["id"]: item for item in self.items()}
            for decision in items:
                if (
                    decision.get("repo_id", self.repo_id) != self.repo_id
                    or decision.get("state") not in STATES
                    or not isinstance(decision.get("id"), str)
                ):
                    raise ValueError("Invalid shared decision identity/state")
                payload = {
                    k: copy.deepcopy(decision[k])
                    for k in [
                        "id",
                        "state",
                        "triage_history",
                        "github_issue",
                        "first_observed",
                        "last_observed",
                    ]
                    if k in decision
                }
                if payload["state"] == "open" and not payload.get("triage_history"):
                    continue
                if not payload.get("triage_history"):
                    payload["triage_history"] = [
                        {
                            "state": payload["state"],
                            "reason": "Shared GitHub issue decision",
                            "at": _now(),
                        }
                    ]
                for observed in ["first_observed", "last_observed"]:
                    if observed in payload:
                        _date(payload[observed])
                previous = current.get(payload["id"])
                if previous:
                    events = {
                        json.dumps(event, sort_keys=True): event
                        for event in previous.get("triage_history", []) + payload["triage_history"]
                    }
                    payload["triage_history"] = sorted(
                        events.values(), key=lambda event: _date(event["at"])
                    )
                    if payload["triage_history"]:
                        payload["state"] = payload["triage_history"][-1]["state"]
                db.execute(
                    "INSERT INTO shared_decisions VALUES (?,?) ON CONFLICT(item_id) DO UPDATE SET data=excluded.data",
                    (payload["id"], json.dumps(payload)),
                )
                if payload["id"] in current:
                    item = current[payload["id"]]
                    first_observed = min(
                        [
                            item["first_observed"],
                            payload.get("first_observed", item["first_observed"]),
                        ],
                        key=_date,
                    )
                    last_observed = max(
                        [
                            item["last_observed"],
                            payload.get("last_observed", item["last_observed"]),
                        ],
                        key=_date,
                    )
                    item.update(
                        {
                            k: v
                            for k, v in payload.items()
                            if k not in {"id", "first_observed", "last_observed"}
                        }
                    )
                    item.update(first_observed=first_observed, last_observed=last_observed)
                    item["observation_status"] = (
                        payload["state"] if payload["state"] != "open" else "recurring"
                    )
                    self._save(item)

    def reconcile(
        self,
        items: list[dict[str, Any]],
        *,
        outcome: str,
        snapshot: str,
        history_complete: bool = True,
        renames: dict[str, str] | None = None,
        now: str | None = None,
    ) -> list[dict[str, Any]]:
        if outcome not in {"complete", "partial", "failed"}:
            raise ValueError("Invalid run outcome")
        now = now or _now()
        _date(now)
        renames = renames or {}
        history_complete = history_complete and self.shared_history_complete
        db = self._db()
        with db:
            existing = {item["id"]: item for item in self.items()}
            seen: set[str] = set()
            for original in items:
                item = copy.deepcopy(original)
                if item["repo_id"] != self.repo_id:
                    raise ValueError("Observation repository differs from cache")
                key = _key(item)
                alias = db.execute(
                    "SELECT item_id FROM aliases WHERE fingerprint=?", (key,)
                ).fetchone()
                item_id = alias[0] if alias else key
                if item_id not in existing:
                    matches = []
                    for historical in existing.values():
                        old_path = historical["primary_location"]["path"]
                        if (
                            renames.get(old_path) == item["primary_location"]["path"]
                            and _key(historical, item["primary_location"]["path"]) == key
                        ):
                            matches.append(historical["id"])
                    if len(matches) == 1:
                        item_id = matches[0]
                    elif len(matches) > 1:
                        item["identity_match"] = {
                            "status": "ambiguous",
                            "candidates": sorted(matches),
                        }
                item["id"] = item_id
                item["snapshot"] = snapshot
                old = existing.get(item_id)
                item["first_observed"] = old["first_observed"] if old else now
                item["last_observed"] = now
                item["state"] = old["state"] if old else "open"
                item["triage_history"] = copy.deepcopy(old.get("triage_history", [])) if old else []
                if old and "github_issue" in old:
                    item["github_issue"] = old["github_issue"]
                shared = db.execute(
                    "SELECT data FROM shared_decisions WHERE item_id=?", (item_id,)
                ).fetchone()
                if shared:
                    decision = json.loads(shared[0])
                    item["first_observed"] = min(
                        [
                            item["first_observed"],
                            decision.get("first_observed", item["first_observed"]),
                        ],
                        key=_date,
                    )
                    item.update(
                        {
                            k: v
                            for k, v in decision.items()
                            if k not in {"id", "first_observed", "last_observed"}
                        }
                    )
                item["observation_status"] = (
                    item["state"] if item["state"] != "open" else "recurring" if old else "new"
                )
                self._save(item)
                db.execute(
                    "INSERT INTO aliases VALUES (?,?) ON CONFLICT(fingerprint) DO UPDATE SET item_id=excluded.item_id",
                    (key, item_id),
                )
                db.execute(
                    "INSERT INTO observations VALUES (?,?,?,?) ON CONFLICT(item_id,snapshot) DO UPDATE SET observed_at=excluded.observed_at,data=excluded.data",
                    (item_id, snapshot, now, json.dumps(item, sort_keys=True)),
                )
                seen.add(item_id)
            if outcome == "complete" and history_complete:
                for item in self.items():
                    if item["id"] not in seen and item["state"] == "open":
                        item.update(
                            state="needs-revalidation", observation_status="needs-revalidation"
                        )
                        self._save(item)
                    history = item.get("triage_history", [])
                    if (
                        history
                        and history[-1].get("expires_at")
                        and _date(history[-1]["expires_at"]) <= _date(now)
                        and item["state"] in {"dismissed", "accepted-risk"}
                    ):
                        item.update(
                            state="needs-revalidation", observation_status="needs-revalidation"
                        )
                        self._save(item)
        return self.items()

    def triage(
        self,
        item_id: str,
        state: str,
        reason: str,
        *,
        expires_at: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        if state not in STATES or not reason.strip():
            raise ValueError("Triage requires a supported state and nonempty reason")
        now = now or _now()
        _date(now)
        if expires_at is not None and _date(expires_at) <= _date(now):
            raise ValueError("Triage expiry must be later than decision time")
        db = self._db()
        row = db.execute("SELECT data FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown backlog item")
        item: dict[str, Any] = json.loads(row[0])
        event: dict[str, Any] = {"state": state, "reason": reason, "at": now}
        if expires_at is not None:
            event["expires_at"] = expires_at
        item["triage_history"].append(event)
        item.update(state=state, observation_status=state if state != "open" else "recurring")
        with db:
            self._save(item)
            db.execute("DELETE FROM shared_decisions WHERE item_id=?", (item_id,))
        return item
