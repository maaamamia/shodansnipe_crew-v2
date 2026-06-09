"""
db.py — SQLCipher-backed storage for ShodanSnipe.

One encrypted SQLite file holds everything: API key, saved queries, searches,
results, snapshots, and audit events. The passphrase is prompted once at
server startup (or read from SHODANSNIPE_PASSPHRASE) and held in memory.

Threading: SQLite/SQLCipher connections are pinned to their creating thread
by default. FastAPI dispatches sync routes across a thread pool, so we open
the connection with check_same_thread=False and serialize all access with a
module-level lock. Correct, simple, and the lock is not a bottleneck since
Shodan rate limits dominate latency.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Iterable

try:
    from sqlcipher3 import dbapi2 as sqlcipher  # provided by sqlcipher3-wheels
except ImportError as e:
    raise ImportError(
        "sqlcipher3 module not found. Install with: pip install sqlcipher3-wheels"
    ) from e

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("SHODANSNIPE_DB", "shodansnipe.db")

_conn: sqlcipher.Connection | None = None
_lock = threading.RLock()


SCHEMA = """
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_queries (
    id         TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    query      TEXT NOT NULL,
    watched    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS searches (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    query      TEXT NOT NULL,
    scope_name TEXT NOT NULL,
    run_at     TEXT NOT NULL,
    result_count INTEGER NOT NULL,
    override   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id) ON DELETE CASCADE,
    ip_str      TEXT NOT NULL,
    payload     TEXT NOT NULL  -- serialized result JSON
);
CREATE INDEX IF NOT EXISTS idx_results_search_id ON results(search_id);
CREATE INDEX IF NOT EXISTS idx_results_ip ON results(ip_str);

CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    query       TEXT NOT NULL,
    scope_name  TEXT NOT NULL,
    taken_at    TEXT NOT NULL,
    payload     TEXT NOT NULL  -- serialized list-of-results JSON
);
CREATE INDEX IF NOT EXISTS idx_snapshots_query_scope ON snapshots(query, scope_name);

CREATE TABLE IF NOT EXISTS audit_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    event      TEXT NOT NULL,
    payload    TEXT NOT NULL  -- JSON blob of the rest of the event
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);

CREATE TABLE IF NOT EXISTS ai_messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    role        TEXT NOT NULL,  -- 'user' | 'assistant' | 'system'
    content     TEXT NOT NULL,
    search_id   INTEGER,        -- link to searches.id if message references results
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_messages_session ON ai_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_ai_messages_ts ON ai_messages(created_at);
"""


def init(passphrase: str) -> None:
    """Open (or create) the encrypted database. Idempotent."""
    global _conn
    with _lock:
        if _conn is not None:
            return
        if not passphrase:
            raise ValueError("Database passphrase is required.")

        # check_same_thread=False is safe because every access goes through _lock
        conn = sqlcipher.connect(DB_PATH, check_same_thread=False)
        # Escape any single quotes in the passphrase
        safe = passphrase.replace("'", "''")
        conn.execute(f"PRAGMA key = '{safe}'")
        # Sanity check: a wrong key fails here, not later
        try:
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except sqlcipher.DatabaseError as e:
            conn.close()
            raise ValueError("Wrong passphrase, or the database file is not a SQLCipher DB.") from e

        conn.executescript(SCHEMA)
        conn.commit()
        _conn = conn
        logger.info("Database opened at %s", DB_PATH)


def close() -> None:
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
            _conn = None


def _c() -> sqlcipher.Connection:
    if _conn is None:
        raise RuntimeError("Database not initialized. Call db.init(passphrase) first.")
    return _conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _locked(fn):
    """Serialize all DB access through the module lock. Decorator."""
    def wrapper(*args, **kwargs):
        with _lock:
            return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


# ---------------------------------------------------------------------------
# Config (key/value store inside the DB - holds the API key)
# ---------------------------------------------------------------------------
@_locked
def get_config(key: str) -> str | None:
    row = _c().execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


@_locked
def set_config(key: str, value: str) -> None:
    _c().execute(
        "INSERT INTO config(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    _c().commit()


@_locked
def delete_config(key: str) -> None:
    _c().execute("DELETE FROM config WHERE key = ?", (key,))
    _c().commit()


# ---------------------------------------------------------------------------
# Saved queries
# ---------------------------------------------------------------------------
@_locked
def saved_list() -> list[dict]:
    rows = _c().execute(
        "SELECT id, label, query, watched, created_at FROM saved_queries ORDER BY created_at DESC"
    ).fetchall()
    return [
        {"id": r[0], "label": r[1], "query": r[2], "watched": bool(r[3]), "created": r[4]}
        for r in rows
    ]


@_locked
def saved_add(item_id: str, label: str, query: str, watched: bool) -> dict:
    entry = {
        "id": item_id, "label": label, "query": query, "watched": watched, "created": _now(),
    }
    _c().execute(
        "INSERT INTO saved_queries(id, label, query, watched, created_at) VALUES(?, ?, ?, ?, ?)",
        (entry["id"], entry["label"], entry["query"], int(entry["watched"]), entry["created"]),
    )
    _c().commit()
    return entry


@_locked
def saved_delete(item_id: str) -> int:
    cur = _c().execute("DELETE FROM saved_queries WHERE id = ?", (item_id,))
    _c().commit()
    return cur.rowcount


# ---------------------------------------------------------------------------
# Searches & results (persistent history)
# ---------------------------------------------------------------------------
@_locked
def search_record(query: str, scope_name: str, results: list[dict], override: bool) -> int:
    """Store a search + its serialized results. Returns the search id."""
    c = _c()
    cur = c.execute(
        "INSERT INTO searches(query, scope_name, run_at, result_count, override) VALUES(?, ?, ?, ?, ?)",
        (query, scope_name, _now(), len(results), int(override)),
    )
    search_id = cur.lastrowid
    c.executemany(
        "INSERT INTO results(search_id, ip_str, payload) VALUES(?, ?, ?)",
        [(search_id, r.get("ip_str", ""), json.dumps(r, default=str)) for r in results],
    )
    c.commit()
    return search_id


@_locked
def search_history(limit: int = 50) -> list[dict]:
    rows = _c().execute(
        "SELECT id, query, scope_name, run_at, result_count, override "
        "FROM searches ORDER BY run_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [
        {"id": r[0], "query": r[1], "scope_name": r[2], "run_at": r[3],
         "result_count": r[4], "override": bool(r[5])}
        for r in rows
    ]


@_locked
def search_load(search_id: int) -> dict | None:
    head = _c().execute(
        "SELECT id, query, scope_name, run_at, result_count, override FROM searches WHERE id = ?",
        (search_id,)
    ).fetchone()
    if not head:
        return None
    rows = _c().execute(
        "SELECT payload FROM results WHERE search_id = ?", (search_id,)
    ).fetchall()
    return {
        "id": head[0], "query": head[1], "scope_name": head[2], "run_at": head[3],
        "result_count": head[4], "override": bool(head[5]),
        "results": [json.loads(r[0]) for r in rows],
    }


@_locked
def search_delete(search_id: int) -> int:
    cur = _c().execute("DELETE FROM searches WHERE id = ?", (search_id,))
    _c().commit()
    return cur.rowcount


# ---------------------------------------------------------------------------
# Snapshots (for diff mode)
# ---------------------------------------------------------------------------
@_locked
def snapshot_save(query: str, scope_name: str, results: list[dict]) -> int:
    cur = _c().execute(
        "INSERT INTO snapshots(query, scope_name, taken_at, payload) VALUES(?, ?, ?, ?)",
        (query, scope_name, _now(), json.dumps(results, default=str)),
    )
    _c().commit()
    return cur.lastrowid


@_locked
def snapshot_latest(query: str, scope_name: str) -> dict | None:
    row = _c().execute(
        "SELECT taken_at, payload FROM snapshots "
        "WHERE query = ? AND scope_name = ? ORDER BY taken_at DESC LIMIT 1",
        (query, scope_name),
    ).fetchone()
    if not row:
        return None
    return {"taken_at": row[0], "results": json.loads(row[1])}


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
@_locked
def audit_write(event: str, payload: dict[str, Any]) -> None:
    try:
        _c().execute(
            "INSERT INTO audit_events(ts, event, payload) VALUES(?, ?, ?)",
            (_now(), event, json.dumps(payload, default=str)),
        )
        _c().commit()
    except Exception as e:
        logger.error("audit_write failed: %s", e)


@_locked
def audit_tail(limit: int = 100) -> list[dict]:
    rows = _c().execute(
        "SELECT ts, event, payload FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    out = []
    for ts, event, payload in rows:
        try:
            d = json.loads(payload)
        except Exception:
            d = {}
        d["timestamp"] = ts
        d["event"] = event
        out.append(d)
    return out

# ---------------------------------------------------------------------------
# AI conversation history
# ---------------------------------------------------------------------------
@_locked
def ai_message_add(session_id: str, role: str, content: str, search_id: int | None = None) -> int:
    cur = _c().execute(
        "INSERT INTO ai_messages(session_id, role, content, search_id, created_at) VALUES(?,?,?,?,?)",
        (session_id, role, content, search_id, _now())
    )
    _c().commit()
    return cur.lastrowid


@_locked
def ai_session_history(session_id: str, limit: int = 100) -> list[dict]:
    rows = _c().execute(
        "SELECT id, role, content, search_id, created_at FROM ai_messages "
        "WHERE session_id=? ORDER BY id ASC LIMIT ?",
        (session_id, limit)
    ).fetchall()
    return [{"id": r[0], "role": r[1], "content": r[2], "search_id": r[3], "created_at": r[4]} for r in rows]


@_locked
def ai_latest_session() -> str | None:
    """Return the most recently active session_id."""
    row = _c().execute(
        "SELECT session_id FROM ai_messages ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else None


@_locked
def ai_all_sessions(limit: int = 20) -> list[dict]:
    rows = _c().execute(
        "SELECT session_id, MIN(created_at) as started, MAX(created_at) as updated, COUNT(*) as msgs "
        "FROM ai_messages GROUP BY session_id ORDER BY updated DESC LIMIT ?",
        (limit,)
    ).fetchall()
    return [{"session_id": r[0], "started": r[1], "updated": r[2], "message_count": r[3]} for r in rows]
