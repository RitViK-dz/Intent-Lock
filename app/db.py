"""SQLite database storage, atomic single-use nonce engine, and audit log.

Security Principles:
1. Atomic Nonce Consumption: Uses primary-key unique constraint insertion.
   Never performs a vulnerable 'check-then-insert' (TOCTOU race condition).
2. Parameterized SQL: Every query uses positional '?' parameter binding to prevent SQL injection.
3. Currency as Integer: Spending amounts are strictly stored as integer cents.
"""

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Generator

from app.config import settings


def _resolve_db_path(db_path: Path | str | None) -> Path:
    """Resolve database path, falling back to application configuration default."""
    if db_path is not None:
        return Path(db_path)
    return settings.db_path


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Create and configure a SQLite database connection with concurrency settings.

    PROTOTYPE LIMITATION: SQLite operates on a local file. In high-traffic production
    environments, a distributed SQL database (such as PostgreSQL) with row-level locks
    and connection pooling would be used.
    """
    path = _resolve_db_path(db_path)
    # Ensure directory exists before connecting
    path.parent.mkdir(parents=True, exist_ok=True)

    # Security: timeout=30.0 avoids immediate busy errors during concurrent thread access
    conn = sqlite3.connect(str(path), timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Performance & Concurrency: Enable WAL (Write-Ahead Logging) and busy timeout
    # WAL allows simultaneous readers and writers without blocking each other.
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 15000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def db_session(db_path: Path | str | None = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager ensuring connection is always committed and closed cleanly."""
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path | str | None = None) -> None:
    """Initialize SQLite database schema with required security tables if missing."""
    with db_session(db_path) as conn:
        # Table 1: Human-in-the-loop pending and decided intents
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS intents (
                id TEXT PRIMARY KEY,
                agent_id TEXT,
                merchant_id TEXT,
                item TEXT,
                amount_cents INTEGER,
                payee_id TEXT,
                summary TEXT,
                status TEXT CHECK (status IN ('pending', 'approved', 'rejected')),
                created_at INTEGER,
                decided_at INTEGER
            );
            """
        )

        # Table 2: Consumed one-time nonces (enforcing single-use tokens atomically)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT PRIMARY KEY,
                used_at INTEGER,
                merchant_id TEXT
            );
            """
        )

        # Table 3: Append-only audit log for forensic traceability
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER,
                event TEXT,
                actor TEXT,
                intent_id TEXT,
                detail_json TEXT
            );
            """
        )

        # Table 4: Completed store orders (records endpoint and recipient payee for attack demonstration)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY,
                agent_id TEXT,
                merchant_id TEXT,
                item TEXT,
                amount_cents INTEGER,
                payee_id TEXT,
                endpoint TEXT,
                created_at INTEGER
            );
            """
        )


def create_intent(
    intent_id: str,
    agent_id: str,
    merchant_id: str,
    item: str,
    amount_cents: int,
    payee_id: str,
    summary: str,
    db_path: Path | str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Create a new pending human approval intent."""
    if not isinstance(amount_cents, int):
        raise TypeError("amount_cents must be an integer (cents)")

    created_at = int(now if now is not None else time.time())
    status = "pending"
    decided_at = None

    # Security: Use strictly parameterised query to prevent SQL injection
    sql = (
        "INSERT INTO intents ("
        "id, agent_id, merchant_id, item, amount_cents, payee_id, summary, status, created_at, decided_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
    )
    params = (
        intent_id,
        agent_id,
        merchant_id,
        item,
        amount_cents,
        payee_id,
        summary,
        status,
        created_at,
        decided_at,
    )

    with db_session(db_path) as conn:
        conn.execute(sql, params)

    return {
        "id": intent_id,
        "agent_id": agent_id,
        "merchant_id": merchant_id,
        "item": item,
        "amount_cents": amount_cents,
        "payee_id": payee_id,
        "summary": summary,
        "status": status,
        "created_at": created_at,
        "decided_at": decided_at,
    }


def get_intent(intent_id: str, db_path: Path | str | None = None) -> dict[str, Any] | None:
    """Retrieve an intent by ID, or None if not found."""
    # Security: Parameterised query prevents SQL injection on intent_id lookup
    sql = "SELECT id, agent_id, merchant_id, item, amount_cents, payee_id, summary, status, created_at, decided_at FROM intents WHERE id = ?;"
    with db_session(db_path) as conn:
        cursor = conn.execute(sql, (intent_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return dict(row)


def list_intents(
    status: str | None = None,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """List intents ordered by creation time, optionally filtered by status."""
    with db_session(db_path) as conn:
        if status is not None:
            # Security: Parameterised query for status filter
            sql = "SELECT id, agent_id, merchant_id, item, amount_cents, payee_id, summary, status, created_at, decided_at FROM intents WHERE status = ? ORDER BY created_at DESC;"
            cursor = conn.execute(sql, (status,))
        else:
            sql = "SELECT id, agent_id, merchant_id, item, amount_cents, payee_id, summary, status, created_at, decided_at FROM intents ORDER BY created_at DESC;"
            cursor = conn.execute(sql)
        return [dict(row) for row in cursor.fetchall()]


def set_intent_status(
    intent_id: str,
    status: str,
    db_path: Path | str | None = None,
    decided_at: int | None = None,
) -> bool:
    """Update intent status (e.g. approve or reject) and record the decision timestamp."""
    decided_ts = int(decided_at if decided_at is not None else time.time())

    # Security: Parameterised query prevents injection during intent state updates
    sql = "UPDATE intents SET status = ?, decided_at = ? WHERE id = ?;"
    params = (status, decided_ts, intent_id)

    with db_session(db_path) as conn:
        cursor = conn.execute(sql, params)
        return cursor.rowcount > 0


def consume_nonce(
    nonce: str,
    merchant_id: str,
    db_path: Path | str | None = None,
    now: int | None = None,
) -> bool:
    """Atomically consume a token nonce.

    CRITICAL SECURITY INVARIANT:
    This function MUST be atomic to prevent token replay attacks and race conditions.
    We execute an immediate INSERT into `used_nonces`. Because `nonce` is the PRIMARY KEY,
    the database engine enforces uniqueness at the storage engine level.
    - If the insertion succeeds, this is the first use of the token -> return True.
    - If the insertion fails with IntegrityError, the nonce was already used -> return False.
    NEVER replace this with a 'SELECT ... check, then INSERT' pattern!
    """
    used_at = int(now if now is not None else time.time())
    sql = "INSERT INTO used_nonces (nonce, used_at, merchant_id) VALUES (?, ?, ?);"
    params = (nonce, used_at, merchant_id)

    # Open dedicated connection for this transaction
    conn = get_connection(db_path)
    try:
        conn.execute(sql, params)
        conn.commit()
        # Nonce was successfully consumed for the first and only time
        return True
    except sqlite3.IntegrityError:
        # Nonce was already consumed (Primary Key violation detected)
        return False
    finally:
        conn.close()


def log_event(
    event: str,
    actor: str,
    intent_id: str | None,
    detail: dict[str, Any],
    db_path: Path | str | None = None,
    now: int | None = None,
) -> int:
    """Append an immutable event to the audit log."""
    ts = int(now if now is not None else time.time())
    detail_json = json.dumps(detail)

    # Security: Parameterised insert into append-only audit trail
    sql = "INSERT INTO audit_log (ts, event, actor, intent_id, detail_json) VALUES (?, ?, ?, ?, ?);"
    params = (ts, event, actor, intent_id, detail_json)

    with db_session(db_path) as conn:
        cursor = conn.execute(sql, params)
        return int(cursor.lastrowid)


def list_audit(
    limit: int = 50,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve audit log entries in reverse-chronological order (newest first)."""
    # Security: Parameterised query enforcing maximum row limit
    sql = "SELECT id, ts, event, actor, intent_id, detail_json FROM audit_log ORDER BY id DESC LIMIT ?;"

    with db_session(db_path) as conn:
        cursor = conn.execute(sql, (int(limit),))
        entries = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            try:
                row_dict["detail"] = json.loads(row_dict.pop("detail_json"))
            except (json.JSONDecodeError, TypeError):
                row_dict["detail"] = {}
            entries.append(row_dict)
        return entries


def create_order(
    order_id: str,
    agent_id: str,
    merchant_id: str,
    item: str,
    amount_cents: int,
    payee_id: str,
    endpoint: str,
    db_path: Path | str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Record a completed store order.

    Stores the processing endpoint ('protected' vs 'unprotected') and destination payee
    to visually demonstrate diverted funds during attack scenarios.
    """
    if not isinstance(amount_cents, int):
        raise TypeError("amount_cents must be an integer (cents)")

    created_at = int(now if now is not None else time.time())

    # Security: Parameterised insert prevents SQL injection on order records
    sql = (
        "INSERT INTO orders ("
        "id, agent_id, merchant_id, item, amount_cents, payee_id, endpoint, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?);"
    )
    params = (
        order_id,
        agent_id,
        merchant_id,
        item,
        amount_cents,
        payee_id,
        endpoint,
        created_at,
    )

    with db_session(db_path) as conn:
        conn.execute(sql, params)

    return {
        "id": order_id,
        "agent_id": agent_id,
        "merchant_id": merchant_id,
        "item": item,
        "amount_cents": amount_cents,
        "payee_id": payee_id,
        "endpoint": endpoint,
        "created_at": created_at,
    }


def list_orders(
    limit: int = 50,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """List completed orders ordered newest first."""
    # Security: Parameterised query enforcing maximum limit
    sql = "SELECT id, agent_id, merchant_id, item, amount_cents, payee_id, endpoint, created_at FROM orders ORDER BY created_at DESC, id DESC LIMIT ?;"

    with db_session(db_path) as conn:
        cursor = conn.execute(sql, (int(limit),))
        return [dict(row) for row in cursor.fetchall()]


def reset_demo_data(db_path: Path | str | None = None) -> None:
    """Clear orders, intents, nonces, and audit entries for demo reset.

    PROTOTYPE LIMITATION: In production environments, tables are never wiped via an API.
    This reset utility is strictly for simulated demonstrations and is only accessible
    when the DEMO_MODE setting is explicitly set to true.
    """
    with db_session(db_path) as conn:
        conn.execute("DELETE FROM orders;")
        conn.execute("DELETE FROM intents;")
        conn.execute("DELETE FROM used_nonces;")
        conn.execute("DELETE FROM audit_log;")

