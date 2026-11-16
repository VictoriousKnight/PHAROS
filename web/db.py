"""
PHAROS Web - Database Management
--------------------------------
Supports dual modes:
1. Turso (libSQL over HTTP) for Serverless/Edge deployments like Vercel:
   Activated when TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are set.
2. Local SQLite with WAL mode for local development:
   Default fallback when Turso env vars are not set.

Tables:
- users: user accounts, bcrypt password hashes, roles.
- scan_records: audit log of scans, threat scores, verdicts, and JSON results.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import bcrypt
import requests

logger = logging.getLogger("web.db")

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Turso environment settings
TURSO_DATABASE_URL = os.environ.get("TURSO_DATABASE_URL", "").strip()
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN", "").strip()

# Local SQLite fallback settings
DB_DIR = Path(os.environ.get("PHAROS_DB_DIR", PROJECT_ROOT / "user_database"))
DB_PATH = DB_DIR / "pharos_users.db"


_turso_circuit_broken = False


def is_turso_enabled() -> bool:
    """Return True if Turso credentials are provided and the circuit is not broken."""
    global _turso_circuit_broken
    if _turso_circuit_broken:
        return False
    return bool(TURSO_DATABASE_URL and TURSO_AUTH_TOKEN)



# ---------------------------------------------------------------------------
# Turso HTTP API Client
# ---------------------------------------------------------------------------
def _turso_http_url() -> str:
    """Normalize libsql:// URL to https:// pipeline URL."""
    url = TURSO_DATABASE_URL
    if url.startswith("libsql://"):
        url = "https://" + url[len("libsql://") :]
    if not url.endswith("/v2/pipeline"):
        url = url.rstrip("/") + "/v2/pipeline"
    return url


def _turso_execute(sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
    """Execute SQL query against Turso via its HTTP v2 pipeline endpoint."""
    endpoint = _turso_http_url()
    headers = {
        "Authorization": f"Bearer {TURSO_AUTH_TOKEN}",
        "Content-Type": "application/json",
    }

    # Format parameter objects for Turso v2 protocol
    named_args: list[dict[str, Any]] = []
    pos_args: list[dict[str, Any]] = []
    for p in params:
        if p is None:
            pos_args.append({"type": "null"})
        elif isinstance(p, int):
            pos_args.append({"type": "integer", "value": str(p)})
        elif isinstance(p, float):
            pos_args.append({"type": "float", "value": p})
        else:
            pos_args.append({"type": "text", "value": str(p)})

    payload = {
        "requests": [
            {
                "type": "execute",
                "stmt": {
                    "sql": sql,
                    "args": pos_args,
                },
            },
            {"type": "close"},
        ]
    }

    resp = requests.post(endpoint, headers=headers, json=payload, timeout=15)
    resp.raise_for_status()
    data = resp.json()

    results = data.get("results", [])
    if not results:
        return []

    first_res = results[0]
    if first_res.get("type") == "error":
        err_msg = first_res.get("error", {}).get("message", "Turso query error")
        raise sqlite3.IntegrityError(err_msg)

    response_data = first_res.get("response", {})
    cols = [c["name"] for c in response_data.get("result", {}).get("cols", [])]
    rows = response_data.get("result", {}).get("rows", [])

    output = []
    for row in rows:
        row_dict = {}
        for col_name, val_obj in zip(cols, row):
            row_dict[col_name] = val_obj.get("value") if val_obj else None
        output.append(row_dict)
    return output


# ---------------------------------------------------------------------------
# Local SQLite Helper
# ---------------------------------------------------------------------------
def _get_local_connection() -> sqlite3.Connection:
    """Create local SQLite connection with WAL mode."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


# ---------------------------------------------------------------------------
# Database Initialization
# ---------------------------------------------------------------------------
def init_db() -> None:
    """Initialize schema tables on Turso or Local SQLite."""
    create_users_table = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at TEXT NOT NULL
        );
    """
    create_scans_table = """
        CREATE TABLE IF NOT EXISTS scan_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            file_name TEXT NOT NULL,
            original_sha256 TEXT NOT NULL,
            clean_sha256 TEXT,
            verdict TEXT NOT NULL,
            risk_score REAL NOT NULL,
            sanitized_file_path TEXT,
            summary_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """

    if is_turso_enabled():
        try:
            _turso_execute(create_users_table)
            _turso_execute(create_scans_table)
            logger.info("Turso cloud database connected and initialized.")
            return
        except Exception as exc:
            logger.warning("Turso cloud unreachable (%s). Falling back to local SQLite.", exc)
            global _turso_circuit_broken
            _turso_circuit_broken = True

    # Local SQLite fallback
    conn = _get_local_connection()
    with conn:
        conn.execute(create_users_table)
        conn.execute(create_scans_table)
    conn.close()
    logger.info("Local SQLite database initialized at %s", DB_PATH)


# ---------------------------------------------------------------------------
# User Authentication & Management
# ---------------------------------------------------------------------------
def create_user(username: str, email: str, password: str, role: str = "analyst") -> tuple[bool, str]:
    """Register a new user with bcrypt-hashed credentials."""
    username = username.strip()
    email = email.strip().lower()

    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    salt = bcrypt.gensalt()
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
    now = datetime.now(timezone.utc).isoformat()

    sql = "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)"
    params = (username, email, pw_hash, role, now)

    if is_turso_enabled():
        try:
            _turso_execute(sql, params)
            return True, "User registered successfully."
        except Exception as exc:
            err = str(exc).lower()
            if "username" in err or "unique" in err:
                return False, "Username or email already exists."
            return False, f"Registration failed: {exc}"
    else:
        conn = _get_local_connection()
        try:
            with conn:
                conn.execute(sql, params)
            return True, "User registered successfully."
        except sqlite3.IntegrityError as exc:
            err = str(exc).lower()
            if "username" in err:
                return False, "Username already exists."
            if "email" in err:
                return False, "Email address already registered."
            return False, "User registration failed due to unique constraint."
        finally:
            conn.close()


def authenticate_user(username_or_email: str, password: str) -> Optional[dict[str, Any]]:
    """Authenticate user by username or email. Returns user dict or None."""
    identifier = username_or_email.strip().lower()
    sql = "SELECT id, username, email, password_hash, role, created_at FROM users WHERE lower(username) = ? OR lower(email) = ?"
    params = (identifier, identifier)

    user: Optional[dict[str, Any]] = None

    if is_turso_enabled():
        rows = _turso_execute(sql, params)
        if rows:
            user = rows[0]
            if "id" in user and user["id"] is not None:
                user["id"] = int(user["id"])
    else:
        conn = _get_local_connection()
        cursor = conn.cursor()
        cursor.execute(sql, params)
        row = cursor.fetchone()
        conn.close()
        if row:
            user = dict(row)

    if not user:
        return None

    stored_hash = user["password_hash"].encode("utf-8")
    if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        return {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "created_at": user["created_at"],
        }
    return None


def get_user_by_id(user_id: int) -> Optional[dict[str, Any]]:
    """Retrieve user details by ID."""
    sql = "SELECT id, username, email, role, created_at FROM users WHERE id = ?"
    params = (user_id,)

    if is_turso_enabled():
        rows = _turso_execute(sql, params)
        if rows:
            u = rows[0]
            u["id"] = int(u["id"])
            return u
        return None
    else:
        conn = _get_local_connection()
        cursor = conn.cursor()
        cursor.execute(sql, params)
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None


def update_user(
    user_id: int,
    username: str | None = None,
    email: str | None = None,
    password: str | None = None,
) -> tuple[bool, str]:
    """Update user username, email, or password."""
    fields = []
    params = []

    if username is not None:
        fields.append("username = ?")
        params.append(username.strip())
    if email is not None:
        fields.append("email = ?")
        params.append(email.strip().lower())
    if password is not None and password != "":
        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        fields.append("password_hash = ?")
        params.append(pw_hash)

    if not fields:
        return False, "No changes provided."

    params.append(user_id)
    query = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"

    if is_turso_enabled():
        try:
            _turso_execute(query, tuple(params))
            return True, "Profile updated successfully."
        except Exception as exc:
            err = str(exc).lower()
            if "username" in err:
                return False, "Username already taken."
            if "email" in err:
                return False, "Email already in use."
            return False, "Failed to update profile."
    else:
        conn = _get_local_connection()
        try:
            with conn:
                conn.execute(query, tuple(params))
            return True, "Profile updated successfully."
        except sqlite3.IntegrityError as exc:
            err = str(exc).lower()
            if "username" in err:
                return False, "Username already taken."
            if "email" in err:
                return False, "Email already in use."
            return False, "Failed to update profile."
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Scan Auditing & Retrieval
# ---------------------------------------------------------------------------
def record_scan(
    *,
    scan_id: str,
    user_id: Optional[int],
    file_name: str,
    original_sha256: str,
    clean_sha256: Optional[str],
    verdict: str,
    risk_score: float,
    sanitized_file_path: Optional[str],
    summary_json: Optional[str],
) -> None:
    """Save an audit record of a completed scan."""
    now = datetime.now(timezone.utc).isoformat()
    sql = """
        INSERT INTO scan_records (
            scan_id, user_id, file_name, original_sha256, clean_sha256,
            verdict, risk_score, sanitized_file_path, summary_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = (
        scan_id,
        user_id,
        file_name,
        original_sha256,
        clean_sha256,
        verdict,
        risk_score,
        sanitized_file_path,
        summary_json,
        now,
    )

    if is_turso_enabled():
        try:
            _turso_execute(sql, params)
        except Exception as exc:
            logger.error("Failed to record scan in Turso: %s", exc)
    else:
        conn = _get_local_connection()
        with conn:
            conn.execute(sql, params)
        conn.close()


def get_user_scans(user_id: int, limit: int = 50) -> list[dict[str, Any]]:
    """Retrieve scan history for a user."""
    sql = """
        SELECT scan_id, file_name, original_sha256, clean_sha256, verdict, risk_score,
               sanitized_file_path, created_at
        FROM scan_records
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT ?
    """
    params = (user_id, limit)

    if is_turso_enabled():
        rows = _turso_execute(sql, params)
        for r in rows:
            if "risk_score" in r and r["risk_score"] is not None:
                r["risk_score"] = float(r["risk_score"])
        return rows
    else:
        conn = _get_local_connection()
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]


def get_scan_by_id(scan_id: str) -> Optional[dict[str, Any]]:
    """Fetch a specific scan by scan_id."""
    sql = """
        SELECT scan_id, user_id, file_name, original_sha256, clean_sha256, verdict,
               risk_score, sanitized_file_path, summary_json, created_at
        FROM scan_records
        WHERE scan_id = ?
    """
    params = (scan_id,)

    if is_turso_enabled():
        rows = _turso_execute(sql, params)
        if rows:
            r = rows[0]
            if "risk_score" in r and r["risk_score"] is not None:
                r["risk_score"] = float(r["risk_score"])
            return r
        return None
    else:
        conn = _get_local_connection()
        cursor = conn.cursor()
        cursor.execute(sql, params)
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None


# Auto-initialize database schema on startup
init_db()
