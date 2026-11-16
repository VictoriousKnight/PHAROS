"""
PHAROS Web - Database Management
--------------------------------
Thread-safe SQLite database interface with WAL mode enabled.
Stores user authentication profiles, scan histories, and sanitized file references.
Database file is maintained strictly under user_database/pharos_users.db.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import bcrypt

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_DIR = PROJECT_ROOT / "user_database"
DB_PATH = DB_DIR / "pharos_users.db"


def get_db_connection() -> sqlite3.Connection:
    """Create a thread-safe connection to the user database with WAL mode."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for high concurrency
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    """Initialize database tables for users and scan audit logs."""
    conn = get_db_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'analyst',
                created_at TEXT NOT NULL
            );
        """)
        conn.execute("""
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
        """)
    conn.close()


def create_user(username: str, email: str, password: str, role: str = "analyst") -> tuple[bool, str]:
    """Register a new user with bcrypt-hashed credentials."""
    username = username.strip()
    email = email.strip().lower()

    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    # Hash password securely
    salt = bcrypt.gensalt()
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, email, pw_hash, role, now),
            )
        return True, "User registered successfully."
    except sqlite3.IntegrityError as exc:
        err_msg = str(exc).lower()
        if "username" in err_msg:
            return False, "Username already exists."
        if "email" in err_msg:
            return False, "Email address already registered."
        return False, "User registration failed due to unique constraint."
    finally:
        conn.close()


def authenticate_user(username_or_email: str, password: str) -> Optional[dict[str, Any]]:
    """Authenticate a user by username or email. Returns user dict or None."""
    identifier = username_or_email.strip().lower()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email, password_hash, role, created_at FROM users WHERE lower(username) = ? OR lower(email) = ?",
        (identifier, identifier),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    user = dict(row)
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
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, created_at FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_user(user_id: int, username: str | None = None, email: str | None = None, password: str | None = None) -> tuple[bool, str]:
    """Update user fields; only non‑None arguments are changed.
    Returns (success, message)."""
    # Build dynamic query
    fields = []
    params = []
    if username is not None:
        fields.append("username = ?")
        params.append(username.strip())
    if email is not None:
        fields.append("email = ?")
        params.append(email.strip().lower())
    if password is not None and password != "":
        # Hash new password
        import bcrypt
        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        fields.append("password_hash = ?")
        params.append(pw_hash)
    if not fields:
        return False, "No changes provided."
    params.append(user_id)
    query = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"
    conn = get_db_connection()
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
    """Retrieve user details by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, created_at FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


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
    conn = get_db_connection()
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scan_records (
                scan_id, user_id, file_name, original_sha256, clean_sha256,
                verdict, risk_score, sanitized_file_path, summary_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
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
            ),
        )
    conn.close()


def get_user_scans(user_id: int, limit: int = 50) -> list[dict[str, Any]]:
    """Retrieve scan history for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT scan_id, file_name, original_sha256, clean_sha256, verdict, risk_score,
               sanitized_file_path, created_at
        FROM scan_records
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (user_id, limit),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_by_id(scan_id: str) -> Optional[dict[str, Any]]:
    """Fetch a specific scan by scan_id."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT scan_id, user_id, file_name, original_sha256, clean_sha256, verdict,
               risk_score, sanitized_file_path, summary_json, created_at
        FROM scan_records
        WHERE scan_id = ?
        """,
        (scan_id,),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


# Auto-initialize database on import
init_db()
