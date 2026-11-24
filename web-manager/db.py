import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.getenv('AUTH_DB_PATH', '/app/data/users.db')


def get_or_create_secret_key() -> bytes:
    env_key = os.getenv('FLASK_SECRET_KEY')
    if env_key:
        return env_key.encode()
    key_path = os.path.join(os.path.dirname(DB_PATH), 'secret_key')
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return f.read()
    key = os.urandom(32)
    with open(key_path, 'wb') as f:
        f.write(key)
    return key


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _connect() as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Password-verified logins waiting for their TOTP code. Kept server
        # side so that replaying the session cookie cannot rewind their state.
        conn.execute('''
            CREATE TABLE IF NOT EXISTS totp_pending (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at REAL NOT NULL,
                first_step INTEGER,
                first_ok INTEGER
            )
        ''')
        # Per-account budget of single-code TOTP attempts.
        conn.execute('''
            CREATE TABLE IF NOT EXISTS totp_attempts (
                user_id INTEGER PRIMARY KEY,
                window_start REAL NOT NULL,
                attempts INTEGER NOT NULL
            )
        ''')
        # Logged-in sessions. The session and remember-me cookies only carry
        # a token pointing here, so a login can be revoked server side.
        conn.execute('''
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at REAL NOT NULL
            )
        ''')
        # Per-client budget of failed password logins.
        conn.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                client TEXT PRIMARY KEY,
                window_start REAL NOT NULL,
                attempts INTEGER NOT NULL
            )
        ''')


def user_count() -> int:
    with _connect() as conn:
        return conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]


def get_user(username: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    return dict(row) if row else None


def get_all_users() -> list:
    with _connect() as conn:
        rows = conn.execute(
            'SELECT id, username, (totp_secret IS NOT NULL) as has_totp, created_at FROM users'
        ).fetchall()
    return [dict(r) for r in rows]


def create_user(username: str, password_hash: str) -> None:
    with _connect() as conn:
        conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                     (username, password_hash))


def create_first_user(username: str, password_hash: str) -> bool:
    """Create a user only if no user exists yet, as a single atomic statement.

    Returns True if the user was created, False if another user already exists.
    """
    with _connect() as conn:
        cursor = conn.execute(
            'INSERT INTO users (username, password_hash) '
            'SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)',
            (username, password_hash))
        return cursor.rowcount == 1


def update_password(user_id: int, password_hash: str) -> None:
    with _connect() as conn:
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))


def set_totp_secret(user_id: int, secret: str | None) -> None:
    with _connect() as conn:
        conn.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (secret, user_id))


def delete_user(user_id: int) -> None:
    with _connect() as conn:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.execute('DELETE FROM auth_sessions WHERE user_id = ?', (user_id,))


# ── TOTP login state ──────────────────────────────────────────────────

def create_totp_pending(token: str, user_id: int, now: float, ttl: float) -> None:
    with _connect() as conn:
        conn.execute('DELETE FROM totp_pending WHERE created_at <= ?', (now - ttl,))
        conn.execute('INSERT INTO totp_pending (token, user_id, created_at) VALUES (?, ?, ?)',
                     (token, user_id, now))


def get_totp_pending(token: str, now: float, ttl: float) -> dict | None:
    with _connect() as conn:
        row = conn.execute('SELECT * FROM totp_pending WHERE token = ? AND created_at > ?',
                           (token, now - ttl)).fetchone()
    return dict(row) if row else None


def set_totp_pending_first_code(token: str, step: int, ok: bool) -> bool:
    """Record the first code of a two-code check; only the first call wins."""
    with _connect() as conn:
        cur = conn.execute('UPDATE totp_pending SET first_step = ?, first_ok = ? '
                           'WHERE token = ? AND first_step IS NULL',
                           (step, int(ok), token))
        return cur.rowcount == 1


def delete_totp_pending(token: str) -> bool:
    """Delete a pending login; True only for the one caller that removed it."""
    with _connect() as conn:
        return conn.execute('DELETE FROM totp_pending WHERE token = ?', (token,)).rowcount == 1


def reserve_totp_attempt(user_id: int, limit: int, window: float, now: float) -> bool:
    """Atomically take one single-code attempt from the account's budget."""
    with _connect() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute('SELECT window_start, attempts FROM totp_attempts WHERE user_id = ?',
                           (user_id,)).fetchone()
        if row is None or row['window_start'] <= now - window:
            conn.execute('INSERT OR REPLACE INTO totp_attempts (user_id, window_start, attempts) '
                         'VALUES (?, ?, 1)', (user_id, now))
            return True
        if row['attempts'] < limit:
            conn.execute('UPDATE totp_attempts SET attempts = attempts + 1 WHERE user_id = ?',
                         (user_id,))
            return True
        return False


def release_totp_attempt(user_id: int) -> None:
    """Give back an attempt that turned out to be a correct code."""
    with _connect() as conn:
        conn.execute('UPDATE totp_attempts SET attempts = attempts - 1 '
                     'WHERE user_id = ? AND attempts > 0', (user_id,))


# ── Logged-in sessions ────────────────────────────────────────────────

def create_auth_session(token: str, user_id: int, now: float, ttl: float) -> None:
    with _connect() as conn:
        conn.execute('DELETE FROM auth_sessions WHERE created_at <= ?', (now - ttl,))
        conn.execute('INSERT INTO auth_sessions (token, user_id, created_at) VALUES (?, ?, ?)',
                     (token, user_id, now))


def get_auth_session_user(token: str, now: float, ttl: float) -> int | None:
    """Return the user id of a live session, or None if revoked or expired."""
    with _connect() as conn:
        row = conn.execute('SELECT user_id FROM auth_sessions WHERE token = ? AND created_at > ?',
                           (token, now - ttl)).fetchone()
    return row['user_id'] if row else None


def delete_auth_session(token: str) -> None:
    with _connect() as conn:
        conn.execute('DELETE FROM auth_sessions WHERE token = ?', (token,))


def delete_user_auth_sessions(user_id: int) -> None:
    with _connect() as conn:
        conn.execute('DELETE FROM auth_sessions WHERE user_id = ?', (user_id,))


# ── Password login throttling ─────────────────────────────────────────

def reserve_login_attempt(client: str, limit: int, window: float, now: float) -> bool:
    """Atomically take one password attempt from the client's budget."""
    with _connect() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute('SELECT window_start, attempts FROM login_attempts WHERE client = ?',
                           (client,)).fetchone()
        if row is None or row['window_start'] <= now - window:
            conn.execute('INSERT OR REPLACE INTO login_attempts (client, window_start, attempts) '
                         'VALUES (?, ?, 1)', (client, now))
            return True
        if row['attempts'] < limit:
            conn.execute('UPDATE login_attempts SET attempts = attempts + 1 WHERE client = ?',
                         (client,))
            return True
        return False


def release_login_attempt(client: str) -> None:
    """Give back an attempt that turned out to be a correct password."""
    with _connect() as conn:
        conn.execute('UPDATE login_attempts SET attempts = attempts - 1 '
                     'WHERE client = ? AND attempts > 0', (client,))
