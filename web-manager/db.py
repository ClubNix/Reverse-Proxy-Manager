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


def update_password(user_id: int, password_hash: str) -> None:
    with _connect() as conn:
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))


def set_totp_secret(user_id: int, secret: str | None) -> None:
    with _connect() as conn:
        conn.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (secret, user_id))


def delete_user(user_id: int) -> None:
    with _connect() as conn:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
