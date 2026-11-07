"""Tests for authentication: first-run setup, login, TOTP, access control, users."""
import pyotp
import pytest
from werkzeug.security import generate_password_hash

import db


def add_user(username, password='secret', totp_secret=None):
    db.create_user(username, generate_password_hash(password))
    user = db.get_user(username)
    if totp_secret:
        db.set_totp_secret(user['id'], totp_secret)
    return user


# ── First run ─────────────────────────────────────────────────────────

def test_without_users_everything_redirects_to_setup(client):
    for url in ('/', '/manager/manage', '/auth/login'):
        response = client.get(url)
        assert response.status_code == 302
        assert response.headers['Location'].endswith('/auth/setup')


def test_setup_creates_first_user(client):
    response = client.post('/auth/setup', data={
        'username': 'admin', 'password': 'pw', 'confirm_password': 'pw'})

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/auth/login')
    assert db.get_user('admin') is not None


def test_setup_rejects_mismatched_passwords(client):
    response = client.post('/auth/setup', data={
        'username': 'admin', 'password': 'pw', 'confirm_password': 'other'})

    assert b'Passwords do not match.' in response.data
    assert db.user_count() == 0


def test_setup_is_closed_once_a_user_exists(client):
    add_user('admin')

    response = client.get('/auth/setup')

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/auth/login')


# ── Login ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize('url', [
    '/', '/manager/manage', '/manager/create', '/manager/backup',
    '/manager/api/status', '/auth/users', '/auth/settings',
])
def test_protected_pages_redirect_to_login(client, url):
    add_user('admin')

    response = client.get(url)

    assert response.status_code == 302
    assert '/auth/login' in response.headers['Location']


def test_login_with_wrong_password(client):
    add_user('admin')

    response = client.post('/auth/login', data={'username': 'admin', 'password': 'nope'})

    assert b'Invalid username or password.' in response.data
    assert client.get('/').status_code == 302


def test_login_and_logout(client):
    add_user('admin')

    response = client.post('/auth/login', data={'username': 'admin', 'password': 'secret'})
    assert response.status_code == 302
    assert client.get('/').status_code == 200

    client.get('/auth/logout')
    assert client.get('/').status_code == 302


def test_login_with_totp_requires_valid_code(client):
    secret = pyotp.random_base32()
    add_user('admin', totp_secret=secret)

    response = client.post('/auth/login', data={'username': 'admin', 'password': 'secret'})
    assert response.headers['Location'].endswith('/auth/totp')
    # Password alone is not enough
    assert client.get('/').status_code == 302

    response = client.post('/auth/totp', data={'code': '000000'})
    assert b'Invalid code' in response.data

    client.post('/auth/totp', data={'code': pyotp.TOTP(secret).now()})
    assert client.get('/').status_code == 200


# ── Settings ──────────────────────────────────────────────────────────

def test_change_password(logged_in_client):
    response = logged_in_client.post('/auth/settings', data={
        'action': 'change_password', 'current_password': 'secret',
        'new_password': 'new', 'confirm_password': 'new'})

    assert b'Password updated successfully.' in response.data
    from werkzeug.security import check_password_hash
    assert check_password_hash(db.get_user('admin')['password_hash'], 'new')


def test_change_password_requires_current_password(logged_in_client):
    response = logged_in_client.post('/auth/settings', data={
        'action': 'change_password', 'current_password': 'wrong',
        'new_password': 'new', 'confirm_password': 'new'})

    assert b'Current password is incorrect.' in response.data


# ── User management ───────────────────────────────────────────────────

def test_admin_can_add_and_delete_users(logged_in_client):
    logged_in_client.post('/auth/users', data={
        'action': 'add', 'username': 'bob', 'password': 'pw'})
    bob = db.get_user('bob')
    assert bob is not None

    logged_in_client.post('/auth/users', data={'action': 'delete', 'user_id': bob['id']})
    assert db.get_user('bob') is None


def test_admin_cannot_delete_itself(logged_in_client):
    response = logged_in_client.post('/auth/users', data={'action': 'delete', 'user_id': 1})

    assert b'You cannot delete your own account.' in response.data
    assert db.get_user('admin') is not None


def test_non_admin_cannot_delete_users(client):
    add_user('admin')
    add_user('bob')
    client.post('/auth/login', data={'username': 'bob', 'password': 'secret'})

    response = client.post('/auth/users', data={'action': 'delete', 'user_id': 1})

    assert b'Only the admin account can delete users.' in response.data
    assert db.get_user('admin') is not None


def test_cannot_add_duplicate_user(logged_in_client):
    response = logged_in_client.post('/auth/users', data={
        'action': 'add', 'username': 'admin', 'password': 'pw'})

    assert b'already exists' in response.data
