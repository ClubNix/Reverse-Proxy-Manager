"""Tests for authentication: first-run setup, login, TOTP, access control, users."""
from datetime import datetime, timedelta, timezone

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


def get_setup_token(app):
    from blueprints.auth import setup_token
    with app.app_context():
        return setup_token()


def test_setup_creates_first_user(app, client):
    response = client.post('/auth/setup', data={
        'setup_token': get_setup_token(app),
        'username': 'admin', 'password': 'pw', 'confirm_password': 'pw'})

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/auth/login')
    assert db.get_user('admin') is not None


@pytest.mark.parametrize('token', [None, '', 'wrong-token', 'é'])
def test_setup_requires_valid_setup_token(client, token):
    data = {'username': 'admin', 'password': 'pw', 'confirm_password': 'pw'}
    if token is not None:
        data['setup_token'] = token

    response = client.post('/auth/setup', data=data)

    assert b'Invalid setup token.' in response.data
    assert db.user_count() == 0


def test_setup_page_logs_setup_token(app, client, caplog):
    client.get('/auth/setup')

    assert get_setup_token(app) in caplog.text


def test_setup_rejects_mismatched_passwords(app, client):
    response = client.post('/auth/setup', data={
        'setup_token': get_setup_token(app),
        'username': 'admin', 'password': 'pw', 'confirm_password': 'other'})

    assert b'Passwords do not match.' in response.data
    assert db.user_count() == 0


def test_create_first_user_only_succeeds_on_empty_database(app):
    assert db.create_first_user('admin', generate_password_hash('pw')) is True
    assert db.create_first_user('attacker', generate_password_hash('pw')) is False

    assert db.user_count() == 1
    assert db.get_user('attacker') is None


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


@pytest.fixture
def clock(monkeypatch):
    """Freeze the time seen by the auth blueprint; move it with clock.tick()."""
    class Clock(datetime):
        current = datetime(2026, 1, 1, 12, 0, 5, tzinfo=timezone.utc)

        @classmethod
        def now(cls, tz=None):
            return cls.current

        @classmethod
        def tick(cls, seconds):
            cls.current += timedelta(seconds=seconds)

    monkeypatch.setattr('blueprints.auth.datetime', Clock)
    return Clock


def password_login(client):
    response = client.post('/auth/login', data={'username': 'admin', 'password': 'secret'})
    assert response.headers['Location'].endswith('/auth/totp')


def wrong_code(totp, when):
    return '000000' if totp.at(when) != '000000' else '111111'


def use_up_totp_attempts(client, totp, when):
    password_login(client)
    for _ in range(5):
        response = client.post('/auth/totp', data={'code': wrong_code(totp, when)})
        assert b'Invalid code. Please try again.' in response.data


def test_totp_attempts_survive_a_new_login(app, clock):
    totp = pyotp.TOTP(pyotp.random_base32())
    add_user('admin', totp_secret=totp.secret)
    attacker = app.test_client()
    use_up_totp_attempts(attacker, totp, clock.current)

    password_login(attacker)
    response = attacker.post('/auth/totp', data={'code': totp.at(clock.current)})

    assert b'Too many failed attempts' in response.data
    assert attacker.get('/').status_code == 302


def test_replaying_the_pending_cookie_does_not_reset_attempts(app, clock):
    totp = pyotp.TOTP(pyotp.random_base32())
    add_user('admin', totp_secret=totp.secret)
    attacker = app.test_client()
    password_login(attacker)
    saved = attacker.get_cookie('session').value
    for _ in range(5):
        attacker.post('/auth/totp', data={'code': wrong_code(totp, clock.current)})

    attacker.set_cookie('session', saved)
    response = attacker.post('/auth/totp', data={'code': totp.at(clock.current)})

    assert b'Too many failed attempts' in response.data
    assert attacker.get('/').status_code == 302


def test_failed_guesses_do_not_lock_out_the_owner(app, clock):
    totp = pyotp.TOTP(pyotp.random_base32())
    add_user('admin', totp_secret=totp.secret)
    use_up_totp_attempts(app.test_client(), totp, clock.current)
    owner = app.test_client()
    password_login(owner)

    response = owner.post('/auth/totp', data={'code': totp.at(clock.current)})
    assert b'Too many failed attempts' in response.data
    response = owner.post('/auth/totp', data={'code': totp.at(clock.current)})
    assert b'Wait for your authenticator to show a new code' in response.data
    assert owner.get('/').status_code == 302

    clock.tick(30)
    owner.post('/auth/totp', data={'code': totp.at(clock.current)})
    assert owner.get('/').status_code == 200


def test_two_code_check_needs_both_codes_right(app, clock):
    totp = pyotp.TOTP(pyotp.random_base32())
    add_user('admin', totp_secret=totp.secret)
    use_up_totp_attempts(app.test_client(), totp, clock.current)
    client = app.test_client()
    password_login(client)

    # A wrong first code gets the same answer as a right one.
    response = client.post('/auth/totp', data={'code': wrong_code(totp, clock.current)})
    assert b'Too many failed attempts' in response.data
    clock.tick(30)
    response = client.post('/auth/totp', data={'code': totp.at(clock.current)})

    assert b'Invalid code. Please sign in again.' in response.data
    assert client.get('/').status_code == 302
    assert client.get('/auth/totp').headers['Location'].endswith('/auth/login')


def test_pending_totp_login_expires(client, clock):
    totp = pyotp.TOTP(pyotp.random_base32())
    add_user('admin', totp_secret=totp.secret)
    password_login(client)

    clock.tick(301)
    response = client.post('/auth/totp', data={'code': totp.at(clock.current)})

    assert response.headers['Location'].endswith('/auth/login')
    assert client.get('/').status_code == 302


@pytest.mark.parametrize('next_url, expected', [
    ('/manager/manage', '/manager/manage'),
    ('https://evil.example/', '/'),
    ('//evil.example/', '/'),
    ('/\\evil.example/', '/'),
    ('/\t/evil.example/', '/'),
])
def test_totp_redirect_only_follows_local_next(client, next_url, expected):
    secret = pyotp.random_base32()
    add_user('admin', totp_secret=secret)

    client.post('/auth/login', data={'username': 'admin', 'password': 'secret',
                                     'next': next_url})
    response = client.post('/auth/totp', data={'code': pyotp.TOTP(secret).now()})

    assert response.status_code == 302
    assert response.headers['Location'] == expected


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

def users_csrf_token(client):
    """Load the users page like a browser would and return its CSRF token."""
    client.get('/auth/users')
    with client.session_transaction() as sess:
        return sess['csrf_token']


def test_admin_can_add_and_delete_users(logged_in_client):
    token = users_csrf_token(logged_in_client)
    logged_in_client.post('/auth/users', data={
        'csrf_token': token, 'action': 'add', 'username': 'bob', 'password': 'pw'})
    bob = db.get_user('bob')
    assert bob is not None

    logged_in_client.post('/auth/users', data={
        'csrf_token': token, 'action': 'delete', 'user_id': bob['id']})
    assert db.get_user('bob') is None


def test_admin_cannot_delete_itself(logged_in_client):
    response = logged_in_client.post('/auth/users', data={
        'csrf_token': users_csrf_token(logged_in_client),
        'action': 'delete', 'user_id': 1})

    assert b'You cannot delete your own account.' in response.data
    assert db.get_user('admin') is not None


def test_non_admin_cannot_delete_users(client):
    add_user('admin')
    add_user('bob')
    client.post('/auth/login', data={'username': 'bob', 'password': 'secret'})

    response = client.post('/auth/users', data={
        'csrf_token': users_csrf_token(client), 'action': 'delete', 'user_id': 1})

    assert b'Only the admin account can delete users.' in response.data
    assert db.get_user('admin') is not None


def test_cannot_add_duplicate_user(logged_in_client):
    response = logged_in_client.post('/auth/users', data={
        'csrf_token': users_csrf_token(logged_in_client),
        'action': 'add', 'username': 'admin', 'password': 'pw'})

    assert b'already exists' in response.data


def test_users_page_forms_carry_csrf_token(logged_in_client):
    db.create_user('bob', generate_password_hash('pw'))
    token = users_csrf_token(logged_in_client)

    page = logged_in_client.get('/auth/users').data.decode()

    field = f'name="csrf_token" value="{token}"'
    assert page.count(field) == 2  # add-user form and delete-bob form


@pytest.mark.parametrize('token', [None, '', 'forged-token'])
def test_users_post_without_valid_csrf_token_is_rejected(logged_in_client, token):
    users_csrf_token(logged_in_client)
    data = {'action': 'add', 'username': 'backdoor', 'password': 'pw'}
    if token is not None:
        data['csrf_token'] = token

    response = logged_in_client.post('/auth/users', data=data)

    assert response.status_code == 400
    assert db.get_user('backdoor') is None


def test_users_post_rejected_when_session_has_no_csrf_token(logged_in_client):
    with logged_in_client.session_transaction() as sess:
        sess.pop('csrf_token', None)

    response = logged_in_client.post('/auth/users', data={
        'csrf_token': '', 'action': 'add', 'username': 'backdoor', 'password': 'pw'})

    assert response.status_code == 400
    assert db.get_user('backdoor') is None
