import hashlib
import hmac
import io
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pyotp
import qrcode
from flask import (Blueprint, render_template, request, redirect,
                   url_for, session, send_file, abort, current_app)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash

from db import (user_count, get_user, get_user_by_id, get_all_users,
                create_user, create_first_user, update_password,
                set_totp_secret, delete_user,
                create_totp_pending, get_totp_pending, set_totp_pending_first_code,
                delete_totp_pending, reserve_totp_attempt, release_totp_attempt,
                create_auth_session, get_auth_session_user, delete_auth_session,
                delete_user_auth_sessions, reserve_login_attempt, release_login_attempt,
                claim_totp_step)

bp = Blueprint('auth', __name__, url_prefix='/auth')
login_manager = LoginManager()

# Seconds a password-verified login has to enter its TOTP code.
TOTP_PENDING_TTL = 300
# Single-code TOTP attempts per account and per window, shared by every
# pending login of that account. Once they are used up, a login still
# succeeds, but only with two correct codes from two different time steps,
# so someone else's failed guesses cannot lock the account owner out.
TOTP_MAX_ATTEMPTS = 5
TOTP_ATTEMPT_WINDOW = 900
# Seconds a login stays valid on the server, whatever the cookies say.
# Matches REMEMBER_COOKIE_DURATION (30 days).
SESSION_LIFETIME = 30 * 24 * 3600
# Failed password logins allowed per client IP and per window. Counted per
# client rather than per account, so nobody can lock someone else out.
LOGIN_MAX_ATTEMPTS = 10
LOGIN_ATTEMPT_WINDOW = 900
# Checked when the username does not exist, so that the response takes as
# long as a wrong password and does not reveal which usernames exist.
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(16))


class User(UserMixin):
    def __init__(self, data: dict, session_token: str | None = None):
        self.id = data['id']
        self.session_token = session_token
        self.username = data['username']
        self.password_hash = data['password_hash']
        self.totp_secret = data['totp_secret']

    @property
    def has_totp(self) -> bool:
        return bool(self.totp_secret)

    def get_id(self) -> str:
        # Stored in the session and remember-me cookies: the user id plus
        # the server-side session token that load_user() checks.
        return f'{self.id}:{self.session_token}'


@login_manager.user_loader
def load_user(user_id: str):
    uid, _, token = user_id.partition(':')
    if not (uid.isdigit() and token):
        return None  # cookie from before server-side sessions, or forged
    now = datetime.now(timezone.utc).timestamp()
    if get_auth_session_user(token, now, SESSION_LIFETIME) != int(uid):
        return None
    data = get_user_by_id(int(uid))
    return User(data, token) if data else None


def _start_session(data: dict) -> None:
    """Log the browser in with a new server-side session."""
    # A new login gets a new CSRF token, so one left in a shared browser by a
    # previous session is useless.
    session.pop('csrf_token', None)
    token = secrets.token_urlsafe(32)
    create_auth_session(token, data['id'], datetime.now(timezone.utc).timestamp(),
                        SESSION_LIFETIME)
    login_user(User(data, token), remember=True)


def _revoke_other_sessions(user_id: int) -> None:
    """End every session of the user, then keep this browser logged in."""
    delete_user_auth_sessions(user_id)
    _start_session(get_user_by_id(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    if user_count() == 0:
        return redirect(url_for('auth.setup'))
    return redirect(url_for('auth.login', next=request.path))


def _safe_next_url(target) -> str:
    """Return target if it is a same-site relative path, else the index URL."""
    fallback = url_for('index')
    if not isinstance(target, str) or not target:
        return fallback
    # Browsers treat '\' like '/' and drop tabs/newlines, which could turn
    # '/\evil.com' or '/\t/evil.com' into the external '//evil.com'.
    if '\\' in target or any(ord(c) < 0x20 or ord(c) == 0x7f for c in target):
        return fallback
    if not target.startswith('/') or target.startswith('//'):
        return fallback
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return fallback
    return target


# ── Login / logout ────────────────────────────────────────────────────

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if user_count() == 0:
        return redirect(url_for('auth.setup'))
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client = request.remote_addr or 'unknown'
        if not reserve_login_attempt(client, LOGIN_MAX_ATTEMPTS, LOGIN_ATTEMPT_WINDOW,
                                     datetime.now(timezone.utc).timestamp()):
            current_app.logger.warning('Login throttled for client %s', client)
            return render_template('login.html', next=request.args.get('next', ''),
                                   error='Too many failed login attempts. Try again later.'), 429
        data = get_user(username)
        password_ok = check_password_hash(
            data['password_hash'] if data else _DUMMY_PASSWORD_HASH, password)
        if data and password_ok:
            release_login_attempt(client)
            if data['totp_secret']:
                token = secrets.token_urlsafe(32)
                create_totp_pending(token, data['id'],
                                    datetime.now(timezone.utc).timestamp(), TOTP_PENDING_TTL)
                session['totp_pending'] = token
                session['totp_next'] = _safe_next_url(request.form.get('next')
                                                      or request.args.get('next'))
                return redirect(url_for('auth.totp'))
            _start_session(data)
            next_url = _safe_next_url(request.form.get('next') or request.args.get('next'))
            return redirect(next_url)
        error = 'Invalid username or password.'

    return render_template('login.html', error=error, next=request.args.get('next', ''))


def _finish_totp_login(token: str, data: dict):
    delete_totp_pending(token)
    session.pop('totp_pending', None)
    next_url = _safe_next_url(session.pop('totp_next', None))
    _start_session(data)
    return redirect(next_url)


@bp.route('/totp', methods=['GET', 'POST'])
def totp():
    token = session.get('totp_pending')
    when = datetime.now(timezone.utc)
    pending = (get_totp_pending(token, when.timestamp(), TOTP_PENDING_TTL)
               if isinstance(token, str) else None)
    if not pending:
        session.pop('totp_pending', None)
        return redirect(url_for('auth.login'))

    error = None
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        data = get_user_by_id(pending['user_id'])
        if not (data and data['totp_secret']):
            error = 'Invalid code. Please try again.'
        else:
            otp = pyotp.TOTP(data['totp_secret'])
            step = otp.timecode(when)
            if reserve_totp_attempt(data['id'], TOTP_MAX_ATTEMPTS, TOTP_ATTEMPT_WINDOW,
                                    when.timestamp()):
                if otp.verify(code, for_time=when):
                    if claim_totp_step(data['id'], step):
                        release_totp_attempt(data['id'])
                        return _finish_totp_login(token, data)
                    error = 'This code was already used. Wait for a new code, then enter it.'
                else:
                    error = 'Invalid code. Please try again.'
            # The account's budget is used up: this login needs two codes from
            # two different time steps. The first is recorded without saying
            # whether it was right; the second is checked once, together with it.
            elif pending['first_step'] is None and set_totp_pending_first_code(
                    token, step, otp.verify(code, for_time=when)):
                error = ('Too many failed attempts on this account. Wait for your '
                         'authenticator to show a new code, then enter it.')
            else:
                pending = get_totp_pending(token, when.timestamp(), TOTP_PENDING_TTL)
                if (pending and pending['first_step'] is not None
                        and step <= pending['first_step']):
                    error = 'Wait for your authenticator to show a new code, then enter it.'
                elif pending and delete_totp_pending(token):
                    if (pending['first_ok'] and otp.verify(code, for_time=when)
                            and claim_totp_step(data['id'], step)):
                        return _finish_totp_login(token, data)
                    session.pop('totp_pending', None)
                    error = 'Invalid code. Please sign in again.'
                else:
                    session.pop('totp_pending', None)
                    return redirect(url_for('auth.login'))

    return render_template('totp.html', error=error)


@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    # POST only, with the CSRF token checked in check_csrf_token(), so that
    # another site cannot end the session.
    if current_user.session_token:
        delete_auth_session(current_user.session_token)
    logout_user()
    session.pop('csrf_token', None)
    return redirect(url_for('auth.login'))


# ── First-run setup ───────────────────────────────────────────────────

def setup_token() -> str:
    """Secret required to complete first-run setup.

    Derived from the app secret key, so every worker process agrees on it, and
    only ever written to the server logs, so only the operator can read it.
    """
    key = current_app.secret_key
    if isinstance(key, str):
        key = key.encode()
    return hmac.new(key, b'reverse-proxy-manager first-run setup',
                    hashlib.sha256).hexdigest()


@bp.route('/setup', methods=['GET', 'POST'])
def setup():
    if user_count() > 0:
        return redirect(url_for('auth.login'))

    error = None
    if request.method == 'POST':
        token = request.form.get('setup_token', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if not hmac.compare_digest(token.encode(), setup_token().encode()):
            error = 'Invalid setup token.'
        elif not username or not password:
            error = 'Username and password are required.'
        elif not password:
            error = 'Password is required.'
        elif password != confirm:
            error = 'Passwords do not match.'
        else:
            create_first_user(username, generate_password_hash(password))
            return redirect(url_for('auth.login'))
    else:
        current_app.logger.warning(
            'No user exists yet. First-run setup token: %s', setup_token())

    return render_template('setup.html', error=error)


# ── Settings (password + TOTP) ────────────────────────────────────────

@bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    message = None
    success = False

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'change_password':
            current_pw = request.form.get('current_password', '')
            new_pw = request.form.get('new_password', '')
            confirm_pw = request.form.get('confirm_password', '')
            data = get_user_by_id(current_user.id)
            if not check_password_hash(data['password_hash'], current_pw):
                message = 'Current password is incorrect.'
            elif not new_pw:
                message = 'New password is required.'
            elif new_pw != confirm_pw:
                message = 'Passwords do not match.'
            else:
                update_password(current_user.id, generate_password_hash(new_pw))
                _revoke_other_sessions(current_user.id)
                message = 'Password updated successfully.'
                success = True

        elif action == 'disable_totp':
            data = get_user_by_id(current_user.id)
            if not check_password_hash(data['password_hash'],
                                       request.form.get('totp_password', '')):
                message = 'Password is incorrect.'
            else:
                set_totp_secret(current_user.id, None)
                _revoke_other_sessions(current_user.id)
                message = 'Two-factor authentication disabled.'
                success = True

    return render_template('settings.html', message=message, success=success)


@bp.route('/settings/totp/setup', methods=['GET', 'POST'])
@login_required
def totp_setup():
    if current_user.has_totp:
        return redirect(url_for('auth.settings'))

    secret = session.get('totp_setup_secret') or pyotp.random_base32()
    session['totp_setup_secret'] = secret

    error = None
    if request.method == 'POST':
        otp = pyotp.TOTP(secret)
        when = datetime.now(timezone.utc)
        data = get_user_by_id(current_user.id)
        if not check_password_hash(data['password_hash'], request.form.get('password', '')):
            error = 'Password is incorrect.'
        elif otp.verify(request.form.get('code', '').strip(), for_time=when):
            set_totp_secret(current_user.id, secret)
            # The enrollment code cannot be replayed to log in.
            claim_totp_step(current_user.id, otp.timecode(when))
            session.pop('totp_setup_secret', None)
            _revoke_other_sessions(current_user.id)
            return redirect(url_for('auth.settings'))
        else:
            error = 'Invalid code. Check your authenticator app and try again.'

    otp_uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.username,
        issuer_name='Reverse Proxy Manager'
    )
    return render_template('totp_setup.html', secret=secret, otp_uri=otp_uri, error=error)


@bp.route('/settings/totp/qr.png')
@login_required
def totp_qr():
    secret = session.get('totp_setup_secret')
    if not secret:
        abort(404)
    otp_uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.username,
        issuer_name='Reverse Proxy Manager'
    )
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')


# ── CSRF protection ───────────────────────────────────────────────────

def get_csrf_token() -> str:
    """Return the session's CSRF token, creating it on first use."""
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


@bp.app_context_processor
def inject_csrf_token() -> dict:
    # Available in every template, e.g. the logout form in base.html.
    return {'csrf_token': get_csrf_token}


@bp.before_request
def check_csrf_token() -> None:
    """Abort with 400 unless a logged-in POST carries the session's CSRF token.

    Anonymous forms (login, TOTP, setup) have no session to protect yet.
    """
    if request.method in ('GET', 'HEAD', 'OPTIONS') or not current_user.is_authenticated:
        return
    expected = session.get('csrf_token')
    submitted = request.form.get('csrf_token', '')
    if not expected or not hmac.compare_digest(expected.encode(),
                                               submitted.encode()):
        abort(400)


# ── User management ───────────────────────────────────────────────────

@bp.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    message = None
    success = False

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            if not username or not password:
                message = 'Username and password are required.'
            elif get_user(username):
                message = f'User "{username}" already exists.'
            else:
                create_user(username, generate_password_hash(password))
                message = f'User "{username}" created.'
                success = True

        elif action == 'delete':
            if current_user.id != 1:
                message = 'Only the admin account can delete users.'
            else:
                user_id = int(request.form.get('user_id'))
                if user_id == current_user.id:
                    message = 'You cannot delete your own account.'
                else:
                    delete_user(user_id)
                    message = 'User deleted.'
                    success = True

    return render_template('users.html', users=get_all_users(),
                           message=message, success=success)
