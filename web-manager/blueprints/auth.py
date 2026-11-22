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
                delete_totp_pending, reserve_totp_attempt, release_totp_attempt)

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


class User(UserMixin):
    def __init__(self, data: dict):
        self.id = data['id']
        self.username = data['username']
        self.password_hash = data['password_hash']
        self.totp_secret = data['totp_secret']

    @property
    def has_totp(self) -> bool:
        return bool(self.totp_secret)


@login_manager.user_loader
def load_user(user_id: str):
    data = get_user_by_id(int(user_id))
    return User(data) if data else None


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
        data = get_user(username)
        if data and check_password_hash(data['password_hash'], password):
            if data['totp_secret']:
                token = secrets.token_urlsafe(32)
                create_totp_pending(token, data['id'],
                                    datetime.now(timezone.utc).timestamp(), TOTP_PENDING_TTL)
                session['totp_pending'] = token
                session['totp_next'] = _safe_next_url(request.form.get('next')
                                                      or request.args.get('next'))
                return redirect(url_for('auth.totp'))
            login_user(User(data), remember=True)
            next_url = request.form.get('next') or request.args.get('next') or url_for('index')
            return redirect(next_url)
        error = 'Invalid username or password.'

    return render_template('login.html', error=error, next=request.args.get('next', ''))


def _finish_totp_login(token: str, data: dict):
    delete_totp_pending(token)
    session.pop('totp_pending', None)
    next_url = _safe_next_url(session.pop('totp_next', None))
    login_user(User(data), remember=True)
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
                    release_totp_attempt(data['id'])
                    return _finish_totp_login(token, data)
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
                    if pending['first_ok'] and otp.verify(code, for_time=when):
                        return _finish_totp_login(token, data)
                    session.pop('totp_pending', None)
                    error = 'Invalid code. Please sign in again.'
                else:
                    session.pop('totp_pending', None)
                    return redirect(url_for('auth.login'))

    return render_template('totp.html', error=error)


@bp.route('/logout')
@login_required
def logout():
    logout_user()
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
                message = 'Password updated successfully.'
                success = True

        elif action == 'disable_totp':
            data = get_user_by_id(current_user.id)
            if not check_password_hash(data['password_hash'],
                                       request.form.get('totp_password', '')):
                message = 'Password is incorrect.'
            else:
                set_totp_secret(current_user.id, None)
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
        if pyotp.TOTP(secret).verify(request.form.get('code', '').strip()):
            set_totp_secret(current_user.id, secret)
            session.pop('totp_setup_secret', None)
            return redirect(url_for('auth.settings'))
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


def check_csrf_token() -> None:
    """Abort with 400 unless the form carries the session's CSRF token."""
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
        check_csrf_token()
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
                           message=message, success=success,
                           csrf_token=get_csrf_token())
