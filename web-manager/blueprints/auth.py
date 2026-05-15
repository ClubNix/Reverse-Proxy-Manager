import io
from datetime import timedelta

import pyotp
import qrcode
from flask import (Blueprint, render_template, request, redirect,
                   url_for, session, send_file, abort)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash

from db import (user_count, get_user, get_user_by_id, get_all_users,
                create_user, update_password, set_totp_secret, delete_user)

bp = Blueprint('auth', __name__, url_prefix='/auth')
login_manager = LoginManager()


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
                session['totp_pending'] = data['id']
                session['totp_next'] = (request.form.get('next')
                                        or request.args.get('next')
                                        or url_for('index'))
                return redirect(url_for('auth.totp'))
            login_user(User(data), remember=True)
            next_url = request.form.get('next') or request.args.get('next') or url_for('index')
            return redirect(next_url)
        error = 'Invalid username or password.'

    return render_template('login.html', error=error, next=request.args.get('next', ''))


@bp.route('/totp', methods=['GET', 'POST'])
def totp():
    user_id = session.get('totp_pending')
    if not user_id:
        return redirect(url_for('auth.login'))

    error = None
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        data = get_user_by_id(user_id)
        if data and data['totp_secret'] and pyotp.TOTP(data['totp_secret']).verify(code):
            session.pop('totp_pending', None)
            next_url = session.pop('totp_next', url_for('index'))
            login_user(User(data), remember=True)
            return redirect(next_url)
        error = 'Invalid code. Please try again.'

    return render_template('totp.html', error=error)


@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


# ── First-run setup ───────────────────────────────────────────────────

@bp.route('/setup', methods=['GET', 'POST'])
def setup():
    if user_count() > 0:
        return redirect(url_for('auth.login'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if not username or not password:
            error = 'Username and password are required.'
        elif not password:
            error = 'Password is required.'
        elif password != confirm:
            error = 'Passwords do not match.'
        else:
            create_user(username, generate_password_hash(password))
            return redirect(url_for('auth.login'))

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
