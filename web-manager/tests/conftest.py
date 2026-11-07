import os
import tempfile

import pytest

# The app reads these at import time, so they must be set before any
# application module is imported.
_SESSION_TMP = tempfile.mkdtemp(prefix='rpm-tests-')
os.environ['LOG_DIR'] = os.path.join(_SESSION_TMP, 'logs')
os.environ['AUTH_DB_PATH'] = os.path.join(_SESSION_TMP, 'data', 'users.db')
os.environ['FLASK_SECRET_KEY'] = 'test-secret-key'

import db  # noqa: E402
from blueprints.manager import ReverseProxyManager  # noqa: E402


@pytest.fixture
def fake_nginx(tmp_path, monkeypatch):
    """Redirect every ReverseProxyManager to temporary folders.

    Also simulates the reverse-proxy container's watcher: `nginx -t` is
    reported as successful and the 1 s wait in reload_nginx() is skipped.
    """
    root = tmp_path / 'nginx'
    scripts = tmp_path / 'scripts'
    original_init = ReverseProxyManager.__init__

    def patched_init(self):
        original_init(self)
        self.app_nginx_path = str(root)
        self.app_conf_path = str(root / 'conf.d')
        self.app_ssl_path = str(root / 'certs')
        self.app_log_path = str(root / 'logs')
        self.app_scripts_path = str(scripts)

    monkeypatch.setattr(ReverseProxyManager, '__init__', patched_init)
    monkeypatch.setattr('blueprints.manager.time.sleep', lambda _: None)
    for path in (root / 'conf.d', root / 'certs', root / 'logs', scripts):
        path.mkdir(parents=True)
    (scripts / 'check_conf_status').write_text('0\n')
    return root


@pytest.fixture
def rpm(fake_nginx):
    """A ReverseProxyManager working on temporary folders."""
    return ReverseProxyManager()


@pytest.fixture
def app(tmp_path, monkeypatch):
    """The Flask app backed by a fresh, empty user database."""
    monkeypatch.setattr(db, 'DB_PATH', str(tmp_path / 'users.db'))
    from app import app as flask_app
    flask_app.config.update(TESTING=True)
    with flask_app.app_context():
        db.init_db()
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in_client(client):
    """A test client logged in as the admin account (id 1)."""
    from werkzeug.security import generate_password_hash
    db.create_user('admin', generate_password_hash('secret'))
    client.post('/auth/login', data={'username': 'admin', 'password': 'secret'})
    return client
