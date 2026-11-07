"""Unit tests for ReverseProxyManager (config files, certificates, reload)."""
import os

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID


def write_conf(rpm, name, content='server { server_name %s; }\n', enabled=True):
    suffix = '.conf' if enabled else '.conf.disabled'
    path = os.path.join(rpm.app_conf_path, name + suffix)
    with open(path, 'w') as f:
        f.write(content % name if '%s' in content else content)
    return path


def touch_cert(rpm, name):
    for ext in ('.crt', '.key'):
        open(os.path.join(rpm.app_ssl_path, name + ext), 'w').close()


# ── Address validation ────────────────────────────────────────────────

@pytest.mark.parametrize('address', [
    '192.168.1.10',
    '192.168.1.10:8080',
    '10.0.0.1:443/app',
    '10.0.0.1/some/path',
    '255.255.255.255:65535',
])
def test_address_check_accepts_valid_addresses(rpm, address):
    assert rpm.address_check(address)


@pytest.mark.parametrize('address', [
    '',
    'example.com',
    '256.1.1.1',
    '192.168.1',
    '192.168.1.10:0',
    '192.168.1.10:70000',
    '192.168.1.10:abc',
])
def test_address_check_rejects_invalid_addresses(rpm, address):
    assert not rpm.address_check(address)


# ── Listing / enable / disable ────────────────────────────────────────

def test_get_conf_list_includes_enabled_and_disabled_only(rpm):
    write_conf(rpm, 'a.example.com')
    write_conf(rpm, 'b.example.com', enabled=False)
    # Files that are not configurations must be ignored
    open(os.path.join(rpm.app_conf_path, 'disabled.unavailable'), 'w').close()
    open(os.path.join(rpm.app_conf_path, 'notes.txt'), 'w').close()

    assert rpm.get_conf_list() == ['a.example.com', 'b.example.com']


def test_disable_then_enable_renames_the_file(rpm):
    write_conf(rpm, 'app.example.com')

    rpm.disable_conf('app.example.com')
    assert not rpm._is_enabled('app.example.com')
    assert os.path.exists(os.path.join(rpm.app_conf_path, 'app.example.com.conf.disabled'))

    rpm.enable_conf('app.example.com')
    assert rpm._is_enabled('app.example.com')
    assert not os.path.exists(os.path.join(rpm.app_conf_path, 'app.example.com.conf.disabled'))


def test_conf_path_raises_for_unknown_conf(rpm):
    with pytest.raises(FileNotFoundError):
        rpm._conf_path('missing.example.com')


# ── Create / edit / remove ────────────────────────────────────────────

def test_create_conf_writes_config_logdir_and_certificate(rpm):
    rpm.create_conf('app.example.com', '10.0.0.5:8080', 'My app', 'http', '*')

    conf = rpm.get_conf('app.example.com')
    assert 'server_name app.example.com;' in conf
    assert 'proxy_pass http://10.0.0.5:8080;' in conf
    assert '# My app' in conf
    assert 'ssl_certificate /etc/nginx/certs/app.example.com.crt;' in conf
    assert os.path.isdir(os.path.join(rpm.app_log_path, 'app.example.com'))

    with open(os.path.join(rpm.app_ssl_path, 'app.example.com.crt'), 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())
    assert 'CN=app.example.com' in cert.subject.rfc4514_string()
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    assert san.value.get_values_for_type(x509.DNSName) == ['app.example.com']


def test_create_conf_uses_uploaded_certificate(rpm, tmp_path):
    cert = tmp_path / 'upload.crt'
    key = tmp_path / 'upload.key'
    cert.write_text('CERT')
    key.write_text('KEY')

    rpm.create_conf('app.example.com', '10.0.0.5', '', 'https', '*', str(cert), str(key))

    with open(os.path.join(rpm.app_ssl_path, 'app.example.com.crt')) as f:
        assert f.read() == 'CERT'
    with open(os.path.join(rpm.app_ssl_path, 'app.example.com.key')) as f:
        assert f.read() == 'KEY'
    # Temporary upload files are cleaned up
    assert not cert.exists() and not key.exists()
    assert 'proxy_pass https://10.0.0.5;' in rpm.get_conf('app.example.com')


def test_edit_conf_normalizes_line_endings(rpm):
    write_conf(rpm, 'app.example.com')

    rpm.edit_conf('app.example.com', '  server {\r\n  listen 80;\r\n}\r\n  ')

    with open(rpm._conf_path('app.example.com')) as f:
        assert f.read() == 'server {\n  listen 80;\n}\n'


def test_edit_conf_keeps_disabled_state(rpm):
    write_conf(rpm, 'app.example.com', enabled=False)

    rpm.edit_conf('app.example.com', 'server {}')

    assert not rpm._is_enabled('app.example.com')
    assert rpm.get_conf('app.example.com') == 'server {}'


def test_remove_conf_deletes_conf_certificate_and_logs(rpm):
    write_conf(rpm, 'app.example.com', enabled=False)
    touch_cert(rpm, 'app.example.com')
    os.makedirs(os.path.join(rpm.app_log_path, 'app.example.com'))

    rpm.remove_conf('app.example.com')

    assert rpm.get_conf_list() == []
    assert os.listdir(rpm.app_ssl_path) == []
    assert not os.path.exists(os.path.join(rpm.app_log_path, 'app.example.com'))


# ── Parsing ───────────────────────────────────────────────────────────

def test_get_conf_infos_and_clone_parse_created_conf(rpm):
    rpm.create_conf('app.example.com', '10.0.0.5:8080', 'My app', 'https', 'https://x.fr')

    infos = rpm.get_conf_infos('app.example.com')
    assert infos['description'] == 'My app'
    assert infos['server_name'] == 'app.example.com'
    assert infos['server'] == 'https://10.0.0.5:8080'
    assert infos['certificate'] is not None

    clone = rpm.parse_conf_for_clone('app.example.com')
    assert clone == {
        'domain': '',
        'server': '10.0.0.5:8080',
        'description': 'My app',
        'allow_origin': 'https://x.fr',
        'service_type': 'https',
    }


def test_get_conf_infos_without_proxy_pass_or_certificate(rpm):
    write_conf(rpm, 'static.example.com')

    infos = rpm.get_conf_infos('static.example.com')

    assert infos['server'] is None
    assert infos['certificate'] is None


def test_get_cert_expiry(rpm):
    assert rpm.get_cert_expiry('missing.example.com') == {'days_left': None, 'expiry': None}

    rpm.ssl_conf['DAYS'] = '30'
    rpm.generate_ssl('app.example.com')

    assert rpm.get_cert_expiry('app.example.com')['days_left'] in (29, 30)


def test_get_all_conf_status(rpm):
    write_conf(rpm, 'a.example.com')
    write_conf(rpm, 'b.example.com', enabled=False)

    status = rpm.get_all_conf_status()

    assert status['a.example.com']['enabled'] is True
    assert status['b.example.com']['enabled'] is False
    assert status['b.example.com']['server_name'] == 'b.example.com'


# ── Unavailable page for disabled confs ───────────────────────────────

def read_unavailable(rpm):
    with open(os.path.join(rpm.app_conf_path, 'disabled.unavailable')) as f:
        return f.read()


def test_unavailable_conf_lists_only_disabled_confs(rpm):
    write_conf(rpm, 'on.example.com')
    write_conf(rpm, 'off.example.com', enabled=False)

    rpm.write_unavailable_conf()

    content = read_unavailable(rpm)
    assert 'server_name off.example.com;' in content
    assert 'on.example.com' not in content
    assert 'include /etc/nginx/unavailable.inc;' in content


def test_unavailable_conf_keeps_own_certificate_when_present(rpm):
    write_conf(rpm, 'with-cert.example.com', enabled=False)
    write_conf(rpm, 'no-cert.example.com', enabled=False)
    touch_cert(rpm, 'with-cert.example.com')

    rpm.write_unavailable_conf()

    blocks = read_unavailable(rpm).split('# ')
    with_cert = next(b for b in blocks if b.startswith('with-cert'))
    no_cert = next(b for b in blocks if b.startswith('no-cert'))
    assert 'listen 443 ssl;' in with_cert
    assert 'ssl_certificate /etc/nginx/certs/with-cert.example.com.crt;' in with_cert
    assert 'listen 443' not in no_cert
    assert 'listen 80;' in no_cert


def test_unavailable_conf_skips_names_that_could_inject_nginx_config(rpm):
    write_conf(rpm, 'bad;name', enabled=False)

    rpm.write_unavailable_conf()

    assert 'bad;name' not in read_unavailable(rpm)


def test_unavailable_conf_is_emptied_when_everything_is_enabled(rpm):
    write_conf(rpm, 'app.example.com', enabled=False)
    rpm.write_unavailable_conf()
    rpm.enable_conf('app.example.com')

    rpm.write_unavailable_conf()

    assert 'server' not in read_unavailable(rpm)


# ── Reload ────────────────────────────────────────────────────────────

def test_reload_nginx_success_triggers_reload(rpm):
    ok, status = rpm.reload_nginx()

    assert (ok, status) == (True, 'OK')
    with open(os.path.join(rpm.app_scripts_path, 'check_conf')) as f:
        assert f.read() == 'check'
    with open(os.path.join(rpm.app_scripts_path, 'reload_nginx')) as f:
        assert f.read() == 'reload'
    # The disabled-domains file is regenerated on every reload
    assert os.path.exists(os.path.join(rpm.app_conf_path, 'disabled.unavailable'))


def test_reload_nginx_failure_returns_error_and_does_not_reload(rpm):
    with open(os.path.join(rpm.app_scripts_path, 'check_conf_status'), 'w') as f:
        f.write('1\nnginx: [emerg] unexpected "}"\n')

    ok, status = rpm.reload_nginx()

    assert ok is False
    assert 'unexpected "}"' in status
    assert not os.path.exists(os.path.join(rpm.app_scripts_path, 'reload_nginx'))


# ── Backup / restore ──────────────────────────────────────────────────

def test_backup_and_restore_round_trip(rpm):
    write_conf(rpm, 'app.example.com')
    touch_cert(rpm, 'app.example.com')
    rpm.backup_nginx()
    archive = os.path.join(rpm.app_scripts_path, 'nginx.tar.gz')

    # Change state after the backup
    rpm.remove_conf('app.example.com')
    write_conf(rpm, 'other.example.com')

    class Upload:
        def save(self, dst):
            with open(archive, 'rb') as src, open(dst, 'wb') as out:
                out.write(src.read())

    rpm.restore_backup(Upload())

    assert rpm.get_conf_list() == ['app.example.com']
    assert sorted(os.listdir(rpm.app_ssl_path)) == ['app.example.com.crt', 'app.example.com.key']
    assert os.path.isdir(os.path.join(rpm.app_log_path, 'app.example.com'))


def test_restore_rejects_archive_without_nginx_folder(rpm, tmp_path):
    import tarfile
    archive = tmp_path / 'bad.tar.gz'
    (tmp_path / 'other').mkdir()
    with tarfile.open(archive, 'w:gz') as tar:
        tar.add(tmp_path / 'other', arcname='other')

    class Upload:
        def save(self, dst):
            with open(archive, 'rb') as src, open(dst, 'wb') as out:
                out.write(src.read())

    with pytest.raises(ValueError):
        rpm.restore_backup(Upload())
