import flask
from flask import Blueprint, render_template, request, send_from_directory, jsonify
from flask_login import login_required
import logging
import os
import subprocess
import socket
import tempfile
from typing import Dict, Any
import shutil
import re
import tarfile
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def handle_logs(logger_name, log_file_name):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(f"/app/logs/{log_file_name}")
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


bp = Blueprint('manager', __name__, url_prefix='/manager')
logger = handle_logs('web_manager', 'web_manager.log')


class ReverseProxyManager:
    def __init__(self) -> None:
        self.real_conf_path = '/etc/nginx/conf.d'
        self.real_ssl_path = '/etc/nginx/certs'
        self.real_log_path = '/var/log/nginx'
        self.app_conf_path = '/app/nginx/conf.d'
        self.app_ssl_path = '/app/nginx/certs'
        self.app_log_path = '/app/nginx/logs'
        self.app_scripts_path = '/app/scripts'
        self.app_nginx_path = '/app/nginx'
        self.ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        self.addr_with_path_pattern = re.compile(
            r'^(?P<host>(?:\d{1,3}\.){3}\d{1,3})'
            r'(?::(?P<port>\d{1,5}))?'
            r'(?P<path>/.*)?$'
        )
        self.ssl_conf = {
            'COUNTRY': os.getenv('SSL_COUNTRY', 'US'),
            'STATE': os.getenv('SSL_STATE', 'California'),
            'LOCATION': os.getenv('SSL_CITY', 'Los Angeles'),
            'ORGANIZATION-GLOBAL': os.getenv('SSL_ORGANIZATION_GLOBAL', 'Company'),
            'ORGANIZATION-UNIT': os.getenv('SSL_ORGANIZATION_UNIT', 'IT'),
            'DAYS': os.getenv('SSL_DAYS', '365')
        }

    # ── Nginx reload ──────────────────────────────────────────────────

    def reload_nginx(self) -> tuple[bool, str]:
        with open(f'{self.app_scripts_path}/check_conf', 'w') as f:
            f.write('check')
        time.sleep(1)
        with open(f'{self.app_scripts_path}/check_conf_status', 'r') as f:
            return_code = f.readline().strip()
            if return_code != '0':
                error = f.read().strip()
                logger.error(f'Configuration check failed: {error}')
                return False, error
            else:
                with open(f'{self.app_scripts_path}/reload_nginx', 'w') as f:
                    f.write('reload')
                logger.info('Reloading Nginx')
                return True, 'OK'

    # ── Address validation ────────────────────────────────────────────

    def address_check(self, server: str) -> bool:
        m = self.addr_with_path_pattern.match(server.strip())
        if not m:
            return False
        host = m.group('host')
        port = m.group('port')
        path = m.group('path')
        if not re.match(self.ip_pattern, host):
            return False
        if port is not None:
            try:
                if not 1 <= int(port) <= 65535:
                    return False
            except ValueError:
                return False
        if path is not None and not path.startswith('/'):
            return False
        return True

    # ── Config file helpers ───────────────────────────────────────────

    def _conf_path(self, conf_name: str) -> str:
        """Return the actual path of the conf file (enabled or disabled)."""
        enabled = f'{self.app_conf_path}/{conf_name}.conf'
        disabled = f'{self.app_conf_path}/{conf_name}.conf.disabled'
        if os.path.exists(enabled):
            return enabled
        if os.path.exists(disabled):
            return disabled
        raise FileNotFoundError(f'No configuration found for {conf_name}')

    def _is_enabled(self, conf_name: str) -> bool:
        return os.path.exists(f'{self.app_conf_path}/{conf_name}.conf')

    def get_conf_list(self) -> list:
        names = set()
        for filename in os.listdir(self.app_conf_path):
            if filename.endswith('.conf.disabled'):
                names.add(filename[:-14])
            elif filename.endswith('.conf'):
                names.add(filename[:-5])
        return sorted(names)

    def get_conf(self, conf_name: str) -> str:
        with open(self._conf_path(conf_name), 'r') as f:
            return f.read().strip()

    def get_conf_infos(self, conf_name: str) -> Dict[str, Any]:
        with open(self._conf_path(conf_name), 'r') as f:
            conf = f.read()
        desc_match = re.search(r'#\s+(.+)\n', conf)
        description = desc_match.group(1).strip() if desc_match else ''
        sn_match = re.search(r'server_name\s+([^;]+);', conf)
        server_name = sn_match.group(1).strip() if sn_match else ''
        pp_match = re.search(r'proxy_pass\s+([^;]+);', conf)
        server = pp_match.group(1).strip() if pp_match else None
        cert_info = None
        cert_path = f'{self.app_ssl_path}/{conf_name}.crt'
        if os.path.exists(cert_path):
            try:
                with open(cert_path, 'rb') as f:
                    crt = x509.load_pem_x509_certificate(f.read(), default_backend())
                cert_info = {
                    'subject': crt.subject.rfc4514_string(),
                    'issuer': crt.issuer.rfc4514_string(),
                    'serial_number': crt.serial_number,
                    'not_valid_before': crt.not_valid_before_utc,
                    'not_valid_after': crt.not_valid_after_utc,
                }
            except Exception:
                pass
        return {
            'name': conf_name,
            'description': description,
            'server_name': server_name,
            'server': server,
            'certificate': cert_info,
        }

    def edit_conf(self,
                  conf_name: str,
                  conf_content: str,
                  cert_path: str = None,
                  key_path: str = None) -> None:
        with open(self._conf_path(conf_name), 'w') as f:
            f.write(conf_content.replace('\r\n', '\n').strip() + '\n')
        if cert_path and key_path:
            shutil.copy(cert_path, f'{self.app_ssl_path}/{conf_name}.crt')
            shutil.copy(key_path, f'{self.app_ssl_path}/{conf_name}.key')
            os.remove(cert_path)
            os.remove(key_path)
        logger.info(f'Configuration {conf_name} edited')

    def create_conf(self,
                    domain: str,
                    server: str,
                    description: str,
                    service_type: str,
                    allow_origin: str = '*',
                    cert_path: str = None,
                    key_path: str = None) -> None:
        conf = rf"""
    map $http_upgrade $connection_upgrade {{
        default upgrade;
        '' close;
    }}

    # {description}
    server {{
        listen 80;
        server_name {domain};
        return 301 https://$host$request_uri;
    }}
    server {{
        listen 443 ssl;

        ssl_certificate {self.real_ssl_path}/{domain}.crt;
        ssl_certificate_key {self.real_ssl_path}/{domain}.key;

        server_name {domain};

        error_log {self.real_log_path}/{domain}/error.log;
        access_log {self.real_log_path}/{domain}/access.log;

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-XSS-Protection "1; mode=block";
        add_header X-Content-Type-Options "nosniff";
        add_header Referrer-Policy "no-referrer";
        add_header Access-Control-Allow-Origin "{allow_origin}";
        add_header Cross-Origin-Embedder-Policy "require-corp";
        add_header Cross-Origin-Opener-Policy "same-origin";
        add_header Cross-Origin-Resource-Policy "same-site";

        # add_header Permissions-Policy ();
        add_header Content-Security-Policy "default-src 'self'; img-src 'self' data: https: http:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'";

        proxy_cookie_flags ~ secure httponly samesite=strict;

        location / {{
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Scheme $scheme;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Real-IP $remote_addr;

            proxy_pass {service_type}://{server};
        }}
    }}
    """
        os.makedirs(f'{self.app_log_path}/{domain}', exist_ok=True)
        with open(f'{self.app_conf_path}/{domain}.conf', 'w') as f:
            f.write(conf)
        if cert_path and key_path:
            shutil.copy(cert_path, f'{self.app_ssl_path}/{domain}.crt')
            shutil.copy(key_path, f'{self.app_ssl_path}/{domain}.key')
            os.remove(cert_path)
            os.remove(key_path)
        else:
            self.generate_ssl(domain)
        logger.info(f"Configuration {domain} created")

    def generate_ssl(self, domain: str) -> None:
        ssl_conf = self.ssl_conf
        ext_cnf_path = f'{self.app_ssl_path}/{domain}.ext.cnf'
        with open(ext_cnf_path, 'w') as f:
            f.write(rf"""
    [req]
    distinguished_name = req_distinguished_name
    x509_extensions = v3_req
    prompt = no
    [req_distinguished_name]
    C = {ssl_conf['COUNTRY']}
    ST = {ssl_conf['STATE']}
    L = {ssl_conf['LOCATION']}
    O = {ssl_conf['ORGANIZATION-GLOBAL']}
    OU = {ssl_conf['ORGANIZATION-UNIT']}
    [v3_req]
    keyUsage = critical, digitalSignature, keyAgreement
    extendedKeyUsage = serverAuth
    subjectAltName = @alt_names
    [alt_names]
    DNS.1 = {domain}
    """)
            try:
                subprocess.run([
                    'openssl', 'req', '-new', '-newkey', 'rsa:4096', '-sha256', '-days',
                    ssl_conf['DAYS'], '-nodes', '-x509', '-keyout', f'{self.app_ssl_path}/{domain}.key',
                    '-out', f'{self.app_ssl_path}/{domain}.crt',
                    '-subj', f"/C={ssl_conf['COUNTRY']}/ST={ssl_conf['STATE']}/L={ssl_conf['LOCATION']}/O={ssl_conf['ORGANIZATION-GLOBAL']}/OU={ssl_conf['ORGANIZATION-UNIT']}/CN={domain}",
                    '-config', ext_cnf_path
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to generate SSL certificate for {domain}: {e}")
            os.remove(ext_cnf_path)
        logger.info(f"SSL certificate for {domain} generated")

    def remove_conf(self, conf_name: str) -> None:
        try:
            os.remove(self._conf_path(conf_name))
        except FileNotFoundError:
            pass
        for ext in ['.crt', '.key']:
            p = f'{self.app_ssl_path}/{conf_name}{ext}'
            if os.path.exists(p):
                os.remove(p)
        shutil.rmtree(f'{self.app_log_path}/{conf_name}', ignore_errors=True)
        logger.info(f'Configuration {conf_name} removed')
        self.reload_nginx()

    def enable_conf(self, conf_name: str) -> None:
        os.rename(
            f'{self.app_conf_path}/{conf_name}.conf.disabled',
            f'{self.app_conf_path}/{conf_name}.conf'
        )
        logger.info(f'Configuration {conf_name} enabled')

    def disable_conf(self, conf_name: str) -> None:
        os.rename(
            f'{self.app_conf_path}/{conf_name}.conf',
            f'{self.app_conf_path}/{conf_name}.conf.disabled'
        )
        logger.info(f'Configuration {conf_name} disabled')

    # ── Status & monitoring ───────────────────────────────────────────

    def get_cert_expiry(self, conf_name: str) -> dict:
        cert_path = f'{self.app_ssl_path}/{conf_name}.crt'
        if not os.path.exists(cert_path):
            return {'days_left': None, 'expiry': None}
        try:
            with open(cert_path, 'rb') as f:
                crt = x509.load_pem_x509_certificate(f.read(), default_backend())
            expiry = crt.not_valid_after_utc
            days_left = (expiry - datetime.now(timezone.utc)).days
            return {'days_left': days_left, 'expiry': expiry.strftime('%Y-%m-%d')}
        except Exception:
            return {'days_left': None, 'expiry': None}

    def get_all_conf_status(self) -> dict:
        """Returns {conf_name: {enabled, days_left, expiry}} for all configs."""
        result = {}
        for conf_name in self.get_conf_list():
            expiry = self.get_cert_expiry(conf_name)
            result[conf_name] = {
                'enabled': self._is_enabled(conf_name),
                'days_left': expiry['days_left'],
                'expiry': expiry['expiry'],
            }
        return result

    def check_backend(self, proxy_pass_value: str) -> bool:
        """TCP connect check to the backend server."""
        server = re.sub(r'^https?://', '', proxy_pass_value.strip())
        m = self.addr_with_path_pattern.match(server)
        if not m:
            return False
        host = m.group('host')
        port = int(m.group('port') or 80)
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def get_log_tail(self, conf_name: str, lines: int = 200) -> str | None:
        log_path = f'{self.app_log_path}/{conf_name}/access.log'
        if not os.path.exists(log_path):
            return None
        with open(log_path, 'r', errors='replace') as f:
            all_lines = f.readlines()
        return ''.join(all_lines[-lines:])

    # ── Backup & restore ──────────────────────────────────────────────

    def backup_nginx(self) -> None:
        with tarfile.open(f'{self.app_scripts_path}/nginx.tar.gz', 'w:gz') as tar:
            tar.add(self.app_nginx_path, arcname=os.path.basename(self.app_nginx_path))
        logger.info('Nginx configuration backed up')

    def restore_backup(self, file_obj) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, 'restore.tar.gz')
            file_obj.save(archive_path)
            with tarfile.open(archive_path, 'r:gz') as tar:
                tar.extractall(path=tmp, filter='data')
            extracted = os.path.join(tmp, 'nginx')
            if not os.path.isdir(extracted):
                raise ValueError('Invalid backup: nginx directory not found in archive')
            # conf.d, certs (and nginx itself) are Docker volume mount points — we
            # cannot rmtree them (EBUSY). Clear their contents file-by-file instead.
            for subdir in ('conf.d', 'certs'):
                src = os.path.join(extracted, subdir)
                dst = os.path.join(self.app_nginx_path, subdir)
                if not os.path.isdir(src):
                    continue
                os.makedirs(dst, exist_ok=True)
                for name in os.listdir(dst):
                    p = os.path.join(dst, name)
                    shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
                for name in os.listdir(src):
                    shutil.copy2(os.path.join(src, name), os.path.join(dst, name))
            # Recreate per-domain log directories so nginx can open its log files
            for conf_name in self.get_conf_list():
                os.makedirs(os.path.join(self.app_log_path, conf_name), exist_ok=True)
        logger.info('Nginx configuration restored from backup')

    # ── Clone helper ──────────────────────────────────────────────────

    def parse_conf_for_clone(self, conf_name: str) -> dict:
        """Extract create-form values from an existing config."""
        conf = self.get_conf(conf_name)
        # description: first # comment
        desc_match = re.search(r'#\s+(.+)\n', conf)
        description = desc_match.group(1).strip() if desc_match else ''
        # allow_origin
        ao_match = re.search(r'Access-Control-Allow-Origin "([^"]+)"', conf)
        allow_origin = ao_match.group(1) if ao_match else '*'
        # service_type and server from proxy_pass
        pp_match = re.search(r'proxy_pass\s+(https?)://([^;]+);', conf)
        if pp_match:
            service_type = pp_match.group(1)
            server = pp_match.group(2).strip()
        else:
            service_type = 'http'
            server = ''
        return {
            'domain': '',  # intentionally blank — user must choose a new domain
            'server': server,
            'description': description,
            'allow_origin': allow_origin,
            'service_type': service_type,
        }

    # ── File upload helper ────────────────────────────────────────────

    def handle_cert_key_upload(self, conf_name: str, form_request: flask.Request) -> tuple[Any, Any]:
        cert = form_request.files['cert'] if 'cert' in form_request.files else None
        key = form_request.files['key'] if 'key' in form_request.files else None
        cert_text = form_request.form['cert_text'] if 'cert_text' in form_request.form else None
        key_text = form_request.form['key_text'] if 'key_text' in form_request.form else None

        tmp_cert_path = f'{self.app_scripts_path}/{conf_name}.crt'
        tmp_key_path = f'{self.app_scripts_path}/{conf_name}.key'

        if (not cert and key) or (not cert_text and key_text):
            tmp_cert_path = tmp_key_path = None
        elif cert and cert.filename and key and key.filename:
            cert.save(tmp_cert_path)
            key.save(tmp_key_path)
        elif cert_text and key_text:
            with open(tmp_cert_path, 'w') as f:
                f.write(cert_text)
            with open(tmp_key_path, 'w') as f:
                f.write(key_text)
        else:
            tmp_cert_path = tmp_key_path = None
        return tmp_cert_path, tmp_key_path


# ── Routes ────────────────────────────────────────────────────────────

@bp.route('/manage', methods=['GET', 'POST'])
@login_required
def manage() -> str | flask.Response:
    handler = ReverseProxyManager()
    conf_list = handler.get_conf_list()
    conf_status = handler.get_all_conf_status()

    if request.method == 'POST':
        # Edit form submission
        if 'new_conf' in request.form:
            conf_name = request.form['conf_name']
            new_conf = request.form['new_conf']
            cert_path, key_path = handler.handle_cert_key_upload(conf_name, request)
            handler.edit_conf(conf_name, new_conf, cert_path, key_path)
            check, status = handler.reload_nginx()
            if not check:
                return render_template('manage.html', conf_list=conf_list, conf_status=conf_status,
                                       message='Failed to reload Nginx — check configuration syntax',
                                       error=status, success=False, conf_edit=new_conf, conf_name=conf_name)
            if 'renew' in request.form:
                handler.generate_ssl(conf_name)
            conf_status = handler.get_all_conf_status()
            return render_template('manage.html', conf_list=conf_list, conf_status=conf_status,
                                   message='Configuration saved', success=True)

        action = request.form['action']
        conf_name = request.form['conf']

        if action == 'view':
            conf_infos = handler.get_conf_infos(conf_name)
            return render_template('manage.html', conf_list=conf_list, conf_status=conf_status,
                                   conf_infos=conf_infos)

        elif action == 'delete':
            handler.remove_conf(conf_name)
            conf_list = handler.get_conf_list()
            conf_status = handler.get_all_conf_status()
            return render_template('manage.html', conf_list=conf_list, conf_status=conf_status,
                                   message=f'"{conf_name}" deleted', success=True)

        elif action == 'edit':
            conf_content = handler.get_conf(conf_name)
            return render_template('manage.html', conf_list=conf_list, conf_status=conf_status,
                                   conf_edit=conf_content, conf_name=conf_name)

        elif action == 'logs':
            log_content = handler.get_log_tail(conf_name, lines=50)
            return render_template('manage.html', conf_list=conf_list, conf_status=conf_status,
                                   log_content=log_content, log_conf_name=conf_name)

        elif action == 'toggle':
            if handler._is_enabled(conf_name):
                handler.disable_conf(conf_name)
                msg = f'"{conf_name}" disabled'
            else:
                handler.enable_conf(conf_name)
                msg = f'"{conf_name}" enabled'
            handler.reload_nginx()
            conf_list = handler.get_conf_list()
            conf_status = handler.get_all_conf_status()
            return render_template('manage.html', conf_list=conf_list, conf_status=conf_status,
                                   message=msg, success=True)

        elif action == 'clone':
            prefill = handler.parse_conf_for_clone(conf_name)
            return render_template('create.html', prefill=prefill, clone_source=conf_name)

    return render_template('manage.html', conf_list=conf_list, conf_status=conf_status)


@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create() -> str:
    if request.method == 'POST':
        handler = ReverseProxyManager()
        domain = request.form['domain']
        server = request.form['server']
        description = request.form['description']
        service_type = request.form['service_type']
        allow_origin = request.form['allow_origin']

        if domain == '' or server == '':
            return render_template('create.html', message='Domain and server address are required', success=False)
        if allow_origin == '':
            allow_origin = '*'

        cert_path, key_path = handler.handle_cert_key_upload(domain, request)

        if domain in handler.get_conf_list():
            return render_template('create.html', message='Domain already exists', success=False)
        if not handler.address_check(server):
            return render_template('create.html', message='Invalid server address', success=False)

        handler.create_conf(domain, server, description, service_type, allow_origin, cert_path, key_path)
        check, status = handler.reload_nginx()
        if not check:
            return render_template('create.html',
                                   message='Configuration created but Nginx failed to reload — check syntax',
                                   error=status, success=False)

        return render_template('create.html', message=f'"{domain}" created successfully', success=True)
    return render_template('create.html')


@bp.route('/backup', methods=['GET'])
@login_required
def backup() -> str:
    return render_template('backup.html')


@bp.route('/backup/download', methods=['GET'])
@login_required
def backup_download() -> flask.Response:
    handler = ReverseProxyManager()
    handler.backup_nginx()
    return send_from_directory(directory=f'{handler.app_scripts_path}',
                               path='nginx.tar.gz', as_attachment=True)


@bp.route('/backup/restore', methods=['POST'])
@login_required
def backup_restore() -> str:
    handler = ReverseProxyManager()
    if 'backup_file' not in request.files or not request.files['backup_file'].filename:
        return render_template('backup.html', message='No file selected', success=False)
    f = request.files['backup_file']
    if not f.filename.endswith('.tar.gz'):
        return render_template('backup.html', message='File must be a .tar.gz archive', success=False)
    try:
        handler.restore_backup(f)
        check, status = handler.reload_nginx()
        if not check:
            return render_template('backup.html',
                                   message='Restored but Nginx failed to reload — check configurations',
                                   error=status, success=False)
        return render_template('backup.html', message='Backup restored and Nginx reloaded', success=True)
    except Exception as e:
        logger.error(f'Restore failed: {e}')
        return render_template('backup.html', message=f'Restore failed: {e}', success=False)


@bp.route('/api/status', methods=['GET'])
@login_required
def api_status() -> flask.Response:
    """Returns JSON {conf_name: bool} indicating backend reachability."""
    handler = ReverseProxyManager()
    conf_list = handler.get_conf_list()

    def check_one(conf_name: str) -> bool:
        try:
            conf = handler.get_conf(conf_name)
            proxy_pass = conf.split('proxy_pass ')[1].split(';')[0].strip()
            return handler.check_backend(proxy_pass)
        except Exception:
            return False

    results = {}
    if conf_list:
        with ThreadPoolExecutor(max_workers=min(len(conf_list), 20)) as executor:
            for conf_name, reachable in zip(conf_list, executor.map(check_one, conf_list)):
                results[conf_name] = reachable

    return jsonify(results)
