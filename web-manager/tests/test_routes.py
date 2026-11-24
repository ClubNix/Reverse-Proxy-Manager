"""Tests for the /manager pages, going through Flask like a browser would."""
import os
import re

import pytest


def csrf_token_from(client, url='/manager/create'):
    """Read the CSRF token from the hidden field of a rendered manager form."""
    page = client.get(url).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)


@pytest.fixture
def web(logged_in_client, fake_nginx):
    """Logged-in client whose actions write into the temporary nginx folders.

    Like a browser submitting the manager's forms, every POST carries the
    CSRF token rendered in those forms.
    """
    token = csrf_token_from(logged_in_client)
    post = logged_in_client.post

    def post_with_csrf_token(*args, data=None, **kwargs):
        return post(*args, data={**(data or {}), 'csrf_token': token}, **kwargs)

    logged_in_client.post = post_with_csrf_token
    return logged_in_client


def create(web, domain='app.example.com', server='10.0.0.5:8080'):
    return web.post('/manager/create', data={
        'domain': domain, 'server': server, 'description': 'My app',
        'service_type': 'http', 'allow_origin': ''})


def test_create_page_creates_configuration(web, fake_nginx):
    response = create(web)

    assert b'created successfully' in response.data
    conf = (fake_nginx / 'conf.d' / 'app.example.com.conf').read_text()
    assert 'proxy_pass http://10.0.0.5:8080;' in conf
    # An empty "allow origin" defaults to "*"
    assert 'Access-Control-Allow-Origin "*"' in conf
    assert (fake_nginx / 'certs' / 'app.example.com.crt').exists()


def test_create_rejects_duplicate_domain(web):
    create(web)

    response = create(web)

    assert b'Domain already exists' in response.data


def test_create_rejects_invalid_server_address(web, fake_nginx):
    response = create(web, server='not-an-ip')

    assert b'Invalid server address' in response.data
    assert not (fake_nginx / 'conf.d' / 'app.example.com.conf').exists()


def test_create_requires_domain_and_server(web):
    response = create(web, domain='', server='')

    assert b'Domain and server address are required' in response.data


def test_create_reports_nginx_check_failure(web, fake_nginx):
    (fake_nginx.parent / 'scripts' / 'check_conf_status').write_text('1\nbad config\n')

    response = create(web)

    assert b'Nginx failed to reload' in response.data
    assert b'bad config' in response.data


def test_toggle_disables_conf_and_publishes_unavailable_page(web, fake_nginx):
    create(web)

    response = web.post('/manager/manage', data={'action': 'toggle', 'conf': 'app.example.com'})

    assert b'disabled' in response.data
    assert (fake_nginx / 'conf.d' / 'app.example.com.conf.disabled').exists()
    unavailable = (fake_nginx / 'conf.d' / 'disabled.unavailable').read_text()
    assert 'server_name app.example.com;' in unavailable

    # Toggling again re-enables it and removes it from the unavailable list
    web.post('/manager/manage', data={'action': 'toggle', 'conf': 'app.example.com'})
    assert (fake_nginx / 'conf.d' / 'app.example.com.conf').exists()
    unavailable = (fake_nginx / 'conf.d' / 'disabled.unavailable').read_text()
    assert 'app.example.com' not in unavailable


def test_delete_removes_conf(web, fake_nginx):
    create(web)

    web.post('/manager/manage', data={'action': 'delete', 'conf': 'app.example.com'})

    assert os.listdir(fake_nginx / 'conf.d') == ['disabled.unavailable']


@pytest.mark.parametrize('action', ['view', 'edit', 'logs', 'toggle', 'clone', 'delete'])
def test_manage_actions_reject_unknown_conf(web, fake_nginx, action):
    # A config outside conf.d that a traversal name would point at
    outside = fake_nginx / 'outside.conf'
    outside.write_text('server { listen 80; }\n')

    response = web.post('/manager/manage', data={'action': action, 'conf': '../outside'})

    assert b'Configuration not found' in response.data
    assert outside.read_text() == 'server { listen 80; }\n'
    assert not (fake_nginx / 'outside.conf.disabled').exists()


def test_edit_saves_new_content(web, fake_nginx):
    create(web)

    response = web.post('/manager/manage', data={
        'conf_name': 'app.example.com', 'new_conf': 'server { listen 80; }'})

    assert b'Configuration saved' in response.data
    assert (fake_nginx / 'conf.d' / 'app.example.com.conf').read_text() == 'server { listen 80; }\n'


def test_view_shows_configuration_details(web):
    create(web)

    response = web.post('/manager/manage', data={'action': 'view', 'conf': 'app.example.com'})

    assert response.status_code == 200
    assert b'app.example.com' in response.data
    assert b'10.0.0.5:8080' in response.data


def test_clone_prefills_create_form(web):
    create(web)

    response = web.post('/manager/manage', data={'action': 'clone', 'conf': 'app.example.com'})

    assert response.status_code == 200
    assert b'10.0.0.5:8080' in response.data


def test_backup_download_returns_archive(web):
    create(web)

    response = web.get('/manager/backup/download')

    assert response.status_code == 200
    assert response.data[:2] == b'\x1f\x8b'  # gzip magic number


def test_restore_rejects_non_tar_gz(web):
    from io import BytesIO
    response = web.post('/manager/backup/restore', data={
        'backup_file': (BytesIO(b'x'), 'backup.zip')}, content_type='multipart/form-data')

    assert b'File must be a .tar.gz archive' in response.data


# ── CSRF protection ───────────────────────────────────────────────────

CREATE_FORM = {'domain': 'app.example.com', 'server': '10.0.0.5:8080', 'description': 'My app',
               'service_type': 'http', 'allow_origin': ''}


@pytest.mark.parametrize('token', [None, '', 'forged-token'])
def test_create_without_valid_csrf_token_is_rejected(logged_in_client, fake_nginx, token):
    csrf_token_from(logged_in_client)  # the session holds a real token
    data = CREATE_FORM if token is None else {**CREATE_FORM, 'csrf_token': token}

    response = logged_in_client.post('/manager/create', data=data)

    assert response.status_code == 400
    assert os.listdir(fake_nginx / 'conf.d') == []


@pytest.mark.parametrize('data', [
    {'conf_name': 'app.example.com', 'new_conf': 'server { listen 80; }'},
    {'action': 'toggle', 'conf': 'app.example.com'},
    {'action': 'delete', 'conf': 'app.example.com'},
])
@pytest.mark.parametrize('token', [None, 'forged-token'])
def test_manage_without_valid_csrf_token_is_rejected(logged_in_client, fake_nginx, data, token):
    real_token = csrf_token_from(logged_in_client)
    logged_in_client.post('/manager/create', data={**CREATE_FORM, 'csrf_token': real_token})
    conf = fake_nginx / 'conf.d' / 'app.example.com.conf'
    original = conf.read_text()
    if token is not None:
        data = {**data, 'csrf_token': token}

    response = logged_in_client.post('/manager/manage', data=data)

    assert response.status_code == 400
    assert conf.read_text() == original


def test_restore_without_csrf_token_is_rejected(logged_in_client, fake_nginx):
    from io import BytesIO
    csrf_token_from(logged_in_client)

    response = logged_in_client.post('/manager/backup/restore', data={
        'backup_file': (BytesIO(b'x'), 'backup.tar.gz')}, content_type='multipart/form-data')

    assert response.status_code == 400


def test_manager_forms_carry_the_session_csrf_token(web):
    create(web)
    token = csrf_token_from(web)

    for url in ('/manager/manage', '/manager/backup'):
        assert csrf_token_from(web, url) == token


def test_anonymous_post_still_redirects_to_login(client):
    response = client.post('/manager/manage', data={'action': 'delete', 'conf': 'app.example.com'})

    assert response.status_code == 302


# ── Create form validation ────────────────────────────────────────────

@pytest.mark.parametrize('domain', [
    'app.example.com\nserver_name evil.com', 'app example.com', 'app.example.com;',
    '-app.example.com', 'app..example.com', 'a' * 64 + '.com', 'app.example.com"',
])
def test_create_rejects_invalid_domain(web, fake_nginx, domain):
    response = create(web, domain=domain)

    assert b'Invalid domain name' in response.data
    assert os.listdir(fake_nginx / 'conf.d') == []


@pytest.mark.parametrize('domain', ['localhost', 'app-1.example.com', '*.example.com'])
def test_create_accepts_valid_domain(web, fake_nginx, domain):
    response = create(web, domain=domain)

    assert b'created successfully' in response.data


@pytest.mark.parametrize('field, value, message', [
    ('description', 'My app\n    } server { listen 80;', b'cannot contain'),
    ('allow_origin', '*" always;\n    add_header X-Evil "1', b'cannot contain'),
    ('allow_origin', 'https://a.example\\', b'cannot contain'),
    ('service_type', 'http://10.0.0.6;#', b'Invalid service type'),
])
def test_create_rejects_text_that_would_inject_nginx_directives(web, fake_nginx,
                                                                field, value, message):
    response = web.post('/manager/create', data={**CREATE_FORM, field: value})

    assert message in response.data
    assert os.listdir(fake_nginx / 'conf.d') == []
