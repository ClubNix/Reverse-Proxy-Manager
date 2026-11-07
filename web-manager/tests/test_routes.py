"""Tests for the /manager pages, going through Flask like a browser would."""
import os

import pytest


@pytest.fixture
def web(logged_in_client, fake_nginx):
    """Logged-in client whose actions write into the temporary nginx folders."""
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
