from fastapi.testclient import TestClient
import pytest

from privacy_bot.app import create_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv('PUBLIC_URL', 'https://privacy.example.com/privacy-bot/')
    monkeypatch.setenv('ROOT_PATH', '/privacy-bot')
    monkeypatch.setenv('PRIVACY_BOT_ACCESS', 'network')
    monkeypatch.setenv('PRIVACY_BOT_ALLOWED_NETWORKS', '10.42.0.0/24,100.64.0.0/10,fd7a:115c:a1e0::/48')
    monkeypatch.setenv('PRIVACY_BOT_TRUSTED_PROXIES', '172.30.0.2/32')
    monkeypatch.delenv('PRIVACY_BOT_TOKEN', raising=False)
    value = create_app(tmp_path)
    yield value
    value.state.db.close()


def client(app, peer):
    return TestClient(app, base_url='https://privacy.example.com', client=(peer, 23456))


@pytest.mark.parametrize('peer', ['10.42.0.10', '100.80.1.2', 'fd7a:115c:a1e0::123'])
def test_home_network_opens_without_token_or_cookie(app, peer):
    c = client(app, peer)
    response = c.get('/privacy-bot/api/session')
    assert response.json() == {'authenticated': True, 'access_mode': 'network'}
    assert 'set-cookie' not in response.headers
    assert c.get('/privacy-bot/api/dashboard').status_code == 200
    assert not (app.state.db.root / 'access-token').exists()


@pytest.mark.parametrize('peer', ['8.8.8.8', '172.30.0.9', '192.168.224.1'])
def test_untrusted_peer_cannot_forge_proxy_identity(app, peer):
    c = client(app, peer)
    response = c.get('/privacy-bot/api/dashboard', headers={'X-Forwarded-For': '10.42.0.9', 'X-Forwarded-Proto': 'https'})
    assert response.status_code == 403
    assert c.get('/privacy-bot/browser.html').status_code == 403


@pytest.mark.parametrize('headers, expected', [
    ({'X-Forwarded-For': '10.42.0.7'}, 200),
    ({'X-Forwarded-For': '100.80.1.2'}, 200),
    ({'X-Forwarded-For': '8.8.8.8'}, 403),
    ({'X-Forwarded-For': '10.42.0.7, 8.8.8.8'}, 403),
    ({}, 403),
    ([('X-Forwarded-For', '10.42.0.7'), ('X-Forwarded-For', '8.8.8.8')], 403),
])
def test_only_explicit_proxy_may_forward_one_allowed_address(app, headers, expected):
    assert client(app, '172.30.0.2').get('/privacy-bot/api/dashboard', headers=headers).status_code == expected


def test_host_origin_and_write_header_still_required(app):
    c = client(app, '10.42.0.10')
    assert c.get('/privacy-bot/api/dashboard', headers={'Host': 'evil.example', 'X-Forwarded-Host': 'privacy.example.com'}).status_code == 400
    assert c.put('/privacy-bot/api/profile', json={'name': 'Forged'}).status_code == 403
    assert c.put('/privacy-bot/api/profile', json={'name': 'Forged'}, headers={'X-Privacy-Bot': '1', 'Origin': 'https://evil.example'}).status_code == 403
    assert c.get('/privacy-bot/api/dashboard').json()['profile']['name'] == ''
    valid = c.put('/privacy-bot/api/profile', json={'name': 'Synthetic LAN Owner'}, headers={'X-Privacy-Bot': '1', 'Origin': 'https://privacy.example.com'})
    assert valid.status_code == 200


def test_public_health_is_not_private_data_access(app):
    c = client(app, '8.8.8.8')
    response = c.get('/healthz', headers={'Host': '127.0.0.1'})
    assert response.status_code == 200 and set(response.json()) == {'status', 'revision', 'scheduler'}
    assert c.get('/privacy-bot/api/session').status_code == 403
