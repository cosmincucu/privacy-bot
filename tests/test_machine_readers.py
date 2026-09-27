import hashlib
import json
import secrets

from fastapi.testclient import TestClient
import pytest

from privacy_bot.app import create_app
from privacy_bot.machine_access import JobReaders, job_metadata


@pytest.fixture
def configured(tmp_path, monkeypatch):
    token = secrets.token_urlsafe(32)
    document = {'schema_version': 1, 'readers': [
        {'id': 'assistant', 'sha256': hashlib.sha256(token.encode()).hexdigest()}]}
    registry = tmp_path/'readers.json'
    registry.write_text(json.dumps(document), encoding='utf-8')
    registry.chmod(0o600)
    monkeypatch.setenv('PRIVACY_BOT_JOB_READERS_FILE', str(registry))
    monkeypatch.setenv('PUBLIC_URL', 'https://privacy.example.test/privacy-bot/')
    monkeypatch.setenv('ROOT_PATH', '/privacy-bot')
    monkeypatch.setenv('PRIVACY_BOT_ACCESS', 'network')
    monkeypatch.setenv('PRIVACY_BOT_ALLOWED_NETWORKS', '10.42.0.0/24')
    monkeypatch.delenv('PRIVACY_BOT_TRUSTED_PROXIES', raising=False)
    app = create_app(tmp_path/'data')
    yield app, token, registry, document
    app.state.db.close()


def client(app, peer='172.30.0.9'):
    return TestClient(app, base_url='https://privacy.example.test', client=(peer, 3456))


def test_named_reader_is_distinct_from_network_access(configured):
    app, token, _, _ = configured
    c = client(app)
    path = '/privacy-bot/api/dashboard'
    assert c.get(path).status_code == 403
    assert c.get(path, headers={'X-Forwarded-For': '10.42.0.8', 'X-Caller': 'assistant'}).status_code == 403
    result = c.get(path, headers={'Authorization': 'Bearer '+token})
    assert result.status_code == 200
    assert result.headers['cache-control'] == 'no-store'
    assert result.json()['sources']
    assert 'profile' not in result.json() and 'credit' not in result.json()


@pytest.mark.parametrize('method,path', [('GET', '/api/profile'), ('GET', '/api/session'),
    ('POST', '/api/login'), ('POST', '/api/sources'), ('POST', '/api/scan'),
    ('PUT', '/api/settings'), ('POST', '/api/removals'), ('HEAD', '/api/dashboard'),
    ('GET', '/api/dashboard/'), ('GET', '/browser.html'), ('GET', '/healthz')])
def test_reader_cannot_write_login_or_read_another_surface(configured, method, path):
    app, token, _, _ = configured
    response = client(app).request(method, '/privacy-bot'+path, headers={
        'Authorization': 'Bearer '+token, 'X-Privacy-Bot': '1', 'Origin': 'https://privacy.example.test'},
        follow_redirects=False)
    assert response.status_code == 403


def test_bad_or_duplicate_credential_cannot_fall_back_to_lan(configured):
    app, token, _, _ = configured
    c = client(app, '10.42.0.5')
    assert c.get('/privacy-bot/api/dashboard').status_code == 200
    for authorization in ('Bearer short', 'Basic ignored', 'Bearer '+secrets.token_urlsafe(32)):
        assert c.get('/privacy-bot/api/dashboard', headers={'Authorization': authorization}).status_code == 401
    assert c.get('/privacy-bot/api/dashboard', headers=[('Authorization', 'Bearer '+token),
        ('Authorization', 'Bearer '+token)]).status_code == 401


def test_reader_preserves_expected_host(configured):
    app, token, _, _ = configured
    assert client(app).get('/privacy-bot/api/dashboard', headers={
        'Authorization': 'Bearer '+token, 'Host': 'wrong.example.test'}).status_code == 400


def test_server_projects_sensitive_nested_content_before_response(configured):
    app, token, _, _ = configured
    db = app.state.db
    db.put('meta', {'name': 'PRIVATE-PROFILE-CANARY'}, 'profile')
    db.put('findings', {'source_id': 'synthetic', 'status': 'possible',
                       'evidence': {'email': 'PRIVATE-FINDING-CANARY'}})
    db.put('runs', {'source_id': 'synthetic', 'status': 'blocked', 'no_match': False,
                   'created_at': '2026-01-01T00:00:00Z', 'detail': 'PRIVATE-RUN-CANARY'})
    result = client(app).get('/privacy-bot/api/dashboard', headers={'Authorization': 'Bearer '+token})
    assert result.status_code == 200
    assert 'PRIVATE-' not in result.text
    assert result.json()['findings'] == [{'source_id': 'synthetic', 'status': 'possible'}]
    assert set(result.json()['runs'][0]) == {'source_id', 'status', 'no_match', 'created_at'}
    for source in result.json()['sources']:
        assert set(source) == {'id', 'name', 'kind', 'region', 'mode', 'enabled', 'status', 'last_checked'}
    assert 'PRIVATE-PROFILE-CANARY' in client(app, '10.42.0.4').get('/privacy-bot/api/dashboard').text


def test_projection_never_queries_profile_or_credit_collections():
    class EmptyStore:
        def all(self, name):
            assert name in {'sources', 'runs', 'findings', 'removals', 'alerts'}
            return []
        def get(self, collection, key):
            assert (collection, key) in {('meta', 'settings'), ('meta', 'notification_status')}
            return {}
    assert job_metadata(EmptyStore())['sources'] == []


def test_registry_refuses_ambiguous_or_expanded_permissions(configured):
    _, _, _, document = configured
    for value in ({}, [], {'schema_version': True, 'readers': []},
        {'schema_version': 1, 'readers': document['readers']*2},
        {'schema_version': 1, 'readers': [{**document['readers'][0], 'scope': '*'}]}):
        with pytest.raises(ValueError):
            JobReaders(value)


def test_registry_permissions_and_revocation(configured, tmp_path):
    _, token, registry, _ = configured
    assert JobReaders.from_file(registry).authenticate(['Bearer '+token]) == 'assistant'
    registry.write_text('{"schema_version":1,"readers":[]}', encoding='utf-8')
    assert JobReaders.from_file(registry).authenticate(['Bearer '+token]) is None
    registry.chmod(0o644)
    with pytest.raises(ValueError):
        JobReaders.from_file(registry)
    registry.chmod(0o600)
    link = tmp_path/'linked-readers'
    link.symlink_to(registry)
    with pytest.raises(ValueError):
        JobReaders.from_file(link)


def test_reader_also_works_in_token_mode(configured, monkeypatch, tmp_path):
    _, token, _, _ = configured
    monkeypatch.setenv('PRIVACY_BOT_ACCESS', 'token')
    app = create_app(tmp_path/'token-mode')
    try:
        c = client(app)
        assert c.get('/privacy-bot/api/dashboard').status_code == 401
        assert c.get('/privacy-bot/api/dashboard', headers={'Authorization': 'Bearer '+token}).status_code == 200
    finally:
        app.state.db.close()
