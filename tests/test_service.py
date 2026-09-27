import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient

from privacy_bot.app import create_app
from privacy_bot.scanner import hibp_lookup, page_matches, scan_source

TOKEN = 'test-token-for-fixtures-only-1234567890'
HEADERS = {'X-Privacy-Bot': '1'}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('PRIVACY_BOT_TOKEN', TOKEN)
    monkeypatch.delenv('PUBLIC_URL', raising=False)
    monkeypatch.delenv('ROOT_PATH', raising=False)
    app = create_app(tmp_path)
    with TestClient(app) as c:
        assert c.post('/api/login', json={'token': TOKEN}, headers=HEADERS).status_code == 200
        c.headers.update(HEADERS)
        yield c


def report(agency='experian', day='2026-01-01'):
    return {'agency': agency, 'report_date': day, 'complete': True, 'searches': [], 'accounts': [], 'addresses': [], 'public_records': []}


def test_access_csrf_and_no_secret_readback(client):
    assert client.get('/api/session').json()['authenticated']
    r = client.put('/api/profile', json={'name': 'Private Fixture', 'email': 'fixture@example.com', 'addresses': [], 'aliases': []}, headers={'Origin': 'https://attacker.example'})
    assert r.status_code == 403
    r = client.put('/api/connections', json={'hibp_api_key': 'fixture-secret-value', 'smtp_host': 'mail.example.com', 'smtp_from': 'fixture@example.com'})
    assert r.status_code == 200
    assert 'fixture-secret-value' not in client.get('/api/connections').text
    assert client.post('/api/logout').status_code == 200
    assert client.get('/api/dashboard').status_code == 401


def test_credit_baseline_soft_hard_and_address_changes(client):
    first = report()
    assert client.post('/api/credit/import', json={'report': first}).json()['baseline']
    second = report(day='2026-01-02')
    second['searches'] = [{'id': 'insurance', 'date': '2026-01-02', 'organisation': 'Insurance Fixture', 'type': 'soft', 'purpose': 'quotation'}]
    r = client.post('/api/credit/import', json={'report': second})
    assert r.status_code == 200, r.text
    assert all(e['severity'] == 'routine' for e in r.json()['events'])
    assert not client.get('/api/dashboard').json()['alerts']
    third = copy.deepcopy(second)
    third['report_date'] = '2026-01-03'
    third['searches'].append({'id': 'loan', 'date': '2026-01-03', 'organisation': 'Bank Fixture', 'type': 'hard', 'purpose': 'application'})
    third['addresses'] = [{'id': 'new-address', 'address': '10 Synthetic Road', 'current': True}]
    r = client.post('/api/credit/import', json={'report': third})
    assert r.status_code == 200, r.text
    assert {'new_hard_search', 'address_added'} <= {e['kind'] for e in r.json()['events']}
    data = client.get('/api/dashboard').json()
    assert len(data['alerts']) == 2
    ex = next(c for c in data['credit'] if c['agency'] == 'experian')
    assert ex['snapshot_count'] == 3 and ex['soft_count'] == 1
    assert client.post('/api/credit/import', json={'report': third}).json()['duplicate']
    assert len(client.get('/api/dashboard').json()['alerts']) == 2


@pytest.mark.parametrize('mutate', [lambda r: r.pop('accounts'), lambda r: r.update(complete=False), lambda r: r.update(searches={}), lambda r: r.update(report_date='2999-01-01')])
def test_malformed_and_future_reports_do_not_erase_baseline(client, mutate):
    first = report()
    client.post('/api/credit/import', json={'report': first})
    newer = report(day='2026-01-02')
    mutate(newer)
    assert client.post('/api/credit/import', json={'report': newer}).status_code == 400
    summaries = client.get('/api/dashboard').json()['credit']
    assert next(c for c in summaries if c['agency'] == 'experian')['snapshot_count'] == 1


def test_three_agencies_independent_and_same_date_conflict(client):
    for agency in ('experian', 'equifax', 'transunion'):
        assert client.post('/api/credit/import', json={'report': report(agency)}).status_code == 200
    conflict = report()
    conflict['addresses'] = [{'id': 'new', 'address': '1 New Street', 'current': True}]
    assert client.post('/api/credit/import', json={'report': conflict}).status_code == 400
    assert client.post('/api/credit/import', json={'report': report(day='2025-12-31')}).status_code == 400
    assert all(c['snapshot_count'] == 1 for c in client.get('/api/dashboard').json()['credit'])


def test_credit_alert_failure_rolls_back_snapshot(client):
    client.post('/api/credit/import', json={'report': report()})
    db = client.app.state.db
    db.conn.execute("CREATE TRIGGER fail_alert BEFORE INSERT ON records WHEN NEW.collection='alerts' BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")
    newer = report(day='2026-01-02')
    newer['addresses'] = [{'id': 'new', 'address': '1 Synthetic Street', 'current': True}]
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        client.post('/api/credit/import', json={'report': newer})
    assert len(db.all('snapshots')) == 1
    assert db.all('credit_events') == [] and db.all('alerts') == []
    db.conn.execute('DROP TRIGGER fail_alert')
    assert client.post('/api/credit/import', json={'report': newer}).status_code == 200
    assert len(db.all('alerts')) == 1


def test_single_source_check_does_not_delay_other_scheduled_sources(client):
    db = client.app.state.db
    before = {'last_scan': '2026-01-01T00:00:00+00:00'}
    db.put('meta', before, 'schedule')
    client.post('/api/scan', json={'source_id': 'hibp'})
    assert db.get('meta', 'schedule')['last_scan'] == before['last_scan']


def test_no_sources_enabled_by_default_and_no_direct_onion(client):
    assert client.post('/api/scan', json={}).json() == {'runs': []}
    assert client.patch('/api/sources/hibp-stealer', json={'mode': 'onion'}).status_code == 400
    assert client.post('/api/browser/hibp-stealer/start').status_code == 400
    assert client.put('/api/connections', json={'tor_proxy': 'socks5://127.0.0.1:9050'}).status_code == 400
    r = client.post('/api/scan', json={'source_id': 'hibp'})
    assert r.json()['runs'][0]['status'] == 'needs_setup'


def test_encrypted_profile_and_report_file_review(client):
    marker = 'private-marker-694732@example.com'
    assert client.put('/api/profile', json={'name': 'Test Person', 'email': marker}).status_code == 200
    for filename in ('privacy.sqlite3', 'privacy.sqlite3-wal'):
        path = client.app.state.db.root / filename
        if path.exists():
            assert marker.encode() not in path.read_bytes()
    r = client.post('/api/credit/extract', files={'file': ('report.txt', b'Hard search: unknown unstructured layout', 'text/plain')})
    assert r.status_code == 200 and r.json()['needs_review'] and r.json()['report'] is None
    r = client.post('/api/credit/extract', files={'file': ('report.json', json.dumps(report()).encode(), 'application/json')})
    assert r.status_code == 200 and not r.json()['needs_review']
    assert all(c['snapshot_count'] == 0 for c in client.get('/api/dashboard').json()['credit'])


def test_removal_requires_review_and_uncertain_send_not_retried(client, monkeypatch):
    client.put('/api/profile', json={'name': 'Fixture Person', 'email': 'fixture@example.com'})
    db = client.app.state.db
    found = db.put('findings', {'source_id': '192', 'title': 'Fixture', 'url': 'https://www.192.com/example', 'status': 'candidate', 'first_seen': '2026-01-01'})
    assert client.post('/api/removals', json={'finding_id': found['id']}).status_code == 400
    client.patch('/api/findings/' + found['id'], json={'status': 'confirmed'})
    r = client.post('/api/removals', json={'finding_id': found['id']})
    assert r.status_code == 200, r.text
    request_id = r.json()['id']
    assert client.post('/api/removals', json={'finding_id': found['id']}).json()['id'] == request_id
    client.patch('/api/removals/' + request_id, json={'recipient': 'privacy@example.com'})
    client.put('/api/connections', json={'smtp_host': 'mail.example.com', 'smtp_from': 'fixture@example.com'})
    calls = []
    def fail_send(*args):
        calls.append(True)
        assert db.get('removals', request_id)['status'] == 'submitting'
        raise TimeoutError('transport failed')
    monkeypatch.setattr('privacy_bot.app.send_email', fail_send)
    r = client.post('/api/removals/' + request_id + '/send', json={'confirm': True})
    assert r.json()['status'] == 'uncertain'
    assert client.post('/api/removals/' + request_id + '/send', json={'confirm': True}).status_code == 400
    assert len(calls) == 1
    assert client.patch('/api/removals/' + request_id, json={'status': 'verified_removed'}).status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize('code, expected', [(404, 'checked'), (401, 'needs_setup'), (403, 'needs_setup'), (429, 'blocked'), (503, 'error'), (302, 'error')])
async def test_hibp_non_success_not_clean(code, expected):
    seen = []
    def respond(req):
        seen.append(req)
        return httpx.Response(code, headers={'location': 'https://evil.example/'}, json={})
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as c:
        result = await hibp_lookup({'mode': 'hibp'}, {'email': 'fixture@example.com'}, {'hibp_api_key': 'test'}, c)
    assert result['status'] == expected
    assert len(seen) == 1 and seen[0].url.host == 'haveibeenpwned.com'
    assert result.get('no_match', False) == (code == 404)


@pytest.mark.asyncio
async def test_breach_and_stealer_metadata_only():
    def respond(req):
        if 'stealerLogs' in req.url.path:
            return httpx.Response(200, json=['example.com'])
        return httpx.Response(200, json=[{'Name': 'Synthetic', 'BreachDate': '2020-01-01', 'DataClasses': ['Email addresses'], 'Description': '<script>evil</script>'}])
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as c:
        for mode in ('hibp', 'hibp_stealer'):
            data = await hibp_lookup({'mode': mode}, {'email': 'fixture@example.com'}, {'hibp_api_key': 'test'}, c)
            assert data['status'] == 'checked' and len(data['findings']) == 1
            assert '<script>' not in json.dumps(data)


@pytest.mark.asyncio
async def test_failed_browser_never_no_match():
    browser = AsyncMock()
    browser.capture.return_value = {'status': 'blocked', 'detail': 'Challenge', 'html': '', 'url': ''}
    result = await scan_source({'id': 'x', 'mode': 'browser', 'kind': 'broker'}, {'email': 'fixture@example.com'}, {}, browser)
    assert result['status'] == 'blocked' and not result.get('no_match')


def test_page_match_is_only_candidate_and_selector_failure_not_clean():
    source = {'name': 'Fixture', 'config': {}}
    profile = {'email': 'fixture@example.com'}
    data = page_matches(source, profile, '<p>fixture@example.com</p>', 'https://example.com/')
    assert data['findings'] and 'echo' in data['findings'][0]['detail']
    source['config']['match_selector'] = '.missing'
    assert page_matches(source, profile, '<p>hello</p>', 'https://example.com/')['status'] == 'error'
