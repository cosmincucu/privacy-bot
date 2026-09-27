"""Regressions motivated by upstream tracker failures, using synthetic data only."""
import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest

from privacy_bot.service import Service
from privacy_bot.storage import Store
from privacy_bot.scanner import fetch_public
from test_service import client  # shared authenticated API fixture


@pytest.mark.asyncio
async def test_slow_source_cannot_starve_next_source(tmp_path, monkeypatch):
    db = Store(tmp_path)
    service = Service(db, AsyncMock())
    # Store returns newest first: the slow source must be attempted first.
    db.put('sources', {'id': 'healthy', 'name': 'Healthy fixture', 'enabled': True})
    db.put('sources', {'id': 'slow', 'name': 'Slow fixture', 'enabled': True})
    attempted, cancelled = [], []

    async def scan(source, *_):
        attempted.append(source['id'])
        if source['id'] == 'slow':
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.append(source['id'])
        return {'status': 'checked', 'detail': 'Fixture check completed', 'findings': []}

    monkeypatch.setattr('privacy_bot.service.scan_source', scan)
    monkeypatch.setattr('privacy_bot.service.SOURCE_TIMEOUT_SECONDS', 0.02)
    try:
        result = await asyncio.wait_for(service.scan(), 1)
        assert attempted == ['slow', 'healthy']
        assert cancelled == ['slow']
        assert [x['status'] for x in result['runs']] == ['error', 'checked']
        assert not result['runs'][0]['no_match']
        assert db.get('sources', 'slow')['status'] == 'error'
        assert db.get('sources', 'healthy')['status'] == 'checked'
        assert not service.lock.locked()
    finally:
        db.close()


def test_removal_verification_requires_scope_and_preserves_evidence(client):
    db = client.app.state.db
    removal = db.put('removals', {'id': 'fixture', 'source_id': '192', 'status': 'submitted',
                                'recipient': 'privacy@example.com', 'body': 'Synthetic request', 'note': ''})
    endpoint = '/api/removals/' + removal['id']
    assert client.patch(endpoint, json={'status': 'verified_removed', 'note': 'Public listing no longer shown'}).status_code == 400
    assert db.get('removals', 'fixture')['status'] == 'submitted'
    scope = 'Public name search for this exact listing; signed-in and paid results not checked'
    result = client.patch(endpoint, json={'status': 'verified_removed', 'note': 'Public listing no longer shown', 'verification_scope': scope})
    assert result.status_code == 200
    assert result.json()['verification_scope'] == scope
    assert result.json()['verification_recorded_at']
    stamp = result.json()['verification_recorded_at']
    assert result.json()['body'] == 'Synthetic request'
    assert client.patch(endpoint, json={'note': 'Same limited scope; no further checks'}).json()['verification_recorded_at'] == stamp
    assert client.patch(endpoint, json={'verification_scope': ''}).status_code == 400


@pytest.mark.parametrize('scope', [None, [], {}, 42, 'x' * 1001])
def test_bad_verification_scope_does_not_mutate_removal(client, scope):
    db = client.app.state.db
    original = db.put('removals', {'id': 'fixture', 'source_id': '192', 'status': 'submitted', 'note': 'Original'})
    result = client.patch('/api/removals/fixture', json={'status': 'verified_removed', 'note': 'Synthetic evidence', 'verification_scope': scope})
    assert result.status_code == 400
    assert db.get('removals', 'fixture') == original


def test_legacy_verification_is_not_backfilled_with_invented_scope(client):
    db = client.app.state.db
    original = db.put('removals', {'id': 'legacy', 'source_id': '192', 'status': 'verified_removed', 'note': 'Older observation'})
    result = client.get('/api/dashboard').json()
    legacy = next(x for x in result['removals'] if x['id'] == 'legacy')
    assert 'verification_scope' not in legacy and 'verification_recorded_at' not in legacy
    assert db.get('removals', 'legacy') == original


@pytest.mark.asyncio
async def test_storage_fault_defers_provider_requeries_and_exposes_health(tmp_path, monkeypatch, caplog):
    db = Store(tmp_path)
    service = Service(db, AsyncMock())
    db.put('sources', {'id': 'fixture', 'name': 'Synthetic broker', 'enabled': True})
    db.put('meta', {'enabled': True, 'interval_hours': 24}, 'settings')
    scan = AsyncMock(return_value={'status': 'checked', 'detail': 'Synthetic observation'})
    monkeypatch.setattr('privacy_bot.service.scan_source', scan)
    put = db.put
    def failing_put(collection, *args, **kwargs):
        if collection == 'runs':
            raise OSError('sensitive-provider-url-must-not-be-logged')
        return put(collection, *args, **kwargs)
    monkeypatch.setattr(db, 'put', failing_put)
    waits = []
    async def sleep(seconds):
        waits.append(seconds)
        if len(waits) == 5:
            raise asyncio.CancelledError
    monkeypatch.setattr('privacy_bot.service.asyncio.sleep', sleep)
    try:
        with pytest.raises(asyncio.CancelledError):
            await service.scheduler()
        assert waits == [300, 600, 1200, 2400, 3600]
        assert scan.await_count == 5
        assert service.scheduler_status['status'] == 'error'
        assert service.scheduler_status['failures'] == 5
        assert service.scheduler_status['retry_at']
        assert 'sensitive-provider-url' not in caplog.text
        assert not service.running
    finally:
        db.close()


@pytest.mark.asyncio
async def test_scheduler_backoff_resets_after_recovery(tmp_path, monkeypatch):
    db = Store(tmp_path)
    service = Service(db, AsyncMock())
    real_snapshot = db.snapshot
    calls = 0
    def snapshot():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError('fixture failure')
        return real_snapshot()
    monkeypatch.setattr(db, 'snapshot', snapshot)
    waits = []
    async def sleep(seconds):
        waits.append(seconds)
        if len(waits) == 2:
            raise asyncio.CancelledError
    monkeypatch.setattr('privacy_bot.service.asyncio.sleep', sleep)
    try:
        with pytest.raises(asyncio.CancelledError):
            await service.scheduler()
        assert waits == [300, 60]
        assert service.scheduler_status == {'status': 'ok', 'failures': 0}
    finally:
        db.close()


def test_monitoring_error_visible_in_health_and_dashboard(client):
    service = client.app.state.service
    service.scheduler_status = {'status': 'error', 'failures': 2, 'retry_at': '2026-09-26T20:00:00+00:00'}
    assert client.get('/healthz').json()['status'] == 'degraded'
    assert client.get('/api/dashboard').json()['monitoring'] == service.scheduler_status


@pytest.mark.asyncio
async def test_redirect_to_new_operator_is_not_fetched(monkeypatch):
    monkeypatch.setattr('privacy_bot.network._resolve', AsyncMock(return_value=['8.8.8.8']))
    calls = []
    def response(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={'location': 'https://parking.example.net/no-records'})
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        with pytest.raises(ValueError, match='allowlist'):
            await fetch_public('https://broker.example.net/listing', client=client)
    assert calls == ['https://broker.example.net/listing']


@pytest.mark.asyncio
async def test_same_broker_redirect_keeps_working(monkeypatch):
    monkeypatch.setattr('privacy_bot.network._resolve', AsyncMock(return_value=['8.8.8.8']))
    calls = []
    def response(request):
        calls.append(str(request.url))
        if request.url.path == '/old':
            return httpx.Response(302, headers={'location': '/current'})
        return httpx.Response(200, text='Synthetic listing')
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        code, body, url = await fetch_public('https://broker.example.net/old', client=client)
    assert code == 200 and body == 'Synthetic listing'
    assert calls == ['https://broker.example.net/old', 'https://broker.example.net/current']
