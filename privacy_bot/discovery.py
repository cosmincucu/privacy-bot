"""Site-restricted discovery through an optional operator-configured Donsetch search service."""
import json
import os
from urllib.parse import urlsplit

import httpx

from .network import validate_public_url

MAX_RESPONSE = 1_000_000


def decode_rpc(raw, call_id):
    messages = [line[5:].strip() for line in raw.splitlines() if line.startswith('data:')]
    if not messages:
        messages = [raw]
    for text in messages:
        try:
            value = json.loads(text)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get('id') == call_id:
            if value.get('error'):
                raise ValueError('Search service rejected the request')
            return value.get('result')
    raise ValueError('Search service returned no matching response')


def extract_results(payload):
    if not isinstance(payload, dict) or payload.get('isError'):
        raise ValueError('Search provider reported a failed search')
    data = payload.get('structuredContent')
    if not isinstance(data, dict):
        data = None
        for part in payload.get('content', []):
            if not isinstance(part, dict) or part.get('type') != 'text':
                continue
            try:
                candidate = json.loads(part.get('text', ''))
            except (ValueError, TypeError):
                continue
            if isinstance(candidate, dict) and 'results' in candidate:
                data = candidate
                break
    if not isinstance(data, dict) or data.get('content_ok') is False or not isinstance(data.get('results'), list):
        raise ValueError('Search response has no usable result list; no absence conclusion')
    return data['results']


async def discover(source, profile, client=None):
    endpoint = os.getenv('DONSETCH_URL', '')
    name = profile.get('name', '').strip()
    if not endpoint or not name:
        return {'status': 'needs_setup', 'detail': 'Add your name and connect the local search service before running broker discovery.', 'findings': []}
    base = urlsplit(endpoint)
    if base.scheme not in {'http', 'https'} or not base.hostname or base.username or base.password:
        raise ValueError('Invalid configured search endpoint')
    target = urlsplit(source['url']).hostname or ''
    await validate_public_url(source['url'])
    # The configured local service may be on the LAN; result URLs may not.
    headers = {'Accept': 'application/json, text/event-stream', 'Content-Type': 'application/json'}
    token = os.getenv('DONSETCH_TOKEN', '')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    own = client is None
    client = client or httpx.AsyncClient(timeout=50, follow_redirects=False, trust_env=False)
    async def rpc(method, params, call_id=None):
        request = {'jsonrpc': '2.0', 'method': method, 'params': params}
        if call_id is not None:
            request['id'] = call_id
        async with client.stream('POST', endpoint, headers=headers, json=request) as response:
            if not 200 <= response.status_code < 300:
                raise ValueError('Local search service unavailable')
            if response.headers.get('mcp-session-id'):
                headers['mcp-session-id'] = response.headers['mcp-session-id']
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_RESPONSE:
                    raise ValueError('Search response exceeded safety limit')
        return decode_rpc(body.decode('utf-8'), call_id) if call_id is not None else None
    try:
        await rpc('initialize', {'protocolVersion': '2024-11-05', 'capabilities': {}, 'clientInfo': {'name': 'privacy-bot', 'version': '0.1.0'}}, 1)
        await rpc('notifications/initialized', {})
        query = '"' + name.replace('"', '').replace('\n', ' ') + '" site:' + target
        payload = await rpc('tools/call', {'name': 'web_search', 'arguments': {'query': query, 'max_results': 7, 'intent': 'web', 'deadline_ms': 30000}}, 2)
        rows = extract_results(payload)
        findings, seen = [], set()
        for row in rows[:20]:
            if not isinstance(row, dict) or not isinstance(row.get('url'), str):
                continue
            url = row['url']
            host = urlsplit(url).hostname or ''
            if host != target and not host.endswith('.' + target):
                continue
            try:
                await validate_public_url(url)
            except ValueError:
                continue
            if url in seen:
                continue
            seen.add(url)
            findings.append({'key': url, 'title': str(row.get('title') or source['name'] + ' search candidate')[:300],
                             'url': url, 'matched': [], 'detail': 'Site-restricted search candidate for your name. Open the listing and verify identity; a search result alone is not proof of exposure.'})
        return {'status': 'checked', 'detail': f'{len(findings)} broker search candidates. Indexed search coverage only; no conclusion about hidden broker records.', 'findings': findings}
    finally:
        if own:
            await client.aclose()
