import json
import httpx
import pytest

from privacy_bot.discovery import decode_rpc, extract_results, discover


def test_nested_tool_content_results():
    rows = [{'url': 'https://example.com/p/1', 'title': 'Fixture'}]
    assert extract_results({'content': [{'type': 'text', 'text': 'heading'}, {'type': 'text', 'text': json.dumps({'results': rows})}]}) == rows
    assert extract_results({'structuredContent': {'results': rows}}) == rows


@pytest.mark.parametrize('payload', [{'isError': True}, {}, {'structuredContent': {'content_ok': False, 'results': []}}, {'structuredContent': {'results': {}}}])
def test_missing_malformed_and_failed_search_not_empty_success(payload):
    with pytest.raises(ValueError):
        extract_results(payload)


def test_sse_matches_requested_id():
    raw = 'data: {"jsonrpc":"2.0","method":"log"}\n\ndata: {"jsonrpc":"2.0","id":2,"result":{"content":[]}}\n'
    assert decode_rpc(raw, 2) == {'content': []}
    with pytest.raises(ValueError):
        decode_rpc(raw, 1)


@pytest.mark.asyncio
async def test_search_results_stay_on_broker_domain(monkeypatch):
    monkeypatch.setenv('DONSETCH_URL', 'http://search.internal/mcp')
    async def validate(url): return url
    monkeypatch.setattr('privacy_bot.discovery.validate_public_url', validate)
    seen = []
    def respond(req):
        body = json.loads(req.content)
        seen.append(body)
        if 'id' not in body:
            return httpx.Response(202)
        value = {} if body['id'] == 1 else {'structuredContent': {'results': [
            {'url': 'https://broker.example/p/1'}, {'url': 'https://broker.example.evil/p/2'},
            {'url': 'https://other.example/p/3'}, {'url': 'https://broker.example/p/1'}]}}
        return httpx.Response(200, json={'jsonrpc': '2.0', 'id': body['id'], 'result': value})
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as c:
        result = await discover({'url': 'https://broker.example/', 'name': 'Broker'}, {'name': 'Synthetic Person'}, c)
    assert len(result['findings']) == 1
    assert result['findings'][0]['matched'] == []
    assert seen[2]['params']['arguments']['query'] == '"Synthetic Person" site:broker.example'
