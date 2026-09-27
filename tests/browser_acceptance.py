"""Explicit browser acceptance against synthetic local state, never a live instance.

Run with the project's Python and Playwright Chromium installed:
PYTHONUTF8=1 PYTHONIOENCODING=utf-8 python -X utf8 tests/browser_acceptance.py --output /absolute/evidence/path
The source-browser check fetches only example.com; personal accounts are not used.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import socket
import sys
import tempfile

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from playwright.async_api import async_playwright
import uvicorn
from privacy_bot.app import create_app
from privacy_bot.browser import BrowserSessions

TOKEN = 'synthetic-browser-test-token-not-a-live-secret'
PAYLOAD = '<img data-upstream-probe src=x onerror="window.upstreamExecuted=true">'


async def main(output):
    output.mkdir(parents=True, exist_ok=True)
    data = Path(tempfile.mkdtemp(prefix='synthetic-', dir=output))
    os.environ.update(PRIVACY_BOT_TOKEN=TOKEN, PRIVACY_BOT_ACCESS='token', ROOT_PATH='', PUBLIC_URL='')
    os.environ.pop('PRIVACY_BOT_KEY', None)
    app = create_app(data / 'app')
    db = app.state.db
    for collection, row in [
        ('sources', {'id': 'evil-title', 'name': PAYLOAD, 'kind': 'broker', 'region': 'GB', 'mode': 'manual', 'enabled': False, 'status': 'needs_setup'}),
        ('findings', {'id': 'finding', 'source_id': 'evil-title', 'title': PAYLOAD, 'detail': PAYLOAD, 'url': 'javascript:window.upstreamExecuted=true', 'matched': [], 'status': 'candidate'}),
        ('alerts', {'id': 'alert', 'kind': 'exposure', 'severity': 'important', 'title': PAYLOAD, 'detail': PAYLOAD, 'read': False}),
        ('runs', {'id': 'run', 'source_id': 'evil-title', 'status': 'error', 'detail': PAYLOAD}),
        ('removals', {'id': 'removal', 'source_id': 'evil-title', 'status': 'submitted', 'subject': PAYLOAD, 'body': 'Synthetic request', 'note': PAYLOAD, 'recipient': 'privacy@example.com'}),
    ]:
        db.put(collection, row)
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen(128)
    base = f'http://127.0.0.1:{sock.getsockname()[1]}/'
    server = uvicorn.Server(uvicorn.Config(app, log_level='error', access_log=False, proxy_headers=False))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    errors, checks = [], []
    sessions = BrowserSessions(data / 'browsers')
    try:
        for _ in range(200):
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started
        app.state.service.scheduler_status = {'status': 'error', 'failures': 1, 'retry_at': '2026-09-26T21:00:00+00:00'}
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, chromium_sandbox=True)
            page = await browser.new_page(viewport={'width': 1440, 'height': 1000})
            page.on('pageerror', lambda error: errors.append(str(error)))
            await page.goto(base)
            await page.locator('input[type=password]').first.fill(TOKEN)
            await page.get_by_role('button', name='Sign in', exact=True).click()
            await page.locator('#login').wait_for(state='hidden')
            await page.get_by_text('Scheduled monitoring needs attention', exact=True).wait_for()
            for width, height in [(1440, 1000), (390, 844)]:
                await page.set_viewport_size({'width': width, 'height': height})
                for view in ['overview', 'exposures', 'removals', 'credit', 'sources', 'research', 'identity']:
                    await page.locator('[data-view=' + view + ']').click()
                    assert await page.locator('[data-upstream-probe]').count() == 0
                    assert not await page.evaluate('Boolean(window.upstreamExecuted)')
                    assert await page.locator('a[href^="javascript:"]').count() == 0
                    if await page.evaluate('document.documentElement.scrollWidth > innerWidth'):
                        await page.screenshot(path=str(output / 'overflow.png'), full_page=True)
                        print(await page.evaluate("Array.from(document.querySelectorAll('*')).filter(e => !e.closest('.table-wrap') && e.getBoundingClientRect().right > innerWidth + 1).map(e => ({tag:e.tagName,cls:e.className,width:e.getBoundingClientRect().width,white:getComputedStyle(e).whiteSpace,overflow:getComputedStyle(e).overflowX})).slice(0,12)"))
                        raise AssertionError((width, view, 'horizontal overflow'))
                    checks.append({'view': view, 'width': width, 'safe_text': True})
            await page.locator('[data-view=removals]').click()
            await page.get_by_text('Preview, edit and send', exact=True).click()
            await page.get_by_label('Status', exact=True).select_option('verified_removed')
            await page.get_by_label('Status note', exact=True).fill('Public listing absent in synthetic test')
            await page.get_by_role('button', name='Save changes', exact=True).click()
            await page.get_by_text('Record exactly which listing or search you checked and whether you were signed in.', exact=True).wait_for()
            scope = 'Public name search only; signed-in and paid records unchecked'
            await page.get_by_label('What you checked for removal', exact=True).fill(scope)
            async with page.expect_response(lambda response: response.url.endswith('/api/removals/removal') and response.request.method == 'PATCH') as pending:
                await page.get_by_role('button', name='Save changes', exact=True).click()
            response = await pending.value
            assert response.status == 200
            saved = await response.json()
            assert saved['verification_scope'] == scope and saved['verification_recorded_at']
            await page.get_by_text('Checked scope: ' + scope, exact=True).wait_for()
            await page.screenshot(path=str(output / 'removal-scope-phone.png'), full_page=True)
            await browser.close()
        peers = []
        for i in range(2):
            source = {'id': f'public-{i}', 'url': 'https://example.com/', 'config': {'allowed_hosts': ['example.com']}}
            result = await sessions.capture(source)
            assert result['status'] == 'ok' and result['title'] == 'Example Domain', result.get('detail')
            peers.append(sessions.egress.proxy_url)
        assert peers[0] == peers[1] and peers[0]
        assert not errors, errors
        receipt = {'ui_checks': checks, 'javascript_errors': errors, 'malicious_text_executed': False,
                   'scope_required_and_saved': True, 'scheduler_warning_visible': True,
                   'sandboxed_repeated_captures': 2, 'shared_proxy_reused': True, 'personal_data_used': False, 'emails_sent': 0}
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(receipt))
    finally:
        await sessions.stop()
        server.should_exit = True
        await task
        sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    asyncio.run(main(parser.parse_args().output.resolve()))
