import asyncio
from contextlib import asynccontextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlsplit

from fastapi import Body, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .access import NetworkAccess
from .machine_access import JobReaders, job_metadata
from .browser import BrowserSessions
from .network import validate_public_url
from .service import Service, send_email
from .storage import Store, now

STATIC = Path(__file__).parent / 'static'
CATALOG = json.loads((Path(__file__).parent / 'catalog.json').read_text(encoding='utf-8'))
MODES = {'manual', 'discovery', 'http', 'browser', 'hibp', 'hibp_stealer'}


def create_app(data_path=None):
    data = Path(data_path or os.getenv('PRIVACY_BOT_DATA', './data'))
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = Store(data)
    browser = BrowserSessions(data)
    service = Service(db, browser)
    root = os.getenv('ROOT_PATH', '').rstrip('/')
    public = os.getenv('PUBLIC_URL', '')
    job_readers = JobReaders.from_file(os.getenv('PRIVACY_BOT_JOB_READERS_FILE'))
    if job_readers.readers and (urlsplit(public).scheme != 'https' or not urlsplit(public).hostname):
        raise ValueError('Machine readers require a configured HTTPS PUBLIC_URL')
    access_mode = os.getenv('PRIVACY_BOT_ACCESS', 'token')
    if access_mode not in {'token', 'network'}:
        raise RuntimeError('PRIVACY_BOT_ACCESS must be token or network')
    network_access = None
    if access_mode == 'network':
        if urlsplit(public).scheme != 'https' or not urlsplit(public).hostname:
            raise RuntimeError('Network access requires a configured HTTPS PUBLIC_URL')
        network_access = NetworkAccess(
            [v.strip() for v in os.getenv('PRIVACY_BOT_ALLOWED_NETWORKS', '').split(',') if v.strip()],
            [v.strip() for v in os.getenv('PRIVACY_BOT_TRUSTED_PROXIES', '').split(',') if v.strip()])
    token = os.getenv('PRIVACY_BOT_TOKEN')
    token_file = data / 'access-token'
    if access_mode == 'token' and not token:
        if not token_file.exists():
            with token_file.open('x', encoding='utf-8') as f:
                os.chmod(token_file, 0o600)
                f.write(secrets.token_urlsafe(32))
        token = token_file.read_text(encoding='utf-8').strip()
    if access_mode == 'token' and len(token) < 24:
        raise RuntimeError('PRIVACY_BOT_TOKEN must contain at least 24 characters')
    for entry in CATALOG['sources']:
        if not db.get('sources', entry['id']):
            db.put('sources', dict(entry, enabled=False, status='needs_setup', last_checked=None, config={}))
    if not db.get('meta', 'settings'):
        db.put('meta', {'interval_hours': 24, 'enabled': False, 'notify_soft': False}, 'settings')
    for item in db.all('removals'):
        if item['status'] == 'submitting':
            db.put('removals', dict(item, status='uncertain', note='Service restarted during submission. Check your mailbox; automatic retry is disabled.', updated_at=now()))
    sessions, failures = {}, {}

    @asynccontextmanager
    async def lifespan(app):
        tasks = [asyncio.create_task(service.scheduler()), asyncio.create_task(browser.reap())]
        yield
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await browser.stop()
        db.close()

    app = FastAPI(title='Privacy Bot', root_path=root, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db, app.state.service, app.state.browser = db, service, browser

    @app.middleware('http')
    async def protect(request, call_next):
        path = request.url.path
        relative = path[len(root):] if root and path.startswith(root + '/') else path
        is_api = relative.startswith('/api/')
        machine_reader = None
        if request.headers.getlist('authorization'):
            machine_reader = job_readers.authenticate(request.headers.getlist('authorization'))
            if machine_reader is None:
                return JSONResponse({'detail': 'Invalid machine credential'}, status_code=401,
                                    headers={'Cache-Control': 'no-store'})
            if request.method != 'GET' or relative != '/api/dashboard':
                return JSONResponse({'detail': 'Machine scope denied'}, status_code=403,
                                    headers={'Cache-Control': 'no-store'})
            hosts = request.headers.getlist('host')
            if not public or len(hosts) != 1 or hosts[0].lower() != urlsplit(public).netloc.lower():
                return JSONResponse({'detail': 'Use the configured Privacy Bot address'}, status_code=400)
            request.state.job_reader = machine_reader
        if network_access is not None and relative != '/healthz':
            hosts = request.headers.getlist('host')
            if len(hosts) != 1 or hosts[0].lower() != urlsplit(public).netloc.lower():
                return JSONResponse({'detail': 'Use the configured Privacy Bot address'}, status_code=400)
            if machine_reader is None and not network_access.permits(request):
                return JSONResponse({'detail': 'Connect through your home network or Tailscale'}, status_code=403)
        if request.headers.get('content-length', '').isdigit() and int(request.headers['content-length']) > 12_000_000:
            return JSONResponse({'detail': 'Upload too large (maximum 10 MB)'}, status_code=413)
        if is_api:
            if request.method not in ('GET', 'HEAD'):
                if request.headers.get('x-privacy-bot') != '1':
                    return JSONResponse({'detail': 'Missing same-origin request header'}, status_code=403)
                origin = request.headers.get('origin')
                expected = urlsplit(public) if public else urlsplit(str(request.base_url))
                if origin and origin != expected.scheme + '://' + expected.netloc:
                    return JSONResponse({'detail': 'Cross-origin request refused'}, status_code=403)
            cookie = request.cookies.get('privacy_session', '')
            authenticated = machine_reader is not None or network_access is not None or sessions.get(hashlib.sha256(cookie.encode()).hexdigest(), 0) > time.time()
            if relative not in ('/api/login', '/api/session') and not authenticated:
                return JSONResponse({'detail': 'Sign in to Privacy Bot'}, status_code=401)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        return response

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({'detail': str(exc)[:400]}, status_code=400)

    def record(collection, key):
        obj = db.get(collection, key)
        if obj is None:
            raise HTTPException(404, 'Record not found')
        return obj

    @app.get('/healthz')
    async def health():
        return {'status': 'degraded' if service.scheduler_status['status'] == 'error' else 'ok',
                'revision': os.getenv('APP_REVISION', 'development'), 'scheduler': service.running}

    @app.get('/api/session')
    async def session(request: Request):
        value = request.cookies.get('privacy_session', '')
        return {'authenticated': network_access is not None or sessions.get(hashlib.sha256(value.encode()).hexdigest(), 0) > time.time(), 'access_mode': access_mode}

    @app.post('/api/login')
    async def login(request: Request, body: dict = Body(...)):
        if network_access is not None:
            return {'authenticated': True, 'access_mode': access_mode}
        client = request.client.host if request.client else 'unknown'
        recent = [t for t in failures.get(client, []) if t > time.time() - 300]
        failures[client] = recent
        if len(recent) >= 10:
            raise HTTPException(429, 'Too many attempts; wait five minutes')
        if not secrets.compare_digest(str(body.get('token', '')).encode(), token.encode()):
            failures[client].append(time.time())
            raise HTTPException(401, 'Access token not recognised')
        value = secrets.token_urlsafe(32)
        sessions[hashlib.sha256(value.encode()).hexdigest()] = time.time() + 12 * 3600
        response = JSONResponse({'authenticated': True})
        response.set_cookie('privacy_session', value, max_age=12 * 3600, httponly=True, secure=public.startswith('https://'),
                            samesite='strict', path=(root + '/') if root else '/')
        return response

    @app.post('/api/logout')
    async def logout(request: Request):
        if network_access is not None:
            return {'authenticated': True, 'access_mode': access_mode}
        value = request.cookies.get('privacy_session', '')
        sessions.pop(hashlib.sha256(value.encode()).hexdigest(), None)
        response = JSONResponse({'authenticated': False})
        response.delete_cookie('privacy_session', path=(root + '/') if root else '/')
        return response

    @app.get('/api/dashboard')
    async def dashboard(request: Request):
        if getattr(request.state, 'job_reader', None) is not None:
            return job_metadata(db)
        return {'profile': db.get('meta', 'profile', {'name': '', 'email': '', 'phone': '', 'addresses': [], 'aliases': [], 'country': 'GB'}),
                'sources': db.all('sources'), 'findings': db.all('findings'), 'removals': db.all('removals'),
                'alerts': db.all('alerts')[:500], 'credit': service.credit_summary(), 'runs': db.all('runs')[:200],
                'settings': db.get('meta', 'settings'), 'research': CATALOG['research'],
                'monitoring': service.scheduler_status,
                'notification_status': db.get('meta', 'notification_status', {'status': 'not_configured'})}

    @app.put('/api/profile')
    async def profile(body: dict = Body(...)):
        allowed = {'name', 'email', 'phone', 'addresses', 'aliases', 'country'}
        value = {k: v for k, v in body.items() if k in allowed}
        for k in ('name', 'email', 'phone'):
            if not isinstance(value.get(k, ''), str) or len(value.get(k, '')) > 300:
                raise ValueError('Invalid profile field: ' + k)
        if value.get('email') and not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value['email']):
            raise ValueError('Enter a valid email address')
        for k in ('addresses', 'aliases'):
            rows = value.setdefault(k, [])
            if not isinstance(rows, list) or len(rows) > 30 or any(not isinstance(v, str) or len(v) > 500 for v in rows):
                raise ValueError('Invalid list: ' + k)
        if value.get('country', 'GB') != 'GB':
            raise ValueError('This installation covers UK credit agencies')
        value['country'] = 'GB'
        return db.put('meta', value, 'profile')

    @app.put('/api/settings')
    async def settings(body: dict = Body(...)):
        current = db.get('meta', 'settings')
        for key in ('enabled', 'notify_soft'):
            if key in body:
                if type(body[key]) is not bool:
                    raise ValueError(key + ' must be true or false')
                current[key] = body[key]
        if 'interval_hours' in body:
            val = body['interval_hours']
            if isinstance(val, bool) or not isinstance(val, (int, float)) or not 1 <= val <= 720:
                raise ValueError('Scan interval must be between 1 and 720 hours')
            current['interval_hours'] = val
        return db.put('meta', current, 'settings')

    async def source_update(body, current=None):
        fields = {'name', 'kind', 'region', 'url', 'privacy_url', 'mode', 'config', 'enabled'}
        value = dict(current or {'id': secrets.token_hex(12), 'enabled': False, 'status': 'needs_setup', 'last_checked': None, 'detail': 'Not checked'})
        value.update({k: v for k, v in body.items() if k in fields})
        if value.get('mode', 'manual') not in MODES:
            raise ValueError('Use manual, discovery, http, browser, hibp or hibp_stealer. Direct dark-web access is disabled.')
        if value.get('kind') not in {'broker', 'credit', 'breach', 'darkweb'} or not isinstance(value.get('name'), str) or not value['name'].strip():
            raise ValueError('Source needs a name and valid kind')
        if value['kind'] == 'darkweb' and value.get('mode') != 'hibp_stealer':
            raise ValueError('Dark-web exposure is queried only through HIBP stealer-log metadata')
        if value['kind'] == 'credit' and (value['id'] not in {'experian', 'equifax', 'transunion'} or value.get('mode') != 'browser'):
            raise ValueError('Use the existing three UK agency connections')
        if type(value.get('enabled')) is not bool or not isinstance(value.get('config', {}), dict):
            raise ValueError('Invalid source settings')
        cfg = value.setdefault('config', {})
        terms = cfg.get('terms', [])
        if not isinstance(terms, list) or any(not isinstance(t, str) or len(t) > 300 for t in terms) or len(terms) > 30:
            raise ValueError('Match terms must be a list of up to 30 short strings')
        for field in ('url', 'privacy_url'):
            if value.get(field):
                await validate_public_url(value[field])
        for field in ('watch_url', 'report_url'):
            if cfg.get(field):
                await validate_public_url(cfg[field])
        return db.put('sources', value)

    @app.post('/api/sources')
    async def add_source(body: dict = Body(...)):
        return await source_update(body)

    @app.patch('/api/sources/{key}')
    async def update_source(key: str, body: dict = Body(...)):
        return await source_update(body, record('sources', key))

    @app.post('/api/scan')
    async def scan(body: dict = Body(default={})):
        return await service.scan(body.get('source_id'))

    @app.patch('/api/findings/{key}')
    async def finding(key: str, body: dict = Body(...)):
        value = record('findings', key)
        if body.get('status') not in {'candidate', 'confirmed', 'dismissed'}:
            raise ValueError('Invalid finding status')
        return db.put('findings', dict(value, status=body['status']))

    @app.post('/api/removals')
    async def draft(body: dict = Body(...)):
        found = record('findings', body['finding_id']) if body.get('finding_id') else None
        source = record('sources', found['source_id'] if found else body.get('source_id', ''))
        if source['kind'] != 'broker':
            raise ValueError('Removal requests apply to broker listings. Credit disputes and breach remediation need their own provider process.')
        if found and found['status'] != 'confirmed':
            raise ValueError('Confirm that this listing is yours before creating a removal request')
        profile = db.get('meta', 'profile', {})
        if not profile.get('name') or not profile.get('email'):
            raise ValueError('Add your name and contact email first')
        for existing in db.all('removals'):
            if existing['source_id'] == source['id'] and existing.get('finding_id') == (found['id'] if found else None) and existing['status'] not in {'rejected', 'verified_removed'}:
                return existing
        url = found['url'] if found else '(add the exact record URL or identifier)'
        body_text = f"Hello,\n\nI am {profile['name']}. Please remove my personal information from the following listing and stop using it for direct marketing:\n{url}\n\nPlease consider this a request for erasure and an objection to direct marketing under applicable UK data protection law. If you need to retain any information, please explain the basis and confirm what has been removed. Please tell me any minimum information needed to verify this request.\n\nPlease reply to {profile['email']}.\n\nThank you,\n{profile['name']}"
        return db.put('removals', {'source_id': source['id'], 'finding_id': found['id'] if found else None,
                                  'status': 'draft', 'subject': 'Personal data removal and marketing objection', 'body': body_text,
                                  'recipient': '', 'created_at': now(), 'updated_at': now(), 'note': '', 'privacy_url': source.get('privacy_url', '')})

    @app.patch('/api/removals/{key}')
    async def update_removal(key: str, body: dict = Body(...)):
        value = record('removals', key)
        status = body.get('status', value['status'])
        transitions = {'draft': {'draft', 'submitted'}, 'submitted': {'submitted', 'acknowledged', 'verified_removed', 'rejected'},
                       'acknowledged': {'acknowledged', 'verified_removed', 'rejected'}, 'uncertain': {'uncertain', 'submitted', 'acknowledged', 'verified_removed', 'rejected'},
                       'verified_removed': {'verified_removed'}, 'rejected': {'rejected'}, 'reappeared': {'reappeared', 'submitted', 'verified_removed'}}
        if status not in transitions.get(value['status'], set()):
            raise ValueError('Invalid removal status transition')
        if status != value['status'] and not str(body.get('note', '')).strip():
            raise ValueError('Add the submission, response or verification evidence in a note')
        scope = body.get('verification_scope', value.get('verification_scope', ''))
        if not isinstance(scope, str) or len(scope) > 1000:
            raise ValueError('Verification scope must be a short description of the pages or searches checked')
        if status == 'verified_removed' and not scope.strip():
            raise ValueError('Record which listing or search was checked and whether it was public or signed in; other broker records may remain')
        for field in ('recipient', 'body', 'note'):
            if field in body:
                if not isinstance(body[field], str) or len(body[field]) > 20000:
                    raise ValueError('Invalid request field')
                if field in {'recipient', 'body'} and value['status'] != 'draft':
                    raise ValueError('Sent requests are immutable; record an evidence note instead')
                value[field] = body[field]
        if 'verification_scope' in body:
            value['verification_scope'] = scope.strip()
        if status == 'verified_removed' and value['status'] != status:
            value['verification_recorded_at'] = now()
        value.update(status=status, updated_at=now())
        return db.put('removals', value)

    @app.post('/api/removals/{key}/send')
    async def send(key: str, body: dict = Body(...)):
        value = record('removals', key)
        if body.get('confirm') is not True or value['status'] != 'draft':
            raise ValueError('Review the draft and explicitly send it once')
        if not re.fullmatch(r'[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+', value['recipient']):
            raise ValueError('Enter one verified broker privacy email address')
        cfg = db.get('meta', 'connections', {})
        if not cfg.get('smtp_host') or not cfg.get('smtp_from'):
            raise ValueError('Configure SMTP before sending')
        db.put('removals', dict(value, status='submitting', updated_at=now()))
        try:
            await asyncio.to_thread(send_email, value, cfg)
            value.update(status='submitted', note='SMTP accepted the request; this is not proof of delivery or removal.')
        except Exception:
            value.update(status='uncertain', note='Send outcome uncertain. Check your mailbox before sending anything again. Automatic retry is disabled.')
        value['updated_at'] = now()
        return db.put('removals', value)

    @app.post('/api/alerts/{key}/read')
    async def read_alert(key: str):
        return db.put('alerts', dict(record('alerts', key), read=True))

    @app.post('/api/credit/import')
    async def import_credit(body: dict = Body(...)):
        result = await service.import_report(body.get('report'))
        await service.notify()
        return result

    @app.get('/api/credit/example')
    async def example():
        return {'agency': 'experian', 'report_date': '2026-01-01', 'complete': True,
                'searches': [], 'accounts': [], 'addresses': [], 'public_records': []}

    @app.post('/api/credit/extract')
    async def extract(file: UploadFile = File(...)):
        raw = await file.read(10_000_001)
        if len(raw) > 10_000_000:
            raise HTTPException(413, 'Report must be under 10 MB')
        if raw.startswith(b'%PDF'):
            from pypdf import PdfReader
            try:
                reader = PdfReader(io.BytesIO(raw))
                if reader.is_encrypted or len(reader.pages) > 100:
                    raise ValueError('Use an unencrypted report with at most 100 pages')
                text = '\n'.join(p.extract_text() or '' for p in reader.pages)
            except Exception:
                raise ValueError('PDF could not be read. Use an unencrypted text report or normalized JSON.') from None
        else:
            try:
                text = raw.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError('Use a UTF-8 text/JSON file or a text-based PDF') from None
        parsed = None
        try:
            candidate = json.loads(text)
            from .credit import validate_report
            parsed = validate_report(candidate)
        except (ValueError, TypeError, KeyError):
            pass
        return {'text': text[:300000], 'report': parsed, 'needs_review': parsed is None}

    @app.get('/api/connections')
    async def connections():
        cfg = db.get('meta', 'connections', {})
        return {'hibp': bool(cfg.get('hibp_api_key')), 'smtp': bool(cfg.get('smtp_host') and cfg.get('smtp_from')),
                'tor': False, 'notifications': bool(cfg.get('notification_url')), 'direct_darkweb': False, 'discovery': bool(os.getenv('DONSETCH_URL')),
                'detail': 'Dark-web exposure uses HIBP metadata only. No onion browsing, passwords or leak archives.'}

    @app.put('/api/connections')
    async def set_connections(body: dict = Body(...)):
        cfg = db.get('meta', 'connections', {})
        fields = {'hibp_api_key', 'smtp_host', 'smtp_from', 'smtp_port', 'smtp_user', 'smtp_password', 'notification_url'}
        if body.get('tor_proxy'):
            raise ValueError('Direct dark-web crawling is disabled; no Tor proxy is accepted')
        for k, v in body.items():
            if k not in fields or v == '':
                continue
            if k == 'smtp_port':
                if not str(v).isdigit() or int(v) not in (465, 587):
                    raise ValueError('SMTP must use TLS on port 465 or 587')
                cfg[k] = int(v)
            elif not isinstance(v, str) or len(v) > 2000 or '\r' in v or '\n' in v:
                raise ValueError('Invalid connection setting')
            elif k == 'notification_url':
                parsed = urlsplit(v)
                if parsed.scheme != 'https' or not parsed.hostname or parsed.username:
                    raise ValueError('Notification endpoint must be HTTPS; local trusted services are allowed')
                cfg[k] = v
            else:
                cfg[k] = v
        db.put('meta', cfg, 'connections')
        return await connections()

    @app.post('/api/browser/{key}/start')
    async def browser_start(key: str):
        source = record('sources', key)
        if source['kind'] in {'darkweb', 'breach'}:
            raise ValueError('Exposure feeds use their API, not a browser')
        return await browser.start(source)

    @app.get('/api/browser/{key}')
    async def browser_snapshot(key: str):
        return await browser.snapshot(key)

    @app.post('/api/browser/{key}/action')
    async def browser_action(key: str, body: dict = Body(...)):
        return await browser.action(key, body)

    @app.post('/api/browser/{key}/close')
    async def browser_close(key: str):
        return await browser.close(key)

    @app.post('/api/browser/{key}/capture')
    async def browser_capture(key: str):
        return await service.scan(key)

    @app.get('/')
    async def index():
        return FileResponse(STATIC / 'index.html')

    @app.get('/browser.html')
    async def browser_page():
        return FileResponse(STATIC / 'browser.html')

    app.mount('/static', StaticFiles(directory=STATIC, check_dir=False), name='static')
    # Assets are also available beside the document for simple relative UI builds.
    def make_asset(filename):
        async def asset():
            return FileResponse(STATIC / filename)
        return asset
    for name in ('app.js', 'styles.css', 'browser.js', 'icon.svg'):
        app.add_api_route('/' + name, make_asset(name), methods=['GET'], include_in_schema=False)
    return app
