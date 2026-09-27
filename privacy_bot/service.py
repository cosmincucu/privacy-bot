"""Monitoring orchestration with durable observations and explicit coverage."""
import asyncio
import hashlib
import json
import logging
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone

import httpx

from .credit import compare_reports, validate_report
from .scanner import scan_source
from .storage import now

# A peer can keep each socket read alive indefinitely by trickling bytes. Bound
# the entire source operation so one failing provider cannot starve other checks.
SOURCE_TIMEOUT_SECONDS = 180


class Service:
    def __init__(self, db, browser):
        self.db, self.browser = db, browser
        self.lock = asyncio.Lock()
        self.credit_lock = asyncio.Lock()
        self.running = False
        self.scheduler_status = {'status': 'ok', 'failures': 0}

    async def import_report(self, report):
        report = validate_report(report, as_of=datetime.now(timezone.utc).date())
        agency = report['agency']
        digest = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()
        async with self.credit_lock:
            snapshots = sorted([s for s in self.db.all('snapshots') if s['agency'] == agency], key=lambda x: x['report']['report_date'])
            if any(s['digest'] == digest for s in snapshots):
                return {'duplicate': True, 'events': []}
            previous = snapshots[-1]['report'] if snapshots else None
            if previous and report['report_date'] <= previous['report_date']:
                raise ValueError('Report must be newer than the latest snapshot; a conflicting same-date report needs review.')
            events = compare_reports(previous, report)
            stamp = now()
            notify_soft = self.db.get('meta', 'settings', {}).get('notify_soft')
            # Snapshot, events and dashboard alerts must survive together.
            with self.db.lock:
                self.db.conn.execute('BEGIN')
                try:
                    rows = [('snapshots', {'id': digest, 'agency': agency, 'digest': digest, 'report': report, 'created_at': stamp})]
                    for event in events:
                        event_id = hashlib.sha256((digest + event['key']).encode()).hexdigest()
                        rows.append(('credit_events', dict(event, id=event_id, agency=agency, created_at=stamp)))
                        if event['severity'] == 'important' or notify_soft:
                            rows.append(('alerts', {'id': event_id, 'kind': 'credit', 'title': event['title'],
                                                    'detail': event['detail'], 'agency': agency, 'severity': event['severity'],
                                                    'created_at': stamp, 'read': False}))
                    for collection, value in rows:
                        payload = self.db.cipher.encrypt(json.dumps(value).encode())
                        self.db.conn.execute('INSERT INTO records VALUES (?,?,?)', (collection, value['id'], payload))
                    self.db.conn.commit()
                except Exception:
                    self.db.conn.rollback()
                    raise
            return {'duplicate': False, 'baseline': previous is None, 'events': events}

    def alert(self, kind, title, detail, **extra):
        return self.db.put('alerts', {'kind': kind, 'severity': 'important', 'title': title, 'detail': detail,
                                      'created_at': now(), 'read': False, **extra})

    def credit_summary(self):
        rows = []
        all_events = self.db.all('credit_events')
        snapshots = self.db.all('snapshots')
        for agency in ('experian', 'equifax', 'transunion'):
            events = [e for e in all_events if e['agency'] == agency]
            owned = [s for s in snapshots if s['agency'] == agency]
            rows.append({'agency': agency, 'latest_at': max((s['report']['report_date'] for s in owned), default=None),
                         'snapshot_count': len(owned), 'important_count': sum(e['severity'] == 'important' for e in events),
                         'soft_count': sum(e['kind'] == 'new_soft_search' for e in events), 'events': events[:200]})
        return rows

    async def scan(self, source_id=None):
        if self.lock.locked():
            raise ValueError('A scan is already running')
        async with self.lock:
            sources = self.db.all('sources')
            if source_id:
                sources = [s for s in sources if s['id'] == source_id]
                if not sources:
                    raise ValueError('Source not found')
            else:
                sources = [s for s in sources if s.get('enabled')]
            profile = self.db.get('meta', 'profile', {})
            connections = self.db.get('meta', 'connections', {})
            runs = []
            for source in sources:
                try:
                    async with asyncio.timeout(SOURCE_TIMEOUT_SECONDS):
                        outcome = await scan_source(source, profile, connections, self.browser)
                    if 'report' in outcome:
                        if outcome['report'].get('agency') != source['id']:
                            raise ValueError('Captured report agency does not match this connection')
                        receipt = await self.import_report(outcome['report'])
                        outcome['detail'] = 'Report accepted. ' + ('Baseline saved.' if receipt.get('baseline') else f"{len(receipt['events'])} changes recorded.")
                    for item in outcome.get('findings', []):
                        key = hashlib.sha256((source['id'] + ':' + item['key']).encode()).hexdigest()
                        old = self.db.get('findings', key)
                        finding = dict(item, id=key, source_id=source['id'], first_seen=old['first_seen'] if old else now(),
                                       last_seen=now(), status=old['status'] if old else 'candidate')
                        self.db.put('findings', finding)
                        if not old:
                            self.alert('exposure', 'New exposure to review: ' + item['title'], 'Open Privacy Bot to review the evidence.')
                        for removal in self.db.all('removals'):
                            if removal.get('finding_id') == key and removal['status'] == 'verified_removed':
                                removal.update(status='reappeared', updated_at=now(), note='Matching evidence appeared again; re-check identity and request status.')
                                self.db.put('removals', removal)
                                self.alert('removal', 'A removed listing may have reappeared', source['name'])
                except TimeoutError:
                    outcome = {'status': 'error', 'detail': 'Source exceeded the check time limit; coverage is unknown. Other sources will still be checked.'}
                except Exception as exc:
                    # Never expose URLs, credentials, third-party bodies or report contents in exceptions.
                    outcome = {'status': 'error', 'detail': f'Check failed ({type(exc).__name__}); no clean or removed conclusion. Review login and source configuration.'}
                source.update(status=outcome['status'], last_checked=now(), detail=outcome['detail'])
                self.db.put('sources', source)
                run = self.db.put('runs', {'source_id': source['id'], 'status': outcome['status'], 'detail': outcome['detail'],
                                          'no_match': outcome.get('no_match', False), 'created_at': now()})
                runs.append(run)
            if source_id is None:
                self.db.put('meta', {'last_scan': now()}, 'schedule')
            await self.notify()
            return {'runs': runs}

    async def notify(self):
        cfg = self.db.get('meta', 'connections', {})
        url = cfg.get('notification_url')
        pending = [a for a in self.db.all('alerts') if not a.get('notified') and a['severity'] == 'important']
        if not url or not pending:
            return
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
                response = await client.post(url, json={'title': 'Privacy Bot', 'message': f'{len(pending)} important changes need review.', 'count': len(pending)})
                response.raise_for_status()
            for item in pending:
                self.db.put('alerts', dict(item, notified=True))
            self.db.put('meta', {'status': 'delivered', 'at': now()}, 'notification_status')
        except Exception:
            self.db.put('meta', {'status': 'error', 'detail': 'Notification delivery failed; alerts remain in the dashboard.', 'at': now()}, 'notification_status')

    async def scheduler(self):
        self.running = True
        failures = 0
        try:
            while True:
                delay = 60
                try:
                    self.db.snapshot()
                    settings = self.db.get('meta', 'settings', {})
                    last = self.db.get('meta', 'schedule', {}).get('last_scan')
                    elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds() if last else float('inf')
                    if settings.get('enabled') and elapsed >= settings.get('interval_hours', 24) * 3600 and not self.lock.locked():
                        await self.scan()
                    await self.notify()
                    failures = 0
                    self.scheduler_status = {'status': 'ok', 'failures': 0}
                except Exception as exc:
                    # Storage may itself be unavailable: keep retry state in memory
                    # instead of repeatedly querying providers then failing to save.
                    failures += 1
                    delay = min(3600, 300 * 2 ** min(failures - 1, 4))
                    self.scheduler_status = {'status': 'error', 'failures': failures,
                                             'retry_at': (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat()}
                    logging.getLogger(__name__).error('Scheduled check failed (%s); retry deferred. No personal data logged.', type(exc).__name__)
                await asyncio.sleep(delay)
        finally:
            self.running = False


def send_email(removal, cfg):
    host, sender = cfg.get('smtp_host'), cfg.get('smtp_from')
    if not host or not sender:
        raise ValueError('Configure SMTP before sending requests')
    for value in (sender, removal['recipient'], removal['subject']):
        if '\r' in value or '\n' in value:
            raise ValueError('Invalid email header')
    msg = EmailMessage()
    msg['From'], msg['To'], msg['Subject'] = sender, removal['recipient'], removal['subject']
    msg.set_content(removal['body'])
    port = int(cfg.get('smtp_port', 587))
    context = ssl.create_default_context()
    if port == 465:
        conn = smtplib.SMTP_SSL(host, port, timeout=20, context=context)
    else:
        conn = smtplib.SMTP(host, port, timeout=20)
    with conn:
        if port != 465:
            conn.starttls(context=context)
        if cfg.get('smtp_user'):
            conn.login(cfg['smtp_user'], cfg.get('smtp_password', ''))
        refused = conn.send_message(msg)
        if refused:
            raise ValueError('SMTP did not accept every recipient')
