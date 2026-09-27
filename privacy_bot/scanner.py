"""Bounded public-page checks and fixed-origin HIBP APIs. No dark-web browsing.

``page_matches`` is the only place a fetched page becomes an exposure verdict, so it fails
closed. A page yields ``checked`` with ``no_match`` only when something on *that* page
positively shows the source answered as a result page: a reviewed result area that rendered
readable content, or the source's own reviewed "no records" marker showing real text. Blank
bodies, sign-in walls, bot challenges, drifted or contradictory layouts and pages with no
identity to look for return ``error`` / ``needs_login`` / ``blocked`` / ``needs_setup``,
because an HTTP 200 is not evidence of absence and a silently-misread page would be filed as
a successful "not in this database" check. A clean page says nothing about the rest of the
source, about removal, or about any other page.
"""
import hashlib
import json
import re
from urllib.parse import quote, urljoin

import httpx
from bs4 import BeautifulSoup

from .network import validate_public_url

LIMIT = 2_000_000
HIBP = 'https://haveibeenpwned.com/api/v3/'
MAX_SELECTOR_CHARS = 400

#: Bot walls. Tested against the whole page *before* any emptiness signal, because a
#: challenge interstitial can carry the source's own "no records" wording and markup.
#: Words that only ever appear on a wall. Trusted at any page length.
CHALLENGE_MARKERS = (
    'verify you are human', 'checking your browser', 'cf-browser-verification', 'unusual traffic',
    'complete the captcha', 'temporarily blocked', 'are you a robot', 'access denied',
)
#: Words that a legitimate page can also carry in a footer badge or a spam note, so they only
#: count as a wall when the page has nothing else on it.
THIN_CHALLENGE_MARKERS = ('captcha', 'just a moment', 'enable javascript and cookies', 'attention required')
#: Sign-in walls that carry no password field (an SSO or "continue" button page).
LOGIN_MARKERS = (
    'sign in to', 'sign into', 'log in to', 'log into', 'signin', 'logon', 'sign-in required',
    'login required', 'enter your password', 'one-time code', 'verification code', 'enter the code',
)
#: A page longer than this counts as real content even when a header "Sign in" link is onscreen.
#: Same threshold the browser module uses, so both readers disagree in the same direction.
CONTENT_ENOUGH_CHARS = 1_500
#: A region with no word this long is chrome, not content: an empty element, a bullet, or a
#: script/template that rendered nothing.
MEANINGFUL_RE = re.compile(r'\w{3}', re.UNICODE)


async def fetch_public(url, headers=None, client=None):
    # A moved/parked broker domain needs review; do not silently scan a different
    # operator after a redirect. A corrected watch URL can be saved explicitly.
    original_host = httpx.URL(url).host
    own = client is None
    egress = None
    if own:
        from .egress import PublicEgress
        egress = PublicEgress()
        proxy = await egress.start()
        client = httpx.AsyncClient(timeout=25, follow_redirects=False, trust_env=False, proxy=proxy)
    try:
        for _ in range(5):
            await validate_public_url(url, allowed_hosts=[original_host])
            async with client.stream('GET', url, headers=headers or {'User-Agent': 'PrivacyBot/0.1 personal-monitor'}) as r:
                if r.is_redirect:
                    url = urljoin(url, r.headers.get('location', ''))
                    continue
                body = bytearray()
                async for chunk in r.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > LIMIT:
                        raise ValueError('Response exceeded the 2 MB safety limit')
                return r.status_code, bytes(body).decode('utf-8', errors='replace'), str(r.url)
        raise ValueError('Too many redirects')
    finally:
        if own:
            await client.aclose()
            await egress.close()


def result(status, detail, findings=None, **extra):
    return {'status': status, 'detail': detail, 'findings': findings or [], **extra}


def _text_of(nodes):
    return ' '.join(node.get_text(' ', strip=True) for node in nodes)


def _hidden(node):
    """True when a person could not see this node: self or any ancestor is hidden.

    Only inline styles and ARIA/hidden attributes are visible without a layout engine, and
    that is enough for the two things this matters for: an empty "no records" template kept
    in the page for JavaScript to reveal, and a results block collapsed by default.
    """
    for candidate in (node, *node.parents):
        if candidate is None or getattr(candidate, 'get', None) is None:
            continue
        if candidate.get('hidden') is not None:
            return True
        if str(candidate.get('aria-hidden', '')).strip().casefold() == 'true':
            return True
        style = str(candidate.get('style', '')).casefold().replace(' ', '')
        if 'display:none' in style or 'visibility:hidden' in style or 'opacity:0' in style:
            return True
    return False


def _password_field(soup):
    """Any password input, whatever quoting or casing the page used."""
    return any(str(node.get('type', '')).strip().casefold() == 'password' for node in soup.find_all('input'))


def _selector_state(soup, raw, key):
    """``(state, visible_text, detail)`` for one configured CSS selector.

    ``none`` = not configured; ``invalid`` = unusable value or CSS; ``absent`` = configured
    but this page rendered nothing readable there; ``present`` = visible, meaningful content.
    An empty, hidden or script-only element is ``absent``, never ``present``.
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return 'none', '', ''
    if isinstance(raw, bool) or not isinstance(raw, str):
        return 'invalid', '', f'The configured {key} is not a CSS selector string.'
    selector = raw.strip()
    if len(selector) > MAX_SELECTOR_CHARS:
        return 'invalid', '', f'The configured {key} is longer than {MAX_SELECTOR_CHARS} characters.'
    try:
        nodes = soup.select(selector)
    except Exception as exc:  # soupsieve raises several syntax/unsupported errors
        return 'invalid', '', f'The configured {key} is not valid CSS ({type(exc).__name__}).'
    visible = [node for node in nodes if getattr(node, 'name', None) and not _hidden(node)]
    text = _text_of(visible)
    if not MEANINGFUL_RE.search(text):
        return 'absent', '', f'The configured {key} was absent or showed no readable text on this page.'
    return 'present', text, ''


def _identity_terms(profile, config):
    """Exact strings to look for, or the reason there are none. Never a fuzzy guess."""
    configured = config.get('terms', [])
    if configured and not isinstance(configured, (list, tuple)):
        return [], 'The configured terms are not a list of strings; add your identity or explicit match terms.'
    if not configured:
        identity = profile if isinstance(profile, dict) else {}
        aliases = identity.get('aliases') or []
        if not isinstance(aliases, (list, tuple)):
            aliases = []
        configured = [identity.get('email'), identity.get('phone'), identity.get('name'), *aliases]
    terms = [t.strip() for t in configured if isinstance(t, str) and len(t.strip()) >= 4]
    if not terms:
        return [], 'Add your name, email, phone or explicit match terms before scanning: a page cannot be checked against nothing.'
    return terms, ''


def page_matches(source, profile, html, url):
    """Verdict for one page: never a clean result without positive evidence of one."""
    url = str(url or '')
    if not isinstance(source, dict):
        return result('error', 'This source is not a readable record; no exposure conclusion.')
    config = source.get('config', {})
    if not isinstance(config, dict):
        return result('error', 'This source configuration is not a readable object; no exposure conclusion.')
    if isinstance(html, (bytes, bytearray)):
        html = bytes(html).decode('utf-8', errors='replace')
    if not isinstance(html, str):
        return result('error', 'The page could not be read as text; no exposure conclusion.')
    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception as exc:
        return result('error', f'The page could not be parsed ({type(exc).__name__}); no exposure conclusion.')
    for tag in soup(['script', 'style', 'noscript', 'template']):
        tag.decompose()
    # Remove hidden descendants too: visible parents must not inherit an empty
    # marker's text from a hidden template nested inside them.
    for tag in list(soup.find_all(True)):
        if tag.attrs is not None and _hidden(tag):
            tag.decompose()
    text = soup.get_text(' ', strip=True)
    lowered = text.casefold()
    # 1. A challenge can imitate anything below it, so it is judged on the whole page first.
    thin = len(text) < CONTENT_ENOUGH_CHARS
    if any(marker in lowered for marker in CHALLENGE_MARKERS) or (thin and any(marker in lowered for marker in THIN_CHALLENGE_MARKERS)):
        return result('blocked', 'The source presented a challenge. Open its private browser to continue.')
    # 2. A login page proves nothing about listings, in either direction.
    if _password_field(soup):
        return result('needs_login', 'The page is a sign-in form, not a result. Nothing was checked: sign in through this source\u2019s private browser, then run the check again.')
    if thin and any(marker in lowered for marker in LOGIN_MARKERS):
        return result('needs_login', 'The page asks you to sign in before showing records, so nothing was checked. Sign in through this source\u2019s private browser, or configure a reviewed match_selector.')
    # 3. Blank / chrome-only documents are a failed check, not a clean one.
    if not MEANINGFUL_RE.search(text):
        return result('error', 'The page carried no readable text (blank, script-only or a blocked render). That is not a no-match result: check the watch URL or use the private browser.')
    match_state, match_text, match_detail = _selector_state(soup, config.get('match_selector'), 'match_selector')
    empty_state, _, empty_detail = _selector_state(soup, config.get('empty_selector'), 'empty_selector')
    if match_state == 'invalid' or empty_state == 'invalid':
        return result('error', (match_detail or empty_detail) + ' Fix it before trusting any conclusion from this source.')
    # 4. Both states at once means the page contradicts its own configuration.
    if match_state == 'present' and empty_state == 'present':
        return result('error', 'This page shows both a populated result area (match_selector) and the configured "no records" marker (empty_selector), so the check contradicts itself and no conclusion was recorded.')
    terms, term_detail = _identity_terms(profile, config)
    if not terms:
        return result('needs_setup', term_detail)
    if match_state == 'present':
        # A reviewed container that rendered real content: searching it and finding nothing
        # your identity in is a legitimate no-match for this page.
        haystack, scoped = match_text, True
    elif match_state == 'absent':
        if empty_state != 'present':
            return result('error', match_detail + ' The layout or login state may have changed; no clean conclusion was recorded.')
        haystack, scoped = text, False
    elif empty_state == 'absent':
        # The reviewed "no records" marker did not render, so this is not the expected empty
        # state — it is whatever else the page turned into (drift, a wall, an error template).
        return result('error', empty_detail + ' The source did not render its expected empty state, so nothing was concluded.')
    else:
        haystack, scoped = text, False
    folded = haystack.casefold()
    matched = [term for term in terms if term.casefold() in folded]
    if matched:
        # Search forms can echo the query and the page may also deny having records; every
        # match stays a candidate for human review and is never auto-confirmed.
        detail = 'Exact text match on the checked page; may include a search-term echo.'
        if empty_state == 'present':
            detail += ' The page also showed its "no records" marker, so open it to review.'
        return result('checked', 'Potential matching text found; confirm identity and listing context before removal.', [{
            'key': hashlib.sha256(url.encode()).hexdigest(), 'title': str(source.get('name', 'Source')) + ' — potential exposure',
            'url': url, 'matched': matched, 'detail': detail,
        }])
    if not scoped and empty_state != 'present':
        return result('needs_setup', 'No reviewed result or empty-state selector was available. Configure match_selector or empty_selector before treating a missing identifier as a completed check.')
    evidence = ('The source showed its configured "no records" marker here' if empty_state == 'present'
                else 'The configured result area rendered content here')
    return result('checked', f'{evidence} and carried no exact configured identifier. That covers this page only: it does not prove absence from the database, from other pages, or any removal.', no_match=True)


async def hibp_lookup(source, profile, connections, client=None):
    key = connections.get('hibp_api_key', '')
    email = profile.get('email', '').strip()
    if not key or not email:
        return result('needs_setup', 'Add a HIBP API key and your email, then enable this source. Queries disclose the email to HIBP.')
    stealer = source.get('mode') == 'hibp_stealer'
    endpoint = ('stealerLogsByEmail/' if stealer else 'breachedaccount/') + quote(email, safe='')
    if not stealer:
        endpoint += '?truncateResponse=false'
    own = client is None
    client = client or httpx.AsyncClient(timeout=25, follow_redirects=False, trust_env=False)
    try:
        # Fixed HTTPS origin and no redirects: API key cannot be sent to another host.
        async with client.stream('GET', HIBP + endpoint,
                                 headers={'hibp-api-key': key, 'User-Agent': 'PrivacyBot/0.1'}) as response:
            status = response.status_code
            if status == 404:
                return result('checked', 'No records returned by this HIBP endpoint. Coverage is limited to its indexed, available data.', no_match=True)
            if status in (401, 403):
                return result('needs_setup', 'HIBP access denied. Check the key and plan; stealer logs require Pro and verified control of the email domain.')
            if status == 429:
                return result('blocked', 'HIBP rate limit reached; wait until the next scheduled check. No automatic rapid retry.')
            if status != 200:
                return result('error', f'HIBP returned HTTP {status}; exposure status is unknown.')
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > LIMIT:
                    raise ValueError('HIBP response exceeded the safety limit')
        data = json.loads(body)
        if not isinstance(data, list):
            raise ValueError('Unexpected HIBP response schema')
        findings = []
        for item in data:
            if stealer:
                if not isinstance(item, str) or not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', item):
                    raise ValueError('Unexpected stealer-log domain schema')
                name, detail = item, 'HIBP reports this website domain in stealer logs for the queried email. No password or raw log is fetched.'
            else:
                if not isinstance(item, dict) or not isinstance(item.get('Name'), str):
                    raise ValueError('Unexpected breach schema')
                name = item['Name']
                detail = 'Breach date: ' + str(item.get('BreachDate', 'unknown')) + '. Data classes: ' + ', '.join(str(x) for x in item.get('DataClasses', []))
            findings.append({'key': name, 'title': name, 'url': 'https://haveibeenpwned.com/', 'matched': [email], 'detail': detail})
        return result('checked', f'HIBP returned {len(findings)} records. This is provider coverage, not a complete dark-web scan.', findings)
    finally:
        if own:
            await client.aclose()


async def scan_source(source, profile, connections, browser, client=None):
    mode = source.get('mode', 'manual')
    if mode == 'discovery':
        from .discovery import discover
        return await discover(source, profile)
    if mode in {'hibp', 'hibp_stealer'}:
        return await hibp_lookup(source, profile, connections, client)
    if mode == 'manual':
        return result('needs_setup', 'Open the source, locate your listing, then configure an exact public-page watch or browser extraction.')
    if mode not in {'http', 'browser'}:
        return result('blocked', 'Direct dark-web crawling is disabled. Use the third-party exposure provider.')
    if source.get('kind') == 'credit':
        if not source.get('config', {}).get('report_selector'):
            return result('needs_setup', 'Import a report or configure a reviewed JSON report selector after logging in. No guessed credit parsing is accepted.')
        capture = await browser.capture(source)
        if capture.get('status') in {'blocked', 'needs_login', 'error', 'unavailable'}:
            return result(capture['status'], capture.get('detail', 'Browser capture did not succeed'))
        report_text = capture.get('report_text')
        if not report_text:
            return result('needs_login', 'No structured report captured. Check login and the configured report selector.')
        return result('checked', 'Captured structured report; validation must pass before it becomes a snapshot.', report=json.loads(report_text))
    if mode == 'browser':
        capture = await browser.capture(source)
        if capture.get('status') in {'blocked', 'needs_login', 'error', 'unavailable'}:
            return result(capture['status'], capture.get('detail', 'Browser capture did not succeed'))
        return page_matches(source, profile, capture['html'], capture['url'])
    url = source.get('config', {}).get('watch_url', '')
    if not url:
        return result('needs_setup', 'Configure an exact listing or search URL; a homepage is not an exposure scan.')
    for field in ('name', 'email', 'phone'):
        url = url.replace('{' + field + '}', quote(profile.get(field, ''), safe=''))
    status, html, final_url = await fetch_public(url, client=client)
    if status in (401, 403, 429):
        return result('blocked', f'Source returned HTTP {status}; sign in or check again later.')
    if status != 200:
        return result('error', f'Source returned HTTP {status}; no exposure conclusion.')
    return page_matches(source, profile, html, final_url)
