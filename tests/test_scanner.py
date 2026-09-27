"""Page-quality gates in scanner.page_matches.

The contract these tests hold: an HTTP 200 is not evidence of absence. A source may be
recorded as ``checked`` with ``no_match`` only when the page itself positively showed a
result state — a reviewed result area with readable content, or the reviewed "no records"
marker with readable content. Blank pages, login walls, bot challenges, drifted layouts and
contradictory pages get a non-clean status instead, and no clean status ever claims more
than the one page that was read.
"""
from unittest.mock import AsyncMock

import pytest

from privacy_bot.scanner import page_matches, scan_source

EMAIL = 'fixture@example.com'
PHONE = '07700900123'
NAME = 'Private Fixture'

#: A populated page; a stray "Sign in" link alone is not evidence of a login wall.
FILLER = ' '.join(f'County court judgement index entry {i} for another person entirely.' for i in range(40))


def source(**config):
    return {'id': 'fixture-broker', 'name': 'Fixture Broker', 'mode': 'http', 'kind': 'broker', 'config': config}


def profile(**overrides):
    base = {'name': NAME, 'email': EMAIL, 'phone': PHONE, 'addresses': [], 'aliases': []}
    base.update(overrides)
    return base


def page(body):
    return f'<html><body><h1>Public register search</h1><p>{FILLER}</p>{body}</body></html>'


def assert_not_clean(data):
    """Nothing that could be filed as a successful "not found" check."""
    assert data['status'] in {'blocked', 'needs_login', 'needs_setup', 'error'}, data
    assert not data.get('no_match')
    assert data['findings'] == []


# (a) ------------------------------------------------------------------ blank pages
@pytest.mark.parametrize('html', [
    '',
    '   ',
    '<html><body></body></html>',
    f'<html><body><script>var note = "{EMAIL}";</script></body></html>',
    f'<html><body><div><noscript>{EMAIL}</noscript><template>{EMAIL}</template></div></body></html>',
    '<html><body><p>....</p><p>- - -</p></body></html>',
])
def test_blank_or_nonrendered_page_is_never_a_no_match(html):
    assert_not_clean(page_matches(source(), profile(), html, 'https://broker.example/search'))


def test_blank_page_stays_non_clean_even_with_a_reviewed_empty_marker():
    data = page_matches(source(empty_selector='.no-results'), profile(), '<html><body></body></html>', 'https://broker.example/search')
    assert_not_clean(data)
    assert data['status'] == 'error'


# (a) ------------------------------------------------------------------ login walls
LOGIN = ('<form action="/account/login" method="post"><label>Email</label>'
         '<input type="email" name="email"><label>Password</label>'
         '<input type="password" name="password"><button>Sign in</button></form>')


def test_password_form_is_never_a_no_match():
    data = page_matches(source(), profile(), LOGIN, 'https://broker.example/search')
    assert data['status'] == 'needs_login'
    assert_not_clean(data)


@pytest.mark.parametrize('config', [
    {},
    {'empty_selector': '.no-results'},
    {'match_selector': '.results'},
    {'match_selector': '.results', 'empty_selector': '.no-results'},
])
def test_login_wall_beats_every_emptiness_signal(config):
    """A page you must sign in on cannot show "no records about you" honestly."""
    html = LOGIN + '<div class="no-results">No records found matching your search.</div>' + \
           '<div class="results">Sign in to see the full register entry.</div>'
    assert_not_clean(page_matches(source(**config), profile(), html, 'https://broker.example/search'))


def test_password_field_in_any_quoting_or_casing_is_still_a_login_wall():
    for html in ('<form><input type=PASSWORD></form>', '<form><input type=\'password\'></form>'):
        assert page_matches(source(), profile(), html, 'https://broker.example/search')['status'] == 'needs_login'


def test_signin_page_without_a_password_field_is_needs_login():
    html = '<html><body><h1>Restricted</h1><p>Sign in to continue to the register.</p><a href="/sso">Continue</a></body></html>'
    data = page_matches(source(empty_selector='.no-results'), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'needs_login'
    assert_not_clean(data)


# (b) ------------------------------------------------------------------ reviewed result selector
def test_missing_reviewed_match_selector_is_error():
    data = page_matches(source(match_selector='.results'), profile(), page('<div class="other">Layout changed</div>'), 'https://broker.example/search')
    assert data['status'] == 'error'
    assert 'match_selector' in data['detail']
    assert_not_clean(data)


def test_match_selector_that_renders_empty_chrome_counts_as_missing():
    data = page_matches(source(match_selector='.results'), profile(), page('<div class="results"><span></span></div>'), 'https://broker.example/search')
    assert_not_clean(data)
    assert data['status'] == 'error'


def test_missing_match_selector_is_rescued_only_by_a_real_empty_marker():
    html = page('<div class="no-results">No records found matching your search criteria.</div>')
    data = page_matches(source(match_selector='.results', empty_selector='.no-results'), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'checked' and data['no_match'] is True and data['findings'] == []


def test_missing_match_selector_without_empty_marker_is_not_clean():
    html = page('<div class="no-results">No records found matching your search criteria.</div>')
    assert_not_clean(page_matches(source(match_selector='.results'), profile(), html, 'https://broker.example/search'))


# (c) ------------------------------------------------------------------ explicit empty marker
def test_configured_empty_marker_with_no_identity_match_is_page_scoped_no_match():
    html = page('<div class="no-results">No records found matching your search criteria.</div>')
    data = page_matches(source(empty_selector='.no-results'), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'checked' and data['no_match'] is True
    assert data['findings'] == []
    # Coverage honesty: one page, not the database, not removal.
    assert 'this page only' in data['detail']
    assert 'removal' in data['detail'] and 'does not prove' in data['detail']


@pytest.mark.parametrize('body', [
    '<div class="no-results"></div>',
    '<div class="no-results">   </div>',
    '<div class="no-results"><span></span><i></i></div>',
    '<div class="no-results" hidden>No records found matching your search criteria.</div>',
    '<div class="no-results" aria-hidden="true">No records found matching your search criteria.</div>',
    '<div class="no-results" style="display:none">No records found matching your search criteria.</div>',
    '<div style="display:none"><div class="no-results">No records found matching your search criteria.</div></div>',
    '<div class="no-results" style="OPACITY: 0">No records found matching your search criteria.</div>',
    f'<div class="no-results"><script>text = "{EMAIL} no records";</script></div>',
    '<div class="no-results"><template>No records found matching your search criteria.</template></div>',
])
def test_empty_marker_must_carry_visible_meaningful_text(body):
    data = page_matches(source(empty_selector='.no-results'), profile(), page(body), 'https://broker.example/search')
    assert_not_clean(data)


def test_configured_empty_marker_that_never_rendered_is_not_clean():
    data = page_matches(source(empty_selector='.no-results'), profile(), page('<p>Some unrelated notice.</p>'), 'https://broker.example/search')
    assert_not_clean(data)
    assert data['status'] == 'error'


# (d) ------------------------------------------------------------------ contradictory page
def test_populated_results_and_empty_marker_together_are_contradictory():
    html = page('<div class="results"><table><tr><td>Another Person</td><td>12 Other Road</td></tr></table></div>'
                '<div class="no-results">No records found matching your search criteria.</div>')
    data = page_matches(source(match_selector='.results', empty_selector='.no-results'), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'error'
    assert 'contradicts itself' in data['detail']
    assert_not_clean(data)


def test_contradiction_is_reported_even_when_the_identity_matches():
    html = page(f'<div class="results"><table><tr><td>{EMAIL}</td></tr></table></div>'
                '<div class="no-results">No records found matching your search criteria.</div>')
    data = page_matches(source(match_selector='.results', empty_selector='.no-results'), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'error' and data['findings'] == []


# (e) ------------------------------------------------------------------ scoped results
def test_populated_result_area_without_the_identifier_is_no_match():
    html = page('<div class="results"><table><tr><td>Another Person</td><td>12 Other Road</td></tr></table></div>')
    data = page_matches(source(match_selector='.results'), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'checked' and data['no_match'] is True
    assert 'result area' in data['detail'] and 'this page only' in data['detail']


def test_identifier_inside_the_result_area_is_a_candidate():
    html = page(f'<div class="results"><table><tr><td>{NAME}</td><td>{EMAIL}</td></tr></table></div>')
    data = page_matches(source(match_selector='.results'), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'checked' and not data.get('no_match') and len(data['findings']) == 1


def test_match_selector_scopes_the_search_to_the_reviewed_area():
    """The container is the operator\u2019s reviewed decision about where listings appear."""
    html = page('<div class="results"><table><tr><td>Another Person</td></tr></table></div>') + f'<footer>{EMAIL}</footer>'
    data = page_matches(source(match_selector='.results'), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'checked' and data['no_match'] is True


def test_empty_marker_does_not_hide_an_identifier_elsewhere_on_the_page():
    html = page(f'<div class="no-results">No records found matching your search criteria.</div><p>{NAME}</p>')
    data = page_matches(source(empty_selector='.no-results'), profile(), html, 'https://broker.example/search')
    assert not data.get('no_match') and len(data['findings']) == 1
    assert 'no records' in data['findings'][0]['detail']


# (f) ------------------------------------------------------------------ nothing to look for
@pytest.mark.parametrize('identity', [
    {},
    {'name': '', 'email': '', 'phone': '', 'aliases': []},
    {'name': 'Al', 'email': 'a@b', 'phone': '123', 'aliases': []},
])
def test_no_identity_and_no_selector_needs_setup_not_checked(identity):
    data = page_matches(source(), identity, page('<div class="results">Anything at all</div>'), 'https://broker.example/search')
    assert data['status'] == 'needs_setup'
    assert_not_clean(data)


def test_terms_must_be_a_list_of_strings():
    data = page_matches(source(terms=EMAIL), profile(name='', email='', phone=''), page('<p>Anything</p>'), 'https://broker.example/search')
    assert data['status'] == 'needs_setup'
    assert_not_clean(data)


def test_explicit_terms_can_replace_the_profile():
    html = page('<p>Judgement against Someone Else</p>')
    clean = page_matches(source(terms=['Unrelated Person Q'], match_selector='p'), profile(name='', email='', phone=''), html, 'https://broker.example/search')
    assert clean['status'] == 'checked' and clean['no_match'] is True
    hit = page_matches(source(terms=['Someone Else']), profile(name='', email='', phone=''), html, 'https://broker.example/search')
    assert hit['status'] == 'checked' and not hit.get('no_match') and len(hit['findings']) == 1


# (g) ------------------------------------------------------------------ identifier alone
def test_identifier_without_any_selector_is_a_candidate_never_confirmed():
    html = page(f'<p>Judgement: {NAME}, {EMAIL}, {PHONE}</p>')
    data = page_matches(source(), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'checked'
    assert not data.get('no_match')
    assert len(data['findings']) == 1
    finding = data['findings'][0]
    # The scanner reports evidence only; confirming an exposure is a human action (service.py
    # files it as a candidate) and "no more work needed" is never one of its fields.
    assert finding.get('status', 'candidate') == 'candidate'
    assert 'removed' not in str(data).lower()
    assert set(finding['matched']) <= {NAME, EMAIL, PHONE} and finding['matched']
    assert 'echo' in finding['detail'] and 'confirm' in data['detail']


def test_thin_unscoped_page_cannot_prove_absence():
    data = page_matches(source(), profile(), '<html><body><p>Search complete.</p></body></html>', 'https://broker.example/search')
    assert data['status'] == 'needs_setup' and 'selector' in data['detail']
    assert_not_clean(data)


def test_rich_unscoped_page_without_the_identifier_needs_reviewed_selector():
    data = page_matches(source(), profile(), page('<p>Listing for Someone Else</p>'), 'https://broker.example/search')
    assert data['status'] == 'needs_setup'
    assert_not_clean(data)


def test_empty_marker_cannot_inherit_hidden_descendant_text():
    html = page('<div class="no-results"><span hidden>No records found</span></div>')
    assert_not_clean(page_matches(source(empty_selector='.no-results'), profile(), html, 'https://broker.example/search'))


# (h) ------------------------------------------------------------------ bad selector config
@pytest.mark.parametrize('key,value', [
    ('match_selector', '.results['),
    ('match_selector', '..drift'),
    ('match_selector', '#'),
    ('match_selector', 42),
    ('match_selector', ['.results']),
    ('match_selector', True),
    ('match_selector', 'x' * 500),
    ('empty_selector', '.no-results['),
    ('empty_selector', 42),
    ('empty_selector', {'sel': '.no-results'}),
    ('empty_selector', True),
])
def test_invalid_selector_or_wrong_type_is_error_not_clean(key, value):
    html = page('<div class="results"><p>Another Person</p></div><div class="no-results">No records found matching your search criteria.</div>')
    data = page_matches(source(**{key: value}), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'error' and not data.get('no_match') and data['findings'] == []


@pytest.mark.parametrize('bad_source', [None, 'source', {'config': 'not-a-dict'}, {'config': []}])
def test_unusable_source_shape_is_error(bad_source):
    assert page_matches(bad_source, profile(), page('<p>Anything</p>'), 'https://broker.example/search')['status'] == 'error'


def test_unusable_html_shape_is_error():
    assert page_matches(source(), profile(), {'not': 'html'}, 'https://broker.example/search')['status'] == 'error'


# --------------------------------------------------------------------- ordering
def test_challenge_detection_precedes_empty_markers():
    html = page('<div class="no-results">No records found matching your search criteria.</div><p>Verify you are human.</p>')
    data = page_matches(source(empty_selector='.no-results'), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'blocked' and not data.get('no_match')


def test_challenge_marker_in_a_footer_badge_does_not_block_a_real_page():
    html = page('<p>Listing for Someone Else</p>') + '<footer><p>This site is protected by reCAPTCHA.</p></footer>'
    data = page_matches(source(match_selector='p'), profile(), html, 'https://broker.example/search')
    assert data['status'] == 'checked' and data['no_match'] is True


def test_challenge_detection_precedes_the_login_gate():
    html = '<p>Checking your browser</p>' + LOGIN
    assert page_matches(source(), profile(), html, 'https://broker.example/search')['status'] == 'blocked'


# --------------------------------------------------------------------- wiring
@pytest.mark.asyncio
@pytest.mark.parametrize('html, expected', [
    ('<html><body></body></html>', 'error'),
    (LOGIN, 'needs_login'),
])
async def test_browser_capture_reaches_the_same_gates(html, expected):
    browser = AsyncMock()
    browser.capture.return_value = {'status': 'ok', 'html': html, 'url': 'https://broker.example/search', 'detail': ''}
    data = await scan_source(dict(source(), mode='browser'), profile(), {}, browser)
    assert data['status'] == expected and not data.get('no_match')


@pytest.mark.asyncio
async def test_http_scan_of_a_login_page_is_not_a_no_match(monkeypatch):
    seen = []

    async def fake_fetch(url, headers=None, client=None):
        seen.append(url)
        return 200, '<html><body><h1>Member area</h1><p>Sign in to view records.</p>' + LOGIN + '</body></html>', 'https://broker.example/search'

    monkeypatch.setattr('privacy_bot.scanner.fetch_public', fake_fetch)
    data = await scan_source(source(watch_url='https://broker.example/search'), profile(), {}, AsyncMock())
    assert seen == ['https://broker.example/search']
    assert data['status'] == 'needs_login' and not data.get('no_match')


@pytest.mark.asyncio
async def test_http_scan_of_a_blank_200_is_not_a_no_match(monkeypatch):
    async def fake_fetch(url, headers=None, client=None):
        return 200, '<html><body></body></html>', 'https://broker.example/search'

    monkeypatch.setattr('privacy_bot.scanner.fetch_public', fake_fetch)
    data = await scan_source(source(watch_url='https://broker.example/search'), profile(), {}, AsyncMock())
    assert data['status'] == 'error' and not data.get('no_match')


@pytest.mark.asyncio
async def test_manual_mode_still_asks_for_setup():
    data = await scan_source({'id': 's', 'name': 'Fixture Broker', 'mode': 'manual', 'kind': 'broker', 'config': {}}, profile(), {}, AsyncMock())
    assert data['status'] == 'needs_setup' and not data.get('no_match')
