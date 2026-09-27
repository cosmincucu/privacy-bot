"""One egress listener per manager, and no driver stranded by a failed launch.

The failure these tests were written for: ``BrowserSessions._launch`` started the shared
``self.egress`` on *every* call, and ``PublicEgress.start`` refuses an already-running listener.
So the second browser session — or the first automated capture after any session — failed
outright, and because the Playwright driver had already been started, that failure also stranded
a driver with nothing left to close it (only ``stop`` closes the proxy, and a session that never
existed is never disposed).

The claims under test, in order of how much they matter:

1. two sessions / two captures in one manager reuse the *same* listening egress socket;
2. an egress that cannot start does not leave a driver running;
3. a launch, ``new_page`` or route-setup failure — cancellation included — closes the context it
   created and stops the driver it started, and leaves the session empty so ``_dispose`` after it
   is a no-op rather than a second, blinder close;
4. a cleanup that itself fails never replaces the error the caller is told about;
5. the lifecycle work does not cost the privacy flags: numeric-loopback proxy with the
   ``<-loopback>`` bypass, sandbox on, downloads refused, service workers blocked, the per-request
   route guard and the 0700 profile;
6. ``stop`` still closes the listener, so the next launch binds a fresh one instead of trusting a
   stale URL.

Nothing here launches Chromium or reaches a network. The Playwright objects are fakes that record
what was started and what was closed; the only real socket is the loopback ``PublicEgress``
listener, which a test connects to locally to prove the reused listener is genuinely live and
still refuses a LAN address.
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import ipaddress
import stat
import sys
from pathlib import Path

import pytest

# Import the code under test from this checkout, so a plain ``pytest`` run works before the
# package is installed (and never picks up another checkout's copy).
ROOT = str(Path(__file__).resolve().parents[1])
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from privacy_bot import network  # noqa: E402
from privacy_bot.browser import (  # noqa: E402
    CHROMIUM_ARGS,
    VIEWPORT,
    BrowserError,
    BrowserSessions,
)

#: A public-looking hostname whose *resolution* is faked below. The navigation guard refuses a
#: numeric literal as an "encoded IP address", so a source URL has to be a name; the egress side
#: still only ever dials the numeric answer it validated.
PUBLIC_V4 = "93.184.216.34"
SOURCE_HOST = "privacy-report.example.com"
START_URL = f"https://{SOURCE_HOST}/report/42"


# --------------------------------------------------------------------------- fakes


@dataclasses.dataclass
class Launch:
    """One ``launch_persistent_context`` call as the browser saw it."""

    profile_dir: str
    options: dict


class FakePage:
    def __init__(self, context: "FakeContext") -> None:
        self._context = context
        self.url = "about:blank"

    async def goto(self, url, **_kwargs):
        self.url = str(url)
        return FakeResponse()

    async def evaluate(self, _script, _args=None):
        return {
            "html": "<html><body>your report is here</body></html>",
            "text": "Here is the account statement content. " * 80,
            "title": "Report",
            "password": False,
        }

    async def screenshot(self, **_kwargs):
        return b"\x89PNG\r\n\x1a\nnot-a-real-screenshot"


class FakeResponse:
    status = 200


class FakeContext:
    def __init__(self, recorder: "FakePlaywright", profile_dir: str, options: dict) -> None:
        self.recorder = recorder
        self.profile_dir = profile_dir
        self.options = options
        self.pages = [] if recorder.no_pages else [FakePage(self)]
        self.routes: list[tuple[str, object]] = []
        self.events: list[str] = []
        self.close_attempts = 0
        self.cdp_attempts = 0

    async def new_page(self):
        if self.recorder.new_page_error is not None:
            raise self.recorder.new_page_error
        page = FakePage(self)
        self.pages.append(page)
        return page

    async def route(self, pattern, handler):
        if self.recorder.route_error is not None:
            raise self.recorder.route_error
        self.routes.append((pattern, handler))

    def on(self, event, handler):
        self.events.append(str(event))

    async def new_cdp_session(self, _page):
        # No CDP in tests: _stop_service_workers must degrade to "CDP is a bonus".
        self.cdp_attempts += 1
        raise RuntimeError("no CDP session in tests")

    async def close(self):
        self.close_attempts += 1
        if self.recorder.close_error is not None:
            raise self.recorder.close_error


class FakeDriver:
    def __init__(self, recorder: "FakePlaywright") -> None:
        self.recorder = recorder
        self.chromium = self
        self.stop_attempts = 0
        self.contexts: list[FakeContext] = []

    async def launch_persistent_context(self, user_data_dir, **options):
        if self.recorder.launch_error is not None:
            raise self.recorder.launch_error
        context = FakeContext(self.recorder, str(user_data_dir), options)
        self.contexts.append(context)
        self.recorder.contexts.append(context)
        self.recorder.launches.append(Launch(str(user_data_dir), options))
        return context

    async def stop(self):
        self.stop_attempts += 1
        if self.recorder.stop_error is not None:
            raise self.recorder.stop_error


class FakePlaywright:
    """``async_playwright`` replacement: counts every driver started and every one accounted for."""

    def __init__(self) -> None:
        self.drivers: list[FakeDriver] = []
        self.contexts: list[FakeContext] = []
        self.launches: list[Launch] = []
        # failure knobs
        self.launch_error: BaseException | None = None
        self.new_page_error: BaseException | None = None
        self.route_error: BaseException | None = None
        self.close_error: BaseException | None = None
        self.stop_error: BaseException | None = None
        self.no_pages = False

    def __call__(self) -> "_Handle":
        return _Handle(self)

    @property
    def stranded_drivers(self) -> list[FakeDriver]:
        """Drivers a launch created and nobody tried to stop — the leak under test."""
        return [driver for driver in self.drivers if driver.stop_attempts == 0]

    @property
    def stranded_contexts(self) -> list[FakeContext]:
        return [context for context in self.contexts if context.close_attempts == 0]


class _Handle:
    def __init__(self, recorder: FakePlaywright) -> None:
        self._recorder = recorder

    async def start(self) -> FakeDriver:
        driver = FakeDriver(self._recorder)
        self._recorder.drivers.append(driver)
        return driver


@pytest.fixture()
def pw(monkeypatch) -> FakePlaywright:
    recorder = FakePlaywright()
    monkeypatch.setattr("playwright.async_api.async_playwright", recorder)
    return recorder


@pytest.fixture(autouse=True)
def no_resolver(monkeypatch):
    """Keep the URL guard's rules but never call libc: these tests use numeric destinations."""

    async def fake_resolve(host: str) -> list[str]:
        # A numeric host answers itself (never reached: the guard refuses those first); a
        # hostname gets one public answer, so no resolver and no network is touched.
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            return [PUBLIC_V4]

    monkeypatch.setattr(network, "_resolve", fake_resolve)


def source(source_id: str, url: str = START_URL) -> dict:
    return {"id": source_id, "name": f"Source {source_id}", "url": url}


def draft_session(source_id: str = "src-a") -> dict:
    """The session shape ``start`` / ``_capture`` hand to ``_launch``."""
    return {
        "id": source_id, "guard": asyncio.Lock(),
        "allowed_hosts": None, "allow_onion": False,
        "expires": 0.0,
        "pw": None, "context": None, "page": None,
        "http_status": None, "http_url": "", "nav_error": "",
    }


async def egress_says_no_to_the_lan(egress) -> str:
    """Ask the live listener to reach a LAN address; the answer must be a bare 403."""
    host, port = egress.bound_address
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(b"CONNECT 192.168.1.1:443 HTTP/1.1\r\nHost: 192.168.1.1:443\r\n\r\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), 5)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return line.decode("latin-1").strip()


# ----------------------------------------------------------------- one egress, many sessions


async def test_two_captures_reuse_one_listening_egress(tmp_path, pw):
    """The regression: capture #2 used to die on "PublicEgress is already running"."""
    manager = BrowserSessions(tmp_path)
    try:
        first = await manager.capture(source("src-a"))
        listening_on = manager.egress.bound_address
        assert first["status"] == "ok", first["detail"]
        assert listening_on is not None

        second = await manager.capture(source("src-b"))

        assert second["status"] == "ok", second["detail"]
        assert manager.egress.bound_address == listening_on, "a second listener replaced the first"
        assert len(pw.launches) == 2
        proxy_urls = {launch.options["proxy"]["server"] for launch in pw.launches}
        assert proxy_urls == {f"http://{listening_on[0]}:{listening_on[1]}"}, proxy_urls
        assert pw.stranded_drivers == [], "a launch left a Playwright driver running"
        assert pw.stranded_contexts == []
        # that single reused socket is really the fail-closed egress, not an open relay
        assert await egress_says_no_to_the_lan(manager.egress) == "HTTP/1.1 403 Forbidden"
    finally:
        await manager.stop()


async def test_two_session_starts_and_a_capture_share_one_egress(tmp_path, pw):
    """Same for the interactive path: MAX_SESSIONS of them, one listener between them."""
    manager = BrowserSessions(tmp_path)
    first = await manager.start(source("src-a"))
    listening_on = manager.egress.bound_address
    second = await manager.start(source("src-b"))
    third = await manager.capture(source("src-c"))
    try:
        assert first["status"] == "ok" and second["status"] == "ok", (second["status"], second["detail"])
        assert third["status"] == "ok", third["detail"]
        assert manager.egress.bound_address == listening_on
        assert len(pw.launches) == 3
        assert {launch.options["proxy"]["server"] for launch in pw.launches} == {
            f"http://{listening_on[0]}:{listening_on[1]}"
        }
        # the throwaway capture released its browser; the two sessions still open keep theirs
        assert [driver.stop_attempts for driver in pw.drivers] == [0, 0, 1]
        assert [context.close_attempts for context in pw.contexts] == [0, 0, 1]
    finally:
        await manager.stop()

    # and stop() is what owns them: no browser object, and no listener, outlives the manager
    assert manager.sessions == {}
    assert manager.egress.proxy_url is None and manager.egress.listening is False
    assert pw.stranded_drivers == [] and pw.stranded_contexts == []


# ------------------------------------------------------------------- failure must not strand


async def test_egress_that_cannot_start_leaves_no_driver(tmp_path, pw, monkeypatch):
    """The driver used to be started *before* the proxy, then orphaned when the proxy raised."""
    manager = BrowserSessions(tmp_path)
    session = draft_session()

    async def broken_start() -> str:
        raise OSError("cannot assign requested address")

    monkeypatch.setattr(manager.egress, "start", broken_start)
    try:
        with pytest.raises(OSError):
            await manager._launch(session)

        assert pw.stranded_drivers == [], "a proxy failure leaked a Playwright driver"
        assert pw.stranded_contexts == []
        assert (session["pw"], session["context"], session["page"]) == (None, None, None)
        await manager._dispose(session)  # nothing left to close, and no error hiding in there
    finally:
        await manager.stop()


@pytest.mark.parametrize(
    "stage", ["launch", "new_page", "route"],
    ids=["chromium-fails", "first-page-fails", "route-setup-fails"],
)
@pytest.mark.parametrize("failure", [RuntimeError, asyncio.CancelledError], ids=["error", "cancelled"])
async def test_failed_launch_closes_what_it_created(tmp_path, pw, stage, failure):
    """Whatever stage breaks, the driver stops and the context created is closed."""
    manager = BrowserSessions(tmp_path)
    session = draft_session()
    setattr(pw, {"launch": "launch_error", "new_page": "new_page_error", "route": "route_error"}[stage],
            failure(f"{stage} died"))
    if stage == "new_page":
        pw.no_pages = True  # no tab to reuse, so _launch has to create one

    try:
        with pytest.raises(failure):
            await manager._launch(session)

        assert pw.stranded_drivers == [], "failed launch left a driver running"
        assert pw.stranded_contexts == [], "failed launch left a browser context open"
        assert (session["pw"], session["context"], session["page"]) == (None, None, None)
        await manager._dispose(session)  # safe to run afterwards
        assert session["pw"] is None and session["context"] is None
    finally:
        await manager.stop()


@pytest.mark.parametrize('cleanup_error', [RuntimeError, asyncio.CancelledError])
async def test_failing_cleanup_does_not_hide_the_original_error(tmp_path, pw, cleanup_error):
    """The caller must still see why the launch failed, not why the rollback also failed."""
    manager = BrowserSessions(tmp_path)
    session = draft_session()
    pw.route_error = BrowserError("route setup exploded")
    pw.close_error = cleanup_error("context close exploded")
    pw.stop_error = cleanup_error("driver stop exploded")
    try:
        with pytest.raises(BrowserError, match="route setup exploded"):
            await manager._launch(session)

        assert [context.close_attempts for context in pw.contexts] == [1]
        assert [driver.stop_attempts for driver in pw.drivers] == [1]
        assert (session["pw"], session["context"], session["page"]) == (None, None, None)
    finally:
        pw.close_error = pw.stop_error = None
        await manager.stop()


# ------------------------------------------------------------------- what may not be lost

async def test_hung_context_cleanup_is_bounded_and_driver_still_stops(tmp_path, pw, monkeypatch):
    manager = BrowserSessions(tmp_path)
    session = draft_session()
    pw.route_error = BrowserError('original route error')
    async def stalled_close(self):
        await asyncio.Event().wait()
    monkeypatch.setattr(FakeContext, 'close', stalled_close)
    monkeypatch.setattr('privacy_bot.browser.DISPOSE_WAIT_SECONDS', 0.01)
    try:
        with pytest.raises(BrowserError, match='original route error'):
            await asyncio.wait_for(manager._launch(session), 1)
        assert [driver.stop_attempts for driver in pw.drivers] == [1]
        assert session['pw'] is None and session['context'] is None
    finally:
        await manager.stop()


async def test_launch_still_hands_chromium_the_privacy_flags(tmp_path, pw):
    manager = BrowserSessions(tmp_path)
    try:
        captured = await manager.capture(source("src-a"))
        assert captured["status"] == "ok", captured["detail"]

        launch = pw.launches[0]
        options = launch.options
        assert options["headless"] is True
        assert options["chromium_sandbox"] is True          # unprivileged renderer, still on
        assert options["accept_downloads"] is False         # a page may not write here
        assert options["args"] == list(CHROMIUM_ARGS)       # no stealth flags added either
        assert options["viewport"] == dict(VIEWPORT)
        assert options["proxy"] == {
            "server": f"http://{manager.egress.bound_address[0]}:{manager.egress.bound_address[1]}",
            "bypass": "<-loopback>",
        }
        assert manager.egress.bound_address[0] == "127.0.0.1"  # loopback only, numeric, no name

        context = pw.contexts[0]
        assert [pattern for pattern, _handler in context.routes] == ["**/*"], "route guard missing"
        assert context.routes[0][1] is not None
        assert "serviceworker" in context.events, "service-worker backstop not subscribed"
        assert context.cdp_attempts == 1  # CDP unavailable here; launch must not fail for it

        profile = Path(launch.profile_dir)
        assert profile == tmp_path / "browser" / "src-a"
        assert stat.S_IMODE(profile.stat().st_mode) == 0o700  # saved cookies stay private
    finally:
        await manager.stop()


async def test_stop_closes_the_listener_and_the_next_launch_rebinds(tmp_path, pw):
    """Reuse must not mean "remember the old port": after stop the next launch binds again."""
    manager = BrowserSessions(tmp_path)
    first = await manager.capture(source("src-a"))
    listening_on = manager.egress.bound_address
    assert first["status"] == "ok", first["detail"]

    await manager.stop()
    assert manager.egress.proxy_url is None and manager.egress.listening is False

    second = await manager.capture(source("src-b"))
    assert second["status"] == "ok", second["detail"]
    assert manager.egress.bound_address is not None
    assert manager.egress.bound_address != listening_on, "the listener never actually restarted"
    assert pw.launches[1].options["proxy"]["server"] == (
        f"http://{manager.egress.bound_address[0]}:{manager.egress.bound_address[1]}"
    )
    assert pw.stranded_drivers == [] and pw.stranded_contexts == []
    await manager.stop()
