"""Private, persistent browser sessions plus bounded page capture for source checks.

Two consumers share one on-disk profile per source (``data/browser/<source-id>/``):

* **Interactive** — the owner signs in, types an OTP or answers a question in this browser
  only. ``start`` / ``snapshot`` / ``action`` / ``close`` return a screenshot and nothing
  else: cookies, storage and typed credentials stay inside the profile directory (mode
  0700) and are never returned by an endpoint, logged or committed.
* **Automated reading** — ``capture(source)`` returns HTML/text (plus optional
  ``report_text``) for the parent to interpret. It drives the *same* profile, so a source
  the owner already logged into can be read without a password stored anywhere.

Deliberate limits, enforced here or in :mod:`privacy_bot.network`:

* every request — navigation *and* subresource — passes ``validate_public_url``: private,
  loopback, link-local, multicast, reserved, credential-bearing and non-``http(s)``
  destinations are refused; ``.onion`` only when the source explicitly asks for it, and
  then never handed to the system resolver;
* main-frame navigation stays inside ``config.allowed_hosts`` when that list is configured;
* service workers are blocked and downloads are refused, so a page cannot keep working
  after an action or drop files on disk;
* output is bounded (HTML / text / report character ceilings), every page operation has a
  timeout, and a failed navigation is reported as ``status: "error"`` with the reason —
  never as an empty page that looks like "nothing found";
* no anti-bot circumvention: no stealth flags, no fingerprint patching, no CAPTCHA
  solving, no proxy rotation. A challenge comes back as ``status: "blocked"`` for a human.

Adapted from Purchase Bot's ``browser_sessions.py``. Differences: per-source ``config``
handling, host allowlists, capture output, per-session locks, 20-minute idle expiry and an
honest ``status`` / ``detail`` on every response.
"""
from __future__ import annotations

import asyncio
import base64
import re
import time
from pathlib import Path
from typing import Any

from .network import UrlNotAllowed, validate_public_url
from .egress import PublicEgress

SESSION_TTL_SECONDS = 20 * 60          # a session dies 20 minutes after its last activity
REAP_INTERVAL_SECONDS = 30
MAX_SESSIONS = 2                       # each persistent profile costs a Chromium
VIEWPORT = {"width": 1280, "height": 900}

NAVIGATE_TIMEOUT_MS = 45_000
SCREENSHOT_TIMEOUT_MS = 15_000
EXTRACT_TIMEOUT_SECONDS = 10
EVALUATE_TIMEOUT_SECONDS = 20
ACTION_SETTLE_SECONDS = 0.4
DISPOSE_WAIT_SECONDS = 5
CAPTURE_TIMEOUT_SECONDS = 150          # backstop around one whole capture

MAX_HTML_CHARS = 300_000
MAX_TEXT_CHARS = 80_000
MAX_REPORT_CHARS = 200_000
MAX_TYPED_CHARS = 3_000
MAX_SELECTOR_CHARS = 300
MAX_URL_CHARS = 2_000

SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ALLOWED_KEYS = frozenset(
    {"Enter", "Tab", "Shift+Tab", "Backspace", "Delete", "Escape", "Home", "End",
     "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Control+A", "Control+Enter"}
)
# Only the service-worker switch. No automation-hiding or fingerprint flags.
CHROMIUM_ARGS = ["--disable-features=ServiceWorker", "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]

BLOCKED_STATUSES = frozenset({403, 407, 429, 503})
CHALLENGE_MARKERS: tuple[tuple[str, str], ...] = (
    (r"\bcaptcha\b|recaptcha|hcaptcha|are you a robot", "captcha"),
    (r"just a moment|checking your browser|cf-browser-verification", "cloudflare_challenge"),
    (r"enable javascript and cookies|javascript is required|please enable javascript", "javascript_required"),
    (r"access denied.*client ip|request blocked|blocked your (?:region|ip)", "edge_denied"),
    (r"unusual traffic from your computer", "unusual_traffic"),
    (r"attention required|you have been temporarily blocked", "challenge_page"),
)
LOGIN_MARKERS = (
    "sign in to", "sign into", "log in to", "log into", "signin", "logon",
    "enter your password", "one-time code", "verification code", "enter the code",
    "two-step verification",
)
#: Text longer than this counts as real content even when a sign-in link is also onscreen.
CONTENT_ENOUGH_CHARS = 1_500
#: Chromium's own pages, shown when a navigation genuinely failed.
ERROR_URL_PREFIXES = ("chrome-error://", "chrome://network-error")

#: Read the visible document without ever shipping more than the ceilings above.
_PAGE_JS = (
    "([htmlLimit, textLimit]) => {"
    "  const root = document.documentElement;"
    "  const body = document.body;"
    "  return {"
    "    html: root && root.outerHTML ? root.outerHTML.slice(0, htmlLimit) : '',"
    "    text: body && body.innerText ? body.innerText.slice(0, textLimit) : '',"
    "    title: document.title || '',"
    "    password: !!document.querySelector('input[type=password]')"
    "  };"
    "}"
)


class BrowserError(ValueError):
    """Readable failure for the UI (``ValueError`` so the API layer maps it to ``detail``)."""


def validate_session_id(value) -> str:
    """Return a source id that is safe to use as a profile directory name.

    Rejects empty ids, ``.``/``..``, path separators, leading dots and anything outside
    ``[A-Za-z0-9._-]``: an id that arrives in an API path must not be able to escape
    ``data/browser/``.
    """
    text = str(value or "").strip()
    if not text:
        raise BrowserError("Source id is required")
    if text in {".", ".."} or not SESSION_ID_RE.fullmatch(text):
        raise BrowserError(f"Source id {text[:80]!r} is not a safe profile name")
    return text


def start_url(source: dict) -> str:
    """Where a session for *source* opens: the reviewed watch URL, else ``source['url']``.

    Credit sources carry no ``watch_url``, so their start URL is ``source['url']``.
    """
    config = dict(source.get("config") or {})
    for candidate in (config.get("watch_url"), source.get("url")):
        text = str(candidate or "").strip()
        if text:
            return text
    raise BrowserError("Source has no URL to open")


def source_options(source: dict) -> dict:
    """Optional per-source browser switches. An absent key means "no extra restriction"."""
    config = dict(source.get("config") or {})
    allowed = config.get("allowed_hosts")
    if isinstance(allowed, str):
        allowed = [part for part in re.split(r"[,\s]+", allowed) if part]
    allowed = [str(item).strip() for item in (allowed or []) if str(item).strip()]
    selector = str(config.get("report_selector") or "").strip()[:MAX_SELECTOR_CHARS]
    return {
        "allowed_hosts": allowed or None,
        "allow_onion": False,
        "report_url": str(config.get("report_url") or "").strip(),
        "report_selector": selector,
    }


def classify_page(
    status: int | None, text: str, html: str, has_password_field: bool, page_url: str = ""
) -> tuple[str, str]:
    """``(status, detail)`` for a rendered page — honest about walls, logins and failures.

    ``ok`` means the page rendered content. It never means "data absent" or "removed":
    that judgement belongs to the parent that reads the text.
    """
    body = (text or "")[:6_000].lower()
    for pattern, label in CHALLENGE_MARKERS:
        if re.search(pattern, body):
            return "blocked", f"challenge page ({label})"
    if (page_url or "").lower().startswith(ERROR_URL_PREFIXES):
        return "error", "navigation ended on a browser error page"
    if status in BLOCKED_STATUSES:
        return "blocked", f"HTTP {status}"
    if status == 401:
        return "needs_login", "HTTP 401 — authentication required"
    if status is not None and status >= 400:
        return "error", f"HTTP {status}"
    if has_password_field:
        return "needs_login", "sign-in form is showing"
    stripped = (text or "").strip()
    if len(stripped) < CONTENT_ENOUGH_CHARS and any(marker in body for marker in LOGIN_MARKERS):
        return "needs_login", "sign-in prompt is showing"
    if not stripped and not (html or "").strip():
        return "error", "page rendered nothing"
    return "ok", ""


class BrowserSessions:
    """Persistent Chromium sessions keyed by source id, one driver at a time."""

    def __init__(self, data: Path) -> None:
        self.data = Path(data)
        self.sessions: dict[str, dict] = {}
        self.lock = asyncio.Lock()  # guards the registry; each session carries its own guard
        self.egress = PublicEgress(max_active_sessions=64)
        self.egress_lock = asyncio.Lock()

    # ------------------------------------------------------------------ public API

    async def start(self, source: dict) -> dict:
        """Open (or reuse) the private session for *source* and return its first snapshot."""
        source = dict(source or {})
        session_id = validate_session_id(source.get("id"))
        options = source_options(source)
        async with self.lock:
            if session_id in self.sessions:
                return await self._snapshot(self.sessions[session_id])
            if len(self.sessions) >= MAX_SESSIONS:
                raise BrowserError("Close an existing browser session before opening another source")
            try:
                target = await self._validate(start_url(source), options)
            except UrlNotAllowed as exc:
                raise BrowserError(f"Start URL refused: {exc}") from exc
            session = {
                "id": session_id,
                "name": str(source.get("name") or session_id)[:120],
                "guard": asyncio.Lock(),
                "allowed_hosts": options["allowed_hosts"],
                "allow_onion": options["allow_onion"],
                "expires": time.monotonic() + SESSION_TTL_SECONDS,
                "pw": None, "context": None, "page": None,
                "http_status": None, "http_url": "", "nav_error": "",
            }
            try:
                await self._launch(session)
            except BrowserError:
                raise
            except Exception as exc:
                raise BrowserError(
                    "Browser unavailable or this profile is busy — wait for the running "
                    f"check to finish ({type(exc).__name__}: {first_line(exc)})"
                ) from exc
            self.sessions[session_id] = session
        # Outside the registry lock: navigation is slow and touches only this session.
        async with session["guard"]:
            try:
                await self._navigate(session, target)
            except BrowserError:
                pass  # the snapshot below reports status="error" with the reason and a screenshot
            return await self._state(session)

    async def snapshot(self, session_id) -> dict:
        async with self.lock:
            session = await self._live(session_id)
        return await self._snapshot(session)

    async def action(self, session_id, body: dict) -> dict:
        body = dict(body or {})
        async with self.lock:
            session = await self._live(session_id)
        async with session["guard"]:
            page = session.get("page")
            if page is None:
                raise BrowserError("Open a browser session first")
            action = str(body.get("action") or "")
            try:
                if action == "click":
                    x, y = float(body.get("x", -1)), float(body.get("y", -1))
                    if not 0 <= x <= VIEWPORT["width"] or not 0 <= y <= VIEWPORT["height"]:
                        raise BrowserError("Click is outside the browser viewport")
                    await page.mouse.click(x, y)
                elif action == "type":
                    await page.keyboard.insert_text(str(body.get("text", ""))[:MAX_TYPED_CHARS])
                elif action == "key":
                    name = body.get("key")
                    if name not in ALLOWED_KEYS:
                        raise BrowserError("Unsupported key")
                    await page.keyboard.press(name)
                elif action == "scroll":
                    dy = int(body.get("dy", 600))
                    await page.mouse.wheel(0, max(-VIEWPORT["height"], min(VIEWPORT["height"], dy)))
                elif action == "goto":
                    url = str(body.get("url") or "").strip()[:MAX_URL_CHARS]
                    try:
                        target = await self._validate(url, session)
                    except UrlNotAllowed as exc:
                        raise BrowserError(f"Navigation refused: {exc}") from exc
                    await self._navigate(session, target)
                elif action in ("back", "refresh"):
                    await self._reload_or_back(session, action)
                else:
                    raise BrowserError("Unsupported browser action")
            finally:
                session["expires"] = time.monotonic() + SESSION_TTL_SECONDS
            await asyncio.sleep(ACTION_SETTLE_SECONDS)
            return await self._state(session)

    async def close(self, session_id) -> dict:
        key = validate_session_id(session_id)
        async with self.lock:
            session = self.sessions.pop(key, None)
        if session is not None:
            await self._dispose(session)
        return {"closed": True}

    async def stop(self) -> None:
        async with self.lock:
            victims = list(self.sessions.values())
            self.sessions.clear()
        for session in victims:
            await self._dispose(session)
        await self.egress.close()

    async def reap(self) -> None:
        """Background loop: drop sessions idle for more than 20 minutes."""
        while True:
            await asyncio.sleep(REAP_INTERVAL_SECONDS)
            now = time.monotonic()
            async with self.lock:
                victims = [
                    self.sessions.pop(key)
                    for key, value in list(self.sessions.items())
                    if now > value["expires"]
                ]
            for session in victims:
                await self._dispose(session)

    async def capture(self, source: dict) -> dict:
        """Read one page as ``{html, text, url, title[, report_text], status, detail}``.

        Runs on the source's own profile, so a login the owner completed by hand is reused.
        The result is text for the parent to interpret — this module never decides what a
        report is, whether data is absent, or whether anything was removed.
        """
        source = dict(source or {})
        options = source_options(source)
        try:
            return await asyncio.wait_for(self._capture(source, options), timeout=CAPTURE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            return _failed_capture(options, f"capture timed out after {CAPTURE_TIMEOUT_SECONDS}s")
        except (BrowserError, UrlNotAllowed) as exc:
            return _failed_capture(options, str(exc))

    # ------------------------------------------------------------------ capture internals

    async def _capture(self, source: dict, options: dict) -> dict:
        session_id = validate_session_id(source.get("id"))
        try:
            start_target = await self._validate(start_url(source), options)
            report_target = ""
            if options["report_url"]:
                report_target = await self._validate(options["report_url"], options)
        except (UrlNotAllowed, BrowserError) as exc:
            return _failed_capture(options, f"start URL refused: {exc}")

        async with self.lock:
            live = self.sessions.get(session_id)

        if live is not None:
            # The owner's session holds this profile; driving it beats failing on Chromium's
            # profile lock, and a second copy of the login state is never opened.
            async with live["guard"]:
                return await self._read_chain(live, start_target, report_target, options["report_selector"], options)

        session = {
            "id": session_id, "guard": asyncio.Lock(),
            "allowed_hosts": options["allowed_hosts"], "allow_onion": options["allow_onion"],
            "expires": time.monotonic() + CAPTURE_TIMEOUT_SECONDS,
            "pw": None, "context": None, "page": None,
            "http_status": None, "http_url": "", "nav_error": "",
        }
        try:
            await self._launch(session)
        except Exception as exc:
            return _failed_capture(options, f"browser unavailable or profile busy: {first_line(exc)}")
        try:
            async with session["guard"]:
                return await self._read_chain(
                    session, start_target, report_target, options["report_selector"], options
                )
        finally:
            await self._dispose(session)

    async def _read_chain(
        self, session: dict, start_target: str, report_target: str, selector: str, options: dict
    ) -> dict:
        """Navigate start -> report, then extract. Any navigation failure stays visible."""
        result = _failed_capture(options, "")
        before = str(session["page"].url or "")
        wanted = report_target or start_target
        chain = [start_target] + ([report_target] if report_target else [])
        moved = False
        try:
            if not _same_url(before, wanted):
                for target in chain:
                    if _same_url(str(session["page"].url or ""), target):
                        continue
                    await self._navigate(session, target)
                    moved = True
                    if session["nav_error"]:
                        break  # read what the failure actually left on screen, labelled as such
            status, detail, page_data = await self._read_page(session, selector=selector)
            if session["nav_error"]:
                status, detail = "error", session["nav_error"]
            result.update(
                html=page_data["html"], text=page_data["text"], url=page_data["url"],
                title=page_data["title"], status=status, detail=detail or page_data["detail"],
            )
            if "report_text" in result:
                result["report_text"] = page_data["report_text"]
                if status == "ok" and not page_data["report_text"].strip():
                    result["detail"] = page_data["detail"] or "report_selector matched nothing"
            result["detail"] = result["detail"][:500]
            return result
        finally:
            session["expires"] = time.monotonic() + SESSION_TTL_SECONDS
            if moved:  # return the human's tab to where they left it
                try:
                    await self._navigate(session, before)
                except Exception:
                    pass

    # ------------------------------------------------------------------ browser plumbing

    @staticmethod
    async def _validate(url: str, options: dict) -> str:
        """Structure + DNS + allowlist check for one main-frame destination."""
        return await validate_public_url(
            url,
            allow_onion=bool(options.get("allow_onion")),
            allowed_hosts=options.get("allowed_hosts"),
        )

    async def _launch(self, session: dict) -> None:
        """Persistent context on the source's own profile: guarded, no downloads, no service workers.

        Lifecycle ownership, because every session and every capture comes through here:

        * the egress listener belongs to the **manager** — the first launch starts it, every later
          session reuses that one socket (``PublicEgress.start`` refuses a second listener), and
          only :meth:`stop` closes it;
        * the driver and the context belong to the **session** — whatever this call creates is
          closed again if this call fails or is cancelled, so no driver outlives a launch that
          never produced a session;
        * the listener is opened *before* the driver, so a proxy that cannot start has no driver
          to orphan, and :meth:`_dispose` can still run afterwards on an emptied session.
        """
        from playwright.async_api import async_playwright

        profile_root = self.data / "browser"
        profile_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        profile = profile_root / session["id"]
        profile.mkdir(parents=True, exist_ok=True, mode=0o700)
        profile.chmod(0o700)  # saved cookies stay readable only by this user

        pw = None
        context = None
        try:
            async with self.egress_lock:
                if not self.egress.listening:  # reuse the socket the other sessions already share
                    await self.egress.start()
                proxy_url = self.egress.proxy_url
            pw = await async_playwright().start()
            options: dict[str, Any] = {
                "headless": True,
                "chromium_sandbox": True,
                "proxy": {"server": proxy_url, "bypass": "<-loopback>"},
                "viewport": dict(VIEWPORT),
                "accept_downloads": False,   # a page may not put files on this machine
                "args": list(CHROMIUM_ARGS),
            }
            context = await pw.chromium.launch_persistent_context(str(profile), service_workers="block", **options)
            pages = list(context.pages)
            session["pw"] = pw
            session["context"] = context
            session["page"] = pages[0] if pages else await context.new_page()
            await context.route("**/*", self._route_guard(session))
            await self._stop_service_workers(session)
        except BaseException:
            # Hand back what this attempt created before the error reaches a caller that discards
            # the session. Cancellation is a reason to clean up, not an excuse to skip it, and a
            # cleanup that itself fails is swallowed so it cannot mask the original error. The
            # session is emptied first, so a later _dispose closes nothing a second time.
            session.update({"pw": None, "context": None, "page": None})
            if context is not None:
                try:
                    await asyncio.wait_for(context.close(), timeout=DISPOSE_WAIT_SECONDS)
                except (Exception, asyncio.CancelledError):
                    pass
            if pw is not None:
                try:
                    await asyncio.wait_for(pw.stop(), timeout=DISPOSE_WAIT_SECONDS)
                except (Exception, asyncio.CancelledError):
                    pass
            raise

    def _route_guard(self, session: dict):
        """Refuse any request — navigation, subresource or worker — to a non-public destination."""
        allowed_hosts = session["allowed_hosts"]
        allow_onion = session["allow_onion"]

        async def guard(route):
            request = route.request
            try:
                if getattr(request, "resource_type", "") == "serviceworker":
                    await route.abort()
                    return
                await validate_public_url(
                    request.url,
                    allow_onion=allow_onion,
                    allowed_hosts=allowed_hosts if _is_main_document(request) else None,
                )
                await route.continue_()
            except Exception:
                # A refused destination stays refused. For a main frame the caller sees a
                # failed navigation (status "error"), never a silently "clean" page.
                try:
                    await route.abort()
                except Exception:
                    pass

        return guard

    async def _stop_service_workers(self, session: dict) -> None:
        """Third line of defence: stop any worker that registered anyway."""

        async def stop(_worker=None):
            client = session.get("cdp")
            if client is None:
                return
            try:
                await client.send("ServiceWorker.stopAllWorkers")
            except Exception:
                pass

        try:
            client = await session["context"].new_cdp_session(session["page"])
            session["cdp"] = client
            await client.send("ServiceWorker.stopAllWorkers")
        except Exception:
            session["cdp"] = None  # CDP is a bonus, not the switch
        try:
            session["context"].on("serviceworker", lambda worker: asyncio.ensure_future(stop(worker)))
        except Exception:
            pass

    async def _navigate(self, session: dict, url: str) -> None:
        """Go to *url*, recording the HTTP status or the failure so nothing is swallowed."""
        session["nav_error"] = ""
        session["http_status"] = None
        session["http_url"] = ""
        if not url or not url.lower().startswith(("http://", "https://")):
            session["nav_error"] = f"refused non-web destination {url[:80]!r}"
            raise BrowserError(session["nav_error"])
        try:
            response = await session["page"].goto(url, wait_until="domcontentloaded", timeout=NAVIGATE_TIMEOUT_MS)
        except Exception as exc:
            session["nav_error"] = f"navigation failed: {type(exc).__name__}: {first_line(exc)}"
            raise BrowserError(session["nav_error"]) from exc
        session["http_status"] = response.status if response is not None else None
        session["http_url"] = str(session["page"].url or "")

    async def _reload_or_back(self, session: dict, action: str) -> None:
        session["nav_error"] = ""
        try:
            if action == "refresh":
                response = await session["page"].reload(wait_until="domcontentloaded", timeout=NAVIGATE_TIMEOUT_MS)
                session["http_status"] = response.status if response is not None else None
                session["http_url"] = str(session["page"].url or "")
            else:
                await session["page"].go_back(timeout=NAVIGATE_TIMEOUT_MS)
        except Exception as exc:
            session["nav_error"] = f"{action} failed: {type(exc).__name__}: {first_line(exc)}"

    async def _read_page(self, session: dict, *, selector: str = "") -> tuple[str, str, dict]:
        """Bounded HTML/text (and optional report text) for the page currently displayed."""
        page = session["page"]
        data = {"html": "", "text": "", "report_text": "", "url": str(page.url or ""), "title": "", "detail": ""}
        try:
            state = await asyncio.wait_for(
                page.evaluate(_PAGE_JS, [MAX_HTML_CHARS, MAX_TEXT_CHARS]), timeout=EVALUATE_TIMEOUT_SECONDS
            )
        except Exception as exc:
            data["detail"] = f"could not read the page: {type(exc).__name__}"
            return "error", data["detail"], data
        data["html"] = str(state.get("html") or "")[:MAX_HTML_CHARS]
        data["text"] = str(state.get("text") or "")[:MAX_TEXT_CHARS]
        data["title"] = str(state.get("title") or "")[:300]
        data["url"] = str(page.url or "")

        if selector:
            try:
                element = page.locator(selector).first
                if await asyncio.wait_for(element.count(), timeout=EVALUATE_TIMEOUT_SECONDS):
                    try:
                        value = await element.inner_text(timeout=EXTRACT_TIMEOUT_SECONDS * 1000)
                    except Exception:
                        value = await element.text_content(timeout=EXTRACT_TIMEOUT_SECONDS * 1000)
                    data["report_text"] = str(value or "")[:MAX_REPORT_CHARS]
                if not data["report_text"].strip():
                    data["detail"] = "report_selector matched nothing readable"
            except Exception as exc:
                data["detail"] = f"report_selector failed: {type(exc).__name__}"
                return "error", data["detail"], data

        # A stale status from the previous page must not colour what is on screen now.
        status = session.get("http_status") if session.get("http_url") == data["url"] else None
        verdict, detail = classify_page(
            status, data["text"], data["html"], bool(state.get("password")), data["url"]
        )
        return verdict, detail or data["detail"], data

    async def _state(self, session: dict) -> dict:
        """Screenshot shape plus the honest status of what is on screen right now."""
        page = session.get("page")
        session["expires"] = time.monotonic() + SESSION_TTL_SECONDS
        if page is None:
            raise BrowserError("Open a browser session first")
        image = ""
        try:
            image = "data:image/png;base64," + base64.b64encode(
                await page.screenshot(timeout=SCREENSHOT_TIMEOUT_MS)
            ).decode()
        except Exception as exc:
            session["nav_error"] = session["nav_error"] or f"screenshot failed: {type(exc).__name__}"
        status, detail, page_data = await self._read_page(session)
        if session["nav_error"]:
            status, detail = "error", session["nav_error"]
        return {
            "source_id": session["id"],
            "url": str(page.url or ""),
            "title": page_data["title"],
            "width": VIEWPORT["width"],
            "height": VIEWPORT["height"],
            "image": image,
            "status": status,
            "detail": detail[:500],
        }

    async def _snapshot(self, session: dict) -> dict:
        async with session["guard"]:
            return await self._state(session)

    async def _live(self, session_id) -> dict:
        """Registry lookup (caller holds ``self.lock``). An expired session is closed, not reused."""
        key = validate_session_id(session_id)
        session = self.sessions.get(key)
        if not session:
            raise BrowserError("Open a browser session first")
        if time.monotonic() > session["expires"]:
            self.sessions.pop(key, None)
            await self._dispose(session)
            raise BrowserError("Session expired. Reopen it; the saved login profile is kept.")
        return session

    async def _dispose(self, session: dict) -> None:
        """Close browser objects, waiting briefly for an in-flight action instead of racing it."""
        guard = session.get("guard")
        held = False
        if isinstance(guard, asyncio.Lock) and guard.locked():
            try:
                await asyncio.wait_for(guard.acquire(), timeout=DISPOSE_WAIT_SECONDS)
                held = True
            except (asyncio.TimeoutError, RuntimeError):
                held = False
        try:
            context, pw = session.get("context"), session.get("pw")
            if context is not None:
                try:
                    await asyncio.wait_for(context.close(), timeout=DISPOSE_WAIT_SECONDS)
                except Exception:
                    pass
                session["context"] = None
            if pw is not None:
                try:
                    await asyncio.wait_for(pw.stop(), timeout=DISPOSE_WAIT_SECONDS)
                except Exception:
                    pass
                session["pw"] = None
        finally:
            if held:
                guard.release()


def _is_main_document(request) -> bool:
    """True for the top-level document of a tab (including one a page just opened).

    ``config.allowed_hosts`` is a *navigation* policy, so it binds the main frame while
    iframe documents and other subresources from different public hosts still pass the
    network guard. Anything whose frame cannot be attributed is treated as main-frame,
    which is the stricter answer.
    """
    try:
        if request.resource_type != "document":
            return False
        frame = request.frame
    except Exception:
        return True
    try:
        return frame.parent_frame is None
    except Exception:
        return True


def _failed_capture(options: dict, detail: str) -> dict:
    """A capture that produced nothing still carries every key the parent may index."""
    result = {"html": "", "text": "", "url": "", "title": "", "status": "error", "detail": detail[:500]}
    if str(options.get("report_selector") or ""):
        result["report_text"] = ""
    return result


def _same_url(left: str, right: str) -> bool:
    return str(left or "").strip().rstrip("/") == str(right or "").strip().rstrip("/")


def first_line(exc: BaseException) -> str:
    lines = str(exc).strip().splitlines()
    return (lines[0] if lines else type(exc).__name__)[:200]
