# Private browser sessions

Each source uses one persistent Chromium profile with user-entered login/OTP,
screenshots and bounded click/type/key/scroll controls.
There is no arbitrary code/evaluate endpoint, CAPTCHA solver or automatic account
application. The owner controls what an interactive click submits.

Profiles live under `data/browser/<source-id>` with restrictive permissions. They
contain sensitive cookies and rely on filesystem protection. Browser traffic goes
to the websites the owner visits; local hosting does not make that traffic private
from those sites. Screenshots are returned only through authenticated APIs.

Chromium always starts with `chromium_sandbox=True`. The container runs as UID
1000, with the checked-in Playwright seccomp profile. Downloads are refused,
service workers are blocked using `service_workers="block"`, and non-proxied UDP
is disabled. No insecure launch fallback is provided.

Every HTTP/HTTPS connection uses [PublicEgress](EGRESS.md), a local proxy which
resolves DNS, rejects any non-public answer, and connects to the checked numeric
address. Chromium is configured to proxy loopback destinations too. A separate
request guard checks redirects, frames and resources. Only ports 80/443 are
allowed. Local addresses, credentials in URLs, special schemes and onion hosts
are refused. An optional `config.allowed_hosts` restricts top-level navigation.
These controls reduce untrusted-page risk; they are not a guarantee against a
browser or host exploit. Keep the pinned browser updated through reviewed changes.

All sessions and captures in one browser manager reuse its single proxy listener.
Failed or cancelled launches close their own context and driver; cleanup waits are
bounded. The listener stays available to other sessions until manager shutdown.

There are at most two simultaneous sessions, each with a 20-minute idle timeout.
Navigation is limited to 45 seconds and a whole capture to 150 seconds. HTML,
text, selector output and screenshots are bounded. Failed login, challenge and
navigation states remain `needs_login`, `blocked` or `error`; they never become
an empty successful report.

## Capture contract

`BrowserSessions(data)` exposes async `start(source)`, `snapshot(id)`,
`action(id, body)`, `close(id)`, `capture(source)`, `reap()` and `stop()`.
Screenshots contain source ID, URL, title, dimensions, image data, status and detail.
Capture adds bounded HTML/text and `report_text` when a selector is configured.

Start uses `config.watch_url` or `source.url`. A configured `report_url` selects
the final report page. Credit capture expects canonical JSON from the reviewed
`report_selector`; it does not pretend arbitrary credit portal HTML is normalized.
The scanner validates agency, completeness, dates and schema before storing it.
A real account/report is required to implement and accept each portal adapter.

## Verification

The network and egress tests cover private/special destinations, mixed DNS answers,
rebinding resistance, ports, redirects and numeric socket connections.
`tests/browser_acceptance.py` exercises sandboxed Chromium against Example Domain,
repeated captures and proxy reuse alongside the UI checks. Repeat browser acceptance
on the target host because kernel capabilities differ. Do not disable the sandbox
to make an unsupported host pass.
The upstream-lesson source review additionally tested two consecutive sandboxed
captures through the same listener and malicious text in the real desktop/phone
UI. Reproduce with `tests/browser_acceptance.py --output /absolute/evidence/path`;
it creates only synthetic local state and fetches example.com for browser captures.
