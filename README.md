# Privacy Bot

A privately hosted dashboard for UK personal-data exposure, broker removal requests
and meaningful changes across Experian, Equifax and TransUnion reports.

- Broker inventory, public-page watches, candidate review, removal drafts and re-checks.
- Credit baselines and changes: hard searches, new accounts, address changes, defaults
  and public records raise attention. Routine soft searches stay in history.
- Optional Have I Been Pwned breach and stealer-log metadata queries. Direct dark-web
  access is disabled. No passwords or leak archives are retrieved.
- Local browser sessions for personal login and source workflows.
- Encrypted SQLite records, private browser profiles, controlled access and daily verified snapshots.
- Responsive UI, source-specific coverage status, evidence notes and optional webhook alerts.

## Setup

Install Python 3.12+ and the locked dependencies, then install this package without
resolving a second dependency set. Run `python -X utf8 -m playwright install chromium`
for a local development install; the pinned Docker image already includes Chromium.

```sh
uv venv --python 3.12
uv pip install -r requirements.lock
uv pip install --no-deps -e .
PYTHONUTF8=1 PYTHONIOENCODING=utf-8 .venv/bin/python -X utf8 -m uvicorn privacy_bot.app:create_app --factory --host 127.0.0.1 --port 8791 --no-access-log
```

Open `http://localhost:8791/`. Token mode is the default: use the generated
`data/access-token` file (mode 0600), or supply `PRIVACY_BOT_TOKEN` through the
environment. For Docker, follow [deployment](docs/DEPLOYMENT.md).
Trusted-network mode is an explicit setting with network/proxy allowlists and an
HTTPS hostname. It grants access by network location, not per-user identity.
The first startup generates `data/encryption.key` unless `PRIVACY_BOT_KEY` is set.
For a separate key location, supply a Fernet key through a protected environment
file before first startup. Back up the matching key: losing it makes records unreadable.
Browser profiles contain sensitive login state and rely on filesystem protection.

All sources and the scheduler start disabled. Enter identity in **Identity & setup**,
connect only the providers you want, then enable sources and a schedule. HIBP needs
your own API entitlement; stealer logs have additional plan/domain restrictions.
No subscription is purchased by this application.

Credit comparison currently accepts the validated format in [CREDIT.md](docs/CREDIT.md).
Your actual portal accounts and reports are needed to validate automated extraction.
PDF/text extraction is a review aid, not a claim that arbitrary report layouts are parsed.
The UI never claims protection from a source that has not been successfully checked.

See [research](docs/RESEARCH.md), [API contract](docs/CONTRACT.md),
[browser controls](docs/BROWSER.md) and [deployment](docs/DEPLOYMENT.md).
Assistants can use optional [named job-status readers](docs/MACHINE_READERS.md)
without receiving browser privileges or personal findings.

## Checks

```sh
uv pip install -e '.[test]'
PYTHONUTF8=1 PYTHONIOENCODING=utf-8 .venv/bin/python -X utf8 -m pytest -q
```

Tests use synthetic identities and isolated temporary data. They never send removal
emails or access your credit accounts.

For the browser acceptance check, install Chromium first and run
`python -X utf8 tests/browser_acceptance.py --output /tmp/privacy-bot-browser-check`.
It uses synthetic records and visits only the public Example Domain page to check
sandboxed browser capture. It does not use personal accounts or send email.

This repository is prepared for private review. No open-source license has been
selected for the application; third-party notices are in [THIRD_PARTY.md](THIRD_PARTY.md).
