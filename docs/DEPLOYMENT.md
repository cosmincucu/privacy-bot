# Deployment and recovery

Privacy Bot needs Python 3.12+ and Chromium with its sandbox enabled. The pinned
Dockerfile includes the browser and locked application dependencies. The supplied
Compose file binds to localhost and uses token access by default.

## First installation

1. Copy `.env.example` to `.env`, set its permissions to 0600, and set
   `APP_REVISION` to the source commit reported by `git rev-parse HEAD`.
2. Create `data/` with owner UID/GID 1000 and permissions 0700. The container runs
   as UID/GID 1000; choose another host data path with `DATA_PATH` if needed.
3. Keep the default `BIND_ADDRESS=127.0.0.1`, `ROOT_PATH=` and
   `PUBLIC_URL=http://localhost:8791/` for local use.
4. Run the commands below and open `http://localhost:8791/`.

```sh
docker compose config --quiet
docker compose build
docker compose up -d
```

With empty `PRIVACY_BOT_TOKEN` and `PRIVACY_BOT_KEY`, the first startup creates
`data/access-token` and `data/encryption.key` with mode 0600. Read the access token
privately and enter it in the sign-in screen. Do not paste either value into
issues, logs or screenshots. Losing the encryption key makes records unreadable.

For a key stored separately from the data mount, supply `PRIVACY_BOT_KEY` through
the protected environment file before the first startup. It must be a Fernet key:
32 random bytes encoded with URL-safe base64. A supplied `PRIVACY_BOT_TOKEN` must
have at least 24 characters. Never substitute placeholder strings for real values
or change an existing database's key without a reviewed migration.

The runtime has a read-only root filesystem, dropped capabilities,
no-new-privileges and the included Playwright seccomp profile. Chromium requires
its sandbox; an unsupported host must fail rather than disable it. See
[browser controls](BROWSER.md). A health response alone does not validate the
browser: run browser acceptance on the target host before enabling browser sources.

All sources and scheduling start disabled. Enter your profile privately, connect
the sources you want, then enable the schedule. A source that has not run remains
unknown. No accounts, subscriptions or external services are created automatically.

## Reverse proxy and network access

For remote access, place the service behind your own trusted TLS proxy. Configure
`PUBLIC_URL` to the external HTTPS URL. For a prefix such as `/privacy-bot/`, set
`ROOT_PATH=/privacy-bot`, include that prefix in `PUBLIC_URL`, and strip it before
proxying to port 8791. Use an empty root path when serving a dedicated hostname.
Confirm the URL, Host header and prefix agree before enabling sources.

Token mode remains available behind a proxy. Optional `PRIVACY_BOT_ACCESS=network`
uses explicit `PRIVACY_BOT_ALLOWED_NETWORKS` and `PRIVACY_BOT_TRUSTED_PROXIES`
instead of a personal login. This grants access to everyone in the selected
networks. It requires an HTTPS `PUBLIC_URL`. The example ranges in `.env.example`
are illustrative; replace them with the networks and exact proxy peers you use.

If a proxy runs in Docker, `PROXY_NETWORK` and `PROXY_NETWORK_EXTERNAL=true` can
attach the application to that existing network. Verify the real socket peer;
do not trust a shared NAT gateway as if it were your sole proxy. A proxy-address
change requires updating the allowlist. The container disables Uvicorn's own
forwarded-header rewriting. The application accepts a single X-Forwarded-For
value only from an explicitly trusted proxy, and rejects cross-origin writes.

Check `/healthz`, the external URL, login behavior and each dashboard view.
Network mode must reject untrusted clients and forged forwarding headers.
Token mode must reject unauthenticated API requests. Use synthetic data for
acceptance; keep actual personal reports and deployment receipts private.

## Optional providers

Experian, ClearScore and Credit Karma use your own login sessions. Real portal
extraction needs representative reports and verification against the portal;
browser controls alone do not establish a working unattended adapter. Canonical
JSON import works without a browser. PDF/text extraction is a review aid.

Broker discovery uses an optional Donsetch-compatible search service. Configure
`DONSETCH_URL` and, if required, `DONSETCH_TOKEN`. Queries send your name and a
broker domain to that service and its upstream search providers. Results are
candidates for review, not verified exposure or comprehensive coverage.

HIBP needs your own API entitlement. Stealer-log access has additional plan and
verified-domain requirements. No Tor client, onion browsing, leak archive or
password retrieval is included. SMTP and webhook alerts are optional. Removal
drafts and manual submissions work without SMTP; sending requires explicit review.

## Backup, recovery and rollback

Encrypted SQLite records are kept in the data directory. Daily online snapshots
in `data/backups` are checked for integrity, but remain on the same host. Protect
and back up the full data directory, matching encryption key, `.env` and accepted
source/image separately. Browser profiles contain login cookies and rely on
filesystem protection; they are not encrypted by Fernet.

Before upgrading an existing installation, take a fresh scoped backup and read
it back. Keep old snapshots and the previous image; the application does not
automatically delete backups. Never restore a database with an unrelated key.

For recovery, stop the application and preserve the current state. Restore a
verified snapshot with its matching key into a new directory. Restore browser
profiles only from trusted backups, or sign in again. Point `DATA_PATH` to that
directory, launch the recorded image, and verify records and provider status.

For application rollback, use the previous image and Compose revision. Keep
state and secrets in place unless a separate recovery plan requires changes.
Stopping a first installation should retain its state and credentials; no data
deletion is part of rollback.
