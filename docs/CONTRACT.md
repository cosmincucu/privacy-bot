# Application contract

API is relative to deployment prefix `/privacy-bot/`. GET healthz is public.
GET api/session returns `{authenticated, access_mode}`. In configured `network`
mode, approved home LAN/Tailscale clients open the UI directly with no token or
session cookie. The raw peer and explicitly trusted proxy headers are validated
before any private route. Host must match PUBLIC_URL. The UI hides Sign out.
In default `token` mode, private endpoints require a session cookie obtained
through POST api/login with `{token}`; POST api/logout clears it.
All writes require `X-Privacy-Bot: 1`; same-origin requests only.
Errors use FastAPI `{detail}` with a readable message. No external fonts/scripts.

GET api/dashboard returns:
`{profile, sources, findings, removals, alerts, credit, runs, settings, research, monitoring}`.
Monitoring: `{status:"ok"|"error",failures,retry_at?}`; health reports `degraded`
after scheduler/storage failures. Retries back off from 5 to 60 minutes; this
operational retry state is in memory and resets on process restart.
Profile: `{name,email,phone,addresses:[],aliases:[],country:"GB"}`.
Settings: `{interval_hours:24,enabled:false,notify_soft:false}`.
Source: `{id,name,kind,region,url,privacy_url,enabled,mode,status,last_checked,detail,config}`.
Kinds: broker, credit, breach, darkweb. Modes: manual, discovery, http, browser, hibp, hibp_stealer.
Status: not_checked, needs_setup, needs_login, blocked, checked, error.
Source config: `{watch_url,terms:[],empty_selector,match_selector,report_selector,report_url}`;
credit browser extraction expects canonical JSON in report_selector for a reviewed adapter.
Broker no-match results require readable reviewed `match_selector` content or an
explicit readable `empty_selector` marker. Missing, blank, hidden or contradictory
markers never establish no match. HTTP redirects stay on the original host or its
subdomains; update the watch URL explicitly when the operator changes.
Finding: `{id,source_id,title,url,matched:[],status,first_seen,last_seen,detail}`;
status candidate, confirmed, dismissed. No match means only no match on that page.
Removal: `{id,source_id,finding_id,status,subject,body,recipient,created_at,updated_at,note}`;
status draft, submitting, submitted, acknowledged, verified_removed, rejected, uncertain, reappeared.
Marking verified_removed also requires `verification_scope` (up to 1000 characters,
which listing/search and public/signed-in context). `verification_recorded_at` is
the server timestamp when that status is recorded, not an invented observation date.
Older records retain missing scope; removal means only the recorded checked scope.
Alert: `{id,kind,severity,title,detail,created_at,read,agency}`.
Run: `{id,source_id,status,detail,created_at}`.
Credit: list `{agency,latest_at,snapshot_count,important_count,soft_count,events}`.
Research: list `{name,url,description,license}`.

PUT api/profile with profile; PUT api/settings with settings.
POST api/sources with `{name,kind,region,url,privacy_url,mode,config}`; server assigns ID.
PATCH api/sources/{id} with editable subset. DELETE is not exposed.
POST api/scan with optional `{source_id}`; stores real results and returns `{runs}`.
Scheduled runs select enabled sources; an explicit source_id is a deliberate
one-off check even when scheduling for that source is off. Each source operation
has a 180-second deadline; a timeout is an error and later sources still run.
PATCH api/findings/{id} with `{status}`. POST api/removals with `{finding_id}`
or `{source_id}` creates a minimum-data removal draft. PATCH api/removals/{id}
with `{status,note,recipient,body}`; submitted requires evidence note.
POST api/removals/{id}/send with `{confirm:true}` sends through configured SMTP,
persisting submitting before send; uncertain transport never retries automatically.
POST api/alerts/{id}/read marks an alert read.

POST api/credit/import `{report:<canonical object>}` accepts normalized reports.
POST api/credit/extract multipart file extracts PDF/text/JSON to `{text,report:null|object,needs_review}`;
unrecognized text needs reviewed normalization; it never becomes a clean snapshot.
GET api/credit/example returns a synthetic canonical example.
Canonical credit report:
`{agency:"experian"|"equifax"|"transunion",report_date:"2026-09-26",complete:true,
 searches:[{id:"s1",date:"2026-09-25",organisation:"Example",type:"hard"|"soft"|"unknown",purpose:"..."}],
 accounts:[{id:"stable-account-key",provider:"Example",type:"loan",opened:"2026-09-01",status:"current",balance:100}],
 addresses:[{id:"addr1",address:"1 Example Road",current:true}],
 public_records:[{id:"p1",type:"ccj",date:"2026-09-01",status:"active"}]}`.
All four arrays REQUIRED. First snapshot is baseline; per-agency later snapshots
compare stable IDs and meaningful fields. Soft enquiries remain history-only by
default. Unknown enquiry types alert for review. Older/same-date conflicting
snapshots and incomplete/malformed data rejected. Exact duplicates idempotent.
Credit pure module exports validate_report(dict)->dict and compare_reports(old|None,new)->list
of `{kind,severity,title,detail,key}`; severity important or routine.

Browser: POST api/browser/{source_id}/start; GET api/browser/{id};
POST api/browser/{id}/action `{action:click|type|key|scroll|goto|refresh,...}`;
POST api/browser/{id}/close; POST api/browser/{id}/capture to run source extraction.
Screenshot shape `{source_id,url,title,width:1280,height:900,image:<data URI>}`.
Login, OTP and CAPTCHA are entered in this private browser. No arbitrary commands.
GET api/connections returns configured booleans for SMTP, HIBP, discovery and notifications.
Tor and direct_darkweb always return false. No secret values are returned.
PUT api/connections accepts an optional HIBP API key, encrypted SMTP settings and
an HTTPS notification URL. Tor proxy settings are rejected. Discovery uses the
operator-configured DONSETCH_URL and DONSETCH_TOKEN environment variables.

Browser module contract: BrowserSessions(data:Path); async start(source), snapshot(id),
action(id,body), close(id), stop(), reap(), capture(source) -> page HTML/text for parent.
Source is dict. Persistent profiles under data/browser/{validated-id}.
Networking module exports async validate_public_url(url,allow_onion=False).
