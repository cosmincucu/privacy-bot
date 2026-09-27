# Credit module — validation and change detection

`privacy_bot/credit.py` is a **pure** module: no files, no SQLite, no network, no wall clock,
no alerting, no FastAPI. It turns a canonical credit report into a validated snapshot, and two
snapshots of the same agency into a list of meaningful changes. Everything that stores,
schedules, alerts or renders lives in the app layer.

The three UK agencies are independent. A report always belongs to exactly one agency, a
baseline is always per-agency, and comparing two agencies raises rather than producing
meaningless churn.

## Exports

```python
from privacy_bot.credit import (
    AGENCIES,            # ("experian", "equifax", "transunion")  — canonical, lowercase
    AGENCY_LABELS,       # {"experian": "Experian", ...}          — display names for the UI
    SEVERITIES,          # ("important", "routine")
    SEVERITY_IMPORTANT,  # "important"
    SEVERITY_ROUTINE,    # "routine"
    CreditValidationError,  # ValueError subclass; str(exc) is safe as an API `detail`
    validate_report,
    compare_reports,
)

validate_report(report: dict, *, as_of: date | str | None = None) -> dict
compare_reports(old: dict | None, new: dict, *, as_of: date | str | None = None) -> list[dict]
```

`as_of` is optional and defaults to `None`. When supplied (a `date` or `"YYYY-MM-DD"`), any
report or entry date after it is rejected as impossible. Left out, the engine deliberately
makes no claim about "today", so unit tests and replays stay reproducible. Pass the operator's
clock in the app layer if you want future-dated extracts refused at import time.

Both functions **never mutate** their input. `validate_report` returns a new normalised dict,
which is what should be persisted.

## Canonical report (accepted shape)

Top level — these seven keys are required, and `financial_associations` is the only optional
addition the engine understands:

| Key | Type | Notes |
| --- | --- | --- |
| `agency` | string | exactly `experian`, `equifax` or `transunion`, lower-case, surrounding space tolerated |
| `report_date` | `"YYYY-MM-DD"` | the date the agency issued the file, not the date we imported it |
| `complete` | boolean | must be `true`; `false`, `"true"` or `1` are all rejected |
| `searches` | list | required, may be empty |
| `accounts` | list | required, may be empty |
| `addresses` | list | required, may be empty |
| `public_records` | list | required, may be empty |
| `financial_associations` | list | optional; absent means "not captured", `[]` means "checked, none" |

Entry keys are equally closed. Unknown or missing keys fail, so a mis-mapped adapter surfaces
as a rejected import instead of silently empty evidence.

| Collection | Required | Optional |
| --- | --- | --- |
| `searches` | `id`, `date`, `organisation`, `type` | `purpose` |
| `accounts` | `id`, `provider`, `type`, `opened`, `status`, `balance` | `credit_limit` |
| `addresses` | `id`, `address`, `current` | — |
| `public_records` | `id`, `type`, `date`, `status` | — |
| `financial_associations` | `id`, `name` | `address`, `date`, `status` |

Normalisation applied to the returned snapshot: strings are whitespace-collapsed and stored
trimmed; `id` is trimmed and must be non-empty text; `search.type` is lower-cased; numbers
(`balance`, `credit_limit`) become finite floats (booleans and `"100"` are rejected); optional
strings become `""` and an optional `credit_limit`/`date` becomes `None`, so comparisons are
always two-valued. Re-validating an already-validated snapshot is a no-op.

### What gets rejected

Anything that would otherwise look "clean" but is not evidenced:

- a non-object report, or an object with an unsupported key;
- a missing or non-list array (`searches: {}`, `accounts: "a1"`, missing `public_records`);
- an entry that is not an object, is missing a required key, or carries an unknown key;
- a missing, empty, whitespace-only or non-string `id`;
- **duplicate ids** inside one collection — list position is never used as identity;
- unknown agency (including `Experian`, `sage`, an empty value);
- `complete` not exactly `true`, or missing;
- any date that is not `YYYY-MM-DD`, is not a real calendar day (`2026-02-30`), is before
  1900, or (when `as_of` is given) lies in the future;
- `balance`/`credit_limit` that are strings, booleans, `NaN` or infinities;
- `current`/`complete` that are not real booleans.

An incomplete extract is a coverage gap, not a clean file: raise it at the caller as
`needs_review` and keep the previous snapshot.

## Comparison semantics

```python
events = compare_reports(stored_snapshot_or_None, imported_report)
```

- `old is None` → this agency's **baseline**: the result is `[]`. A first snapshot never
  produces new-credit alarms, however bad the file looks. Store it and compare from the next
  one onwards.
- **exact duplicate** content (any date) → `[]`, idempotent, so a re-import of a stored
  snapshot cannot double-alert.
- **older** report with different content → `CreditValidationError` ("refusing to overwrite
  history").
- **same date** with different content → `CreditValidationError` ("conflicting report"). This
  includes an extract that gained the optional `financial_associations` section on a date we
  already hold: re-import a changed file under a new `report_date`.
- different agency on either side → `CreditValidationError` ("each agency is tracked
  independently").
- otherwise every collection is matched by `id` and compared on content, so reordering lists,
  re-trimming text or `100` vs `100.0` produce nothing.

Both arguments are validated again inside `compare_reports`: a stored snapshot that no longer
validates fails loudly instead of diffing against garbage.

### Event shape

Exactly five keys, nothing else — `{kind, severity, title, detail, key}`. `severity` is only
ever `"important"` or `"routine"`. `key` is `<kind>|<agency>|<entry-id>|<12-hex digest of the
change>`: stable when the same change is re-detected (so the alert layer can de-duplicate) and
distinct for a different change to the same account or enquiry (so a second, genuinely new
default is never swallowed by the first one's key). Events come back important-first, then by
`kind` and `key`, so a UI can render the head of the list as the actionable part.

### Kinds and severities

| `kind` | Severity | Trigger |
| --- | --- | --- |
| `new_hard_search` | important | a search with type `hard` appears |
| `new_soft_search` | routine | a search with type `soft` appears (history-only by default) |
| `new_unknown_search` | important | a search whose type this service cannot classify as soft or hard — explicitly a review item, never filed as soft |
| `search_removed` | routine | an enquiry dropped out of the reported window |
| `search_changed` | important / routine | same enquiry id, different date/organisation/type (important); different `purpose` wording only (routine) |
| `new_account` | important | an account appears |
| `account_removed` | important | an account vanishes — could be age-off, could be a wrong extract; never neutral |
| `account_defaulted` | important | status becomes arrears/default/missed-payment wording |
| `account_closed` | important | status becomes closed/cancelled/terminated wording |
| `account_reopened` | important | a previously closed status is live again |
| `account_status_changed` | important when arrears wording was involved on either side, otherwise routine | any other status change |
| `account_identity_changed` | important | same stable id now names a different provider, product type or open date — review the extract |
| `account_balance_changed` | routine | balance only. Never cancels another event on the same account |
| `account_credit_limit_changed` | important | limit differs when **both** snapshots report one |
| `account_credit_limit_first_reported` | routine | limit newly appears or disappears: no change can be confirmed, only that the field was not captured before |
| `address_changed` | important | same address id, genuinely different text (case, spacing and trailing punctuation are ignored) |
| `address_current_changed` | important | `current` flag flipped |
| `address_added` / `address_removed` | important | address history grew or shrank |
| `public_record_added` | important | any new public record — CCJ, bankruptcy, IVA and unknown types alike |
| `public_record_removed` | routine | absent from the new snapshot; verify with the agency, do not assume removal |
| `public_record_changed` | important | same id, different type or date |
| `public_record_status_changed` | routine live→satisfied, important satisfied→live or unclassifiable wording | the record is still on file either way and the detail says so |
| `financial_association_added` | important | new link against a baseline that already captured the section |
| `financial_association_removed` | routine | link no longer listed; confirm it was actually severed |
| `financial_association_changed` | important | same link id, different name/address/date/status |
| `financial_associations_first_reported` | routine | section appears for the first time — nothing may be called new |
| `financial_associations_no_longer_reported` | routine | section disappeared after being captured: missing data, not a severed link |

Severity is computed **per event**. One balance movement sitting next to a new default or a
new CCJ produces both events and cannot demote either of them.

The status word lists (`_STATUS_MARKERS`, `_CLOSED_MARKERS`, `_RESOLVED_MARKERS`,
`_LIVE_MARKERS`) are the tunable part: they are matched on normalised wording, and a status
this file has never seen is compared, reported and classified as routine *wording* — the
exception being public records, where unclassifiable wording is escalated instead.

## Wiring it into the API

The app layer keeps per-agency state; this module stays stateless.

1. `POST api/credit/import`: `report = validate_report(body["report"])` inside
   `except CreditValidationError` → HTTP 400 with `str(exc)` as `detail`, and record the
   attempt as a failed run, not as a clean snapshot. Persist `report` as the agency's latest
   snapshot only after it validates.
2. Diff against that agency's previously stored snapshot: `events = compare_reports(latest, report)`.
   Store the events; `latest is None` means baseline and no alerts.
3. Dashboard `credit` entries: `latest_at` from `report_date`, `snapshot_count` from stored
   snapshots, `important_count` from important events, `soft_count` from soft-search events,
   `events` from the list above. De-duplicate alerts on `key`.
4. Alerts for `new_unknown_search`, `account_identity_changed`, `search_changed` and
   `public_record_changed` should read as "review the extract" — they may be an adapter
   problem rather than a credit event.
5. Soft enquiries stay history-only unless `settings.notify_soft` is on; the module still
   returns them so the history is complete.

## Deliberate choices worth a second opinion

- **Closed key sets.** Unknown keys are rejected rather than ignored, so an adapter that wants
  to pass metadata through has to negotiate it here first.
- **`balance` is required** on accounts, because the canonical shape says so; a genuinely
  balance-less tradeline should arrive as `0` only when the agency really reported zero.
- **Same-date conflicts reject**, even when the only difference is a newly present optional
  section. Loud beats silently re-dated.
- **`account_removed` and `search_removed` differ in severity** (important vs routine): a
  vanished tradeline moves scoring, an aged-off enquiry does not.
- **`purpose`-only rewording is routine** so an adapter improvement does not alert on every
  historical enquiry at once.
