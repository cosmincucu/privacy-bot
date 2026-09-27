"""Pure validation and change detection for canonical UK credit reports.

The three UK credit reference agencies (Experian, Equifax, TransUnion) are handled
independently: one report is always one agency's snapshot and two snapshots are only ever
compared inside one agency. Nothing here reads files, opens sockets or uses the wall clock;
callers pass ``report_date`` (and optionally an explicit ``as_of``) themselves, so the same
input always produces the same verdict.

Exports (docs/CONTRACT.md):

* ``validate_report(dict) -> dict``  -- canonical, normalised copy or raise.
* ``compare_reports(old | None, new) -> list[{kind, severity, title, detail, key}]``.

Severity is only ever ``"important"`` or ``"routine"``.

* important: a change that can move a lending decision or signal identity misuse -- new hard
  search, new or vanished account, default or closure, credit limit change, address rewrite,
  new public record, new financial association, or two snapshots disagreeing about a stable
  id (which may be a parsing error, so it is flagged for review too).
* routine: history worth keeping without alarming -- soft searches, balance movement,
  resolved public records, optional data reported for the first
  time, enquiries dropping out of the reporting window.

Honest-coverage rules this module will not bend:

* A report becomes a snapshot only if it validates. Anything doubtful raises with a readable
  message so the caller records a coverage gap instead of a clean file.
* Unknown data is never read as absent data. Missing optional values come back as ``None``
  (or ``""``) and an absent-then-present value is reported as *first reported*, never as a
  change; a balance movement can never hide a default or a County Court Judgment.
* List position is not identity. Entries are matched on their own stable ``id`` and duplicate
  ids are rejected rather than guessed at.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import date as _date
from typing import Any

__all__ = [
    "AGENCIES",
    "AGENCY_LABELS",
    "SEVERITIES",
    "SEVERITY_IMPORTANT",
    "SEVERITY_ROUTINE",
    "CreditValidationError",
    "validate_report",
    "compare_reports",
]

AGENCIES = ("experian", "equifax", "transunion")

#: Display names, because the alerts land in front of a person.
AGENCY_LABELS = {"experian": "Experian", "equifax": "Equifax", "transunion": "TransUnion"}

SEVERITY_IMPORTANT = "important"
SEVERITY_ROUTINE = "routine"
SEVERITIES = (SEVERITY_IMPORTANT, SEVERITY_ROUTINE)

SEARCH_TYPE_SOFT = "soft"
SEARCH_TYPE_HARD = "hard"
SEARCH_TYPE_UNKNOWN = "unknown"

#: Required canonical keys plus the optional ones this engine understands. Keeping the set
#: closed means a mis-mapped adapter field fails loudly instead of silently dropping evidence.
_TOP_REQUIRED = (
    "agency",
    "report_date",
    "complete",
    "searches",
    "accounts",
    "addresses",
    "public_records",
)
_TOP_ALLOWED = _TOP_REQUIRED + ("financial_associations",)

_SEARCH_KEYS = ("id", "date", "organisation", "type", "purpose")
_ACCOUNT_KEYS = ("id", "provider", "type", "opened", "status", "balance", "credit_limit")
_ADDRESS_KEYS = ("id", "address", "current")
_PUBLIC_RECORD_KEYS = ("id", "type", "date", "status")
_FINANCIAL_ASSOCIATION_KEYS = ("id", "name", "address", "date", "status")

#: Per collection: (keys that must be present, all keys that may be present). An adapter field
#: that is missing or unrecognised is a coverage gap to be reported, never a silent empty string.
_SEARCH_SHAPE = tuple(_SEARCH_KEYS[:4]), _SEARCH_KEYS
_ACCOUNT_SHAPE = tuple(_ACCOUNT_KEYS[:6]), _ACCOUNT_KEYS
_ADDRESS_SHAPE = _ADDRESS_KEYS, _ADDRESS_KEYS
_PUBLIC_RECORD_SHAPE = _PUBLIC_RECORD_KEYS, _PUBLIC_RECORD_KEYS
_FINANCIAL_ASSOCIATION_SHAPE = ("id", "name"), _FINANCIAL_ASSOCIATION_KEYS

#: Collections compared by stable id, in a fixed order so output is reproducible.
_COLLECTIONS = {
    "searches": _SEARCH_SHAPE,
    "accounts": _ACCOUNT_SHAPE,
    "addresses": _ADDRESS_SHAPE,
    "public_records": _PUBLIC_RECORD_SHAPE,
    "financial_associations": _FINANCIAL_ASSOCIATION_SHAPE,
}
_COLLECTION_ORDER = ("searches", "accounts", "addresses", "public_records", "financial_associations")

_DATE_PATTERN = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})\Z")
_MIN_YEAR = 1900

#: Account status wording that means "this tradeline is in trouble". Matching is substring on
#: normalised wording, so "Missed Payments" and "missed payment 1x" both land here.
_STATUS_MARKERS = (
    "default",
    "arrear",
    "missed",
    "late",
    "written off",
    "write off",
    "bankrupt",
    "disputed",
    "declined",
    "unsatisfied",
)
#: Account status wording that means "this tradeline is closed".
_CLOSED_MARKERS = (
    "closed",
    "cancelled",
    "canceled",
    "terminated",
    "retired",
    "completed",
    "inactive",
)
#: Public record status wording that means "no longer live".
_RESOLVED_MARKERS = (
    "satisfied",
    "settled",
    "discharged",
    "cancelled",
    "canceled",
    "expired",
    "closed",
    "removed",
)
#: Public record status wording that means "still live".
_LIVE_MARKERS = ("active", "open", "outstanding", "live", "unsatisfied", "current")


class CreditValidationError(ValueError):
    """The report cannot be trusted as a snapshot.

    Subclasses :class:`ValueError` so existing ``except ValueError`` callers keep working;
    ``str(error)`` is a readable, personal-data-free message suitable for an API ``detail``.
    """


def validate_report(report: Any, *, as_of: Any = None) -> dict:
    """Return a normalised copy of ``report``, or raise :class:`CreditValidationError`.

    The input is never mutated and never returned as-is. ``as_of`` accepts a ``date`` or a
    ``YYYY-MM-DD`` string; when given, dates after it are rejected. Left as ``None`` the
    engine makes no claim about "today", so results stay reproducible.
    """
    limit = _as_of_limit(as_of)
    if not isinstance(report, dict):
        raise CreditValidationError("credit report must be a JSON object")

    _check_keys(report, _TOP_REQUIRED, _TOP_ALLOWED, "credit report")

    agency = _text(report["agency"], "credit report agency", allow_empty=False)
    if agency not in AGENCIES:
        raise CreditValidationError(
            f"unknown credit agency '{agency}' (expected one of: {', '.join(AGENCIES)})"
        )

    report_date = _date_value(report["report_date"], "credit report report_date", limit)

    complete = report["complete"]
    if not isinstance(complete, bool):
        raise CreditValidationError("credit report complete must be true or false")
    if complete is not True:
        raise CreditValidationError(
            "incomplete credit report: a partial extract is never a clean snapshot"
        )

    validated: dict[str, Any] = {
        "agency": agency,
        "report_date": report_date,
        "complete": True,
    }

    for name in _COLLECTION_ORDER:
        required, allowed = _COLLECTIONS[name]
        if name == "financial_associations" and name not in report:
            # Optional schema: absent stays absent, it does not mean "none reported".
            continue
        raw = report[name]
        if not isinstance(raw, list):
            raise CreditValidationError(f"credit report field '{name}' must be a list")
        validated[name] = _validate_collection(name, raw, required, allowed, limit)

    return validated


def compare_reports(old: Any, new: Any, *, as_of: Any = None) -> list[dict]:
    """Return the meaningful changes between two snapshots of the same agency.

    ``old`` is ``None`` for the first snapshot of an agency, which is the baseline and
    therefore produces no new-credit alarms. Identical content is idempotent and produces no
    events; older or same-date content that disagrees raises instead of rewriting history.
    """
    new_report = validate_report(new, as_of=as_of)
    if old is None:
        return []
    old_report = validate_report(old, as_of=as_of)

    if old_report["agency"] != new_report["agency"]:
        raise CreditValidationError(
            f"cannot compare {new_report['agency']} report with {old_report['agency']} baseline: "
            "each agency is tracked independently"
        )

    old_date = _parse_date(old_report["report_date"], "old report_date")
    new_date = _parse_date(new_report["report_date"], "report_date")
    same_payload = _payload(old_report) == _payload(new_report)

    if new_date < old_date:
        if same_payload:
            return []
        raise CreditValidationError(
            f"report dated {new_report['report_date']} is older than stored baseline "
            f"{old_report['report_date']} and has different content; refusing to overwrite history"
        )
    if new_date == old_date:
        if same_payload:
            return []  # exact duplicate import, idempotent
        raise CreditValidationError(
            f"conflicting report for {new_report['agency']} dated {new_report['report_date']}: "
            "same date, different content"
        )

    events: list[dict] = []
    _compare_searches(old_report, new_report, events)
    _compare_accounts(old_report, new_report, events)
    _compare_addresses(old_report, new_report, events)
    _compare_public_records(old_report, new_report, events)
    _compare_financial_associations(old_report, new_report, events)

    events.sort(key=lambda item: (item["severity"] != SEVERITY_IMPORTANT, item["kind"], item["key"]))
    return events


# --------------------------------------------------------------------------- validation


def _validate_collection(name: str, items: list, required: tuple, allowed: tuple, limit: _date | None) -> list[dict]:
    builder = _ENTRY_VALIDATORS[name]
    validated: list[dict] = []
    seen: dict[str, str] = {}
    for position, item in enumerate(items):
        label = f"{name} entry {position}"
        if not isinstance(item, dict):
            raise CreditValidationError(f"{label} must be a JSON object")
        _check_keys(item, required, allowed, label)
        entry_id = _entry_id(item, label)
        if entry_id in seen:
            raise CreditValidationError(
                f"{name} has duplicate id '{entry_id}' (entries {seen[entry_id]} and {position}): "
                "stable ids must be unique, list position is not identity"
            )
        seen[entry_id] = str(position)
        validated.append(builder(item, entry_id, label, limit))
    return validated


def _validate_search(item: dict, entry_id: str, label: str, limit: _date | None) -> dict:
    raw_type = _text(item["type"], f"{label} type", allow_empty=False)
    return {
        "id": entry_id,
        "date": _date_value(item["date"], f"{label} date", limit),
        "organisation": _text(item["organisation"], f"{label} organisation", allow_empty=False),
        # Anything the agency does not name is kept verbatim and treated as unknown, never as
        # soft: an unrecognised enquiry classification has to be looked at by a human.
        "type": raw_type.lower(),
        "purpose": _optional_text(item, "purpose", label),
    }


def _validate_account(item: dict, entry_id: str, label: str, limit: _date | None) -> dict:
    return {
        "id": entry_id,
        "provider": _text(item["provider"], f"{label} provider", allow_empty=False),
        "type": _text(item["type"], f"{label} type", allow_empty=False),
        "opened": _date_value(item["opened"], f"{label} opened", limit),
        "status": _text(item["status"], f"{label} status", allow_empty=False),
        "balance": _number(item["balance"], f"{label} balance"),
        "credit_limit": (
            None if item.get("credit_limit") is None else _number(item["credit_limit"], f"{label} credit_limit")
        ),
    }


def _validate_address(item: dict, entry_id: str, label: str, limit: _date | None) -> dict:
    current = item["current"]
    if not isinstance(current, bool):
        raise CreditValidationError(f"{label} current must be true or false")
    return {"id": entry_id, "address": _text(item["address"], f"{label} address", allow_empty=False), "current": current}


def _validate_public_record(item: dict, entry_id: str, label: str, limit: _date | None) -> dict:
    return {
        "id": entry_id,
        "type": _text(item["type"], f"{label} type", allow_empty=False),
        "date": _date_value(item["date"], f"{label} date", limit),
        "status": _text(item["status"], f"{label} status", allow_empty=False),
    }


def _validate_financial_association(item: dict, entry_id: str, label: str, limit: _date | None) -> dict:
    date_value = item.get("date")
    return {
        "id": entry_id,
        "name": _text(item["name"], f"{label} name", allow_empty=False),
        "address": _optional_text(item, "address", label),
        "date": None if date_value is None else _date_value(date_value, f"{label} date", limit),
        "status": _optional_text(item, "status", label),
    }


def _check_keys(container: dict, required: tuple, allowed: tuple, label: str) -> None:
    missing = sorted(key for key in required if key not in container)
    if missing:
        raise CreditValidationError(f"{label} is missing required field(s) {', '.join(repr(k) for k in missing)}")
    unsupported = sorted(key for key in container if key not in allowed)
    if unsupported:
        raise CreditValidationError(
            f"{label} has unsupported field(s) {', '.join(repr(k) for k in unsupported)} "
            f"(supported: {', '.join(allowed)})"
        )


def _optional_text(item: dict, key: str, label: str) -> str:
    """An absent or null optional string is normalised to "" so comparisons stay two-valued."""
    value = item.get(key)
    if value is None:
        return ""
    return _text(value, f"{label} {key}", allow_empty=True)


def _entry_id(item: dict, label: str) -> str:
    return _text(item["id"], f"{label} id", allow_empty=False)


def _text(value: Any, label: str, *, allow_empty: bool) -> str:
    if not isinstance(value, str):
        raise CreditValidationError(f"{label} must be a string")
    cleaned = " ".join(value.split())
    if not cleaned and not allow_empty:
        raise CreditValidationError(f"{label} must not be empty")
    return cleaned


def _number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CreditValidationError(f"{label} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise CreditValidationError(f"{label} must be a finite number")
    return number


def _date_value(value: Any, label: str, limit: _date | None) -> str:
    text = _text(value, label, allow_empty=False)
    parsed = _parse_date(text, label)
    if parsed.year < _MIN_YEAR:
        raise CreditValidationError(f"{label} date '{text}' is before {_MIN_YEAR} and cannot be real")
    if limit is not None and parsed > limit:
        raise CreditValidationError(f"{label} date '{text}' is in the future (after {limit.isoformat()})")
    return text


def _parse_date(text: str, label: str) -> _date:
    match = _DATE_PATTERN.match(text)
    if not match:
        raise CreditValidationError(f"{label} date '{text}' must be formatted YYYY-MM-DD")
    year, month, day = (int(part) for part in match.groups())
    try:
        return _date(year, month, day)
    except ValueError as error:
        raise CreditValidationError(f"{label} date '{text}' is not a real calendar date ({error})") from None


def _as_of_limit(as_of: Any) -> _date | None:
    if as_of is None:
        return None
    if isinstance(as_of, _date):
        return as_of
    if isinstance(as_of, str):
        return _parse_date(as_of, "as_of")
    raise CreditValidationError("as_of must be a date or a YYYY-MM-DD string")


def _payload(report: dict) -> dict:
    return {name: report[name] for name in _COLLECTION_ORDER if name in report}


# --------------------------------------------------------------------------- comparison


def _rows(report: dict, name: str) -> dict[str, dict]:
    return {item["id"]: item for item in report.get(name, [])}


def _compare_searches(old: dict, new: dict, events: list[dict]) -> None:
    agency = new["agency"]
    old_rows, new_rows = _rows(old, "searches"), _rows(new, "searches")
    for entry_id in sorted(set(new_rows) - set(old_rows)):
        row = new_rows[entry_id]
        kind, severity = _search_classification(row["type"])
        described = f"{row['organisation']} on {row['date']}"
        if kind == "new_unknown_search":
            _emit(
                events,
                kind,
                SEVERITY_IMPORTANT,
                f"Unrecognised search type on {_agency_label(agency)}",
                f"Search {described} has type '{row['type']}', which this service does not "
                "classify as soft or hard. Review it before treating it as routine.",
                agency,
                entry_id,
                {"type": row["type"], "organisation": row["organisation"], "date": row["date"]},
            )
        else:
            _emit(
                events,
                kind,
                severity,
                f"New {'hard' if kind == 'new_hard_search' else 'soft'} search on {_agency_label(agency)}",
                f"{row['organisation']} made a {'hard' if kind == 'new_hard_search' else 'soft'} "
                f"search on {row['date']}"
                + (f" for '{row['purpose']}'" if row["purpose"] else "")
                + ".",
                agency,
                entry_id,
                {"organisation": row["organisation"], "date": row["date"], "type": row["type"]},
            )
    for entry_id in sorted(set(old_rows) - set(new_rows)):
        row = old_rows[entry_id]
        _emit(
            events,
            "search_removed",
            SEVERITY_ROUTINE,
            f"Search no longer reported on {_agency_label(agency)}",
            f"{row['organisation']} {row['type']} search dated {row['date']} has dropped out of "
            "the reported history; this can be normal window roll-off.",
            agency,
            entry_id,
            {"organisation": row["organisation"], "date": row["date"], "removed": True},
        )
    for entry_id in sorted(set(old_rows) & set(new_rows)):
        before, after = old_rows[entry_id], new_rows[entry_id]
        changed = {field: (before[field], after[field]) for field in ("date", "organisation", "type", "purpose") if before[field] != after[field]}
        if not changed:
            continue
        if set(changed) == {"purpose"}:
            # Descriptive wording only: an adapter that learned to fill in a purpose is not a
            # change to the enquiry, so it is recorded without an alert.
            _emit(
                events,
                "search_changed",
                SEVERITY_ROUTINE,
                f"Search wording changed on {_agency_label(agency)}",
                f"{after['organisation']} search dated {after['date']} is now described as "
                f"'{after['purpose'] or 'no stated purpose'}' instead of '{before['purpose'] or 'no stated purpose'}'. "
                "The enquiry itself is unchanged.",
                agency,
                entry_id,
                {"changed": changed},
            )
            continue
        # An enquiry record does not legitimately mutate; disagreement means either a real
        # correction or a mis-parse, and both deserve a look.
        _emit(
            events,
            "search_changed",
            SEVERITY_IMPORTANT,
            f"Search details differ on {_agency_label(agency)}",
            "Search entry "
            + ", ".join(f"{field} was {old_value!r}, now {new_value!r}" for field, (old_value, new_value) in changed.items())
            + ". Review the extract: enquiry records do not normally change.",
            agency,
            entry_id,
            {"changed": changed},
        )


_STATUS_TITLES = {
    "account_defaulted": "Account in default",
    "account_closed": "Account closed",
    "account_reopened": "Account reopened",
}


def _compare_accounts(old: dict, new: dict, events: list[dict]) -> None:
    agency = new["agency"]
    old_rows, new_rows = _rows(old, "accounts"), _rows(new, "accounts")
    for entry_id in sorted(set(new_rows) - set(old_rows)):
        row = new_rows[entry_id]
        _emit(
            events,
            "new_account",
            SEVERITY_IMPORTANT,
            f"New account on {_agency_label(agency)}",
            f"{row['provider']} {row['type']} opened {row['opened']}, status {row['status']}, "
            f"balance {_format_amount(row['balance'])}.",
            agency,
            entry_id,
            {"provider": row["provider"], "type": row["type"], "opened": row["opened"]},
        )
    for entry_id in sorted(set(old_rows) - set(new_rows)):
        row = old_rows[entry_id]
        _emit(
            events,
            "account_removed",
            SEVERITY_IMPORTANT,
            f"Account no longer reported on {_agency_label(agency)}",
            f"{row['provider']} {row['type']} (last seen status {row['status']}, balance "
            f"{_format_amount(row['balance'])}) has disappeared. That can be a closed account "
            "ageing off the file or a wrong extract, so it is never treated as neutral.",
            agency,
            entry_id,
            {"provider": row["provider"], "type": row["type"], "removed": True},
        )
    for entry_id in sorted(set(old_rows) & set(new_rows)):
        before, after = old_rows[entry_id], new_rows[entry_id]
        identity = {
            field: (before[field], after[field])
            for field in ("provider", "type", "opened")
            if before[field] != after[field]
        }
        if identity:
            _emit(
                events,
                "account_identity_changed",
                SEVERITY_IMPORTANT,
                f"Account details differ on {_agency_label(agency)}",
                f"Account {entry_id} "
                + ", ".join(f"{field} was {old_value!r}, now {new_value!r}" for field, (old_value, new_value) in identity.items())
                + ". Review the extract: the same stable id should describe the same account.",
                agency,
                entry_id,
                {"changed": identity},
            )

        if before["status"] != after["status"]:
            was_negative = _is_negative_status(before["status"])
            is_negative = _is_negative_status(after["status"])
            was_closed = _is_closed_status(before["status"])
            is_closed = _is_closed_status(after["status"])
            if is_negative or was_negative:
                kind = "account_defaulted" if (is_negative and not was_negative) else "account_status_changed"
                severity = SEVERITY_IMPORTANT
                note = " Status wording indicates arrears or a default." if is_negative else " The earlier status indicated arrears or a default."
            elif is_closed or was_closed:
                kind, severity = "account_closed" if is_closed else "account_reopened", SEVERITY_IMPORTANT
                note = (
                    f" The tradeline is now reported as {after['status']}, which changes scoring and "
                    "can follow a closure nobody asked for."
                    if is_closed
                    else f" The tradeline is reported as {after['status']} again after being closed."
                )
            else:
                kind, severity, note = "account_status_changed", SEVERITY_ROUTINE, ""
            _emit(
                events,
                kind,
                severity,
                _STATUS_TITLES.get(kind, "Account status changed") + f" on {_agency_label(agency)}",
                f"{after['provider']} {after['type']}: status {before['status']} -> {after['status']}." + note,
                agency,
                entry_id,
                {"status": (before["status"], after["status"])},
            )

        if before["balance"] != after["balance"]:
            _emit(
                events,
                "account_balance_changed",
                SEVERITY_ROUTINE,
                f"Account balance changed on {_agency_label(agency)}",
                f"{after['provider']} {after['type']}: balance {_format_amount(before['balance'])} -> "
                f"{_format_amount(after['balance'])}. Balance movement alone is not an alert.",
                agency,
                entry_id,
                {"balance": [before["balance"], after["balance"]]},
            )

        if before["credit_limit"] != after["credit_limit"]:
            if before["credit_limit"] is None or after["credit_limit"] is None:
                _emit(
                    events,
                    "account_credit_limit_first_reported",
                    SEVERITY_ROUTINE,
                    f"Credit limit now reported on {_agency_label(agency)}",
                    f"{after['provider']} {after['type']}: credit limit "
                    + (
                        f"{_format_amount(after['credit_limit'])} is reported for the first time."
                        if after["credit_limit"] is not None
                        else "is no longer reported."
                    )
                    + " The earlier snapshot did not capture this field, so no change can be confirmed.",
                    agency,
                    entry_id,
                    {"credit_limit_first_reported": [before["credit_limit"], after["credit_limit"]]},
                )
            else:
                _emit(
                    events,
                    "account_credit_limit_changed",
                    SEVERITY_IMPORTANT,
                    f"Credit limit changed on {_agency_label(agency)}",
                    f"{after['provider']} {after['type']}: credit limit {_format_amount(before['credit_limit'])} -> "
                    f"{_format_amount(after['credit_limit'])}. A limit change moves utilisation and can "
                    "signal new or reduced borrowing.",
                    agency,
                    entry_id,
                    {"credit_limit": [before["credit_limit"], after["credit_limit"]]},
                )


def _compare_addresses(old: dict, new: dict, events: list[dict]) -> None:
    agency = new["agency"]
    old_rows, new_rows = _rows(old, "addresses"), _rows(new, "addresses")
    for entry_id in sorted(set(new_rows) - set(old_rows)):
        row = new_rows[entry_id]
        _emit(
            events,
            "address_added",
            SEVERITY_IMPORTANT,
            f"Address added on {_agency_label(agency)}",
            f"{row['address']} ({'current' if row['current'] else 'not current'}) now appears on the file.",
            agency,
            entry_id,
            {"address": row["address"], "added": True},
        )
    for entry_id in sorted(set(old_rows) - set(new_rows)):
        row = old_rows[entry_id]
        _emit(
            events,
            "address_removed",
            SEVERITY_IMPORTANT,
            f"Address no longer reported on {_agency_label(agency)}",
            f"{row['address']} has dropped out of the reported address history.",
            agency,
            entry_id,
            {"address": row["address"], "removed": True},
        )
    for entry_id in sorted(set(old_rows) & set(new_rows)):
        before, after = old_rows[entry_id], new_rows[entry_id]
        if _address_key(before["address"]) != _address_key(after["address"]):
            _emit(
                events,
                "address_changed",
                SEVERITY_IMPORTANT,
                f"Address changed on {_agency_label(agency)}",
                f"Stored address {before['address']} is now reported as {after['address']}. "
                "An edit to an existing address entry can indicate mail redirection.",
                agency,
                entry_id,
                {"address": [before["address"], after["address"]]},
            )
        if before["current"] != after["current"]:
            _emit(
                events,
                "address_current_changed",
                SEVERITY_IMPORTANT,
                f"Address status changed on {_agency_label(agency)}",
                f"{after['address']} changed from "
                f"{'current' if before['current'] else 'not current'} to "
                f"{'current' if after['current'] else 'not current'}.",
                agency,
                entry_id,
                {"current": [before["current"], after["current"]]},
            )


def _compare_public_records(old: dict, new: dict, events: list[dict]) -> None:
    agency = new["agency"]
    old_rows, new_rows = _rows(old, "public_records"), _rows(new, "public_records")
    for entry_id in sorted(set(new_rows) - set(old_rows)):
        row = new_rows[entry_id]
        _emit(
            events,
            "public_record_added",
            SEVERITY_IMPORTANT,
            f"Public record added on {_agency_label(agency)}",
            f"{row['type']} dated {row['date']}, status {row['status']}. A County Court Judgment, "
            "bankruptcy or IVA on the file is a major credit event.",
            agency,
            entry_id,
            {"type": row["type"], "date": row["date"], "status": row["status"]},
        )
    for entry_id in sorted(set(old_rows) - set(new_rows)):
        row = old_rows[entry_id]
        _emit(
            events,
            "public_record_removed",
            SEVERITY_ROUTINE,
            f"Public record no longer reported on {_agency_label(agency)}",
            f"{row['type']} dated {row['date']} (last seen status {row['status']}) is absent from "
            "this snapshot. Verify with the agency rather than assuming it was removed.",
            agency,
            entry_id,
            {"type": row["type"], "date": row["date"], "removed": True},
        )
    for entry_id in sorted(set(old_rows) & set(new_rows)):
        before, after = old_rows[entry_id], new_rows[entry_id]
        if before["type"] != after["type"] or before["date"] != after["date"]:
            _emit(
                events,
                "public_record_changed",
                SEVERITY_IMPORTANT,
                f"Public record details differ on {_agency_label(agency)}",
                f"Record {before['type']} dated {before['date']} is now reported as {after['type']} "
                f"dated {after['date']}. Review the extract.",
                agency,
                entry_id,
                {"type": [before["type"], after["type"]], "date": [before["date"], after["date"]]},
            )
        if before["status"] != after["status"]:
            was_live, was_resolved = _is_live_status(before["status"]), _is_resolved_status(before["status"])
            now_live, now_resolved = _is_live_status(after["status"]), _is_resolved_status(after["status"])
            if now_resolved and not was_resolved:
                severity = SEVERITY_ROUTINE  # live -> satisfied: an improvement, record still listed
            elif now_live and not was_live:
                severity = SEVERITY_IMPORTANT  # satisfied -> live: it came back
            elif (was_live or was_resolved) and (now_live or now_resolved) and now_live == was_live and now_resolved == was_resolved:
                severity = SEVERITY_ROUTINE  # rewording inside the same class (active -> outstanding)
            else:
                severity = SEVERITY_IMPORTANT  # one side uses wording we cannot classify
            _emit(
                events,
                "public_record_status_changed",
                severity,
                f"Public record status changed on {_agency_label(agency)}",
                f"{after['type']} dated {after['date']}: status {before['status']} -> {after['status']}. "
                "The record itself is still on file.",
                agency,
                entry_id,
                {"status": [before["status"], after["status"]], "type": after["type"], "date": after["date"]},
            )


def _compare_financial_associations(old: dict, new: dict, events: list[dict]) -> None:
    """Optional section. Absent on either side is never read as an empty list."""
    agency = new["agency"]
    if "financial_associations" not in old or "financial_associations" not in new:
        if "financial_associations" in new and new["financial_associations"]:
            _emit(
                events,
                "financial_associations_first_reported",
                SEVERITY_ROUTINE,
                f"Financial associations now reported on {_agency_label(agency)}",
                f"{len(new['financial_associations'])} financial association(s) are reported, but the "
                "earlier snapshot did not capture this section, so none of them can be confirmed as new.",
                agency,
                "financial_associations",
                {"first_reported": len(new["financial_associations"])},
            )
        elif "financial_associations" in old and old["financial_associations"]:
            _emit(
                events,
                "financial_associations_no_longer_reported",
                SEVERITY_ROUTINE,
                f"Financial associations not reported on {_agency_label(agency)}",
                f"The previous snapshot listed {len(old['financial_associations'])} financial "
                "association(s) and this one carries no section at all. That is missing data, not "
                "evidence that a link was severed.",
                agency,
                "financial_associations",
                {"no_longer_reported": len(old["financial_associations"])},
            )
        return
    old_rows, new_rows = _rows(old, "financial_associations"), _rows(new, "financial_associations")
    for entry_id in sorted(set(new_rows) - set(old_rows)):
        row = new_rows[entry_id]
        _emit(
            events,
            "financial_association_added",
            SEVERITY_IMPORTANT,
            f"Financial association added on {_agency_label(agency)}",
            f"Linked to {row['name']}"
            + (f" at {row['address']}" if row["address"] else "")
            + (f" since {row['date']}" if row["date"] else "")
            + ". Their credit behaviour is now applied to your file.",
            agency,
            entry_id,
            {"name": row["name"], "address": row["address"], "date": row["date"]},
        )
    for entry_id in sorted(set(old_rows) - set(new_rows)):
        row = old_rows[entry_id]
        _emit(
            events,
            "financial_association_removed",
            SEVERITY_ROUTINE,
            f"Financial association no longer reported on {_agency_label(agency)}",
            f"Association with {row['name']} is absent from this snapshot; confirm the link was "
            "actually severed with the agency.",
            agency,
            entry_id,
            {"name": row["name"], "removed": True},
        )
    for entry_id in sorted(set(old_rows) & set(new_rows)):
        before, after = old_rows[entry_id], new_rows[entry_id]
        changed = {
            field: (before[field], after[field])
            for field in ("name", "address", "date", "status")
            if before[field] != after[field]
        }
        if changed:
            _emit(
                events,
                "financial_association_changed",
                SEVERITY_IMPORTANT,
                f"Financial association details differ on {_agency_label(agency)}",
                f"Association {entry_id} "
                + ", ".join(f"{field} was {old_value!r}, now {new_value!r}" for field, (old_value, new_value) in changed.items())
                + ". Review the extract.",
                agency,
                entry_id,
                {"changed": changed},
            )


def _emit(
    events: list[dict],
    kind: str,
    severity: str,
    title: str,
    detail: str,
    agency: str,
    entry_id: str,
    payload: dict,
) -> None:
    if severity not in SEVERITIES:  # guard against a future typo changing the contract shape
        raise AssertionError(f"unsupported severity '{severity}'")
    scope = f"{agency}:{kind}:{entry_id}"
    digest = hashlib.sha1(
        json.dumps({"scope": scope, "payload": payload}, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()[:12]
    events.append(
        {
            "kind": kind,
            "severity": severity,
            "title": title,
            "detail": " ".join(detail.split()),
            "key": f"{kind}|{agency}|{entry_id}|{digest}",
        }
    )


def _search_classification(raw_type: str) -> tuple[str, str]:
    """Map an enquiry type to (kind, severity). Anything unrecognised needs review."""
    if raw_type == SEARCH_TYPE_SOFT:
        return "new_soft_search", SEVERITY_ROUTINE
    if raw_type == SEARCH_TYPE_HARD:
        return "new_hard_search", SEVERITY_IMPORTANT
    return "new_unknown_search", SEVERITY_IMPORTANT


def _is_negative_status(status: str) -> bool:
    normalised = _status_key(status)
    return any(marker in normalised for marker in _STATUS_MARKERS)


def _is_closed_status(status: str) -> bool:
    return any(marker in _status_key(status) for marker in _CLOSED_MARKERS)


def _is_resolved_status(status: str) -> bool:
    return any(marker in _status_key(status) for marker in _RESOLVED_MARKERS)


def _is_live_status(status: str) -> bool:
    return any(marker in _status_key(status) for marker in _LIVE_MARKERS)


def _status_key(status: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", status.lower())).strip()


def _address_key(address: str) -> str:
    """Comparison form of an address: casing and stray punctuation are not evidence of a move."""
    return re.sub(r"\s+", " ", address.lower()).strip().rstrip(".,;")


def _format_amount(value: float | None) -> str:
    if value is None:
        return "not reported"
    return f"GBP {value:,.2f}"


def _agency_label(agency: str) -> str:
    return AGENCY_LABELS.get(agency, agency.capitalize())


_ENTRY_VALIDATORS = {
    "searches": _validate_search,
    "accounts": _validate_account,
    "addresses": _validate_address,
    "public_records": _validate_public_record,
    "financial_associations": _validate_financial_association,
}
