"""Fixtures and tests for the pure credit validation / change-detection engine.

Fixtures are independent of the implementation: reports are built as plain dicts from the
canonical shape in docs/CONTRACT.md and the baseline example in the project brief, so a test
fails when the engine drifts rather than when it is refactored.
"""

import copy
import json
import math

import pytest

from privacy_bot.credit import AGENCIES, CreditValidationError, compare_reports, validate_report

BASE_DATE = "2026-09-01"
LATER_DATE = "2026-09-26"
NEXT_DATE = "2026-10-01"  # a third snapshot, for history that must drop entries


def baseline_report(agency="experian", report_date=BASE_DATE):
    """The canonical first snapshot from the project brief."""
    return {
        "agency": agency,
        "report_date": report_date,
        "complete": True,
        "searches": [
            {"id": "s1", "date": "2026-09-01", "organisation": "Insurer", "type": "soft", "purpose": "quote"},
        ],
        "accounts": [
            {"id": "a1", "provider": "Bank", "type": "loan", "opened": "2026-01-01", "status": "current", "balance": 100},
        ],
        "addresses": [{"id": "d1", "address": "1 Example Road", "current": True}],
        "public_records": [],
    }


def later(mutate=None, agency="experian", report_date=LATER_DATE):
    """A second snapshot, optionally edited by ``mutate`` (which edits the dict in place)."""
    report = baseline_report(agency=agency, report_date=report_date)
    if mutate is not None:
        mutate(report)
    return report


def kinds(events):
    return [event["kind"] for event in events]


def severities(events):
    return {event["severity"] for event in events}


def only(events, kind):
    matches = [event for event in events if event["kind"] == kind]
    assert len(matches) == 1, f"expected exactly one '{kind}' event, got {kinds(events)}"
    return matches[0]


def important(events):
    return [event for event in events if event["severity"] == "important"]


# ----------------------------------------------------------------------- validate_report


def test_contract_exports_are_importable():
    from privacy_bot import credit

    assert callable(credit.validate_report)
    assert callable(credit.compare_reports)
    assert credit.AGENCIES == ("experian", "equifax", "transunion")
    assert issubclass(credit.CreditValidationError, ValueError)


def test_valid_report_is_normalised_into_a_detached_copy():
    source = baseline_report()
    snapshot = validate_report(source)

    assert snapshot["agency"] == "experian"
    assert snapshot["report_date"] == BASE_DATE
    assert snapshot["complete"] is True
    assert [row["id"] for row in snapshot["searches"]] == ["s1"]
    assert [row["id"] for row in snapshot["accounts"]] == ["a1"]
    assert [row["id"] for row in snapshot["addresses"]] == ["d1"]
    assert snapshot["public_records"] == []
    # Whitespace is normalised, not significant.
    assert validate_report(_padded(source))["accounts"][0]["provider"] == "Bank"

    snapshot["accounts"][0]["balance"] = 999
    snapshot["extra"] = "written"
    assert source["accounts"][0]["balance"] == 100  # input untouched
    assert "extra" not in source
    assert snapshot is not source


def _padded(report):
    padded = copy.deepcopy(report)
    padded["agency"] = f"  {padded['agency']}  "
    padded["accounts"][0]["provider"] = "  Bank "
    return padded


@pytest.mark.parametrize("agency", list(AGENCIES))
def test_each_of_the_three_agencies_is_valid_and_tracked_separately(agency):
    snapshot = validate_report(baseline_report(agency=agency))
    assert snapshot["agency"] == agency
    assert compare_reports(None, baseline_report(agency=agency)) == []


def test_optional_fields_are_accepted_and_default_predictably():
    report = baseline_report()
    report["accounts"][0]["credit_limit"] = 1000
    report["financial_associations"] = [{"id": "f1", "name": "Partner"}]

    snapshot = validate_report(report)

    assert snapshot["accounts"][0]["credit_limit"] == 1000
    assert snapshot["financial_associations"][0]["name"] == "Partner"
    # Optional values that were not supplied are explicit "not reported" markers.
    assert validate_report(baseline_report())["accounts"][0]["credit_limit"] is None
    assert "financial_associations" not in validate_report(baseline_report())


# --- required shape -------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, [], "report", 7, True])
def test_non_object_report_is_rejected(value):
    with pytest.raises(CreditValidationError):
        validate_report(value)


@pytest.mark.parametrize(
    "field",
    ["agency", "report_date", "complete", "searches", "accounts", "addresses", "public_records"],
)
def test_missing_required_top_level_field_is_rejected(field):
    report = baseline_report()
    del report[field]
    with pytest.raises(CreditValidationError) as error:
        validate_report(report)
    assert field in str(error.value)


def test_missing_any_array_is_rejected_even_when_the_others_are_present():
    for field in ("searches", "accounts", "addresses", "public_records"):
        report = baseline_report()
        del report[field]
        with pytest.raises(CreditValidationError):
            validate_report(report)


@pytest.mark.parametrize("field", ["searches", "accounts", "addresses", "public_records"])
@pytest.mark.parametrize("value", [{}, "s1", 3, None, {"id": "s1"}])
def test_arrays_must_be_lists(field, value):
    report = baseline_report()
    report[field] = value
    with pytest.raises(CreditValidationError):
        validate_report(report)


def test_empty_arrays_are_valid_history_not_missing_history():
    report = baseline_report()
    report["searches"] = []
    report["accounts"] = []
    report["addresses"] = []
    snapshot = validate_report(report)
    assert snapshot["searches"] == [] and snapshot["accounts"] == [] and snapshot["addresses"] == []


# --- agency / completeness ------------------------------------------------------------


@pytest.mark.parametrize("agency", ["sage", "experien", "Experian", "EXPERIAN", " experian extra", "", None, 1])
def test_unknown_agency_is_rejected(agency):
    report = baseline_report()
    report["agency"] = agency
    with pytest.raises(CreditValidationError):
        validate_report(report)


@pytest.mark.parametrize("complete", [False, "true", 1, 0, None, {}])
def test_incomplete_or_non_boolean_complete_is_rejected(complete):
    report = baseline_report()
    report["complete"] = complete
    with pytest.raises(CreditValidationError):
        validate_report(report)


# --- dates ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["", "2026-13-01", "2026-02-30", "2026-09-31", "26-09-01", "2026/09/01", "1899-12-31", "0000-01-01", "not-a-date", 20260901, None],
)
def test_invalid_report_date_is_rejected(value):
    report = baseline_report()
    report["report_date"] = value
    with pytest.raises(CreditValidationError):
        validate_report(report)


def test_the_earliest_credible_date_is_kept_but_one_year_earlier_is_not():
    assert validate_report(baseline_report(report_date="1900-01-01"))["report_date"] == "1900-01-01"


@pytest.mark.parametrize(
    "path,value",
    [
        (("searches", 0, "date"), "2026-13-01"),
        (("searches", 0, "date"), "yesterday"),
        (("accounts", 0, "opened"), "2026-02-30"),
        (("accounts", 0, "opened"), None),
    ],
)
def test_invalid_nested_dates_are_rejected(path, value):
    report = baseline_report()
    report[path[0]][path[1]][path[2]] = value
    with pytest.raises(CreditValidationError):
        validate_report(report)


def test_public_record_date_must_be_real():
    report = baseline_report()
    report["public_records"] = [{"id": "p1", "type": "ccj", "date": "2026-11-31", "status": "active"}]
    with pytest.raises(CreditValidationError):
        validate_report(report)


def test_as_of_rejects_future_dated_entries_but_accepts_the_day_itself():
    assert validate_report(baseline_report(), as_of=LATER_DATE)["report_date"] == BASE_DATE

    future = baseline_report(report_date="2027-01-01")
    with pytest.raises(CreditValidationError) as error:
        validate_report(future, as_of="2026-09-26")
    assert "future" in str(error.value)

    with pytest.raises(CreditValidationError):
        validate_report(baseline_report(), as_of="not-a-date")


def test_without_as_of_the_engine_makes_no_claim_about_today():
    assert validate_report(baseline_report(report_date="2099-01-01"))["report_date"] == "2099-01-01"


# --- nested items ---------------------------------------------------------------------


@pytest.mark.parametrize("field", ["searches", "accounts", "addresses", "public_records"])
@pytest.mark.parametrize("item", ["s1", None, 5, ["id"], {"id": "x"}])
def test_malformed_nested_objects_are_rejected(field, item):
    report = baseline_report()
    report[field] = [item]
    with pytest.raises(CreditValidationError):
        validate_report(report)


def test_deeply_nested_garbage_inside_an_item_is_rejected():
    report = baseline_report()
    report["accounts"][0]["provider"] = {"name": "Bank"}
    with pytest.raises(CreditValidationError):
        validate_report(report)


def full_report(agency="experian", report_date=BASE_DATE):
    """Baseline with all four collections populated, for per-entry tests."""
    report = baseline_report(agency=agency, report_date=report_date)
    report["public_records"] = [{"id": "p1", "type": "ccj", "date": "2026-05-01", "status": "active"}]
    return report


@pytest.mark.parametrize("field", ["searches", "accounts", "addresses", "public_records"])
@pytest.mark.parametrize("id_value", ["", "   ", None, 5, {"id": "a1"}, []])
def test_stable_identifiers_are_required_and_must_be_text(field, id_value):
    report = full_report()
    report[field][0]["id"] = id_value
    with pytest.raises(CreditValidationError):
        validate_report(report)


@pytest.mark.parametrize("field", ["searches", "accounts", "addresses", "public_records"])
def test_an_entry_without_any_identifier_is_rejected(field):
    report = full_report()
    del report[field][0]["id"]
    with pytest.raises(CreditValidationError):
        validate_report(report)


@pytest.mark.parametrize("field", ["searches", "accounts", "addresses", "public_records"])
def test_duplicate_ids_are_rejected_rather_than_guessed(field):
    report = full_report()
    first = copy.deepcopy(report[field][0])
    report[field] = [first, dict(first)]
    with pytest.raises(CreditValidationError) as error:
        validate_report(report)
    assert "duplicate" in str(error.value)


def test_duplicate_ids_after_whitespace_normalisation_are_rejected():
    report = baseline_report()
    report["accounts"].append(dict(copy.deepcopy(report["accounts"][0]), id=" a1 "))
    with pytest.raises(CreditValidationError):
        validate_report(report)


def test_ids_may_repeat_across_collections_because_keys_are_scoped():
    def rename_everything(r):
        r["accounts"][0]["id"] = "x1"
        r["searches"][0]["id"] = "x1"
        r["addresses"][0]["id"] = "x1"

    shared = later(rename_everything)
    snapshot = validate_report(shared)
    assert snapshot["accounts"][0]["id"] == snapshot["searches"][0]["id"] == "x1"

    # Renaming every stable id looks like a total replacement, and the keys stay distinct.
    events = compare_reports(baseline_report(), shared)
    assert len({event["key"] for event in events}) == len(events)
    assert {"new_account", "account_removed", "new_soft_search", "search_removed", "address_added", "address_removed"} <= set(kinds(events))


@pytest.mark.parametrize("field,index,key", [("searches", 0, "organisation"), ("accounts", 0, "provider"), ("accounts", 0, "type"), ("addresses", 0, "address")])
@pytest.mark.parametrize("value", [None, 5, ["x"], {"a": 1}, True])
def test_scalar_fields_must_be_text(field, index, key, value):
    report = baseline_report()
    report[field][index][key] = value
    with pytest.raises(CreditValidationError):
        validate_report(report)


@pytest.mark.parametrize("value", ["100", None, True, False, {}, [], float("nan"), float("inf"), "-"])
def test_balance_must_be_a_finite_number(value):
    report = baseline_report()
    report["accounts"][0]["balance"] = value
    with pytest.raises(CreditValidationError):
        validate_report(report)


def test_negative_balance_is_a_real_overdraft_not_malformed_data():
    report = baseline_report()
    report["accounts"][0]["balance"] = -250.5
    assert validate_report(report)["accounts"][0]["balance"] == -250.5


@pytest.mark.parametrize("value", ["true", 1, 0, None, "yes"])
def test_current_flag_must_be_boolean(value):
    report = baseline_report()
    report["addresses"][0]["current"] = value
    with pytest.raises(CreditValidationError):
        validate_report(report)


@pytest.mark.parametrize("value", ["1000", True, float("nan"), {"limit": 1}])
def test_optional_credit_limit_must_be_a_number_or_absent(value):
    report = baseline_report()
    report["accounts"][0]["credit_limit"] = value
    with pytest.raises(CreditValidationError):
        validate_report(report)


def test_optional_financial_associations_must_still_be_well_formed():
    for bad in [{}, "f1", [{"id": "f1"}], [{"id": "f1", "name": 5}], [{"id": "", "name": "Partner"}]]:
        report = baseline_report()
        report["financial_associations"] = bad
        with pytest.raises(CreditValidationError):
            validate_report(report)


def test_unsupported_fields_are_rejected_loudly_not_dropped():
    report = baseline_report()
    report["seraches"] = []
    with pytest.raises(CreditValidationError) as error:
        validate_report(report)
    assert "seraches" in str(error.value)

    report = baseline_report()
    report["accounts"][0]["credit_limit_eur"] = 5
    with pytest.raises(CreditValidationError):
        validate_report(report)


def test_required_item_fields_cannot_be_omitted():
    for field, key in [("searches", "organisation"), ("accounts", "opened"), ("addresses", "current"), ("public_records", "status")]:
        report = baseline_report()
        if not report[field]:
            report[field] = [{"id": "p1", "type": "ccj", "date": BASE_DATE, "status": "active"}]
        del report[field][0][key]
        with pytest.raises(CreditValidationError):
            validate_report(report)


def test_error_messages_are_readable_and_hold_no_personal_data():
    report = baseline_report()
    report["complete"] = False
    with pytest.raises(CreditValidationError) as error:
        validate_report(report)
    message = str(error.value)
    assert message and " " in message
    assert "1 Example Road" not in message


# ------------------------------------------------------------------------ compare_reports


def test_first_snapshot_is_a_quiet_baseline_for_every_agency():
    for agency in AGENCIES:
        assert compare_reports(None, baseline_report(agency=agency)) == []


def test_baseline_is_quiet_even_when_the_report_is_full_of_adverse_items():
    report = baseline_report()
    report["public_records"] = [{"id": "p1", "type": "ccj", "date": "2026-08-01", "status": "active"}]
    report["accounts"].append({"id": "a2", "provider": "Store", "type": "credit card", "opened": "2026-08-01", "status": "default", "balance": 0})
    report["searches"].append({"id": "s2", "date": "2026-08-30", "organisation": "Lender", "type": "hard", "purpose": "application"})

    assert compare_reports(None, report) == []


def test_identical_report_produces_no_events():
    report = baseline_report()
    assert compare_reports(report, copy.deepcopy(report)) == []
    assert compare_reports(report, validate_report(report)) == []


def test_reordering_lists_is_not_a_change():
    report = later(lambda r: r["searches"].extend([
        {"id": "s2", "date": "2026-09-02", "organisation": "Lender", "type": "soft", "purpose": "quote"},
        {"id": "s3", "date": "2026-09-03", "organisation": "Utility", "type": "soft", "purpose": ""},
    ]))
    reordered = copy.deepcopy(report)
    reordered["searches"] = list(reversed(reordered["searches"]))
    reordered["report_date"] = "2026-09-27"

    # The intermediate report must be valid first, and then a pure re-order is silent.
    compare_reports(baseline_report(), report)
    assert compare_reports(report, reordered) == []


# --- the brief's worked example -------------------------------------------------------


def test_new_soft_search_is_routine_history_only():
    events = compare_reports(baseline_report(), later(lambda r: r["searches"].append(
        {"id": "s2", "date": "2026-09-10", "organisation": "Insurer Two", "type": "soft", "purpose": "quote"},
    )))

    assert len(events) == 1
    event = only(events, "new_soft_search")
    assert event["severity"] == "routine"
    assert "Insurer Two" in event["detail"]
    assert important(events) == []


def test_new_hard_search_is_important():
    events = compare_reports(baseline_report(), later(lambda r: r["searches"].append(
        {"id": "s3", "date": "2026-09-11", "organisation": "Lender", "type": "hard", "purpose": "loan application"},
    )))

    event = only(events, "new_hard_search")
    assert event["severity"] == "important"
    assert "Lender" in event["detail"] and "2026-09-11" in event["detail"]


def test_new_account_is_important():
    events = compare_reports(baseline_report(), later(lambda r: r["accounts"].append(
        {"id": "a2", "provider": "Store", "type": "credit card", "opened": "2026-09-05", "status": "open", "balance": 0},
    )))

    event = only(events, "new_account")
    assert event["severity"] == "important"
    assert "Store" in event["detail"]


def test_existing_account_moving_to_default_is_important():
    events = compare_reports(baseline_report(), later(lambda r: r["accounts"][0].__setitem__("status", "default")))

    event = only(events, "account_defaulted")
    assert event["severity"] == "important"
    assert "default" in event["title"].lower(), "the headline a UI shows must name the problem"
    assert "current" in event["detail"] and "default" in event["detail"]


@pytest.mark.parametrize("status", ["arrears", "Missed payments", "Written off", "Late payment", "bankruptcy petition"])
def test_adverse_status_wording_is_treated_as_a_default_marker(status):
    events = compare_reports(baseline_report(), later(lambda r, status=status: r["accounts"][0].__setitem__("status", status)))
    assert important(events), f"'{status}' must not be filed as routine"


def test_benign_status_wording_change_stays_routine():
    report = baseline_report()
    report["accounts"][0]["status"] = "open"
    events = compare_reports(report, later(lambda r: r["accounts"][0].__setitem__("status", "current")))
    assert severities(events) == {"routine"}


def test_same_address_id_with_new_text_is_important():
    events = compare_reports(baseline_report(), later(lambda r: r["addresses"][0].__setitem__("address", "2 Different Close")))

    event = only(events, "address_changed")
    assert event["severity"] == "important"
    assert "1 Example Road" in event["detail"] and "2 Different Close" in event["detail"]


def test_casing_and_punctuation_in_an_address_are_not_a_move():
    for variant in ["1 EXAMPLE ROAD", "  1  Example Road  ", "1 Example Road."]:
        events = compare_reports(baseline_report(), later(lambda r, variant=variant: r["addresses"][0].__setitem__("address", variant)))
        assert events == [], variant


def test_current_flag_flip_is_routine():
    events = compare_reports(baseline_report(), later(lambda r: r["addresses"][0].__setitem__("current", False)))
    assert only(events, "address_current_changed")["severity"] == "important"


def test_public_record_added_is_important():
    events = compare_reports(baseline_report(), later(lambda r: r["public_records"].append(
        {"id": "p1", "type": "ccj", "date": "2026-09-02", "status": "active"},
    )))

    event = only(events, "public_record_added")
    assert event["severity"] == "important"
    assert "ccj" in event["detail"]


def test_unknown_enquiry_type_is_an_important_review():
    events = compare_reports(baseline_report(), later(lambda r: r["searches"].append(
        {"id": "s9", "date": "2026-09-12", "organisation": "Employer", "type": "employer_check", "purpose": ""},
    )))

    event = only(events, "new_unknown_search")
    assert event["severity"] == "important"
    assert "employer_check" in event["detail"]
    assert "review" in (event["title"] + event["detail"]).lower()


def test_search_declared_as_unknown_type_is_also_important():
    events = compare_reports(baseline_report(), later(lambda r: r["searches"].append(
        {"id": "s10", "date": "2026-09-12", "organisation": "Unknown", "type": "unknown", "purpose": ""},
    )))
    assert only(events, "new_unknown_search")["severity"] == "important"


def test_case_of_a_search_type_is_not_significant():
    events = compare_reports(baseline_report(), later(lambda r: r["searches"].append(
        {"id": "s11", "date": "2026-09-12", "organisation": "Lender", "type": "HARD", "purpose": ""},
    )))
    assert only(events, "new_hard_search")["severity"] == "important"


# --- balances, limits, closures --------------------------------------------------------


def test_balance_movement_alone_is_routine():
    events = compare_reports(baseline_report(), later(lambda r: r["accounts"][0].__setitem__("balance", 140)))

    assert len(events) == 1
    assert only(events, "account_balance_changed")["severity"] == "routine"


def test_int_and_float_balances_of_equal_value_are_the_same_balance():
    assert compare_reports(baseline_report(), later(lambda r: r["accounts"][0].update(balance=100.0))) == []


def test_balance_movement_never_suppresses_a_default():
    events = compare_reports(baseline_report(), later(lambda r: r["accounts"][0].update(status="default", balance=450)))

    assert only(events, "account_defaulted")["severity"] == "important"
    assert only(events, "account_balance_changed")["severity"] == "routine"


def test_new_ccj_is_not_hidden_by_other_changes():
    events = compare_reports(baseline_report(), later(lambda r: (
        r["accounts"][0].update(balance=500, status="closed"),
        r["public_records"].append({"id": "p1", "type": "ccj", "date": "2026-09-02", "status": "active"}),
        r["searches"].append({"id": "s2", "date": "2026-09-04", "organisation": "Insurer", "type": "soft", "purpose": ""}),
    )))

    assert only(events, "public_record_added")["severity"] == "important"
    assert only(events, "account_closed")["severity"] == "important"
    assert important(events) and len(events) == 4


def test_public_record_going_satisfied_is_routine_but_still_reported():
    old = baseline_report(report_date=BASE_DATE)
    old["public_records"] = [{"id": "p1", "type": "ccj", "date": "2026-01-02", "status": "active"}]
    new = copy.deepcopy(old)
    new["report_date"] = LATER_DATE
    new["public_records"][0]["status"] = "satisfied"

    events = compare_reports(old, new)
    event = only(events, "public_record_status_changed")
    assert event["severity"] == "routine"
    assert "still on file" in event["detail"]


def test_public_record_becoming_live_again_is_important():
    old = baseline_report(report_date=BASE_DATE)
    old["public_records"] = [{"id": "p1", "type": "ccj", "date": "2026-01-02", "status": "satisfied"}]
    new = copy.deepcopy(old)
    new["report_date"] = LATER_DATE
    new["public_records"][0]["status"] = "active"

    assert only(compare_reports(old, new), "public_record_status_changed")["severity"] == "important"


def test_unclassifiable_public_record_wording_is_escalated():
    old = baseline_report(report_date=BASE_DATE)
    old["public_records"] = [{"id": "p1", "type": "iva", "date": "2026-01-02", "status": "something new"}]
    new = copy.deepcopy(old)
    new["report_date"] = LATER_DATE
    new["public_records"][0]["status"] = "something else"

    assert only(compare_reports(old, new), "public_record_status_changed")["severity"] == "important"


def test_account_closure_is_important_and_reopening_is_important():
    closed = compare_reports(baseline_report(), later(lambda r: r["accounts"][0].__setitem__("status", "closed")))
    assert only(closed, "account_closed")["severity"] == "important"

    old = baseline_report(report_date=BASE_DATE)
    old["accounts"][0]["status"] = "closed"
    reopened = compare_reports(old, later(lambda r: r["accounts"][0].__setitem__("status", "current")))
    assert only(reopened, "account_reopened")["severity"] == "important"


def test_credit_limit_change_is_reported_when_both_snapshots_have_one():
    old = baseline_report(report_date=BASE_DATE)
    old["accounts"][0]["credit_limit"] = 1000
    new = copy.deepcopy(old)
    new["report_date"] = LATER_DATE
    new["accounts"][0]["credit_limit"] = 1500

    event = only(compare_reports(old, new), "account_credit_limit_changed")
    assert event["severity"] == "important"
    assert "1,000.00" in event["detail"] and "1,500.00" in event["detail"]


def test_credit_limit_absent_then_present_is_not_claimed_as_a_change():
    new = later(lambda r: r["accounts"][0].__setitem__("credit_limit", 1500))
    events = compare_reports(baseline_report(), new)

    event = only(events, "account_credit_limit_first_reported")
    assert event["severity"] == "routine"
    assert important(events) == []


def test_dropping_an_unreported_limit_is_silent_routine():
    old = baseline_report(report_date=BASE_DATE)
    old["accounts"][0]["credit_limit"] = 1500
    new = copy.deepcopy(old)
    new["report_date"] = LATER_DATE
    del new["accounts"][0]["credit_limit"]

    events = compare_reports(old, new)
    assert only(events, "account_credit_limit_first_reported")["severity"] == "routine"


# --- adds and removals -----------------------------------------------------------------


def test_vanished_account_is_important_not_clean():
    old = later(lambda r: r["accounts"].append(
        {"id": "a2", "provider": "Store", "type": "credit card", "opened": "2020-01-01", "status": "current", "balance": 5},
    ))
    events = compare_reports(old, baseline_report(report_date=NEXT_DATE))

    event = only(events, "account_removed")
    assert event["severity"] == "important"
    assert "Store" in event["detail"]


def test_searches_aging_out_of_the_window_is_routine():
    old = later(lambda r: r["searches"].append(
        {"id": "s2", "date": "2026-09-10", "organisation": "Insurer Two", "type": "soft", "purpose": ""},
    ))
    events = compare_reports(old, baseline_report(report_date=NEXT_DATE))

    assert only(events, "search_removed")["severity"] == "routine"


def test_added_and_removed_addresses_are_important():
    added = compare_reports(baseline_report(), later(lambda r: r["addresses"].append(
        {"id": "d2", "address": "9 New Street", "current": False},
    )))
    assert only(added, "address_added")["severity"] == "important"

    removed = compare_reports(later(lambda r: r["addresses"].append(
        {"id": "d2", "address": "9 New Street", "current": False},
    )), baseline_report(report_date=NEXT_DATE))
    assert only(removed, "address_removed")["severity"] == "important"


def test_same_stable_id_with_different_account_identity_is_a_review_not_a_new_account():
    events = compare_reports(baseline_report(), later(lambda r: r["accounts"][0].update(provider="Someone Else", opened="2026-01-02")))

    event = only(events, "account_identity_changed")
    assert event["severity"] == "important"
    assert "review" in (event["title"] + event["detail"]).lower()
    assert "new_account" not in kinds(events)


def test_changed_search_row_is_escalated():
    events = compare_reports(baseline_report(), later(lambda r: r["searches"][0].__setitem__("organisation", "Impersonator")))
    assert only(events, "search_changed")["severity"] == "important"


def test_purpose_wording_alone_is_not_an_alert():
    events = compare_reports(baseline_report(), later(lambda r: r["searches"][0].__setitem__("purpose", "application")))

    assert len(events) == 1
    assert only(events, "search_changed")["severity"] == "routine"


def test_a_purpose_change_carried_with_a_real_change_stays_important():
    events = compare_reports(baseline_report(), later(lambda r: r["searches"][0].update(purpose="application", type="hard")))
    assert only(events, "search_changed")["severity"] == "important"


# --- optional financial associations ---------------------------------------------------


def test_financial_section_absent_from_both_snapshots_produces_no_events():
    assert compare_reports(baseline_report(), later()) == []


def test_new_financial_association_against_a_captured_baseline_is_important():
    old = baseline_report(report_date=BASE_DATE)
    old["financial_associations"] = []
    new = copy.deepcopy(old)
    new["report_date"] = LATER_DATE
    new["financial_associations"] = [{"id": "f1", "name": "Partner", "address": "1 Example Road"}]

    event = only(compare_reports(old, new), "financial_association_added")
    assert event["severity"] == "important"


def test_financial_associations_reported_for_the_first_time_are_not_called_new():
    new = later(lambda r: r.__setitem__("financial_associations", [{"id": "f1", "name": "Partner"}]))
    events = compare_reports(baseline_report(), new)

    assert events == [] or all(event["severity"] == "routine" for event in events)
    assert only(events, "financial_associations_first_reported")["severity"] == "routine"


def test_a_dropped_financial_section_is_missing_data_not_a_severed_link():
    old = baseline_report(report_date=BASE_DATE)
    old["financial_associations"] = [{"id": "f1", "name": "Partner"}]
    new = copy.deepcopy(old)
    new["report_date"] = LATER_DATE
    del new["financial_associations"]

    events = compare_reports(old, new)
    event = only(events, "financial_associations_no_longer_reported")
    assert event["severity"] == "routine"
    assert "missing data" in event["detail"]
    assert "financial_association_removed" not in kinds(events)


def test_financial_association_details_changing_is_important():
    old = baseline_report(report_date=BASE_DATE)
    old["financial_associations"] = [{"id": "f1", "name": "Partner", "address": "1 Example Road"}]
    new = copy.deepcopy(old)
    new["report_date"] = LATER_DATE
    new["financial_associations"] = [{"id": "f1", "name": "Partner", "address": "8 Other Way"}]

    assert only(compare_reports(old, new), "financial_association_changed")["severity"] == "important"


def test_optional_section_can_be_added_without_breaking_the_required_schema():
    report = baseline_report()
    report["financial_associations"] = [{"id": "f1", "name": "Partner", "date": "2020-01-01", "status": "linked"}]
    assert validate_report(report)["financial_associations"][0]["date"] == "2020-01-01"


# --- snapshot ordering and agency isolation --------------------------------------------


def test_older_snapshot_with_different_content_is_refused():
    old = baseline_report(report_date=LATER_DATE)
    new = later(lambda r: r["accounts"][0].__setitem__("balance", 900), report_date="2026-09-02")

    with pytest.raises(CreditValidationError) as error:
        compare_reports(old, new)
    assert "older" in str(error.value)


def test_same_date_with_different_content_is_refused():
    old = baseline_report(report_date=LATER_DATE)
    conflicting = later(lambda r: r["accounts"][0].update(balance=500), report_date=LATER_DATE)
    with pytest.raises(CreditValidationError) as error:
        compare_reports(old, conflicting)
    assert "conflicting" in str(error.value)


def test_same_date_with_only_a_balance_change_is_still_a_conflict():
    # Balance differences prove the two extracts disagree, which no alert rule can reconcile.
    old = later(lambda r: r["accounts"][0].update(balance=500), report_date=LATER_DATE)
    new = later(lambda r: r["accounts"][0].update(balance=900), report_date=LATER_DATE)
    with pytest.raises(CreditValidationError):
        compare_reports(old, new)


def test_exact_duplicate_import_is_idempotent_whatever_the_date():
    report = baseline_report(report_date=LATER_DATE)
    assert compare_reports(report, copy.deepcopy(report)) == []
    assert compare_reports(report, copy.deepcopy(report), as_of="2026-12-31") == []


def test_optional_section_appearing_on_the_stored_date_is_a_conflict_not_a_silent_upgrade():
    old = baseline_report(report_date=LATER_DATE)
    new = later(lambda r: r.__setitem__("financial_associations", []), report_date=LATER_DATE)

    with pytest.raises(CreditValidationError):
        compare_reports(old, new)


@pytest.mark.parametrize("agency", ["equifax", "transunion"])
def test_agencies_are_never_compared_against_each_other(agency):
    with pytest.raises(CreditValidationError) as error:
        compare_reports(baseline_report(agency="experian"), baseline_report(agency=agency, report_date=LATER_DATE))
    assert "independently" in str(error.value)


def test_same_change_at_different_agencies_gets_different_keys():
    def add_ccj(r):
        r["public_records"] = [{"id": "p1", "type": "ccj", "date": "2026-09-02", "status": "active"}]

    experian = compare_reports(baseline_report(agency="experian"), later(add_ccj, agency="experian"))
    equifax = compare_reports(baseline_report(agency="equifax"), later(add_ccj, agency="equifax"))

    assert experian and equifax
    assert experian[0]["key"] != equifax[0]["key"]


def test_changes_do_not_leak_across_agencies():
    events = compare_reports(baseline_report(agency="transunion"), later(lambda r: r["accounts"][0].__setitem__("status", "default"), agency="transunion"))
    assert only(events, "account_defaulted")
    assert compare_reports(baseline_report(agency="equifax"), later(report_date=LATER_DATE, agency="equifax")) == []


# --- event contract --------------------------------------------------------------------


def test_events_match_the_documented_shape_exactly():
    def change_everything(r):
        r["searches"].append({"id": "s2", "date": "2026-09-09", "organisation": "Lender", "type": "hard", "purpose": "mortgage"})
        r["searches"].append({"id": "s3", "date": "2026-09-10", "organisation": "Insurer", "type": "soft", "purpose": ""})
        r["searches"].append({"id": "s4", "date": "2026-09-11", "organisation": "Employer", "type": "other", "purpose": ""})
        r["accounts"].append({"id": "a2", "provider": "Store", "type": "card", "opened": "2026-09-01", "status": "current", "balance": 10})
        r["accounts"][0].update(status="default", balance=300)
        r["addresses"][0]["address"] = "2 Different Close"
        r["public_records"] = [{"id": "p1", "type": "ccj", "date": "2026-09-02", "status": "active"}]

    events = compare_reports(baseline_report(), later(change_everything))

    assert events, "the change set above must produce events"
    for event in events:
        assert set(event) == {"kind", "severity", "title", "detail", "key"}
        assert event["severity"] in ("important", "routine")
        assert isinstance(event["kind"], str) and event["kind"]
        assert isinstance(event["title"], str) and event["title"]
        assert isinstance(event["detail"], str) and event["detail"].endswith((".", "!", "?"))
        assert isinstance(event["key"], str) and event["key"]
        assert event["key"].startswith(event["kind"])
        assert event["kind"].islower() and " " not in event["kind"]
    assert len({event["key"] for event in events}) == len(events)
    # important first, so a UI can render the head of the list as the actionable part
    ranks = [event["severity"] != "important" for event in events]
    assert ranks == sorted(ranks)


def test_keys_are_stable_for_the_same_change_and_distinct_for_a_different_one():
    def default(r):
        r["accounts"][0]["status"] = "default"

    def balance(r):
        r["accounts"][0]["balance"] = 900

    first = compare_reports(baseline_report(), later(default))
    second = compare_reports(baseline_report(), later(default))
    assert [event["key"] for event in first] == [event["key"] for event in second]

    other = compare_reports(baseline_report(), later(balance))
    assert set(event["key"] for event in first).isdisjoint(event["key"] for event in other)


def test_a_repeated_default_on_a_moving_balance_does_not_reuse_one_key():
    step_one = baseline_report(report_date="2026-09-01")
    step_two = copy.deepcopy(step_one)
    step_two["report_date"] = "2026-09-08"
    step_two["accounts"][0].update(status="default", balance=200)
    step_three = copy.deepcopy(step_two)
    step_three["report_date"] = "2026-09-15"
    step_three["accounts"][0].update(status="closed", balance=300)

    events_a = compare_reports(step_one, step_two)
    events_b = compare_reports(step_two, step_three)

    assert important(events_a) and important(events_b)
    assert set(event["key"] for event in events_a).isdisjoint(event["key"] for event in events_b)


def test_comparison_validates_both_sides():
    broken = baseline_report()
    broken["complete"] = False
    with pytest.raises(CreditValidationError):
        compare_reports(baseline_report(), broken)
    with pytest.raises(CreditValidationError):
        compare_reports(broken, baseline_report(report_date=LATER_DATE))
    with pytest.raises(CreditValidationError):
        compare_reports("not a report", baseline_report(report_date=LATER_DATE))


def test_compare_does_not_mutate_its_inputs():
    old = baseline_report()
    new = later(lambda r: r["accounts"][0].__setitem__("status", "default"))
    old_before, new_before = copy.deepcopy(old), copy.deepcopy(new)

    compare_reports(old, new)

    assert old == old_before and new == new_before


def test_a_two_step_history_is_computed_step_by_step():
    step_one = baseline_report(report_date="2026-09-01")
    step_two = copy.deepcopy(step_one)
    step_two["report_date"] = "2026-09-08"
    step_two["searches"].append({"id": "s2", "date": "2026-09-05", "organisation": "Lender", "type": "hard", "purpose": ""})
    step_three = copy.deepcopy(step_two)
    step_three["report_date"] = "2026-09-15"
    step_three["public_records"] = [{"id": "p1", "type": "ccj", "date": "2026-09-10", "status": "active"}]

    assert only(compare_reports(step_one, step_two), "new_hard_search")["severity"] == "important"
    assert only(compare_reports(step_two, step_three), "public_record_added")["severity"] == "important"
    assert compare_reports(step_three, copy.deepcopy(step_three)) == []


# ------------------------------------------------------------------------ worked example


def test_the_brief_worked_example_step_by_step():
    """Walk the sequence from the project brief and pin every severity it names."""
    snapshot = validate_report(baseline_report())
    assert compare_reports(None, snapshot) == []
    assert compare_reports(snapshot, copy.deepcopy(snapshot)) == []

    def add_soft(r):
        r["searches"].append({"id": "s2", "date": "2026-09-02", "organisation": "Insurer B", "type": "soft", "purpose": "quote"})

    def add_hard(r):
        r["searches"].append({"id": "s3", "date": "2026-09-03", "organisation": "Lender", "type": "hard", "purpose": "credit card"})

    def add_account(r):
        r["accounts"].append({"id": "a2", "provider": "Store", "type": "credit card", "opened": "2026-09-01", "status": "open", "balance": 0})

    step_two = later(add_soft, report_date="2026-09-04")
    events = compare_reports(snapshot, step_two)
    assert severities(events) == {"routine"} and kinds(events) == ["new_soft_search"]

    step_three = later(add_soft, report_date="2026-09-05")
    add_hard(step_three)
    assert kinds(compare_reports(step_two, step_three)) == ["new_hard_search"]
    assert severities(compare_reports(step_two, step_three)) == {"important"}

    step_four = later(add_soft, report_date="2026-09-06")
    add_hard(step_four)
    add_account(step_four)
    assert kinds(compare_reports(step_three, step_four)) == ["new_account"]
    assert severities(compare_reports(step_three, step_four)) == {"important"}

    step_five = later(add_soft, report_date="2026-09-07")
    add_hard(step_five)
    add_account(step_five)
    step_five["accounts"][0]["status"] = "default"
    assert kinds(compare_reports(step_four, step_five)) == ["account_defaulted"]
    assert severities(compare_reports(step_four, step_five)) == {"important"}

    step_six = later(add_soft, report_date="2026-09-08")
    add_hard(step_six)
    add_account(step_six)
    step_six["accounts"][0]["status"] = "default"
    step_six["addresses"][0]["address"] = "2 Different Close"
    assert kinds(compare_reports(step_five, step_six)) == ["address_changed"]
    assert severities(compare_reports(step_five, step_six)) == {"important"}

    step_seven = later(add_soft, report_date="2026-09-09")
    add_hard(step_seven)
    add_account(step_seven)
    step_seven["accounts"][0]["status"] = "default"
    step_seven["addresses"][0]["address"] = "2 Different Close"
    step_seven["public_records"].append({"id": "p1", "type": "ccj", "date": "2026-09-08", "status": "active"})
    assert kinds(compare_reports(step_six, step_seven)) == ["public_record_added"]
    assert severities(compare_reports(step_six, step_seven)) == {"important"}

    # Nothing about that history is reversible: the same content replayed stays silent, and the
    # whole file now carries an active CCJ plus a default.
    assert compare_reports(step_seven, copy.deepcopy(step_seven)) == []
    assert only(compare_reports(step_two, step_seven), "public_record_added")["severity"] == "important"


@pytest.mark.parametrize("agency", list(AGENCIES))
def test_a_full_report_round_trips_through_validation_unchanged(agency):
    report = full_report(agency=agency)
    once = validate_report(report)
    assert validate_report(once) == once
    assert json.loads(json.dumps(once)) == once  # storable as the canonical JSON the UI expects


def test_finite_number_check_rejects_infinity_without_math_hacks():
    report = baseline_report()
    report["accounts"][0]["balance"] = math.inf
    with pytest.raises(CreditValidationError):
        validate_report(report)
