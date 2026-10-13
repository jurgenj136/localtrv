"""Valve decoding, scaling, limits, setpoint encoding and identification (no I/O)."""

from __future__ import annotations

import math

import pytest

from vicare_local_ble.valves import (
    A_BATTERY,
    A_HEATING_DEMAND,
    A_LOCAL_TEMPERATURE,
    A_LQI,
    A_MODEL_ID,
    A_RSSI,
    A_SETPOINT,
    A_SYSTEM_MODE,
    A_WINDOW_OPEN,
    ATTR_ABS_MAX_HEAT,
    ATTR_ABS_MIN_HEAT,
    ATTR_BATTERY_PERCENTAGE,
    ATTR_LAST_MESSAGE_LQI,
    ATTR_LAST_MESSAGE_RSSI,
    ATTR_LOCAL_TEMPERATURE,
    ATTR_MANUFACTURER_NAME,
    ATTR_MAX_HEAT,
    ATTR_MIN_HEAT,
    ATTR_MODEL_ID,
    ATTR_OCCUPIED_HEATING_SETPOINT,
    ATTR_PI_HEATING_DEMAND,
    ATTR_POWER_SOURCE,
    ATTR_SW_BUILD_ID,
    ATTR_SYSTEM_MODE,
    ATTR_WINDOW_OPEN,
    ATTRS,
    CLUSTER_BASIC,
    CLUSTER_DIAGNOSTICS,
    CLUSTER_POWER,
    CLUSTER_THERMOSTAT,
    CONFIRM_SETPOINT,
    DEFAULT_LIMITS,
    FAST,
    HEATING_DEMAND_MAX,
    IDENTIFY,
    LIMITS_BAND_C,
    MFR_VIESSMANN,
    OUI_HINT,
    SETPOINT_STEP_C,
    SLOW,
    STATIC,
    AttrIssue,
    BasicInfo,
    ReadPlan,
    SetpointLimits,
    ValveState,
    apply_reads,
    clamp_setpoint,
    decode_attr,
    has_oui_hint,
    heating_active,
    is_supported_valve,
    parse_basic,
    read_issues,
    setpoint_record,
    spec_for,
    window_open,
)
from vicare_local_ble.valves import models as valve_models
from vicare_local_ble.zigbee_direct.codec.zcl import AttributeRecord, ReadAttributeStatus
from vicare_local_ble.zigbee_direct.codec.zcl_types import ZclDataType
from vicare_local_ble.zigbee_direct.types import Eui64

I16, U8, I8, E8, STR = (
    ZclDataType.INT16,
    ZclDataType.UINT8,
    ZclDataType.INT8,
    ZclDataType.ENUM8,
    ZclDataType.CHARSTR,
)


def ok(attr: int, dtype: ZclDataType, value: object) -> ReadAttributeStatus:
    return ReadAttributeStatus(attr, 0x00, dtype, value)  # type: ignore[arg-type]


# --- scaling ---------------------------------------------------------------------------


def test_temperature_scaling_from_wire_bytes() -> None:
    raw = int.from_bytes(bytes.fromhex("AD07"), "little", signed=True)
    assert raw == 1965
    assert decode_attr(A_LOCAL_TEMPERATURE, I16, raw) == 19.65


def test_battery_scaling() -> None:
    assert decode_attr(A_BATTERY, U8, 126) == 63.0
    assert decode_attr(A_BATTERY, U8, 0) == 0.0
    assert decode_attr(A_BATTERY, U8, 200) == 100.0


@pytest.mark.parametrize(
    ("spec", "dtype", "raw", "expected"),
    [
        (A_SETPOINT, I16, 2150, 21.5),
        (A_HEATING_DEMAND, U8, 3, 3),
        (A_LQI, U8, 200, 200),
        (A_RSSI, I8, -60, -60),
        (A_SYSTEM_MODE, E8, 4, 4),
        (A_WINDOW_OPEN, E8, 3, 3),
    ],
)
def test_plain_scaling(spec, dtype, raw, expected) -> None:  # type: ignore[no-untyped-def]
    assert decode_attr(spec, dtype, raw) == expected


def test_string_attribute_is_stripped() -> None:
    assert decode_attr(A_MODEL_ID, STR, " 7637434 ") == "7637434"
    assert decode_attr(A_MODEL_ID, STR, "   ") is None
    assert decode_attr(A_MODEL_ID, STR, 5) is None


# --- sentinels ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "dtype", "raw"),
    [
        (A_LOCAL_TEMPERATURE, I16, -0x8000),
        (A_SETPOINT, I16, -0x8000),
        (A_BATTERY, U8, 0xFF),
        (A_HEATING_DEMAND, U8, 0xFF),
        (A_LQI, U8, 0xFF),
        (A_RSSI, I8, -0x80),
        (A_SYSTEM_MODE, E8, 0xFF),
        (A_WINDOW_OPEN, E8, 0xFF),
    ],
)
def test_sentinels_become_unknown(spec, dtype, raw) -> None:  # type: ignore[no-untyped-def]
    assert decode_attr(spec, dtype, raw) is None
    assert read_issues(
        spec.cluster, [ok(spec.attr, dtype, raw)], manufacturer=spec.manufacturer
    ) == (AttrIssue(spec.cluster, spec.attr, "sentinel"),)
    state = ValveState(local_temperature_c=1.0, setpoint_c=2.0, battery_pct=3.0, lqi=4, rssi=-5)
    new = apply_reads(
        state, spec.cluster, [ok(spec.attr, dtype, raw)], manufacturer=spec.manufacturer
    )
    assert getattr(new, spec.field) is None


# --- type mismatches -----------------------------------------------------------------------


@pytest.mark.parametrize("spec", [s for s in ATTRS if s.field is not None])
def test_wrong_zcl_type_is_unknown_with_type_issue(spec) -> None:  # type: ignore[no-untyped-def]
    wrong = ZclDataType.UINT16 if spec.zcl_type != ZclDataType.UINT16 else ZclDataType.UINT32
    rec = AttributeRecord(spec.attr, wrong, 100)
    assert decode_attr(spec, wrong, 100) is None
    assert read_issues(spec.cluster, [rec], manufacturer=spec.manufacturer) == (
        AttrIssue(spec.cluster, spec.attr, "type"),
    )


def test_missing_or_non_int_values_are_type_issues() -> None:
    assert decode_attr(A_LOCAL_TEMPERATURE, None, None) is None
    assert decode_attr(A_LOCAL_TEMPERATURE, I16, "19") is None
    assert decode_attr(A_LOCAL_TEMPERATURE, I16, True) is None
    assert decode_attr(A_LOCAL_TEMPERATURE, I16, 19.5) is None


# --- ranges ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(-5000, -50.0), (10000, 100.0), (-5001, None), (10001, None), (0, 0.0)],
)
def test_temperature_range(raw: int, expected: float | None) -> None:
    assert decode_attr(A_LOCAL_TEMPERATURE, I16, raw) == expected
    issues = read_issues(
        CLUSTER_THERMOSTAT, [ok(ATTR_LOCAL_TEMPERATURE, I16, raw)], manufacturer=None
    )
    assert issues == (() if expected is not None else (AttrIssue(0x0201, 0, "range"),))


def test_battery_range() -> None:
    assert decode_attr(A_BATTERY, U8, 201) is None
    assert decode_attr(A_BATTERY, U8, 254) is None
    assert read_issues(
        CLUSTER_POWER, [ok(ATTR_BATTERY_PERCENTAGE, U8, 201)], manufacturer=None
    ) == (AttrIssue(CLUSTER_POWER, ATTR_BATTERY_PERCENTAGE, "range"),)


def test_heating_demand_above_seven_is_kept_with_issue() -> None:
    assert HEATING_DEMAND_MAX == 7
    assert decode_attr(A_HEATING_DEMAND, U8, 7) == 7
    assert decode_attr(A_HEATING_DEMAND, U8, 80) == 80
    for raw in (8, 80):
        rec = ok(ATTR_PI_HEATING_DEMAND, U8, raw)
        assert read_issues(CLUSTER_THERMOSTAT, [rec], manufacturer=None) == (
            AttrIssue(CLUSTER_THERMOSTAT, ATTR_PI_HEATING_DEMAND, "demand_scale"),
        )
        new = apply_reads(ValveState(), CLUSTER_THERMOSTAT, [rec], manufacturer=None)
        assert new.heating_demand == raw
    for raw in (0, 5, 6, 7):
        rec = ok(ATTR_PI_HEATING_DEMAND, U8, raw)
        assert read_issues(CLUSTER_THERMOSTAT, [rec], manufacturer=None) == ()


@pytest.mark.parametrize(
    ("demand", "expected"),
    [(None, None), (0, False), (1, True), (7, True), (8, None), (80, None), (-1, None)],
)
def test_heating_active(demand: int | None, expected: bool | None) -> None:
    assert heating_active(demand) is expected


# --- apply_reads ---------------------------------------------------------------------------


def test_apply_reads_is_pure_and_sets_updated_at() -> None:
    state = ValveState(setpoint_c=20.0)
    before = state
    statuses = [
        ok(ATTR_LOCAL_TEMPERATURE, I16, 1965),
        ok(ATTR_PI_HEATING_DEMAND, U8, 2),
        ok(ATTR_OCCUPIED_HEATING_SETPOINT, I16, 2100),
        ok(ATTR_SYSTEM_MODE, E8, 4),
    ]
    new = apply_reads(state, CLUSTER_THERMOSTAT, statuses, manufacturer=None, at=12.5)
    assert state is before
    assert state == ValveState(setpoint_c=20.0)
    assert new == ValveState(
        local_temperature_c=19.65,
        setpoint_c=21.0,
        heating_demand=2,
        system_mode=4,
        updated_at=12.5,
    )


def test_apply_reads_accepts_report_records() -> None:
    rec = AttributeRecord(ATTR_LOCAL_TEMPERATURE, I16, 2000)
    new = apply_reads(ValveState(), CLUSTER_THERMOSTAT, [rec], manufacturer=None, at=1.0)
    assert new.local_temperature_c == 20.0


def test_non_success_status_leaves_field_unchanged() -> None:
    state = ValveState(local_temperature_c=18.0, updated_at=1.0)
    bad = ReadAttributeStatus(ATTR_LOCAL_TEMPERATURE, 0x86)
    assert apply_reads(state, CLUSTER_THERMOSTAT, [bad], manufacturer=None, at=9.0) is state
    assert read_issues(CLUSTER_THERMOSTAT, [bad], manufacturer=None) == ()


def test_unchanged_values_keep_updated_at() -> None:
    state = ValveState(local_temperature_c=19.65, updated_at=1.0)
    same = ok(ATTR_LOCAL_TEMPERATURE, I16, 1965)
    assert apply_reads(state, CLUSTER_THERMOSTAT, [same], manufacturer=None, at=2.0) is state


def test_change_without_at_keeps_updated_at() -> None:
    state = ValveState(updated_at=1.0)
    new = apply_reads(state, CLUSTER_THERMOSTAT, [ok(ATTR_SYSTEM_MODE, E8, 4)], manufacturer=None)
    assert new.system_mode == 4
    assert new.updated_at == 1.0


def test_invalid_value_sets_known_field_to_none() -> None:
    state = ValveState(battery_pct=50.0)
    new = apply_reads(
        state, CLUSTER_POWER, [ok(ATTR_BATTERY_PERCENTAGE, U8, 0xFF)], manufacturer=None, at=3.0
    )
    assert new.battery_pct is None
    assert new.updated_at == 3.0


def test_unknown_attributes_and_wrong_cluster_are_ignored() -> None:
    state = ValveState(lqi=7)
    unknown = ok(0x7777, U8, 1)
    limit = ok(ATTR_ABS_MAX_HEAT, I16, 3000)  # spec exists but feeds no state field
    assert apply_reads(state, CLUSTER_THERMOSTAT, [unknown, limit], manufacturer=None) is state
    # LQI attribute id in the wrong cluster
    wrong = ok(ATTR_LAST_MESSAGE_LQI, U8, 1)
    assert apply_reads(state, CLUSTER_THERMOSTAT, [wrong], manufacturer=None) is state


def test_duplicate_attribute_last_value_wins() -> None:
    state = ValveState(lqi=7)
    recs = [ok(ATTR_LAST_MESSAGE_LQI, U8, 1), ok(ATTR_LAST_MESSAGE_LQI, U8, 7)]
    assert apply_reads(state, CLUSTER_DIAGNOSTICS, recs, manufacturer=None, at=1.0) is state


def test_diagnostics_and_manufacturer_window() -> None:
    state = apply_reads(
        ValveState(),
        CLUSTER_DIAGNOSTICS,
        [ok(ATTR_LAST_MESSAGE_LQI, U8, 180), ok(ATTR_LAST_MESSAGE_RSSI, I8, -61)],
        manufacturer=None,
    )
    assert (state.lqi, state.rssi) == (180, -61)
    rec = ok(ATTR_WINDOW_OPEN, E8, 3)
    state = apply_reads(state, CLUSTER_THERMOSTAT, [rec], manufacturer=MFR_VIESSMANN)
    assert state.window_open_raw == 3
    # without the manufacturer flag 0x4000 on 0201 is not a v1 attribute
    assert apply_reads(ValveState(), CLUSTER_THERMOSTAT, [rec], manufacturer=None) == ValveState()


# --- spec_for ---------------------------------------------------------------------------


def test_spec_for_lookup() -> None:
    assert spec_for(0x0201, 0x0000, manufacturer=None) is A_LOCAL_TEMPERATURE
    assert spec_for(0x0201, 0x4000, manufacturer=MFR_VIESSMANN) is A_WINDOW_OPEN
    assert spec_for(0x0201, 0x4000, manufacturer=None) is None
    assert spec_for(0x0201, 0x4012, manufacturer=MFR_VIESSMANN) is None
    assert spec_for(0x0020, 0x0000, manufacturer=None) is None
    for spec in ATTRS:
        assert spec_for(spec.cluster, spec.attr, manufacturer=spec.manufacturer) is spec


# --- limits ------------------------------------------------------------------------------


def test_limits_band_mirror_matches_constants() -> None:
    assert valve_models._LIMITS_BAND_C == LIMITS_BAND_C


def test_valid_limits_inside_abs() -> None:
    lim = SetpointLimits.from_attrs(min_c=10, max_c=28, abs_min_c=8, abs_max_c=30)
    assert lim == SetpointLimits(10, 28, "limits")


def test_valid_limits_without_abs() -> None:
    assert SetpointLimits.from_attrs(min_c=5, max_c=35) == SetpointLimits(5, 35, "limits")


@pytest.mark.parametrize(
    ("lo", "hi"),
    [(20, 10), (10, 10), (4.99, 20), (10, 35.01), (None, 20), (10, None), (math.nan, 20)],
)
def test_invalid_limits_fall_back_to_abs_then_default(lo, hi) -> None:  # type: ignore[no-untyped-def]
    abs_ok = SetpointLimits.from_attrs(min_c=lo, max_c=hi, abs_min_c=8, abs_max_c=30)
    assert abs_ok == SetpointLimits(8, 30, "abs")
    assert SetpointLimits.from_attrs(min_c=lo, max_c=hi) == DEFAULT_LIMITS
    assert DEFAULT_LIMITS.source == "default"
    assert (DEFAULT_LIMITS.min_c, DEFAULT_LIMITS.max_c) == (8.0, 30.0)


def test_limits_outside_valid_abs_fall_back_to_abs() -> None:
    lim = SetpointLimits.from_attrs(min_c=6, max_c=34, abs_min_c=8, abs_max_c=30)
    assert lim == SetpointLimits(8, 30, "abs")
    lim = SetpointLimits.from_attrs(min_c=10, max_c=32, abs_min_c=8, abs_max_c=30)
    assert lim.source == "abs"


@pytest.mark.parametrize(("a_lo", "a_hi"), [(30, 8), (3, 30), (8, 40), (None, 30), (8, None)])
def test_invalid_abs_is_ignored_when_limits_valid(a_lo, a_hi) -> None:  # type: ignore[no-untyped-def]
    lim = SetpointLimits.from_attrs(min_c=10, max_c=28, abs_min_c=a_lo, abs_max_c=a_hi)
    assert lim == SetpointLimits(10, 28, "limits")
    assert SetpointLimits.from_attrs(min_c=None, max_c=None, abs_min_c=a_lo, abs_max_c=a_hi) == (
        DEFAULT_LIMITS
    )


def test_everything_invalid_gives_default() -> None:
    assert SetpointLimits.from_attrs(min_c=None, max_c=None) == DEFAULT_LIMITS


def test_from_reads_scales_and_validates() -> None:
    reads = [
        ok(ATTR_ABS_MIN_HEAT, I16, 800),
        ok(ATTR_ABS_MAX_HEAT, I16, 3000),
        ok(ATTR_MIN_HEAT, I16, 1000),
        ok(ATTR_MAX_HEAT, I16, 2800),
    ]
    assert SetpointLimits.from_reads(reads) == SetpointLimits(10.0, 28.0, "limits")


def test_from_reads_sentinels_failures_and_type_errors() -> None:
    reads = [
        ok(ATTR_ABS_MIN_HEAT, I16, 800),
        ok(ATTR_ABS_MAX_HEAT, I16, 3000),
        ok(ATTR_MIN_HEAT, I16, -0x8000),
        ReadAttributeStatus(ATTR_MAX_HEAT, 0x86),
    ]
    assert SetpointLimits.from_reads(reads) == SetpointLimits(8.0, 30.0, "abs")
    wrong_type = [ok(ATTR_ABS_MIN_HEAT, U8, 8), ok(ATTR_ABS_MAX_HEAT, U8, 30)]
    assert SetpointLimits.from_reads(wrong_type) == DEFAULT_LIMITS
    assert SetpointLimits.from_reads([]) == DEFAULT_LIMITS


# --- setpoint ------------------------------------------------------------------------------

LIMITS = SetpointLimits(10.0, 28.0, "limits")


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_non_finite_setpoint_rejected(bad: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        clamp_setpoint(bad, LIMITS)
    with pytest.raises(ValueError, match="finite"):
        setpoint_record(bad, LIMITS)


@pytest.mark.parametrize(
    ("given", "expected"),
    [(5.0, 10.0), (35.0, 28.0), (21.0, 21.0), (21.004, 21.0), (21.006, 21.01), (-1e9, 10.0)],
)
def test_clamp_and_round(given: float, expected: float) -> None:
    assert clamp_setpoint(given, LIMITS) == expected


def test_setpoint_record_encoding() -> None:
    rec = setpoint_record(21.5, LIMITS)
    assert rec == AttributeRecord(ATTR_OCCUPIED_HEATING_SETPOINT, ZclDataType.INT16, 2150)
    assert rec.data_type == 0x29
    assert rec.encode() == bytes.fromhex("12002966") + b"\x08"
    assert setpoint_record(100.0, LIMITS).value == 2800
    assert setpoint_record(19.65, LIMITS).value == 1965
    assert isinstance(setpoint_record(21.5, LIMITS).value, int)


def test_setpoint_step() -> None:
    assert SETPOINT_STEP_C == 0.5


# --- window --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(3, True), (4, True), (1, False), (None, None), (0, None), (2, None), (5, None), (0xFF, None)],
)
def test_window_open(raw: int | None, expected: bool | None) -> None:
    assert window_open(raw) is expected


def test_window_open_rejects_bool() -> None:
    assert window_open(True) is None


# --- plans ---------------------------------------------------------------------------------


def test_plan_grouping_rules() -> None:
    for plan in (FAST, SLOW, STATIC):
        keys = [(r.cluster, r.manufacturer) for r in plan]
        assert len(keys) == len(set(keys))  # one request per cluster + manufacturer flag
        for req in plan:
            assert 1 <= len(req.attrs) <= 4
            for attr in req.attrs:
                assert spec_for(req.cluster, attr, manufacturer=req.manufacturer) is not None


def _sets(plan: ReadPlan) -> dict[tuple[int, int | None], set[int]]:
    return {(r.cluster, r.manufacturer): set(r.attrs) for r in plan}


def test_exact_plan_contents() -> None:
    assert _sets(FAST) == {(0x0201, None): {0x0000, 0x0008, 0x0012, 0x001C}}
    assert _sets(SLOW) == {
        (0x0001, None): {0x0021},
        (0x0B05, None): {0x011C, 0x011D},
        (0x0201, MFR_VIESSMANN): {0x4000},
    }
    assert _sets(STATIC) == {
        (0x0201, None): {0x0003, 0x0004, 0x0015, 0x0016},
        (0x0000, None): {0x0004, 0x0005, 0x0007, 0x4000},
    }
    assert IDENTIFY in STATIC
    assert (CONFIRM_SETPOINT.cluster, CONFIRM_SETPOINT.attrs) == (0x0201, (0x0012,))


def test_plans_never_touch_forbidden_attributes() -> None:
    for req in (*FAST, *SLOW, *STATIC, CONFIRM_SETPOINT):
        assert req.cluster not in (0x0020, 0x000A)
        assert 0x4012 not in req.attrs


# --- identification ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mfr", "model", "expected"),
    [
        ("Viessmann", "7637434", True),
        (" Viessmann ", " 7637434\n", True),
        ("Viessmann", "other", False),
        ("Acme", "7637434", False),
        ("viessmann", "7637434", False),
        (None, "7637434", False),
        ("Viessmann", None, False),
        (None, None, False),
    ],
)
def test_is_supported_valve(mfr: str | None, model: str | None, expected: bool) -> None:
    assert is_supported_valve(mfr, model) is expected


def test_oui_hint() -> None:
    assert has_oui_hint(Eui64.from_str("14:2D:41:00:00:00:00:01"))
    assert has_oui_hint(Eui64.from_str("142d410000000001"))
    assert has_oui_hint(Eui64.from_str("28:DB:A7:00:00:00:00:01"))
    assert has_oui_hint(Eui64.from_str("28dba70000000001"))
    assert OUI_HINT == ("14:2D:41", "28:DB:A7")
    assert not has_oui_hint(Eui64.from_str("AA:BB:CC:00:00:00:00:01"))
    # OUI is the first display octets, not the first wire bytes
    assert not has_oui_hint(Eui64.from_str("01:00:00:00:00:41:2D:14"))


def test_parse_basic() -> None:
    reads = [
        ok(ATTR_MANUFACTURER_NAME, STR, "Viessmann"),
        ok(ATTR_MODEL_ID, STR, "7637434"),
        ok(ATTR_POWER_SOURCE, E8, 3),
        ok(ATTR_SW_BUILD_ID, STR, "1.2.3"),
    ]
    assert parse_basic(reads) == BasicInfo("Viessmann", "7637434", 3, "1.2.3")


def test_parse_basic_missing_failed_or_invalid() -> None:
    reads = [
        ReadAttributeStatus(ATTR_MANUFACTURER_NAME, 0x86),
        ok(ATTR_MODEL_ID, U8, 1),
        ok(ATTR_POWER_SOURCE, E8, 0xFF),
        ok(0x7777, STR, "x"),
    ]
    assert parse_basic(reads) == BasicInfo(None, None, None, None)
    assert parse_basic([]) == BasicInfo(None, None, None, None)
    assert read_issues(CLUSTER_BASIC, reads, manufacturer=None) == (
        AttrIssue(CLUSTER_BASIC, ATTR_MODEL_ID, "type"),
        AttrIssue(CLUSTER_BASIC, ATTR_POWER_SOURCE, "sentinel"),
    )
