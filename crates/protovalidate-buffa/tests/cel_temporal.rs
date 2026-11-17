#![warn(rust_2018_idioms)]

use protovalidate_buffa::cel::{
    Duration, duration_from_secs_nanos, now_local, parse_duration, parse_timestamp,
    timestamp_from_secs_nanos,
};

#[test]
fn timestamp_conversion_preserves_precision_and_epoch_rounding() {
    for (seconds, nanos, text) in [
        (-1, 999_999_999, "1969-12-31T23:59:59.999999999Z"),
        (0, 1, "1970-01-01T00:00:00.000000001Z"),
        (-62_135_596_800, 0, "0001-01-01T00:00:00Z"),
        (
            253_402_300_799,
            999_999_999,
            "9999-12-31T23:59:59.999999999Z",
        ),
    ] {
        let actual = timestamp_from_secs_nanos(seconds, nanos);
        assert_eq!(actual.timestamp(), seconds);
        assert_eq!(Some(actual), parse_timestamp(text), "{text}");
    }
}

#[test]
fn malformed_timestamp_fields_retain_the_epoch_fallback() {
    let epoch = timestamp_from_secs_nanos(0, 0);
    for (seconds, nanos) in [
        (i64::MIN, 0),
        (i64::MAX, 0),
        (0, 1_000_000_000),
        (0, i32::MAX),
    ] {
        assert_eq!(timestamp_from_secs_nanos(seconds, nanos), epoch);
    }
    assert_eq!(
        timestamp_from_secs_nanos(1, -1),
        timestamp_from_secs_nanos(1, 0)
    );
}

#[test]
fn timestamp_parsing_requires_rfc3339_and_compares_instants() {
    let epoch = timestamp_from_secs_nanos(0, 0);
    for text in [
        "1970-01-01T00:00:00Z",
        "1970-01-01t00:00:00z",
        "1970-01-01 00:00:00Z",
        "1970-01-01T01:00:00+01:00",
    ] {
        assert_eq!(parse_timestamp(text), Some(epoch), "{text}");
    }
    for text in [
        "",
        "1970-01-01",
        "1970-01-01X00:00:00Z",
        "1970-01-01T00:00:00",
        "1970-01-01T00:00:00Z trailing",
        "2023-02-29T00:00:00Z",
    ] {
        assert!(parse_timestamp(text).is_none(), "{text}");
    }
}

#[test]
fn duration_conversion_preserves_sign_and_saturation() {
    for (seconds, nanos, total) in [
        (0, -1, -1),
        (-1, -1, -1_000_000_001),
        (-1, 1, -999_999_999),
        (1, -1, 999_999_999),
    ] {
        assert_eq!(
            duration_from_secs_nanos(seconds, nanos).num_nanoseconds(),
            Some(total)
        );
    }
    for (seconds, nanos, millis) in [
        (i64::MAX, i32::MAX, i64::MAX),
        (i64::MIN, i32::MIN, -i64::MAX),
        (9_223_372_036_854_776, -1_000_000_000, i64::MAX),
        (-9_223_372_036_854_776, 1_000_000_000, -i64::MAX),
        (9_223_372_036_854_775, 808_000_000, i64::MAX),
    ] {
        assert_eq!(
            duration_from_secs_nanos(seconds, nanos).num_milliseconds(),
            millis
        );
    }
}

#[test]
fn duration_parser_preserves_its_existing_grammar() {
    for (text, nanos) in [
        ("-1.5s", -1_500_000_000),
        ("+1ms", 1_000_000),
        (" 2µs ", 2_000),
        ("1h", 3_600_000_000_000),
    ] {
        assert_eq!(
            parse_duration(text).and_then(Duration::num_nanoseconds),
            Some(nanos),
            "{text}"
        );
    }
    for text in ["", "0", "1h30m", "1d", "NaNs", "infs"] {
        assert!(parse_duration(text).is_none(), "{text}");
    }
}

#[test]
fn now_uses_the_current_utc_instant() {
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now = now_local().timestamp();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((before..=after).contains(&u64::try_from(now).unwrap()));
}

#[test]
fn leap_seconds_are_rejected_instead_of_clamped() {
    for text in ["2016-12-31T23:59:60Z", "2017-01-01T00:59:60.5+01:00"] {
        assert!(parse_timestamp(text).is_none(), "{text}");
    }
    assert_eq!(
        timestamp_from_secs_nanos(59, 1_000_000_000),
        timestamp_from_secs_nanos(0, 0)
    );
}

#[test]
fn checked_arithmetic_preserves_fractional_signs_and_limits() {
    let instant = timestamp_from_secs_nanos(-1, 999_999_999);
    let nano = duration_from_secs_nanos(0, 1);
    let epoch = timestamp_from_secs_nanos(0, 0);
    assert_eq!(instant.checked_add_signed(nano), Some(epoch));
    assert_eq!(epoch.checked_sub_signed(nano), Some(instant));
    assert_eq!(
        instant.signed_duration_since(epoch).num_nanoseconds(),
        Some(-1)
    );
    let max = duration_from_secs_nanos(i64::MAX, 0);
    let min = duration_from_secs_nanos(i64::MIN, 0);
    assert!(max.checked_add(nano).is_none());
    assert!(min.checked_sub(nano).is_none());
    assert_eq!(max.checked_add(min).unwrap().num_nanoseconds(), Some(0));
}

#[test]
fn timestamp_construction_retains_the_previous_calendar_limits() {
    // https://docs.rs/chrono/0.4.45/chrono/struct.DateTime.html#associatedconstant.MIN_UTC
    let min = timestamp_from_secs_nanos(-8_334_601_228_800, 0);
    let max = timestamp_from_secs_nanos(8_210_266_876_799, 999_999_999);
    assert_eq!(min.year(), -262_143);
    assert_eq!(max.year(), 262_142);
    let nano = duration_from_secs_nanos(0, 1);
    assert!(min.checked_sub_signed(nano).is_none());
    assert!(max.checked_add_signed(nano).is_none());
    let epoch = timestamp_from_secs_nanos(0, 0);
    assert_eq!(timestamp_from_secs_nanos(-8_334_601_228_801, 0), epoch);
    assert_eq!(timestamp_from_secs_nanos(8_210_266_876_800, 0), epoch);
}
