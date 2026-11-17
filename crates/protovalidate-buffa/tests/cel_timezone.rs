#![warn(rust_2018_idioms)]
#![cfg(feature = "tz")]

use protovalidate_buffa::cel::{in_time_zone, parse_timestamp, timestamp_from_secs_nanos};

#[test]
fn timezone_accessors_preserve_offsets_and_utc_instants() {
    let epoch = timestamp_from_secs_nanos(0, 0);
    for (zone, hour, minute) in [
        ("", 0, 0),
        ("UTC", 0, 0),
        ("America/New_York", 19, 0),
        ("US/Eastern", 19, 0),
        ("+05:30", 5, 30),
        ("-00:30", 23, 30),
        ("-23:59", 0, 1),
    ] {
        let actual = in_time_zone(epoch, zone).unwrap();
        assert_eq!(actual, epoch, "{zone}");
        assert_eq!((actual.hour(), actual.minute()), (hour, minute), "{zone}");
    }
    for zone in [
        "Mars/Olympus",
        "america/new_york",
        "+24:00",
        "+01:60",
        "-01:-30",
    ] {
        assert!(in_time_zone(epoch, zone).is_none(), "{zone}");
    }
}

#[test]
fn timezone_lookup_observes_dst_transitions() {
    for (text, hour, minute) in [
        ("2024-03-10T06:59:59Z", 1, 59),
        ("2024-03-10T07:00:00Z", 3, 0),
        ("2024-11-03T05:59:59Z", 1, 59),
        ("2024-11-03T06:00:00Z", 1, 0),
    ] {
        let instant = parse_timestamp(text).unwrap();
        let zoned = in_time_zone(instant, "America/New_York").unwrap();
        assert_eq!((zoned.hour(), zoned.minute()), (hour, minute), "{text}");
        assert_eq!(zoned, instant);
    }
}

#[test]
fn timezone_conversion_can_cross_the_protobuf_calendar_bounds() {
    let last = parse_timestamp("9999-12-31T23:59:59.999999999Z").unwrap();
    let shifted = in_time_zone(last, "+01:00").unwrap();
    assert_eq!(shifted.year(), 10_000);
    assert_eq!(shifted, last);
    let first = parse_timestamp("0001-01-01T00:00:00Z").unwrap();
    assert_eq!(in_time_zone(first, "-01:00").unwrap().year(), 0);
}

#[test]
fn historical_offsets_retain_seconds() {
    let instant = parse_timestamp("1900-01-01T00:00:00Z").unwrap();
    let paris = in_time_zone(instant, "Europe/Paris").unwrap();
    assert_eq!((paris.hour(), paris.minute(), paris.second()), (0, 9, 21));
    assert_eq!(paris, instant);
}
