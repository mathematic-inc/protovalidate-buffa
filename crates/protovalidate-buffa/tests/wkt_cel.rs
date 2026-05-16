//! `AsCelValue` impls for supported `google.protobuf.*` well-known types.
//! Each test compiles and runs a real CEL expression against the WKT,
//! exercising the same `CelConstraint::eval` path used by plugin-emitted CEL
//! rules.

use buffa_types::google::protobuf::{Any, Duration, Empty, FieldMask, Timestamp};
use protovalidate_buffa::cel::CelConstraint;

#[test]
fn any_exposes_type_url() {
    static RULE: CelConstraint = CelConstraint::new(
        "test.any.type_url",
        "Any type URL must match",
        "this.type_url == 'type.googleapis.com/example.Widget'",
    );

    let any = Any {
        type_url: "type.googleapis.com/example.Widget".to_string(),
        ..Any::default()
    };

    RULE.eval(&any).expect("matching type_url should pass");
}

#[test]
fn empty_is_empty_map() {
    static RULE: CelConstraint =
        CelConstraint::new("test.empty.map", "Empty has no fields", "size(this) == 0");

    RULE.eval(&Empty::default())
        .expect("Empty should expose an empty CEL map");
}

#[test]
fn field_mask_paths_all_true() {
    static RULE: CelConstraint = CelConstraint::new(
        "test.field_mask.paths_all",
        "every path must be 'display_name' or 'icon'",
        "this.paths.all(p, p == 'display_name' || p == 'icon')",
    );

    let mask = FieldMask {
        paths: vec!["display_name".to_string(), "icon".to_string()],
        ..FieldMask::default()
    };

    RULE.eval(&mask).expect("rule should pass");
}

#[test]
fn field_mask_paths_all_false() {
    static RULE: CelConstraint = CelConstraint::new(
        "test.field_mask.paths_all",
        "path not allowed",
        "this.paths.all(p, p == 'display_name')",
    );

    let mask = FieldMask {
        paths: vec!["display_name".to_string(), "icon".to_string()],
        ..FieldMask::default()
    };

    let err = RULE.eval(&mask).expect_err("rule should reject 'icon'");
    assert_eq!(err.rule_id, "test.field_mask.paths_all");
}

#[test]
fn field_mask_size_zero_empty() {
    static RULE: CelConstraint = CelConstraint::new(
        "test.field_mask.non_empty",
        "field mask must not be empty",
        "size(this.paths) > 0",
    );

    let empty = FieldMask::default();
    RULE.eval(&empty).expect_err("empty mask should fail");

    let nonempty = FieldMask {
        paths: vec!["x".to_string()],
        ..FieldMask::default()
    };
    RULE.eval(&nonempty).expect("non-empty mask should pass");
}

#[test]
fn duration_compare_positive() {
    static RULE: CelConstraint = CelConstraint::new(
        "test.duration.positive",
        "must be greater than zero",
        "this > duration('0s')",
    );

    let positive = Duration {
        seconds: 5,
        nanos: 0,
        ..Duration::default()
    };
    RULE.eval(&positive).expect("positive duration passes");

    let zero = Duration::default();
    RULE.eval(&zero).expect_err("zero duration fails");
}

#[test]
fn duration_nanos_resolution() {
    static RULE: CelConstraint = CelConstraint::new(
        "test.duration.sub_second",
        "must be at least 1ms",
        "this >= duration('0.001s')",
    );

    let one_ms = Duration {
        seconds: 0,
        nanos: 1_000_000,
        ..Duration::default()
    };
    RULE.eval(&one_ms).expect("1ms passes");

    let half_ms = Duration {
        seconds: 0,
        nanos: 500_000,
        ..Duration::default()
    };
    RULE.eval(&half_ms).expect_err("0.5ms fails");
}

#[test]
fn timestamp_compare_before_max() {
    static RULE: CelConstraint = CelConstraint::new(
        "test.timestamp.before_max",
        "must be before 9999-12-31",
        "this < timestamp('9999-12-31T23:59:59Z')",
    );

    let ts = Timestamp {
        seconds: 1_700_000_000,
        nanos: 0,
        ..Timestamp::default()
    };
    RULE.eval(&ts).expect("normal timestamp passes");
}

#[test]
fn timestamp_in_past() {
    static RULE: CelConstraint = CelConstraint::new(
        "test.timestamp.in_past",
        "must be in the past",
        "this < now",
    );

    let past = Timestamp {
        seconds: 1_000_000_000,
        nanos: 0,
        ..Timestamp::default()
    };
    RULE.eval(&past).expect("past timestamp passes");

    let future = Timestamp {
        seconds: 99_999_999_999,
        nanos: 0,
        ..Timestamp::default()
    };
    RULE.eval(&future).expect_err("future timestamp fails");
}
