#![warn(rust_2018_idioms)]

use buffa::{Message as _, MessageView as _};
use protovalidate_buffa::Validate as _;

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    elided_lifetimes_in_paths,
    non_camel_case_types,
    unused_imports,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_html_tags,
    reason = "buffa-build generated code"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/_include.rs"));
}

macro_rules! range_test {
    ($name:ident, $owned:ident, $view:ident, $wkt:ident, $rule:literal, $guarded:literal) => {
        // https://github.com/mathematic-inc/protovalidate-buffa/discussions/44
        #[test]
        fn $name() {
            use generated::buf::validate::conformance::cases::{__buffa::view::$view, $owned};

            for (start, end, valid) in [
                (None, None, $guarded),
                (Some((0, 0)), None, $guarded),
                (None, Some((0, 0)), $guarded),
                (None, Some((0, 1)), true),
                (Some((-1, 0)), None, true),
                (None, Some((-1, 0)), $guarded),
                (Some((0, 0)), Some((0, 0)), false),
                (Some((0, 0)), Some((0, 1)), true),
                (Some((0, 1)), Some((0, 0)), false),
                (Some((-1, 0)), Some((0, 0)), true),
                (Some((1, 0)), Some((0, 0)), false),
            ] {
                let field = |value: Option<(i64, i32)>| {
                    value
                        .map(|(seconds, nanos)| generated::google::protobuf::$wkt {
                            seconds,
                            nanos,
                            ..Default::default()
                        })
                        .into()
                };
                let owned = $owned {
                    start: field(start),
                    end: field(end),
                    ..Default::default()
                };
                let bytes = owned.encode_to_vec();
                let view = $view::decode_view(&bytes).expect("range must decode");
                for result in [owned.validate(), view.validate()] {
                    assert_eq!(result.is_ok(), valid, "{start:?} < {end:?}: {result:?}");
                    if let Err(error) = result {
                        assert!(error.compile_error.is_none(), "{error:?}");
                        assert!(error.runtime_error.is_none(), "{error:?}");
                        assert_eq!(error.violations.len(), 1);
                        assert_eq!(error.violations[0].rule_id, $rule);
                    }
                }
            }
        }
    };
}

range_test!(
    timestamp_ordering_preserves_presence,
    CelTimestampRange,
    CelTimestampRangeView,
    Timestamp,
    "timestamp_range.ordered",
    true
);
range_test!(
    duration_ordering_preserves_presence,
    CelDurationRange,
    CelDurationRangeView,
    Duration,
    "duration_range.ordered",
    true
);

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/44
#[test]
fn wkt_item_and_map_value_rules_use_cel_values() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::CelWktElementsView, CelWktElements,
    };
    use generated::google::protobuf::{Duration, Timestamp};

    for (seconds, nanos, valid) in [(0, 1, true), (1, 0, true), (0, 0, false), (-1, 0, false)] {
        let owned = CelWktElements {
            timestamps: vec![Timestamp {
                seconds,
                nanos,
                ..Default::default()
            }],
            durations: std::iter::once((
                "value".to_string(),
                Duration {
                    seconds,
                    nanos,
                    ..Default::default()
                },
            ))
            .collect(),
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let view = CelWktElementsView::decode_view(&bytes).expect("elements must decode");
        for result in [owned.validate(), view.validate()] {
            assert_eq!(result.is_ok(), valid, "{seconds}s {nanos}ns: {result:?}");
            if let Err(error) = result {
                assert!(error.compile_error.is_none(), "{error:?}");
                assert!(error.runtime_error.is_none(), "{error:?}");
                let ids: Vec<_> = error
                    .violations
                    .iter()
                    .map(|v| v.rule_id.as_ref())
                    .collect();
                assert_eq!(ids, ["timestamp.after_epoch", "duration.positive"]);
            }
        }
    }
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/44
#[test]
fn nested_field_rules_preserve_presence() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::CelNestedTimestampRangeView, CelNestedTimestampRange, CelTimestampEnvelope,
        CelTimestampFields,
    };
    use generated::google::protobuf::Timestamp;

    for (range, valid) in [
        (None, true),
        (Some(CelTimestampFields::default()), true),
        (
            Some(CelTimestampFields {
                start: Timestamp::default().into(),
                end: Timestamp {
                    nanos: 1,
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            }),
            true,
        ),
        (
            Some(CelTimestampFields {
                start: Timestamp::default().into(),
                end: Timestamp::default().into(),
                ..Default::default()
            }),
            false,
        ),
    ] {
        let owned = CelNestedTimestampRange {
            envelope: CelTimestampEnvelope {
                range: range.into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let view =
            CelNestedTimestampRangeView::decode_view(&bytes).expect("nested range must decode");
        for result in [owned.validate(), view.validate()] {
            assert_eq!(result.is_ok(), valid, "{result:?}");
            if let Err(error) = result {
                assert!(error.compile_error.is_none(), "{error:?}");
                assert!(error.runtime_error.is_none(), "{error:?}");
                assert_eq!(error.violations.len(), 1);
                assert_eq!(
                    error.violations[0].rule_id,
                    "nested_timestamp_range.ordered"
                );
            }
        }
    }
}

// Expected values verified against protovalidate-go at
// 573e8070aa030baf4d4f574293364b998a133a52 using these descriptors.
range_test!(
    unset_timestamps_read_as_epoch,
    CelTimestampDefaults,
    CelTimestampDefaultsView,
    Timestamp,
    "timestamp_defaults.ordered",
    false
);
range_test!(
    unset_durations_read_as_zero,
    CelDurationDefaults,
    CelDurationDefaultsView,
    Duration,
    "duration_defaults.ordered",
    false
);

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/44
// Upstream skips rules on an absent envelope; reads inside a present envelope
// use defaults for absent nested messages and temporal fields.
#[test]
fn nested_reads_use_defaults_but_absent_field_rules_are_skipped() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::CelNestedTimestampDefaultsView, CelNestedTimestampDefaults,
        CelTimestampEnvelope, CelTimestampFields,
    };
    use generated::google::protobuf::Timestamp;

    for (envelope, valid) in [
        (None, true),
        (Some(CelTimestampEnvelope::default()), false),
        (
            Some(CelTimestampEnvelope {
                range: CelTimestampFields {
                    end: Timestamp {
                        nanos: 1,
                        ..Default::default()
                    }
                    .into(),
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            }),
            true,
        ),
    ] {
        let owned = CelNestedTimestampDefaults {
            envelope: envelope.into(),
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let view = CelNestedTimestampDefaultsView::decode_view(&bytes)
            .expect("nested defaults must decode");
        for result in [owned.validate(), view.validate()] {
            assert_eq!(result.is_ok(), valid, "{result:?}");
            if let Err(error) = result {
                assert!(error.compile_error.is_none(), "{error:?}");
                assert!(error.runtime_error.is_none(), "{error:?}");
                assert_eq!(error.violations.len(), 1);
                assert_eq!(
                    error.violations[0].rule_id,
                    "nested_timestamp_defaults.ordered"
                );
            }
        }
    }
}

fn field_mask(paths: &[&str]) -> generated::google::protobuf::FieldMask {
    generated::google::protobuf::FieldMask {
        paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        ..Default::default()
    }
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/90
#[test]
fn field_mask_paths_validate_nested_update_requests() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::CelFieldMaskPathsView, CelFieldMaskPaths, cel_field_mask_paths::Item,
    };

    for (name, paths, expected) in [
        (None, None, None),
        (
            Some(""),
            Some(&[][..]),
            Some(("update_mask.not_empty", "the update writes no fields")),
        ),
        (
            None,
            Some(&["display_name"][..]),
            Some(("item.display_name.required", "display_name is required")),
        ),
        (
            Some(""),
            Some(&["display_name"][..]),
            Some(("item.display_name.required", "display_name is required")),
        ),
        (Some("set"), Some(&["display_name"][..]), None),
        (Some(""), Some(&["other"][..]), None),
    ] {
        let owned = CelFieldMaskPaths {
            item: name
                .map(|name| Item {
                    display_name: name.to_owned(),
                    ..Default::default()
                })
                .into(),
            update_mask: paths.map(field_mask).into(),
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let view = CelFieldMaskPathsView::decode_view(&bytes).expect("update request must decode");
        for result in [owned.validate(), view.validate()] {
            assert_eq!(
                result.is_ok(),
                expected.is_none(),
                "{name:?} {paths:?}: {result:?}"
            );
            if let (Err(error), Some((rule, message))) = (result, expected) {
                assert!(error.compile_error.is_none(), "{error:?}");
                assert!(error.runtime_error.is_none(), "{error:?}");
                assert_eq!(error.violations.len(), 1, "{error:?}");
                assert_eq!(error.violations[0].rule_id, rule);
                assert_eq!(error.violations[0].message, message);
            }
        }
    }
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/90
#[test]
fn field_mask_list_operations_preserve_presence_and_rule_paths() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::CelFieldMaskOperationsView, CelFieldMaskOperations,
    };
    use protovalidate_buffa::{FieldType, Subscript};

    for (paths, failed_rules) in [
        (None, &[0usize, 1, 2, 3][..]),
        (Some(&[][..]), &[0, 1, 2, 3][..]),
        (Some(&["other"][..]), &[2, 3][..]),
        (Some(&["display_name"][..]), &[][..]),
        (Some(&["other", "display_name"][..]), &[][..]),
    ] {
        let owned = CelFieldMaskOperations {
            update_mask: paths.map(field_mask).into(),
            mask_present: paths.is_some(),
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let view =
            CelFieldMaskOperationsView::decode_view(&bytes).expect("mask operations must decode");
        for result in [owned.validate(), view.validate()] {
            assert_eq!(
                result.is_ok(),
                failed_rules.is_empty(),
                "{paths:?}: {result:?}"
            );
            if let Err(error) = result {
                assert!(error.compile_error.is_none(), "{error:?}");
                assert!(error.runtime_error.is_none(), "{error:?}");
                // Field CEL now composes with the value's standard rules.
                let scopes = if paths.is_some() {
                    &["field", "message"][..]
                } else {
                    &["message"][..]
                };
                let expected: Vec<_> = scopes
                    .iter()
                    .flat_map(|scope| {
                        failed_rules.iter().map(move |index| {
                            format!(
                                "{scope}.{}",
                                ["size", "receiver_size", "in", "exists"][*index]
                            )
                        })
                    })
                    .collect();
                let actual: Vec<_> = error
                    .violations
                    .iter()
                    .map(|v| v.rule_id.as_ref())
                    .collect();
                assert_eq!(actual, expected, "{paths:?}");
                for (violation, index) in error
                    .violations
                    .iter()
                    .filter(|v| v.rule_id.starts_with("field."))
                    .zip(failed_rules)
                {
                    assert_eq!(violation.field.to_string(), "update_mask");
                    assert_eq!(violation.field.elements[0].field_number, Some(1));
                    assert_eq!(
                        violation.field.elements[0].field_type,
                        Some(FieldType::Message)
                    );
                    assert_eq!(violation.rule.to_string(), format!("cel[{index}]"));
                    assert_eq!(violation.rule.elements[0].field_number, Some(23));
                    assert!(
                        matches!(violation.rule.elements[0].subscript, Some(Subscript::Index(actual)) if actual == *index as u64)
                    );
                    assert_eq!(
                        violation.message,
                        if *index < 2 {
                            "paths must not be empty"
                        } else {
                            "paths must contain display_name"
                        }
                    );
                    assert!(!violation.for_key);
                }
            }
        }
    }
}

/// 0001-01-01T00:00:00Z and 9999-12-31T23:59:59Z, CEL's timestamp bounds.
const YEAR_1: i64 = -62_135_596_800;
const YEAR_9999: i64 = 253_402_300_799;
const HOUR: i64 = 3600;

fn timestamp(seconds: i64, nanos: i32) -> generated::google::protobuf::Timestamp {
    generated::google::protobuf::Timestamp {
        seconds,
        nanos,
        ..Default::default()
    }
}

fn duration(seconds: i64, nanos: i32) -> generated::google::protobuf::Duration {
    generated::google::protobuf::Duration {
        seconds,
        nanos,
        ..Default::default()
    }
}

/// What validating a message produced.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The IDs of the rules it failed, if any.
    Failed(Vec<String>),
    /// A runtime error, which replaces any violations.
    RuntimeError(String),
}

fn outcome(result: Result<(), protovalidate_buffa::ValidationError>) -> Outcome {
    let Err(error) = result else {
        return Outcome::Failed(Vec::new());
    };
    assert!(error.compile_error.is_none(), "{error:?}");
    if let Some(message) = error.runtime_error {
        assert!(error.violations.is_empty(), "{:?}", error.violations);
        return Outcome::RuntimeError(message);
    }
    Outcome::Failed(
        error
            .violations
            .into_iter()
            .map(|v| v.rule_id.into_owned())
            .collect(),
    )
}

/// Validates an owned message and its view, which must agree, and returns
/// their [`Outcome`].
macro_rules! validate_both {
    ($view:ident, $owned:expr) => {{
        let owned = $owned;
        let bytes = owned.encode_to_vec();
        let view = $view::decode_view(&bytes).expect("message must decode");
        let outcome = outcome(owned.validate());
        assert_eq!(outcome, self::outcome(view.validate()), "{owned:?}");
        outcome
    }};
}

fn failed(rules: &[&str]) -> Outcome {
    Outcome::Failed(rules.iter().map(|rule| (*rule).to_owned()).collect())
}

fn runtime_error(rule: &str, reason: &str) -> Outcome {
    Outcome::RuntimeError(format!("cel runtime error in rule {rule:?}: {reason}"))
}

#[test]
fn timestamp_differences_compare_with_duration_literals() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::CelTimestampSpanView, CelTimestampSpan,
    };

    for (from, to, expected) in [
        ((0, 0), (24 * HOUR, 0), failed(&[])),
        ((0, 0), (25 * HOUR, 0), failed(&[])),
        ((0, 0), (25 * HOUR, 1), failed(&["board.range"])),
        ((0, 0), (26 * HOUR, 0), failed(&["board.range"])),
        ((-HOUR, 500), (HOUR, 0), failed(&[])),
        ((0, 0), (0, 0), failed(&["board.range"])),
        ((HOUR, 0), (0, 0), failed(&["board.range"])),
    ] {
        let actual = validate_both!(
            CelTimestampSpanView,
            CelTimestampSpan {
                from: timestamp(from.0, from.1).into(),
                to: timestamp(to.0, to.1).into(),
                ..Default::default()
            }
        );
        assert_eq!(actual, expected, "{from:?} to {to:?}");
    }
}

#[test]
fn scheduled_spans_compare_with_duration_literals() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::CelScheduledSpanView, CelScheduledSpan,
    };

    for (start, end, expected) in [
        (0, 11 * HOUR, failed(&[])),
        (0, 12 * HOUR, failed(&[])),
        (0, 13 * HOUR, failed(&["assign.length"])),
        (HOUR, 0, failed(&["assign.length"])),
        (HOUR, HOUR, failed(&["assign.length"])),
    ] {
        let actual = validate_both!(
            CelScheduledSpanView,
            CelScheduledSpan {
                scheduled_start: timestamp(start, 0).into(),
                scheduled_end: timestamp(end, 0).into(),
                ..Default::default()
            }
        );
        assert_eq!(actual, expected, "{start} to {end}");
    }
}

#[test]
fn timestamp_and_duration_arithmetic_follows_cel() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::CelTemporalArithmeticView, CelTemporalArithmetic,
    };

    let all_spans = [
        "timestamp_plus_duration",
        "duration_plus_timestamp",
        "timestamp_minus_duration",
        "timestamp_minus_timestamp",
    ];
    for (start, end, length, rest, expected) in [
        (
            (1000, 0),
            (1000 + 2 * HOUR, 0),
            (2 * HOUR, 0),
            (HOUR, 0),
            failed(&[]),
        ),
        // Before the epoch, nanos still count up from the second.
        ((-10, 999_999_999), (-9, 0), (0, 1), (0, 0), failed(&[])),
        ((-10, 0), (-11, 0), (-1, 0), (-1, 0), failed(&[])),
        (
            (0, 0),
            (2 * HOUR, 1),
            (2 * HOUR, 0),
            (0, 0),
            failed(&all_spans),
        ),
        (
            (0, 0),
            (2 * HOUR, 0),
            (2 * HOUR, 0),
            (3 * HOUR, 0),
            failed(&["duration_minus_duration"]),
        ),
        (
            (0, 0),
            (2 * HOUR, 0),
            (2 * HOUR, 0),
            (6 * HOUR, 0),
            failed(&["duration_minus_duration", "duration_plus_duration"]),
        ),
    ] {
        let actual = validate_both!(
            CelTemporalArithmeticView,
            CelTemporalArithmetic {
                start: timestamp(start.0, start.1).into(),
                end: timestamp(end.0, end.1).into(),
                length: duration(length.0, length.1).into(),
                rest: duration(rest.0, rest.1).into(),
                ..Default::default()
            }
        );
        assert_eq!(actual, expected, "{start:?} {end:?} {length:?} {rest:?}");
    }
}

#[test]
fn timestamp_and_duration_overflow_is_a_runtime_error() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::CelTemporalOverflowView, CelTemporalOverflow,
    };

    // The longest duration CEL allows is i64::MAX nanoseconds.
    let half_max = (4_611_686_018, 427_387_903);
    let century = 100 * 365 * 24 * HOUR;
    for (start, end, shift, expected) in [
        ((0, 0), (0, 0), (0, 0), failed(&[])),
        (
            (YEAR_1, 0),
            (YEAR_9999, 0),
            (0, 0),
            runtime_error("span", "duration overflow"),
        ),
        (
            (YEAR_9999 - century, 0),
            (YEAR_9999, 999_999_999),
            (0, 0),
            failed(&[]),
        ),
        (
            (YEAR_9999 - century, 0),
            (YEAR_9999, 999_999_999),
            (0, 1),
            runtime_error("shifted", "timestamp overflow"),
        ),
        (
            (YEAR_1, 0),
            (YEAR_1, 0),
            (0, -1),
            runtime_error("shifted", "timestamp overflow"),
        ),
        ((0, 0), (0, 0), half_max, failed(&[])),
        (
            (0, 0),
            (0, 0),
            (half_max.0, half_max.1 + 1),
            runtime_error("doubled", "duration overflow"),
        ),
    ] {
        let actual = validate_both!(
            CelTemporalOverflowView,
            CelTemporalOverflow {
                start: timestamp(start.0, start.1).into(),
                end: timestamp(end.0, end.1).into(),
                shift: duration(shift.0, shift.1).into(),
                ..Default::default()
            }
        );
        assert_eq!(actual, expected, "{start:?} {end:?} {shift:?}");
    }
}

#[test]
fn logical_operators_discard_errors_the_other_operand_overrides() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::CelTemporalLogicalErrorsView, CelTemporalLogicalErrors,
    };

    for (start, end, expected) in [
        (0, HOUR / 2, failed(&[])),
        (0, 2 * HOUR, failed(&["and", "or"])),
        (2 * HOUR, 0, failed(&["and"])),
        // The span overflows: `end > start` decides `and`, and `end <= start`
        // decides `or`.
        (YEAR_9999, YEAR_1, failed(&["and"])),
        // Neither right operand decides, so the error stands.
        (YEAR_1, YEAR_9999, runtime_error("and", "duration overflow")),
    ] {
        let actual = validate_both!(
            CelTemporalLogicalErrorsView,
            CelTemporalLogicalErrors {
                start: timestamp(start, 0).into(),
                end: timestamp(end, 0).into(),
                ..Default::default()
            }
        );
        assert_eq!(actual, expected, "{start} to {end}");
    }
}

#[test]
fn quantifiers_discard_errors_another_element_overrides() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::CelTemporalQuantifierErrorsView, CelTemporalQuantifierErrors,
        cel_temporal_quantifier_errors::Slot,
    };

    let slot = |start: i64, end: i64| Slot {
        start: timestamp(start, 0).into(),
        end: timestamp(end, 0).into(),
        ..Default::default()
    };
    let overflow = || slot(YEAR_1, YEAR_9999);
    for (slots, expected) in [
        (vec![], failed(&["exists"])),
        (vec![slot(0, HOUR / 2)], failed(&["exists"])),
        (vec![slot(0, 2 * HOUR)], failed(&["all"])),
        (vec![overflow(), slot(0, 2 * HOUR)], failed(&["all"])),
        (vec![slot(0, 2 * HOUR), overflow()], failed(&["all"])),
        (vec![overflow()], runtime_error("all", "duration overflow")),
        (
            vec![slot(0, HOUR / 2), overflow()],
            runtime_error("all", "duration overflow"),
        ),
    ] {
        let actual = validate_both!(
            CelTemporalQuantifierErrorsView,
            CelTemporalQuantifierErrors {
                slots: slots.clone(),
                ..Default::default()
            }
        );
        assert_eq!(actual, expected, "{slots:?}");
    }
}
