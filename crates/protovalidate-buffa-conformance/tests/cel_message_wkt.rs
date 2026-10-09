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

fn field_mask(paths: Option<&[&str]>) -> Option<generated::google::protobuf::FieldMask> {
    paths.map(|paths| generated::google::protobuf::FieldMask {
        paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        ..Default::default()
    })
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
            update_mask: field_mask(paths).into(),
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
            update_mask: field_mask(paths).into(),
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
                let scopes = if paths.is_some() {
                    &["message", "field"][..]
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
