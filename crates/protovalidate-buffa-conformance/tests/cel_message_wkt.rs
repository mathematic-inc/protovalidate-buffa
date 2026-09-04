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
    ($name:ident, $owned:ident, $view:ident, $wkt:ident, $rule:literal) => {
        // https://github.com/mathematic-inc/protovalidate-buffa/discussions/44
        #[test]
        fn $name() {
            use generated::buf::validate::conformance::cases::{__buffa::view::$view, $owned};

            for (start, end, valid) in [
                (None, None, true),
                (Some((0, 0)), None, true),
                (None, Some((0, 0)), true),
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
    "timestamp_range.ordered"
);
range_test!(
    duration_ordering_preserves_presence,
    CelDurationRange,
    CelDurationRangeView,
    Duration,
    "duration_range.ordered"
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
