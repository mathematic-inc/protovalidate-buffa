//! Scalar filters compile and validate in owned messages and views.

#![warn(rust_2018_idioms)]

use buffa::{HasMessageView, Message};
use protovalidate_buffa::Validate;

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

use generated::validation::cel_filter::FilteredScalars;

fn assert_filtered(message: &FilteredScalars, expected: &[&str]) -> Result<(), buffa::DecodeError> {
    let bytes = message.encode_to_vec();
    let view = FilteredScalars::decode_view(&bytes)?;
    for result in [message.validate(), view.validate()] {
        let actual = result.err().map_or_else(Vec::new, |error| {
            assert!(error.compile_error.is_none(), "{error:?}");
            assert!(error.runtime_error.is_none(), "{error:?}");
            error
                .violations
                .into_iter()
                .map(|violation| violation.rule_id.into_owned())
                .collect::<Vec<_>>()
        });
        assert_eq!(actual, expected);
    }
    Ok(())
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/110
#[test]
fn empty_and_valid_scalar_filters_pass() -> Result<(), buffa::DecodeError> {
    assert_filtered(&FilteredScalars::default(), &[])?;
    assert_filtered(
        &FilteredScalars {
            primary: true,
            flags: vec![false, true, false],
            amounts: vec![0, 1, 5],
            counts: vec![0, 1, 5],
            ratios: vec![0.0, 0.5, 1.0],
            ..Default::default()
        },
        &[],
    )
}

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/110
#[test]
fn scalar_filters_report_each_failed_rule() -> Result<(), buffa::DecodeError> {
    assert_filtered(
        &FilteredScalars {
            primary: true,
            tertiary: true,
            flags: vec![true, false, true],
            amounts: vec![-1, 6],
            counts: vec![6, 7],
            ratios: vec![1.5],
            ..Default::default()
        },
        &[
            "filter.bool_literal",
            "filter.bool_list",
            "filter.int_list",
            "filter.uint_list",
            "filter.double_list",
            "map.bool_list",
            "map.int_list",
            "map.uint_list",
            "map.double_list",
        ],
    )
}
