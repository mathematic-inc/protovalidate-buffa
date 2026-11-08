#![warn(rust_2018_idioms)]

use buffa::{Message as _, MessageView as _};
use protovalidate_buffa::{Validate as _, ValidationError};

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

use generated::buf::validate::conformance::cases::{
    __buffa::{
        oneof::cel_message_cross_field::Choice,
        view::{CelMessageCrossFieldView, CelMessageMapView},
    },
    CelMessageCrossField, CelMessageMap, CelOneofChild,
};

fn assert_rules(result: Result<(), ValidationError>, expected: &[&str]) {
    if expected.is_empty() {
        assert!(result.is_ok(), "{result:?}");
    } else {
        let error = result.expect_err("expected validation violations");
        assert!(error.compile_error.is_none(), "{error:?}");
        assert!(error.runtime_error.is_none(), "{error:?}");
        let rules: Vec<_> = error
            .violations
            .iter()
            .map(|v| v.rule_id.as_ref())
            .collect();
        assert_eq!(rules, expected);
    }
}

#[test]
fn message_cel_reads_a_maps_size_presence_and_values() {
    /// The map's entries, `want_size`, `want_k`, and the rules that fail.
    type Case = (
        &'static [(&'static str, &'static str)],
        i64,
        &'static str,
        &'static [&'static str],
    );

    let cases: [Case; 6] = [
        (&[], 0, "", &[]),
        (&[("k", "v")], 1, "v", &[]),
        (&[("k", "v"), ("j", "w")], 2, "v", &[]),
        (&[("k", "v")], 0, "v", &["map.size", "map.has"]),
        (&[], 1, "", &["map.size", "map.has"]),
        (&[("k", "v")], 1, "other", &["map.lookup"]),
    ];
    for (labels, want_size, want_k, rules) in cases {
        let owned = CelMessageMap {
            labels: labels
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
            want_size,
            want_k: want_k.to_owned(),
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let borrowed = CelMessageMapView::decode_view(&bytes).unwrap();
        assert_rules(owned.validate(), rules);
        assert_rules(borrowed.validate(), rules);
    }
}

#[test]
fn message_cel_counts_a_repeated_map_key_once() {
    fn entry(value: u8) -> [u8; 8] {
        [0x0a, 0x06, 0x0a, 0x01, b'k', 0x12, 0x01, value]
    }

    let mut bytes = entry(b'a').to_vec();
    bytes.extend(entry(b'b'));
    // `want_size` is 1, `want_k` is "b".
    bytes.extend([0x10, 0x01, 0x1a, 0x01, b'b']);
    let owned = CelMessageMap::decode_from_slice(&bytes).unwrap();
    let borrowed = CelMessageMapView::decode_view(&bytes).unwrap();

    assert_eq!(borrowed.labels.len(), 2);
    assert_rules(owned.validate(), &[]);
    assert_rules(borrowed.validate(), &[]);
}

#[test]
fn message_cel_spans_a_map_and_a_oneof_alternative() {
    let child = |id: &str| {
        Some(Choice::Child(
            CelOneofChild {
                id: id.to_owned(),
                ..Default::default()
            }
            .into(),
        ))
    };
    for (labeled, choice, rules) in [
        (false, None, &[][..]),
        (false, child("c"), &[][..]),
        (true, None, &[][..]),
        (true, Some(Choice::Text("t".to_owned())), &[][..]),
        (true, child(""), &[][..]),
        (true, child("c"), &["cross_field"][..]),
    ] {
        let owned = CelMessageCrossField {
            labels: labeled
                .then(|| ("k".to_owned(), "v".to_owned()))
                .into_iter()
                .collect(),
            choice,
            ..Default::default()
        };
        let bytes = owned.encode_to_vec();
        let borrowed = CelMessageCrossFieldView::decode_view(&bytes).unwrap();
        assert_rules(owned.validate(), rules);
        assert_rules(borrowed.validate(), rules);
    }
}
