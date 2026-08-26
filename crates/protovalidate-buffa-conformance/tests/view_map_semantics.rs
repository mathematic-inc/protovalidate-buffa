#![warn(rust_2018_idioms)]
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    elided_lifetimes_in_paths,
    non_camel_case_types,
    unused_imports,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_html_tags,
    reason = "buffa-build generated code — upstream codegen style; do not police"
)]

use buffa::{Message as _, MessageView as _};
use protovalidate_buffa::Validate as _;

pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/_include.rs"));
}

fn fixed32_map_entry(key: u8, value: f32) -> Vec<u8> {
    let mut entry = vec![0x0a, 0x07, 0x08, key, 0x15];
    entry.extend_from_slice(&value.to_le_bytes());
    entry
}

fn uint_map_entry(key: u8, value: u8) -> [u8; 6] {
    [0x0a, 0x04, 0x08, key, 0x10, value]
}

// https://github.com/mathematic-inc/protovalidate-buffa/pull/28
#[test]
fn duplicate_keys_do_not_satisfy_min_pairs() {
    use generated::buf::validate::conformance::cases::{__buffa::view::MapMinView, MapMin};

    let mut bytes = fixed32_map_entry(1, 1.0);
    bytes.extend(fixed32_map_entry(1, 2.0));
    let owned = MapMin::decode_from_slice(&bytes).expect("fixture must decode as an owned map");
    let view = MapMinView::decode_view(&bytes).expect("fixture must decode as a map view");

    assert_eq!(owned.val.len(), 1);
    assert_eq!(view.val.len(), 2);
    assert!(owned.validate().is_err());
    assert!(view.validate().is_err());
}

// https://github.com/mathematic-inc/protovalidate-buffa/pull/28
#[test]
fn duplicate_keys_do_not_inflate_cel_map_size() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::PredefinedMapRuleProto3View, PredefinedMapRuleProto3,
    };

    let bytes = uint_map_entry(1, 1).repeat(5);
    let owned = PredefinedMapRuleProto3::decode_from_slice(&bytes)
        .expect("fixture must decode as an owned map");
    let view = PredefinedMapRuleProto3View::decode_view(&bytes)
        .expect("fixture must decode as a map view");

    assert_eq!(owned.val.len(), 1);
    assert_eq!(view.val.len(), 5);
    assert!(owned.validate().is_err());
    assert!(view.validate().is_err());
}
