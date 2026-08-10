//! Every message gets a validator for both of buffa's representations: the
//! owned struct and its borrowed view. These tests pin the three places where
//! the two bodies differ — the impl target, the oneof enum module, and map
//! counting/iteration — plus the `views` option that tracks whether, and under
//! what `cfg`, the message crate's view types exist.
//!
//! Behavioural agreement between the two is covered by the differential
//! conformance run; see `crates/protovalidate-buffa-conformance/README.md`.

use protoc_gen_protovalidate_buffa::emit::{Options, ViewImpls, render_with_options};
use protoc_gen_protovalidate_buffa::scan::{
    FieldKind, FieldValidator, Ignore, MapStandard, MessageValidators, OneofValidator,
    StandardRules, StringStandard,
};

fn render_source(msg: MessageValidators, opts: &Options) -> String {
    render_with_options(&[msg], opts)
        .expect("render must not fail")
        .into_iter()
        .filter_map(|f| f.content)
        .collect::<Vec<_>>()
        .join("\n")
}

fn field(field_name: &str, field_type: FieldKind, standard: StandardRules) -> FieldValidator {
    FieldValidator {
        field_number: 1,
        field_name: field_name.to_string(),
        field_type,
        required: false,
        ignore: Ignore::Unspecified,
        standard,
        cel: Vec::new(),
        oneof_index: None,
        oneof_name: None,
        is_legacy_required: false,
        is_group: false,
    }
}

fn message(
    proto_name: &str,
    field_rules: Vec<FieldValidator>,
    oneof_rules: Vec<OneofValidator>,
) -> MessageValidators {
    MessageValidators {
        proto_name: proto_name.to_string(),
        package: "test.v1".to_string(),
        source_file: "test.proto".to_string(),
        message_cel: Vec::new(),
        message_oneofs: Vec::new(),
        field_rules,
        oneof_rules,
        compile_error: None,
    }
}

fn string_field(field_name: &str) -> FieldValidator {
    field(
        field_name,
        FieldKind::String,
        StandardRules {
            string: Some(StringStandard {
                min_len: Some(1),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
}

fn map_field(field_name: &str) -> FieldValidator {
    field(
        field_name,
        FieldKind::Map {
            key: Box::new(FieldKind::String),
            value: Box::new(FieldKind::String),
        },
        StandardRules {
            map: Some(MapStandard {
                min_pairs: Some(2),
                max_pairs: None,
                keys: None,
                values: None,
            }),
            ..Default::default()
        },
    )
}

/// Both impls are emitted, and the view one targets the `__buffa::view::` type
/// with a borrow lifetime.
#[test]
fn emits_owned_and_view_impls() {
    let src = render_source(
        message("test.v1.M", vec![string_field("name")], Vec::new()),
        &Options::default(),
    );
    assert!(
        src.contains("impl ::protovalidate_buffa::Validate for M {"),
        "owned impl must be emitted; generated source was:\n{src}"
    );
    assert!(
        src.contains("impl ::protovalidate_buffa::Validate for __buffa::view::MView<'_> {"),
        "view impl must target `__buffa::view::MView<'_>`; generated source was:\n{src}"
    );
}

/// A nested message's view keeps buffa's `snake_case` parent modules and gains
/// the `View` suffix on the leaf only.
#[test]
fn nested_message_view_path_snake_cases_parents() {
    let src = render_source(
        message(
            "test.v1.Outer.Inner",
            vec![string_field("name")],
            Vec::new(),
        ),
        &Options::default(),
    );
    assert!(
        src.contains(
            "impl ::protovalidate_buffa::Validate for __buffa::view::outer::InnerView<'_> {"
        ),
        "nested view impl must be `__buffa::view::outer::InnerView<'_>`; generated source was:\n{src}"
    );
}

/// An owned `HashMap` is already deduplicated by the decoder; a `MapView` is
/// the raw wire entry list, so the view body rebuilds the canonical map with a
/// single linear pass and counts distinct keys off that.
#[test]
fn map_rules_count_distinct_keys_on_views() {
    let src = render_source(
        message("test.v1.M", vec![map_field("vals")], Vec::new()),
        &Options::default(),
    );
    assert!(
        src.contains("self.vals.len() < 2usize"),
        "owned impl must count entries directly; generated source was:\n{src}"
    );
    assert!(
        src.contains("__pv_last.len() < 2usize"),
        "view impl must count distinct keys; generated source was:\n{src}"
    );
    // One pass to index, one to walk — not a quadratic scan per entry.
    assert_eq!(
        src.matches("__pv_last.insert(__pv_k, __pv_i);").count(),
        1,
        "view impl must index keys in a single pass; generated source was:\n{src}"
    );
    assert!(
        !src.contains("len_unique") && !src.contains("iter_unique"),
        "the O(n^2) MapView helpers must not be used; generated source was:\n{src}"
    );
}

/// Oneof match arms resolve against the view's own enum tree.
#[test]
fn oneof_arms_use_the_view_enum_module() {
    let mut member = string_field("name");
    member.oneof_name = Some("kind".to_string());
    member.oneof_index = Some(0);
    let oneof = OneofValidator {
        name: "kind".to_string(),
        required: false,
        parent_msg_name: "M".to_string(),
        fields: vec![member],
    };
    let src = render_source(
        message("test.v1.M", Vec::new(), vec![oneof]),
        &Options::default(),
    );
    assert!(
        src.contains("__buffa::oneof::m::Kind::Name"),
        "owned impl must match the owned oneof enum; generated source was:\n{src}"
    );
    assert!(
        src.contains("__buffa::view::oneof::m::Kind::Name"),
        "view impl must match the view oneof enum; generated source was:\n{src}"
    );
}

/// `views=false` is the escape hatch for message crates generated with buffa's
/// `generate_views` turned off — naming view types there would not compile.
#[test]
fn views_option_suppresses_the_view_impl() {
    let opts = Options {
        views: ViewImpls::Never,
        ..Default::default()
    };
    let src = render_source(
        message("test.v1.M", vec![string_field("name")], Vec::new()),
        &opts,
    );
    assert!(
        src.contains("impl ::protovalidate_buffa::Validate for M {"),
        "owned impl must still be emitted; generated source was:\n{src}"
    );
    assert!(
        !src.contains("__buffa::view::"),
        "no view impl may be emitted with views=false; generated source was:\n{src}"
    );
}

/// A message crate built with `gate_impls_on_crate_features` puts its whole
/// `__buffa::view` module behind a crate feature; the validators must carry
/// the same `cfg` so they appear exactly when the types they name do.
#[test]
fn gated_views_stamp_the_matching_cfg() {
    let opts = Options {
        views: ViewImpls::Gated("views".to_string()),
        ..Default::default()
    };
    let src = render_source(
        message("test.v1.M", vec![string_field("name")], Vec::new()),
        &opts,
    );
    assert!(
        src.contains("#[cfg(feature = \"views\")]"),
        "view impl must be cfg-gated on the named feature; generated source was:\n{src}"
    );
    let owned_at = src
        .find("impl ::protovalidate_buffa::Validate for M {")
        .expect("owned impl must be emitted");
    assert!(
        !src[..owned_at].contains("#[cfg(feature"),
        "the owned impl must stay unconditional; generated source was:\n{src}"
    );
}
