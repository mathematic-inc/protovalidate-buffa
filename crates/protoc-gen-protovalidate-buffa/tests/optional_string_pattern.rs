//! Regression test for `optional string` (explicit presence) and oneof string
//! members carrying a `string.pattern` rule.
//!
//! `emit_string_checks_on` is shared between the explicit-presence path (which
//! binds `v` as an owned `String`) and oneof members (which bind `&String`).
//! The `pattern` check passes `v` to `Regex::is_match`, which takes `&str`, but
//! an owned `String` does not coerce in argument position. These tests pin that
//! the emitted check borrows via `v.as_str()`, so both paths compile. See
//! `emit_string_checks_on` in `src/emit/field.rs` for why this matters.

use protoc_gen_protovalidate_buffa::emit::render;
use protoc_gen_protovalidate_buffa::scan::{
    FieldKind, FieldValidator, Ignore, MessageValidators, OneofValidator, StandardRules,
    StringStandard,
};

fn render_to_source(msg: MessageValidators) -> String {
    let files = render(&[msg]).expect("render must not fail");
    files
        .into_iter()
        .filter_map(|f| f.content)
        .collect::<Vec<_>>()
        .join("\n")
}

fn string_field_with_pattern(field_type: FieldKind) -> FieldValidator {
    let standard = StandardRules {
        string: Some(StringStandard {
            pattern: Some("^a".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    FieldValidator {
        field_number: 1,
        field_name: "name".to_string(),
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
    field_rules: Vec<FieldValidator>,
    oneof_rules: Vec<OneofValidator>,
) -> MessageValidators {
    MessageValidators {
        proto_name: "test.v1.M".to_string(),
        package: "test.v1".to_string(),
        source_file: "test.proto".to_string(),
        message_cel: Vec::new(),
        message_oneofs: Vec::new(),
        field_rules,
        oneof_rules,
        compile_error: None,
    }
}

/// The emitted `pattern` check must borrow the value (`v.as_str()`); passing an
/// owned `String` to `is_match` would fail to compile.
fn assert_pattern_borrows(src: &str) {
    assert!(
        src.contains("is_match(v.as_str())"),
        "pattern check must borrow the value (`v.as_str()`); generated source was:\n{src}"
    );
    assert!(
        !src.contains("is_match(v)"),
        "pattern check must not pass an owned `String` to `is_match`; generated source was:\n{src}"
    );
}

/// An `optional string` field binds `v` as an owned `String`.
#[test]
fn optional_string_pattern_borrows_value() {
    let f = string_field_with_pattern(FieldKind::Optional(Box::new(FieldKind::String)));
    let src = render_to_source(message(vec![f], Vec::new()));
    assert_pattern_borrows(&src);
}

/// A oneof string member binds `v` as a `&String`; the same `as_str()` borrow
/// must keep this path compiling.
#[test]
fn oneof_string_pattern_borrows_value() {
    let mut member = string_field_with_pattern(FieldKind::String);
    member.oneof_name = Some("kind".to_string());
    member.oneof_index = Some(0);

    let oneof = OneofValidator {
        name: "kind".to_string(),
        required: false,
        parent_msg_name: "M".to_string(),
        fields: vec![member],
    };
    let src = render_to_source(message(Vec::new(), vec![oneof]));
    assert_pattern_borrows(&src);
}
