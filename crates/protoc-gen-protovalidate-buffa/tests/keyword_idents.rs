//! Regression tests for fields / oneofs whose proto name is a Rust keyword.
//!
//! buffa names the generated struct field for a proto field `type` as the raw
//! identifier `r#type` (and `self`/`super`/`Self`/`crate`, which cannot be raw
//! identifiers, as `self_`/`super_`/`Self_`/`crate_`). The validator codegen
//! must emit accessors that match, otherwise `prettyplease`/`syn` cannot parse
//! the output and `proc_macro2::Ident::new` panics at generation time.
//!
//! See `buffa_codegen::idents::make_field_ident` for the source-of-truth
//! escaping these tests pin down.

use protoc_gen_protovalidate_buffa::emit::render;
use protoc_gen_protovalidate_buffa::scan::{
    CelRule, FieldKind, FieldValidator, Ignore, MessageValidators, OneofValidator, StandardRules,
};

/// Concatenate every emitted file's body so a test can assert on the generated
/// source regardless of which per-package / per-source file an accessor landed
/// in.
fn render_to_source(msg: MessageValidators) -> String {
    let files = render(&[msg]).expect("render must not fail for keyword-named fields");
    files
        .into_iter()
        .filter_map(|f| f.content)
        .collect::<Vec<_>>()
        .join("\n")
}

fn field(name: &str, field_type: FieldKind) -> FieldValidator {
    FieldValidator {
        field_number: 1,
        field_name: name.to_string(),
        field_type,
        required: false,
        ignore: Ignore::Unspecified,
        standard: StandardRules::default(),
        cel: Vec::new(),
        oneof_index: None,
        oneof_name: None,
        is_legacy_required: false,
        is_group: false,
    }
}

fn message(field_rules: Vec<FieldValidator>) -> MessageValidators {
    MessageValidators {
        proto_name: "kw.v1.M".to_string(),
        package: "kw.v1".to_string(),
        source_file: "kw.proto".to_string(),
        message_cel: Vec::new(),
        message_oneofs: Vec::new(),
        field_rules,
        oneof_rules: Vec::new(),
        compile_error: None,
    }
}

/// A plain (raw-able) keyword field name must become `self.r#type`.
#[test]
fn required_field_named_type_uses_raw_ident() {
    let mut f = field("type", FieldKind::String);
    f.required = true;
    let src = render_to_source(message(vec![f]));
    assert!(
        src.contains("self.r#type"),
        "expected `self.r#type` accessor, generated source was:\n{src}"
    );
}

/// `self` cannot be a raw identifier, so buffa suffixes it: the accessor must
/// be `self.self_`. Today this panics in `Ident::new_raw`.
#[test]
fn required_field_named_self_uses_suffixed_ident() {
    let mut f = field("self", FieldKind::String);
    f.required = true;
    let src = render_to_source(message(vec![f]));
    assert!(
        src.contains("self.self_"),
        "expected `self.self_` accessor, generated source was:\n{src}"
    );
}

/// A field-level CEL rule on a keyword-named field. Today the field accessor is
/// built with `format_ident!("{}", "type")`, which panics.
#[test]
fn field_cel_on_keyword_named_field_does_not_panic() {
    let mut f = field("type", FieldKind::String);
    f.cel = vec![CelRule {
        id: "type_rule".to_string(),
        message: "must be non-empty".to_string(),
        expression: "this != ''".to_string(),
        is_cel_expression: false,
    }];
    // Must not panic during render.
    let _ = render_to_source(message(vec![f]));
}

/// A required oneof whose proto name is a keyword. Today the accessor is built
/// with `parse_str::<syn::Ident>("type")`, which returns `Err` and fails codegen.
#[test]
fn required_oneof_named_type_uses_raw_ident() {
    let mut msg = message(Vec::new());
    msg.oneof_rules = vec![OneofValidator {
        name: "type".to_string(),
        required: true,
        parent_msg_name: "M".to_string(),
        fields: Vec::new(),
    }];
    let src = render_to_source(msg);
    assert!(
        src.contains("self.r#type"),
        "expected `self.r#type` oneof accessor, generated source was:\n{src}"
    );
}
