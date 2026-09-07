#![cfg(feature = "protos")]

mod support;

use buffa::{Message, MessageName};
use protovalidate_buffa::{FieldPath, FieldPathElement, FieldType, Subscript, proto};
use support::single_violation;

#[test]
fn lossless_details_preserve_all_selector_variants() {
    use proto::__buffa::oneof::field_path_element::Subscript as P;
    let variants = [
        (Subscript::Index(u64::MAX), P::Index(u64::MAX)),
        (Subscript::BoolKey(false), P::BoolKey(false)),
        (Subscript::IntKey(i64::MIN), P::IntKey(i64::MIN)),
        (Subscript::UintKey(u64::MAX), P::UintKey(u64::MAX)),
        (
            Subscript::StringKey("ключ\"\n".into()),
            P::StringKey("ключ\"\n".into()),
        ),
    ];
    for (input, expected) in variants {
        let mut error = single_violation();
        error.violations[0].field.elements[0].subscript = Some(input.clone());
        error.violations[0].rule.elements[0].subscript = Some(input);
        let details = error.to_proto();
        assert_eq!(proto::Violations::FULL_NAME, "buf.validate.Violations");
        let decoded = proto::Violations::decode_from_slice(&details.encode_to_vec()).unwrap();
        assert_eq!(decoded, details);
        let v = &decoded.violations[0];
        assert_eq!(v.field.elements[0].subscript.as_ref(), Some(&expected));
        assert_eq!(v.rule.elements[0].subscript.as_ref(), Some(&expected));
        assert_eq!(v.rule_id.as_deref(), Some("address.code"));
        assert_eq!(v.message.as_deref(), Some("invalid value: private-value"));
        assert_eq!(v.for_key, Some(true));
    }
}

#[test]
fn all_descriptor_types_keep_their_canonical_numbers() {
    let variants = [
        FieldType::Double,
        FieldType::Float,
        FieldType::Int64,
        FieldType::Uint64,
        FieldType::Int32,
        FieldType::Fixed64,
        FieldType::Fixed32,
        FieldType::Bool,
        FieldType::String,
        FieldType::Group,
        FieldType::Message,
        FieldType::Bytes,
        FieldType::Uint32,
        FieldType::Enum,
        FieldType::Sfixed32,
        FieldType::Sfixed64,
        FieldType::Sint32,
        FieldType::Sint64,
    ];
    for (number, variant) in (1..=18).zip(variants) {
        let mut error = single_violation();
        let element = &mut error.violations[0].field.elements[0];
        element.field_type = Some(variant);
        element.key_type = Some(variant);
        element.value_type = Some(variant);
        let details = error.to_proto();
        let element = &details.violations[0].field.elements[0];
        assert_eq!(element.field_type.unwrap() as i32, number);
        assert_eq!(element.key_type.unwrap() as i32, number);
        assert_eq!(element.value_type.unwrap() as i32, number);
    }
}

#[test]
fn absent_identity_is_not_invented_and_diagnostics_are_not_truncated() {
    let mut error = single_violation();
    let v = &mut error.violations[0];
    v.field = FieldPath::default();
    v.rule = FieldPath {
        elements: vec![FieldPathElement::default()],
    };
    v.rule_id = "".into();
    v.for_key = false;
    v.message = "diagnostic".repeat(10_000).into();
    let details = error.to_proto();
    let v = &details.violations[0];
    assert!(v.field.as_option().is_none());
    assert_eq!(v.rule.elements[0], proto::FieldPathElement::default());
    assert!(v.rule_id.is_none());
    assert!(v.for_key.is_none());
    assert_eq!(v.message.as_ref().unwrap().len(), 100_000);
}
