//! Collection enum rules must match upstream Protovalidate's numeric semantics.
//!
//! Reference: https://github.com/bufbuild/protovalidate/blob/main/proto/protovalidate/buf/validate/validate.proto
//! The vendored enums.proto also defines RepeatedEnumDefined, MapEnumDefined,
//! and their cross-package variants. These cases additionally cover disabled
//! rules, negative numbers, combined rules, views, and full violation metadata.

#![warn(rust_2018_idioms)]
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    elided_lifetimes_in_paths,
    non_camel_case_types,
    unused_imports,
    reason = "generated Buffa and validator modules — compile and behavior fixtures, not style targets"
)]

use buffa::{HasMessageView, Message, MessageView};
use protovalidate_buffa::{FieldType, Subscript, Validate, ValidationError};

include!(concat!(env!("OUT_DIR"), "/module_tree_mounts.rs"));

fn results<M>(bytes: &[u8]) -> [Result<(), ValidationError>; 2]
where
    M: HasMessageView + Validate,
    for<'a> M::View<'a>: Validate,
{
    let owned = M::decode_from_slice(bytes).expect("decode collection message");
    let view = M::View::decode_view(bytes).expect("decode collection view");
    [owned.validate(), view.validate()]
}

// Encode the same raw enum number for both message forms. Repeated fields
// contain a valid element first so a failure must retain index 1. Map fields
// use string and signed integer keys to verify both selector representations.
fn input(field: u32, value: i32) -> Vec<u8> {
    use buffa::encoding::encode_varint;
    let raw_value = i64::from(value) as u64;
    let mut bytes = Vec::new();
    if field <= 2 {
        encode_varint(u64::from(field << 3), &mut bytes);
        encode_varint(1, &mut bytes);
        encode_varint(u64::from(field << 3), &mut bytes);
        encode_varint(raw_value, &mut bytes);
    } else {
        let mut entry = Vec::new();
        if field == 3 {
            entry.extend_from_slice(&[0x0a, 3, b'c', b'a', b'p']);
        } else {
            entry.push(0x08);
            encode_varint(-7i64 as u64, &mut entry);
        }
        entry.push(0x10);
        encode_varint(raw_value, &mut entry);
        encode_varint(u64::from((field << 3) | 2), &mut bytes);
        encode_varint(entry.len() as u64, &mut bytes);
        bytes.extend(entry);
    }
    bytes
}

fn assert_rules<M>(field: u32, value: i32, expected: &[&str])
where
    M: HasMessageView + Validate,
    for<'a> M::View<'a>: Validate,
{
    for result in results::<M>(&input(field, value)) {
        if expected.is_empty() {
            assert!(result.is_ok(), "field {field}, value {value}: {result:?}");
            continue;
        }
        let error = result.expect_err("collection enum rules must reject this numeric value");
        assert!(error.compile_error.is_none());
        assert!(error.runtime_error.is_none());
        assert_eq!(error.violations.len(), expected.len());
        for (violation, rule) in error.violations.iter().zip(expected) {
            assert_eq!(violation.rule_id, format!("enum.{rule}"));
            assert!(!violation.for_key);
            assert_eq!(violation.field.elements.len(), 1);
            let element = &violation.field.elements[0];
            assert_eq!(element.field_number, Some(field as i32));
            let name = ["top", "nested", "top_values", "nested_values"][field as usize - 1];
            assert_eq!(element.field_name.as_deref(), Some(name));
            if field <= 2 {
                assert_eq!(element.field_type, Some(FieldType::Enum));
                assert_eq!(element.key_type, None);
                assert_eq!(element.value_type, None);
                assert!(matches!(element.subscript, Some(Subscript::Index(1))));
            } else {
                assert_eq!(element.field_type, Some(FieldType::Message));
                assert_eq!(element.value_type, Some(FieldType::Enum));
                if field == 3 {
                    assert_eq!(element.key_type, Some(FieldType::String));
                    assert!(
                        matches!(&element.subscript, Some(Subscript::StringKey(key)) if key == "cap")
                    );
                } else {
                    assert_eq!(element.key_type, Some(FieldType::Int32));
                    assert!(matches!(element.subscript, Some(Subscript::IntKey(-7))));
                }
            }
            let prefix = if field <= 2 {
                "repeated.items"
            } else {
                "map.values"
            };
            assert_eq!(violation.rule.to_string(), format!("{prefix}.enum.{rule}"));
            let (outer, child) = if field <= 2 { (18, 4) } else { (19, 5) };
            let inner = match *rule {
                "const" => 1,
                "defined_only" => 2,
                "in" => 3,
                "not_in" => 4,
                _ => panic!("unexpected enum rule"),
            };
            let numbers: Vec<_> = violation
                .rule
                .elements
                .iter()
                .map(|part| part.field_number)
                .collect();
            assert_eq!(numbers, [Some(outer), Some(child), Some(16), Some(inner)]);
            for (index, part) in violation.rule.elements.iter().enumerate() {
                let field_type = if index < 3 {
                    FieldType::Message
                } else if *rule == "defined_only" {
                    FieldType::Bool
                } else {
                    FieldType::Int32
                };
                assert_eq!(part.field_type, Some(field_type));
                assert_eq!(part.key_type, None);
                assert_eq!(part.value_type, None);
                assert!(part.subscript.is_none());
            }
        }
    }
}

macro_rules! collection_tests {
    ($name:ident, $messages:path) => {
        mod $name {
            use super::*;
            use messages::module_tree::runtime::v1::{
                EnumCollectionsAbsent, EnumCollectionsCombined, EnumCollectionsDefined,
                EnumCollectionsDisabled, EnumCollectionsOtherRules,
            };
            use $messages as messages;

            #[test]
            fn defined_values_and_empty_collections_pass() {
                for result in results::<EnumCollectionsDefined>(&[]) {
                    assert!(result.is_ok());
                }
                for field in 1..=4 {
                    for value in [0, 1, -1] {
                        assert_rules::<EnumCollectionsDefined>(field, value, &[]);
                    }
                }
            }

            #[test]
            fn undefined_positive_and_negative_numbers_report_locations() {
                for field in 1..=4 {
                    for value in [99, -99, i32::MAX, i32::MIN] {
                        assert_rules::<EnumCollectionsDefined>(field, value, &["defined_only"]);
                    }
                }
            }

            #[test]
            fn disabled_and_absent_defined_only_preserve_not_in() {
                for field in 1..=4 {
                    for value in [1, -1, 99, -99, i32::MAX, i32::MIN] {
                        assert_rules::<EnumCollectionsDisabled>(field, value, &[]);
                        assert_rules::<EnumCollectionsAbsent>(field, value, &[]);
                    }
                    assert_rules::<EnumCollectionsDisabled>(field, 0, &["not_in"]);
                    assert_rules::<EnumCollectionsAbsent>(field, 0, &["not_in"]);
                }
            }

            #[test]
            fn combined_rules_report_each_applicable_violation() {
                for field in 1..=4 {
                    assert_rules::<EnumCollectionsCombined>(field, 1, &[]);
                    assert_rules::<EnumCollectionsCombined>(field, 0, &["not_in"]);
                    assert_rules::<EnumCollectionsCombined>(field, -99, &["defined_only"]);
                    assert_rules::<EnumCollectionsCombined>(field, 99, &["defined_only", "not_in"]);
                }
            }

            #[test]
            fn shared_enum_emission_preserves_const_and_in() {
                assert_rules::<EnumCollectionsOtherRules>(1, 1, &[]);
                assert_rules::<EnumCollectionsOtherRules>(1, 99, &["const"]);
                assert_rules::<EnumCollectionsOtherRules>(3, 1, &[]);
                assert_rules::<EnumCollectionsOtherRules>(3, 99, &["in"]);
            }

            #[test]
            fn membership_uses_the_numeric_value() {
                let message = EnumCollectionsDefined {
                    top: vec![buffa::EnumValue::Unknown(1)],
                    ..Default::default()
                };
                assert!(message.validate().is_ok());
            }
        }
    };
}

collection_tests!(default_module, crate::proto);
collection_tests!(custom_module, crate::custom::messages);
