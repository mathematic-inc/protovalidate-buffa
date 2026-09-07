//! Discussion #53: compile actual buffa types with matching validators in both
//! naming modes. Decode identical protobuf bytes to check validation behavior
//! and the original protobuf field spelling in errors, for owned and view types.
#![warn(rust_2018_idioms)]
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    elided_lifetimes_in_paths,
    non_camel_case_types,
    non_snake_case,
    unused_imports,
    reason = "generated Buffa and validator modules are compile and behavior fixtures"
)]

include!(concat!(env!("OUT_DIR"), "/field_name_mounts.rs"));

/// These fixtures only use one-byte tags and payload lengths.
fn bytes_field(number: u8, value: &[u8]) -> Vec<u8> {
    assert!(number < 16 && value.len() < 128);
    let mut bytes = vec![(number << 3) | 2, value.len() as u8];
    bytes.extend_from_slice(value);
    bytes
}

macro_rules! naming_tests {
    ($mode:ident) => {
        mod $mode {
            use crate::bytes_field;
            use crate::$mode::proto::field_names::{
                __buffa::view::{
                    ChoicesView, CollisionView, FallbackView, InheritedView, NamesView,
                },
                Choices, Collision, Fallback, Inherited, Names,
            };
            use buffa::{Message as _, MessageView as _};
            use protovalidate_buffa::{Validate, ValidationError};

            fn assert_failure(
                result: Result<(), ValidationError>,
                rule: &str,
                field: Option<&str>,
            ) {
                let error = result.expect_err("fixture must fail validation");
                assert!(error.compile_error.is_none(), "{error:?}");
                assert!(error.runtime_error.is_none(), "{error:?}");
                assert!(
                    error.violations.iter().any(|violation| {
                        violation.rule_id == rule
                            && field.is_none_or(|name| {
                                violation.field.elements[0].field_name.as_deref() == Some(name)
                            })
                    }),
                    "expected {rule} on {field:?}: {error:?}"
                );
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/53
            #[test]
            fn scalar_optional_collection_and_nested_names_preserve_paths() {
                let valid = bytes_field(1, b"ok");
                assert!(Names::decode_from_slice(&valid).unwrap().validate().is_ok());
                assert!(NamesView::decode_view(&valid).unwrap().validate().is_ok());
                for (number, payload, field) in [
                    (1, b"x".to_vec(), "userName"),
                    (2, b"x".to_vec(), "optionalName"),
                    (3, b"x".to_vec(), "manyNames"),
                    (
                        4,
                        [bytes_field(1, b"key"), bytes_field(2, b"x")].concat(),
                        "nameMap",
                    ),
                    (5, bytes_field(1, b"x"), "childValue"),
                    (6, bytes_field(1, b"x"), "manyChildren"),
                ] {
                    let bytes = [valid.clone(), bytes_field(number, &payload)].concat();
                    assert_failure(
                        Names::decode_from_slice(&bytes).unwrap().validate(),
                        "string.min_len",
                        Some(field),
                    );
                    assert_failure(
                        NamesView::decode_view(&bytes).unwrap().validate(),
                        "string.min_len",
                        Some(field),
                    );
                }
            }

            #[test]
            fn cel_uses_proto_names_and_resolved_rust_accessors() {
                for (number, payload, rule, field) in [
                    (1, b"blocked".to_vec(), "names.cel", None),
                    (2, b"blocked".to_vec(), "names.cel", None),
                    (
                        5,
                        bytes_field(1, b"blocked"),
                        "child.cel",
                        Some("childValue"),
                    ),
                    (
                        6,
                        bytes_field(1, b"blocked"),
                        "children.cel",
                        Some("manyChildren"),
                    ),
                    (7, b"blocked".to_vec(), "acronym.cel", Some("XML2Request")),
                    (
                        8,
                        b"blocked".to_vec(),
                        "underscore.cel",
                        Some("_leadingName_"),
                    ),
                    (9, b"blocked".to_vec(), "keyword.cel", Some("Type")),
                    (10, b"blocked".to_vec(), "self.cel", Some("Self")),
                ] {
                    let bytes = [bytes_field(1, b"ok"), bytes_field(number, &payload)].concat();
                    assert_failure(
                        Names::decode_from_slice(&bytes).unwrap().validate(),
                        rule,
                        field,
                    );
                    assert_failure(
                        NamesView::decode_view(&bytes).unwrap().validate(),
                        rule,
                        field,
                    );
                }
            }

            #[test]
            fn oneof_accessors_preserve_enum_variants_and_presence() {
                let valid = bytes_field(1, b"ok");
                assert!(
                    Choices::decode_from_slice(&valid)
                        .unwrap()
                        .validate()
                        .is_ok()
                );
                assert!(ChoicesView::decode_view(&valid).unwrap().validate().is_ok());
                for (bytes, rule, field) in [
                    (vec![], "required", Some("choiceValue")),
                    (bytes_field(1, b"x"), "string.min_len", Some("textValue")),
                    (vec![0x10, 1], "choice.cel", None),
                    (
                        [valid, bytes_field(3, b"ok")].concat(),
                        "message.oneof",
                        None,
                    ),
                ] {
                    assert_failure(
                        Choices::decode_from_slice(&bytes).unwrap().validate(),
                        rule,
                        field,
                    );
                    assert_failure(
                        ChoicesView::decode_view(&bytes).unwrap().validate(),
                        rule,
                        field,
                    );
                }
            }

            #[test]
            fn collisions_fallback_and_inherited_adjustments_validate() {
                let valid = [
                    bytes_field(1, b"ok"),
                    bytes_field(2, b""),
                    bytes_field(3, b""),
                    bytes_field(4, b"ok"),
                ]
                .concat();
                assert!(
                    Collision::decode_from_slice(&valid)
                        .unwrap()
                        .validate()
                        .is_ok()
                );
                assert!(
                    CollisionView::decode_view(&valid)
                        .unwrap()
                        .validate()
                        .is_ok()
                );
                for (number, value, rule, field) in [
                    (1, b"x".as_slice(), "string.min_len", "userName"),
                    (1, b"blocked".as_slice(), "collision.cel", ""),
                    (4, b"x".as_slice(), "string.min_len", "textValue"),
                ] {
                    let bytes = [valid.clone(), bytes_field(number, value)].concat();
                    let field = if field.is_empty() { None } else { Some(field) };
                    assert_failure(
                        Collision::decode_from_slice(&bytes).unwrap().validate(),
                        rule,
                        field,
                    );
                    assert_failure(
                        CollisionView::decode_view(&bytes).unwrap().validate(),
                        rule,
                        field,
                    );
                }
                let fallback = [
                    bytes_field(11, b"ok"),
                    bytes_field(12, b""),
                    bytes_field(13, b""),
                    bytes_field(14, b"ok"),
                ]
                .concat();
                assert!(
                    Fallback::decode_from_slice(&fallback)
                        .unwrap()
                        .validate()
                        .is_ok()
                );
                assert!(
                    FallbackView::decode_view(&fallback)
                        .unwrap()
                        .validate()
                        .is_ok()
                );
                for (number, field) in [(11, "otherName"), (14, "unrelatedName")] {
                    let bytes = [fallback.clone(), bytes_field(number, b"x")].concat();
                    assert_failure(
                        Fallback::decode_from_slice(&bytes).unwrap().validate(),
                        "string.min_len",
                        Some(field),
                    );
                    assert_failure(
                        FallbackView::decode_view(&bytes).unwrap().validate(),
                        "string.min_len",
                        Some(field),
                    );
                }
                let inherited = [bytes_field(1, b"ok"), bytes_field(11, b"ok")].concat();
                assert!(
                    Inherited::decode_from_slice(&inherited)
                        .unwrap()
                        .validate()
                        .is_ok()
                );
                assert!(
                    InheritedView::decode_view(&inherited)
                        .unwrap()
                        .validate()
                        .is_ok()
                );
                for (number, field) in [(1, "userName"), (11, "otherName")] {
                    let bytes = [inherited.clone(), bytes_field(number, b"x")].concat();
                    assert_failure(
                        Inherited::decode_from_slice(&bytes).unwrap().validate(),
                        "string.min_len",
                        Some(field),
                    );
                    assert_failure(
                        InheritedView::decode_view(&bytes).unwrap().validate(),
                        "string.min_len",
                        Some(field),
                    );
                }
            }
        }
    };
}

mod checks {
    naming_tests!(verbatim);
    naming_tests!(idiomatic);
}
