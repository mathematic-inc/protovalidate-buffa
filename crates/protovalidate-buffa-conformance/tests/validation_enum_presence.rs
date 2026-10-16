//! Explicit-presence enums enforce the same rules in owned messages and views.
//! Regression: <https://github.com/mathematic-inc/protovalidate-buffa/discussions/103>

#![warn(rust_2018_idioms)]

use buffa::{HasMessageView, encoding::encode_varint};
use protovalidate_buffa::{FieldType, Validate};

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

/// Decode the same wire value into both representations, distinguishing explicit
/// zero from absence. Unknown numbers are retained by open enums and treated as
/// absent by closed enums. `None` supplies an absent field.
fn assert_enum<M>(
    number: u8,
    name: &str,
    value: Option<i32>,
    expected: &[&str],
) -> Result<(), buffa::DecodeError>
where
    M: HasMessageView + Validate,
    for<'a> M::View<'a>: Validate,
{
    let mut bytes = Vec::new();
    if let Some(value) = value {
        encode_varint(u64::from(number) << 3, &mut bytes);
        #[allow(
            clippy::cast_sign_loss,
            reason = "protobuf encodes negative int32 as a sign-extended varint"
        )]
        let raw = i64::from(value) as u64;
        encode_varint(raw, &mut bytes);
    }
    let owned = M::decode_from_slice(&bytes)?;
    let view = M::decode_view(&bytes)?;
    for result in [owned.validate(), view.validate()] {
        let violations = result
            .err()
            .into_iter()
            .flat_map(|error| {
                assert!(error.compile_error.is_none(), "{error:?}");
                assert!(error.runtime_error.is_none(), "{error:?}");
                error.violations
            })
            .collect::<Vec<_>>();
        assert_eq!(
            violations.len(),
            expected.len(),
            "{name}={value:?}: {violations:?}"
        );
        for (violation, rule) in violations.iter().zip(expected) {
            let (id, rule_fields) = match *rule {
                "required" => (
                    "required".to_string(),
                    vec![("required", 25, FieldType::Bool)],
                ),
                rule => {
                    let (inner, kind) = match rule {
                        "const" => (1, FieldType::Int32),
                        "defined_only" => (2, FieldType::Bool),
                        "in" => (3, FieldType::Int32),
                        "not_in" => (4, FieldType::Int32),
                        _ => unreachable!("unexpected enum rule {rule}"),
                    };
                    (
                        format!("enum.{rule}"),
                        vec![("enum", 16, FieldType::Message), (rule, inner, kind)],
                    )
                }
            };
            assert_eq!(violation.rule_id, id);
            assert!(!violation.for_key, "{violation:?}");
            assert_eq!(violation.field.elements.len(), 1);
            let field = &violation.field.elements[0];
            assert_eq!(field.field_number, Some(i32::from(number)));
            assert_eq!(field.field_name.as_deref(), Some(name));
            assert_eq!(field.field_type, Some(FieldType::Enum));
            assert_eq!(field.key_type, None);
            assert_eq!(field.value_type, None);
            assert!(field.subscript.is_none(), "{field:?}");
            assert_eq!(violation.rule.elements.len(), rule_fields.len());
            for (part, (name, number, kind)) in violation.rule.elements.iter().zip(rule_fields) {
                assert_eq!(part.field_name.as_deref(), Some(name));
                assert_eq!(part.field_number, Some(number));
                assert_eq!(part.field_type, Some(kind));
                assert_eq!(part.key_type, None);
                assert_eq!(part.value_type, None);
                assert!(part.subscript.is_none(), "{part:?}");
            }
        }
    }
    Ok(())
}

macro_rules! presence_tests {
    ($syntax:ident, $unknown:expr, $combined_unknown:expr, $required_unknown:expr) => {
        mod $syntax {
            use super::{
                assert_enum,
                generated::validation::enum_presence::$syntax::{EnumRules, RequiredEnum},
            };

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/103
            #[test]
            fn absent_and_valid_present_enums_pass() -> Result<(), buffa::DecodeError> {
                assert_enum::<EnumRules>(1, "defined", None, &[])?;
                for value in [0, 1, -1] {
                    assert_enum::<EnumRules>(1, "defined", Some(value), &[])?;
                }
                for (number, name) in [
                    (2, "constant"),
                    (3, "allowed"),
                    (4, "disallowed"),
                    (6, "combined"),
                ] {
                    assert_enum::<EnumRules>(number, name, Some(1), &[])?;
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/103
            #[test]
            fn undefined_numbers_follow_enum_openness() -> Result<(), buffa::DecodeError> {
                for value in [7, -7, i32::MIN, i32::MAX] {
                    assert_enum::<EnumRules>(1, "defined", Some(value), &$unknown)?;
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/103
            #[test]
            fn present_zero_enforces_const_in_and_not_in() -> Result<(), buffa::DecodeError> {
                for (number, name, rule) in [
                    (2, "constant", "const"),
                    (3, "allowed", "in"),
                    (4, "disallowed", "not_in"),
                ] {
                    assert_enum::<EnumRules>(number, name, Some(0), &[rule])?;
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/103
            #[test]
            fn combined_rules_report_every_violation() -> Result<(), buffa::DecodeError> {
                assert_enum::<EnumRules>(6, "combined", Some(0), &["const", "in", "not_in"])?;
                assert_enum::<EnumRules>(6, "combined", Some(7), &$combined_unknown)
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/103
            #[test]
            fn disabled_defined_only_preserves_not_in() -> Result<(), buffa::DecodeError> {
                assert_enum::<EnumRules>(5, "disabled", Some(7), &[])?;
                assert_enum::<EnumRules>(5, "disabled", Some(0), &["not_in"])
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/103
            #[test]
            fn ignore_rules_preserve_explicit_presence() -> Result<(), buffa::DecodeError> {
                assert_enum::<EnumRules>(7, "ignored", Some(7), &[])?;
                assert_enum::<EnumRules>(8, "zero", None, &[])?;
                assert_enum::<EnumRules>(8, "zero", Some(0), &["not_in"])
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/103
            #[test]
            fn required_checks_presence_before_enum_rules() -> Result<(), buffa::DecodeError> {
                assert_enum::<RequiredEnum>(1, "value", None, &["required"])?;
                assert_enum::<RequiredEnum>(1, "value", Some(1), &[])?;
                assert_enum::<RequiredEnum>(1, "value", Some(0), &["not_in"])?;
                assert_enum::<RequiredEnum>(1, "value", Some(7), &$required_unknown)
            }
        }
    };
}

presence_tests!(
    editions,
    ["defined_only"],
    ["const", "defined_only", "in"],
    ["defined_only"]
);
presence_tests!(proto2, [], [], ["required"]);
presence_tests!(
    proto3,
    ["defined_only"],
    ["const", "defined_only", "in"],
    ["defined_only"]
);
