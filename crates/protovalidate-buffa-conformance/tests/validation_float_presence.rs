//! Finite rules retain presence and violation metadata in owned messages and views.

#![warn(rust_2018_idioms)]

use buffa::{HasMessageView, encoding::encode_varint};
use protovalidate_buffa::{FieldType, Subscript, Validate};

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

fn push_value(bytes: &mut Vec<u8>, number: u8, kind: FieldType, value: f64) {
    let tag = u64::from(number) << 3;
    match kind {
        FieldType::Float => {
            encode_varint(tag | 5, bytes);
            #[allow(
                clippy::cast_possible_truncation,
                reason = "test values fit f32 or are nonfinite"
            )]
            let value = value as f32;
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        FieldType::Double => {
            encode_varint(tag | 1, bytes);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        _ => unreachable!("floating-point fixtures only"),
    }
}

/// Raw wire input preserves explicit zero and NaN. Repeated cases prepend
/// valid elements so the failing index must survive both decoding paths.
fn assert_float<M>(
    number: u8,
    name: &str,
    kind: FieldType,
    value: Option<f64>,
    index: Option<u64>,
    expected: &[&str],
) -> Result<(), buffa::DecodeError>
where
    M: HasMessageView + Validate,
    for<'a> M::View<'a>: Validate,
{
    let mut bytes = Vec::new();
    if let Some(value) = value {
        for _ in 0..index.unwrap_or(0) {
            push_value(&mut bytes, number, kind, 1.0);
        }
        push_value(&mut bytes, number, kind, value);
    }
    let owned = M::decode_from_slice(&bytes)?;
    let view = M::decode_view(&bytes)?;
    let (family, family_number) = match kind {
        FieldType::Float => ("float", 1),
        FieldType::Double => ("double", 2),
        _ => unreachable!("floating-point fixtures only"),
    };
    for result in [owned.validate(), view.validate()] {
        let violations = result.err().map_or_else(Vec::new, |error| {
            assert!(error.compile_error.is_none(), "{error:?}");
            assert!(error.runtime_error.is_none(), "{error:?}");
            error.violations
        });
        assert_eq!(
            violations.len(),
            expected.len(),
            "{name}={value:?}: {violations:?}"
        );
        for (violation, rule) in violations.iter().zip(expected) {
            assert_eq!(violation.rule_id, format!("{family}.{rule}"));
            assert!(!violation.for_key);
            assert_eq!(violation.field.elements.len(), 1);
            let field = &violation.field.elements[0];
            assert_eq!(field.field_name.as_deref(), Some(name));
            assert_eq!(field.field_number, Some(i32::from(number)));
            assert_eq!(field.field_type, Some(kind));
            assert_eq!(field.key_type, None);
            assert_eq!(field.value_type, None);
            match (&field.subscript, index) {
                (Some(Subscript::Index(actual)), Some(expected)) => assert_eq!(*actual, expected),
                (None, None) => {}
                _ => panic!("unexpected subscript: {field:?}"),
            }
            let (rule_number, rule_type) = match *rule {
                "finite" => (8, FieldType::Bool),
                "gt" => (4, kind),
                "gte" => (5, kind),
                _ => unreachable!("unexpected floating-point rule"),
            };
            let mut path = Vec::new();
            if index.is_some() {
                path.extend([
                    ("repeated", 18, FieldType::Message),
                    ("items", 4, FieldType::Message),
                ]);
            }
            path.extend([
                (family, family_number, FieldType::Message),
                (rule, rule_number, rule_type),
            ]);
            assert_eq!(violation.rule.elements.len(), path.len());
            for (part, (name, number, kind)) in violation.rule.elements.iter().zip(path) {
                assert_eq!(part.field_name.as_deref(), Some(name));
                assert_eq!(part.field_number, Some(number));
                assert_eq!(part.field_type, Some(kind));
                assert_eq!(part.key_type, None);
                assert_eq!(part.value_type, None);
                assert!(part.subscript.is_none());
            }
        }
    }
    Ok(())
}

macro_rules! presence_tests {
    ($syntax:ident) => {
        mod $syntax {
            use super::{
                assert_float, generated::validation::float_presence::$syntax::FiniteRules,
            };
            use protovalidate_buffa::FieldType::{Double, Float};

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/111
            #[test]
            fn absent_and_finite_values_pass() -> Result<(), buffa::DecodeError> {
                for (number, name, kind, index) in [
                    (1, "float_value", Float, None),
                    (2, "double_value", Double, None),
                    (3, "float_items", Float, Some(1)),
                    (4, "double_items", Double, Some(1)),
                ] {
                    assert_float::<FiniteRules>(number, name, kind, None, index, &[])?;
                    for value in [
                        0.0,
                        -0.0,
                        1.0,
                        -1.0,
                        f64::from(f32::MAX),
                        f64::from(f32::MIN_POSITIVE),
                    ] {
                        assert_float::<FiniteRules>(number, name, kind, Some(value), index, &[])?;
                    }
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/111
            #[test]
            fn nonfinite_values_report_finite_with_metadata() -> Result<(), buffa::DecodeError> {
                for (number, name, kind, index) in [
                    (1, "float_value", Float, None),
                    (2, "double_value", Double, None),
                    (3, "float_items", Float, Some(1)),
                    (4, "double_items", Double, Some(1)),
                ] {
                    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
                        assert_float::<FiniteRules>(
                            number,
                            name,
                            kind,
                            Some(value),
                            index,
                            &["finite"],
                        )?;
                    }
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/111
            #[test]
            fn finite_and_bounds_report_independent_violations() -> Result<(), buffa::DecodeError> {
                for (number, name, kind, index, bound) in [
                    (5, "float_bounds", Float, None, "gt"),
                    (6, "double_bounds", Double, None, "gt"),
                    (7, "float_bound_items", Float, Some(1), "gte"),
                    (8, "double_bound_items", Double, Some(1), "gte"),
                ] {
                    assert_float::<FiniteRules>(number, name, kind, Some(1.0), index, &[])?;
                    assert_float::<FiniteRules>(number, name, kind, Some(-1.0), index, &[bound])?;
                    assert_float::<FiniteRules>(
                        number,
                        name,
                        kind,
                        Some(f64::INFINITY),
                        index,
                        &["finite"],
                    )?;
                    for value in [f64::NAN, f64::NEG_INFINITY] {
                        assert_float::<FiniteRules>(
                            number,
                            name,
                            kind,
                            Some(value),
                            index,
                            &[bound, "finite"],
                        )?;
                    }
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/111
            #[test]
            fn disabled_and_ignored_finite_rules_pass() -> Result<(), buffa::DecodeError> {
                for (number, name, kind, index) in [
                    (9, "float_disabled", Float, None),
                    (10, "double_disabled", Double, None),
                    (11, "float_ignored", Float, None),
                    (12, "double_ignored", Double, None),
                    (15, "float_ignored_items", Float, Some(1)),
                    (16, "double_ignored_items", Double, Some(1)),
                ] {
                    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
                        assert_float::<FiniteRules>(number, name, kind, Some(value), index, &[])?;
                    }
                }
                Ok(())
            }

            // https://github.com/mathematic-inc/protovalidate-buffa/discussions/111
            #[test]
            fn ignore_zero_preserves_presence_and_checks_nonfinite_values()
            -> Result<(), buffa::DecodeError> {
                for (number, name, kind, index) in [
                    (13, "float_zero", Float, None),
                    (14, "double_zero", Double, None),
                    (17, "float_zero_items", Float, Some(1)),
                    (18, "double_zero_items", Double, Some(1)),
                ] {
                    assert_float::<FiniteRules>(number, name, kind, None, index, &[])?;
                    let zero_rules = if index.is_some() {
                        &[][..]
                    } else {
                        &["gt"][..]
                    };
                    assert_float::<FiniteRules>(number, name, kind, Some(0.0), index, zero_rules)?;
                    assert_float::<FiniteRules>(
                        number,
                        name,
                        kind,
                        Some(f64::INFINITY),
                        index,
                        &["finite"],
                    )?;
                    assert_float::<FiniteRules>(
                        number,
                        name,
                        kind,
                        Some(f64::NAN),
                        index,
                        &["gt", "finite"],
                    )?;
                }
                Ok(())
            }
        }
    };
}

presence_tests!(proto2);
presence_tests!(proto3);
presence_tests!(editions2023);
presence_tests!(editions2024);

// https://github.com/mathematic-inc/protovalidate-buffa/discussions/111
#[test]
fn implicit_presence_and_repeated_fields_enforce_finite() -> Result<(), buffa::DecodeError> {
    use generated::validation::float_presence::proto3::ImplicitFinite;
    use protovalidate_buffa::FieldType::{Double, Float};

    for (number, name, kind, index) in [
        (1, "float_value", Float, None),
        (2, "double_value", Double, None),
        (3, "float_items", Float, Some(1)),
        (4, "double_items", Double, Some(1)),
    ] {
        assert_float::<ImplicitFinite>(number, name, kind, None, index, &[])?;
        assert_float::<ImplicitFinite>(number, name, kind, Some(0.0), index, &[])?;
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_float::<ImplicitFinite>(number, name, kind, Some(value), index, &["finite"])?;
        }
    }
    Ok(())
}
