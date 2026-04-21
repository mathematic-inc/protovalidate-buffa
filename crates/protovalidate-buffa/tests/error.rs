use std::borrow::Cow;

use protovalidate_buffa::{FieldPath, FieldPathElement, Subscript, ValidationError, Violation};

fn path(parts: &[(&'static str, Option<u64>)]) -> FieldPath {
    let elements = parts
        .iter()
        .map(|(name, idx)| FieldPathElement {
            field_number: None,
            field_name: Some(Cow::Borrowed(name)),
            field_type: None,
            key_type: None,
            value_type: None,
            subscript: idx.map(Subscript::Index),
        })
        .collect();
    FieldPath { elements }
}

#[test]
fn display_formats_single_violation() {
    let err = ValidationError {
        violations: vec![Violation {
            field: path(&[("pom", None), ("code", None)]),
            rule: path(&[("string", None), ("min_len", None)]),
            rule_id: "string.min_len".into(),
            message: "value length must be at least 1 byte (got 0)".into(),
            for_key: false,
        }],
        ..Default::default()
    };
    assert_eq!(
        err.to_string(),
        "pom.code: value length must be at least 1 byte (got 0) [string.min_len]",
    );
}

#[test]
fn display_joins_multiple_with_semicolons() {
    let err = ValidationError {
        violations: vec![
            Violation {
                field: path(&[("tags", Some(3))]),
                rule: path(&[
                    ("repeated", None),
                    ("items", None),
                    ("string", None),
                    ("min_len", None),
                ]),
                rule_id: "string.min_len".into(),
                message: "value length must be at least 1 byte".into(),
                for_key: false,
            },
            Violation {
                field: path(&[("code", None)]),
                rule: path(&[("string", None), ("pattern", None)]),
                rule_id: "string.pattern".into(),
                message: "value must match /^\\S+$/".into(),
                for_key: false,
            },
        ],
        ..Default::default()
    };
    assert_eq!(
        err.to_string(),
        "tags[3]: value length must be at least 1 byte [string.min_len]; code: value must match /^\\S+$/ [string.pattern]",
    );
}

#[test]
fn empty_violations_is_invalid_construction_still_ok() {
    let err = ValidationError::default();
    assert_eq!(err.to_string(), "");
}

#[test]
fn string_subscript_renders_with_quotes() {
    let err = ValidationError {
        violations: vec![Violation {
            field: FieldPath {
                elements: vec![FieldPathElement {
                    field_number: None,
                    field_name: Some(Cow::Borrowed("deltas")),
                    field_type: None,
                    key_type: None,
                    value_type: None,
                    subscript: Some(Subscript::StringKey(Cow::Borrowed("xs"))),
                }],
            },
            rule: path(&[("map", None), ("values", None)]),
            rule_id: "string.max_len".into(),
            message: "too long".into(),
            for_key: false,
        }],
        ..Default::default()
    };
    assert_eq!(err.to_string(), "deltas[\"xs\"]: too long [string.max_len]");
}
