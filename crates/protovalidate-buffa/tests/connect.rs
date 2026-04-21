#![cfg(feature = "connect")]

use std::borrow::Cow;

use connectrpc::ErrorCode;
use protovalidate_buffa::{FieldPath, FieldPathElement, ValidationError, Violation};

fn single_violation() -> ValidationError {
    ValidationError {
        violations: vec![Violation {
            field: FieldPath {
                elements: vec![FieldPathElement {
                    field_number: None,
                    field_name: Some(Cow::Borrowed("code")),
                    field_type: None,
                    key_type: None,
                    value_type: None,
                    subscript: None,
                }],
            },
            rule: FieldPath::default(),
            rule_id: "string.min_len".into(),
            message: "value length must be at least 1 byte".into(),
            for_key: false,
        }],
        ..Default::default()
    }
}

#[test]
fn into_connect_error_maps_to_invalid_argument() {
    let err = single_violation().into_connect_error();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    let msg = err.message.as_deref().unwrap_or("");
    assert!(msg.contains("code"), "message was: {msg}");
    assert!(msg.contains("string.min_len"), "message was: {msg}");
}
