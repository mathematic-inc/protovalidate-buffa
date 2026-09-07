#![cfg(feature = "connect")]

mod support;

use std::error::Error as _;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use buffa::Message;
use connectrpc::{ErrorCode, ErrorDetail};
use protovalidate_buffa::{FieldPath, Subscript, ValidationError, decode_violations, proto};
use support::single_violation;

#[test]
fn request_details_retain_identity_and_redact_input() {
    use proto::__buffa::oneof::field_path_element::Subscript as P;
    let error = single_violation().into_connect_error();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.message.as_deref(), Some("request validation failed"));
    assert_eq!(error.details.len(), 1);
    assert_eq!(error.details[0].type_url, "buf.validate.Violations");
    assert!(error.details[0].debug.is_none());
    let details = decode_violations(&error.details[0]).unwrap().unwrap();
    let violation = &details.violations[0];
    assert_eq!(violation.rule_id.as_deref(), Some("address.code"));
    assert!(violation.message.is_none());
    assert_eq!(violation.for_key, Some(true));
    assert!(violation.field.elements[0].subscript.is_none());
    assert_eq!(
        violation.field.elements[0].field_name.as_deref(),
        Some("addresses")
    );
    assert_eq!(violation.field.elements[0].field_number, Some(7));
    assert_eq!(violation.field.elements[1].subscript, Some(P::Index(0)));
    assert_eq!(violation.rule.elements[0].subscript, Some(P::Index(2)));
    let bytes = details.encode_to_vec();
    assert!(!String::from_utf8_lossy(&bytes).contains("private-"));
    let original = error
        .source()
        .unwrap()
        .downcast_ref::<ValidationError>()
        .unwrap();
    assert!(original.violations[0].message.contains("private-value"));
    assert!(matches!(
        original.violations[0].field.elements[0].subscript,
        Some(Subscript::StringKey(_))
    ));
}

#[test]
fn all_map_selectors_are_omitted_from_both_paths() {
    for key in [
        Subscript::BoolKey(false),
        Subscript::IntKey(i64::MIN),
        Subscript::UintKey(u64::MAX),
        Subscript::StringKey("secret".into()),
    ] {
        let mut error = single_violation();
        error.violations[0].field.elements[0].subscript = Some(key.clone());
        error.violations[0].rule.elements[0].subscript = Some(key);
        let rpc = error.into_connect_error();
        let details = decode_violations(&rpc.details[0]).unwrap().unwrap();
        assert!(details.violations[0].field.elements[0].subscript.is_none());
        assert!(details.violations[0].rule.elements[0].subscript.is_none());
    }
}

#[test]
fn defects_take_precedence_over_violations_even_with_empty_diagnostics() {
    for compile_error in [None, Some(String::new()), Some("private-compile".into())] {
        for runtime_error in [None, Some(String::new()), Some("private-runtime".into())] {
            for violations in [vec![], single_violation().violations] {
                if compile_error.is_none() && runtime_error.is_none() && !violations.is_empty() {
                    continue;
                }
                let rpc = ValidationError {
                    violations,
                    compile_error: compile_error.clone(),
                    runtime_error: runtime_error.clone(),
                }
                .into_connect_error();
                assert_eq!(rpc.code, ErrorCode::Internal);
                assert_eq!(rpc.message.as_deref(), Some("validation failed"));
                assert!(rpc.details.is_empty());
                let source = rpc
                    .source()
                    .unwrap()
                    .downcast_ref::<ValidationError>()
                    .unwrap();
                assert_eq!(source.compile_error, compile_error);
                assert_eq!(source.runtime_error, runtime_error);
            }
        }
    }
}

/// A sole rule ID uses two three-byte length-delimited wrappers at this size:
/// 4090 ID bytes + 3 for `Violation.rule_id` + 3 for `Violations.violations` = 4096.
#[test]
fn byte_boundary_keeps_whole_identifiers_and_reports_truncation() {
    for (id_len, fits) in [(4089, true), (4090, true), (4091, false)] {
        let mut error = single_violation();
        let v = &mut error.violations[0];
        v.field = FieldPath::default();
        v.rule = FieldPath::default();
        v.for_key = false;
        v.rule_id = "x".repeat(id_len).into();
        let rpc = error.into_connect_error();
        assert_eq!(rpc.code, ErrorCode::InvalidArgument);
        assert_eq!(rpc.details.is_empty(), !fits);
        assert_eq!(rpc.message.as_deref().unwrap().contains("truncated"), !fits);
        if fits {
            let details = decode_violations(&rpc.details[0]).unwrap().unwrap();
            assert_eq!(details.encode_to_vec().len(), id_len + 6);
            assert_eq!(
                details.violations[0].rule_id.as_ref().unwrap().len(),
                id_len
            );
        }
    }
}

#[test]
fn many_violations_are_a_bounded_prefix_and_source_is_complete() {
    let mut error = single_violation();
    error.violations = vec![error.violations[0].clone(); 1000];
    let rpc = error.into_connect_error();
    let details = decode_violations(&rpc.details[0]).unwrap().unwrap();
    assert!(details.encode_to_vec().len() <= 4096);
    assert_ne!(details.violations.len(), 0);
    assert!(details.violations.len() < 1000);
    assert!(rpc.message.as_deref().unwrap().contains("truncated"));
    assert_eq!(
        rpc.source()
            .unwrap()
            .downcast_ref::<ValidationError>()
            .unwrap()
            .violations
            .len(),
        1000
    );
}

#[test]
fn oversized_schema_names_are_omitted_and_rejected_values_are_never_copied() {
    let mut error = single_violation();
    error.violations[0].message = "private-value".repeat(100_000).into();
    error.violations[0].field.elements[0].subscript =
        Some(Subscript::StringKey("private-key".repeat(100_000).into()));
    assert_eq!(error.clone().into_connect_error().details.len(), 1);
    error.violations[0].field.elements[0].field_name = Some("schema_name".repeat(1000).into());
    let rpc = error.into_connect_error();
    assert!(rpc.details.is_empty());
    assert!(rpc.message.as_deref().unwrap().contains("truncated"));
}

#[test]
fn decoder_accepts_type_urls_padding_peer_data_and_unknown_fields() {
    let diagnostic = single_violation().to_proto();
    let mut bytes = diagnostic.encode_to_vec();
    // Unknown field 100, varint 1, is valid forward-compatible protobuf.
    bytes.extend_from_slice(&[0xa0, 0x06, 0x01]);
    for name in [
        "buf.validate.Violations",
        "type.googleapis.com/buf.validate.Violations",
        "https://example.com/types/buf.validate.Violations",
    ] {
        for value in [STANDARD.encode(&bytes), STANDARD_NO_PAD.encode(&bytes)] {
            let detail = ErrorDetail {
                type_url: name.into(),
                value: Some(value),
                debug: None,
            };
            let decoded = decode_violations(&detail).unwrap().unwrap();
            assert_eq!(decoded.violations, diagnostic.violations);
        }
    }
}

#[test]
fn decoder_distinguishes_unrelated_details_from_invalid_matching_details() {
    let mut detail = ErrorDetail {
        type_url: "other.Violations".into(),
        value: Some("!".repeat(6000)),
        debug: None,
    };
    assert!(decode_violations(&detail).unwrap().is_none());
    detail.type_url = "buf.validate.ViolationsExtra".into();
    assert!(decode_violations(&detail).unwrap().is_none());
    detail.type_url = "buf.validate.Violations".into();
    for value in [
        None,
        Some("!".into()),
        Some(String::new()),
        Some(STANDARD_NO_PAD.encode([0x0a, 0xff])),
        Some(STANDARD_NO_PAD.encode([0xa0, 0x06, 1])),
        Some("A".repeat(5465)),
    ] {
        detail.value = value;
        assert!(decode_violations(&detail).is_err());
    }
    // 4097 decoded bytes still fit in 5464 base64 bytes; the decoded limit
    // must be checked independently, before protobuf parsing/allocation.
    detail.value = Some(STANDARD.encode(vec![0; 4097]));
    assert!(decode_violations(&detail).is_err());
}
