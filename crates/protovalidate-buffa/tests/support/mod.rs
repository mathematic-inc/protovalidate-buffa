use protovalidate_buffa::{
    FieldPath, FieldPathElement, FieldType, Subscript, ValidationError, Violation,
};

pub fn single_violation() -> ValidationError {
    ValidationError {
        violations: vec![Violation {
            field: FieldPath {
                elements: vec![
                    FieldPathElement {
                        field_number: Some(7),
                        field_name: Some("addresses".into()),
                        field_type: Some(FieldType::Message),
                        key_type: Some(FieldType::String),
                        value_type: Some(FieldType::Message),
                        subscript: Some(Subscript::StringKey("private-key".into())),
                    },
                    FieldPathElement {
                        field_number: Some(1),
                        field_name: Some("codes".into()),
                        field_type: Some(FieldType::String),
                        subscript: Some(Subscript::Index(0)),
                        ..Default::default()
                    },
                ],
            },
            rule: FieldPath {
                elements: vec![FieldPathElement {
                    field_number: Some(23),
                    field_name: Some("cel".into()),
                    field_type: Some(FieldType::Message),
                    subscript: Some(Subscript::Index(2)),
                    ..Default::default()
                }],
            },
            rule_id: "address.code".into(),
            message: "invalid value: private-value".into(),
            for_key: true,
        }],
        ..Default::default()
    }
}
