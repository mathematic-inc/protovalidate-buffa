use buffa_descriptor::generated::descriptor::field_descriptor_proto::Type;

use crate::{FieldPath, FieldType, Subscript, ValidationError, Violation, proto};

pub enum Exposure {
    Diagnostic,
    #[cfg(feature = "connect")]
    Public,
}

impl ValidationError {
    /// Copies all violations into the canonical `buf.validate.Violations` type.
    ///
    /// Requires `protos`. Preserves messages, map keys, indexes, schema paths,
    /// and rule IDs without a size limit. Empty paths, rule IDs and messages are
    /// absent; `for_key` is present only when true. Compilation and evaluation
    /// diagnostics remain on `self`: the schema has no fields for them.
    ///
    /// This diagnostic representation can contain rejected data. For public RPC
    /// request errors, use `into_connect_error` (requires `connect`), which
    /// applies redaction, size limits, and status classification.
    ///
    /// ```
    /// use protovalidate_buffa::{ValidationError, proto};
    /// let error = ValidationError::default();
    /// let details: proto::Violations = error.to_proto();
    /// assert!(details.violations.is_empty());
    /// ```
    #[must_use]
    pub fn to_proto(&self) -> proto::Violations {
        proto::Violations {
            violations: self
                .violations
                .iter()
                .map(|v| convert_violation(v, &Exposure::Diagnostic))
                .collect(),
            ..Default::default()
        }
    }
}

pub fn convert_violation(v: &Violation, exposure: &Exposure) -> proto::Violation {
    proto::Violation {
        field: convert_path(&v.field, exposure).into(),
        rule: convert_path(&v.rule, exposure).into(),
        rule_id: nonempty(&v.rule_id),
        message: match exposure {
            Exposure::Diagnostic => nonempty(&v.message),
            #[cfg(feature = "connect")]
            Exposure::Public => None,
        },
        for_key: v.for_key.then_some(true),
        ..Default::default()
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn convert_path(path: &FieldPath, exposure: &Exposure) -> Option<proto::FieldPath> {
    if path.elements.is_empty() {
        return None;
    }
    Some(proto::FieldPath {
        elements: path
            .elements
            .iter()
            .map(|element| proto::FieldPathElement {
                field_number: element.field_number,
                field_name: element.field_name.as_deref().map(str::to_owned),
                field_type: element.field_type.map(convert_type),
                key_type: element.key_type.map(convert_type),
                value_type: element.value_type.map(convert_type),
                subscript: element
                    .subscript
                    .as_ref()
                    .filter(|subscript| {
                        let _ = subscript; // Also compiled without the connect feature.
                        match exposure {
                            Exposure::Diagnostic => true,
                            // Indexes are structural; map keys contain input data.
                            #[cfg(feature = "connect")]
                            Exposure::Public => matches!(subscript, Subscript::Index(_)),
                        }
                    })
                    .map(convert_subscript),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    })
}

fn convert_subscript(
    subscript: &Subscript,
) -> proto::__buffa::oneof::field_path_element::Subscript {
    use proto::__buffa::oneof::field_path_element::Subscript as S;
    match subscript {
        Subscript::Index(value) => S::Index(*value),
        Subscript::BoolKey(value) => S::BoolKey(*value),
        Subscript::IntKey(value) => S::IntKey(*value),
        Subscript::UintKey(value) => S::UintKey(*value),
        Subscript::StringKey(value) => S::StringKey(value.to_string()),
    }
}

const fn convert_type(field_type: FieldType) -> Type {
    match field_type {
        FieldType::Double => Type::TYPE_DOUBLE,
        FieldType::Float => Type::TYPE_FLOAT,
        FieldType::Int64 => Type::TYPE_INT64,
        FieldType::Uint64 => Type::TYPE_UINT64,
        FieldType::Int32 => Type::TYPE_INT32,
        FieldType::Fixed64 => Type::TYPE_FIXED64,
        FieldType::Fixed32 => Type::TYPE_FIXED32,
        FieldType::Bool => Type::TYPE_BOOL,
        FieldType::String => Type::TYPE_STRING,
        FieldType::Group => Type::TYPE_GROUP,
        FieldType::Message => Type::TYPE_MESSAGE,
        FieldType::Bytes => Type::TYPE_BYTES,
        FieldType::Uint32 => Type::TYPE_UINT32,
        FieldType::Enum => Type::TYPE_ENUM,
        FieldType::Sfixed32 => Type::TYPE_SFIXED32,
        FieldType::Sfixed64 => Type::TYPE_SFIXED64,
        FieldType::Sint32 => Type::TYPE_SINT32,
        FieldType::Sint64 => Type::TYPE_SINT64,
    }
}
