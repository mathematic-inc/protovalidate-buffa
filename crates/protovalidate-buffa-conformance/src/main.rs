//! Executor for the upstream `protovalidate-conformance` harness.
//!
//! Protocol: read a `TestConformanceRequest` on stdin, write a
//! `TestConformanceResponse` on stdout. Each case is a `google.protobuf.Any`
//! whose `type_url` identifies a message type.

use std::io::{self, Read, Write};

use buffa::Message;

pub mod generated {
    #![allow(
        clippy::all,
        clippy::pedantic,
        clippy::nursery,
        dead_code,
        non_camel_case_types,
        unused_imports,
        reason = "buffa-build generated code — upstream codegen style; do not police"
    )]
    include!(concat!(env!("OUT_DIR"), "/_include.rs"));
}

pub mod registry;

use generated::buf::validate::conformance::harness::{
    test_result, TestConformanceRequest, TestConformanceResponse, TestResult,
};
pub use generated::{buf::validate as pb_validate, google::protobuf as pb_google};

fn main() -> anyhow::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let request = TestConformanceRequest::decode_from_slice(&input)?;

    let mut results: std::collections::HashMap<String, TestResult> =
        std::collections::HashMap::new();
    for (name, any) in &request.cases {
        results.insert(name.clone(), run_case(any));
    }

    let response = TestConformanceResponse {
        results,
        ..Default::default()
    };
    let mut out = Vec::new();
    response.encode(&mut out);
    io::stdout().write_all(&out)?;
    Ok(())
}

fn run_case(any: &pb_google::Any) -> TestResult {
    let type_url = any.type_url.as_str();
    let fqn = type_url.rsplit_once('/').map_or(type_url, |(_, n)| n);
    // Bare google.protobuf.* inputs have no user validator — treat as valid.
    if fqn.starts_with("google.protobuf.") {
        return TestResult {
            result: Some(test_result::Result::Success(true)),
            ..Default::default()
        };
    }
    let result = match registry::dispatch(fqn, &any.value) {
        registry::CaseOutcome::Valid => test_result::Result::Success(true),
        registry::CaseOutcome::Invalid(v) => test_result::Result::ValidationError(Box::new(v)),
        registry::CaseOutcome::RuntimeError(msg) => test_result::Result::RuntimeError(msg),
        registry::CaseOutcome::CompilationError(msg) => test_result::Result::CompilationError(msg),
        registry::CaseOutcome::Unsupported => {
            test_result::Result::UnexpectedError(format!("unsupported message type: {fqn}"))
        }
    };
    TestResult {
        result: Some(result),
        ..Default::default()
    }
}

pub fn to_harness_violations(err: protovalidate_buffa::ValidationError) -> pb_validate::Violations {
    pb_validate::Violations {
        violations: err.violations.into_iter().map(convert_violation).collect(),
        ..Default::default()
    }
}

fn convert_violation(v: protovalidate_buffa::Violation) -> pb_validate::Violation {
    let field = if v.field.elements.is_empty() {
        None
    } else {
        Some(convert_path(&v.field))
    };
    let rule = if v.rule.elements.is_empty() {
        None
    } else {
        Some(convert_path(&v.rule))
    };
    let rule_id = if v.rule_id.is_empty() {
        None
    } else {
        Some(v.rule_id.into_owned())
    };
    let message = if v.message.is_empty() {
        None
    } else {
        Some(v.message.into_owned())
    };
    let for_key = if v.for_key { Some(true) } else { None };
    pb_validate::Violation {
        field: field.into(),
        rule: rule.into(),
        rule_id,
        message,
        for_key,
        ..Default::default()
    }
}

fn convert_path(path: &protovalidate_buffa::FieldPath) -> pb_validate::FieldPath {
    pb_validate::FieldPath {
        elements: path.elements.iter().map(convert_path_element).collect(),
        ..Default::default()
    }
}

fn convert_path_element(
    e: &protovalidate_buffa::FieldPathElement,
) -> pb_validate::FieldPathElement {
    use protovalidate_buffa::Subscript;
    pb_validate::FieldPathElement {
        field_number: e.field_number,
        field_name: e.field_name.as_ref().map(|s| s.clone().into_owned()),
        field_type: e.field_type.map(field_type_to_proto),
        key_type: e.key_type.map(field_type_to_proto),
        value_type: e.value_type.map(field_type_to_proto),
        subscript: e.subscript.as_ref().map(|s| match s {
            Subscript::Index(i) => pb_validate::field_path_element::Subscript::Index(*i),
            Subscript::BoolKey(b) => pb_validate::field_path_element::Subscript::BoolKey(*b),
            Subscript::IntKey(i) => pb_validate::field_path_element::Subscript::IntKey(*i),
            Subscript::UintKey(u) => pb_validate::field_path_element::Subscript::UintKey(*u),
            Subscript::StringKey(s) => {
                pb_validate::field_path_element::Subscript::StringKey(s.clone().into_owned())
            }
        }),
        ..Default::default()
    }
}

const fn field_type_to_proto(
    t: protovalidate_buffa::FieldType,
) -> pb_google::field_descriptor_proto::Type {
    use pb_google::field_descriptor_proto::Type as T;
    use protovalidate_buffa::FieldType as F;
    match t {
        F::Double => T::TYPE_DOUBLE,
        F::Float => T::TYPE_FLOAT,
        F::Int64 => T::TYPE_INT64,
        F::Uint64 => T::TYPE_UINT64,
        F::Int32 => T::TYPE_INT32,
        F::Fixed64 => T::TYPE_FIXED64,
        F::Fixed32 => T::TYPE_FIXED32,
        F::Bool => T::TYPE_BOOL,
        F::String => T::TYPE_STRING,
        F::Group => T::TYPE_GROUP,
        F::Message => T::TYPE_MESSAGE,
        F::Bytes => T::TYPE_BYTES,
        F::Uint32 => T::TYPE_UINT32,
        F::Enum => T::TYPE_ENUM,
        F::Sfixed32 => T::TYPE_SFIXED32,
        F::Sfixed64 => T::TYPE_SFIXED64,
        F::Sint32 => T::TYPE_SINT32,
        F::Sint64 => T::TYPE_SINT64,
    }
}
