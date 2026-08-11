//! Executor for the upstream `protovalidate-conformance` harness.
//!
//! Protocol: read a `TestConformanceRequest` on stdin, write a
//! `TestConformanceResponse` on stdout. Each case is a `google.protobuf.Any`
//! whose `type_url` identifies a message type.

use std::io::{self, Read, Write};

use buffa::Message;
use protovalidate_buffa_conformance::{
    generated::buf::validate::conformance::harness::{
        __buffa::oneof::test_result, TestConformanceRequest, TestConformanceResponse, TestResult,
    },
    pb_google, registry,
};

fn main() -> anyhow::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let request = TestConformanceRequest::decode_from_slice(&input)?;

    // Build into the response's own map field rather than naming the type:
    // buffa generates map fields with its `foldhash` hasher, not the
    // `std::hash::RandomState` that a bare `HashMap<K, V>` would default to.
    let mut response = TestConformanceResponse::default();
    for (name, any) in &request.cases {
        response.results.insert(name.clone(), run_case(any));
    }

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
