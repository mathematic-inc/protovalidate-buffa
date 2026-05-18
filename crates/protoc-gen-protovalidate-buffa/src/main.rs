//! Reads a `CodeGeneratorRequest` on stdin, emits a `CodeGeneratorResponse`
//! on stdout.

use std::io::{self, Read, Write};

use buffa::Message;
use buffa_codegen::generated::{
    compiler::{CodeGeneratorRequest, CodeGeneratorResponse},
    descriptor::Edition,
};
use protoc_gen_protovalidate_buffa::{emit, scan};

fn main() -> anyhow::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let request = CodeGeneratorRequest::decode_from_slice(&input)?;

    let response = match run(&request) {
        Ok(files) => CodeGeneratorResponse {
            supported_features: Some(1 | 2), // PROTO3_OPTIONAL | SUPPORTS_EDITIONS
            minimum_edition: Some(Edition::EDITION_PROTO2 as i32),
            maximum_edition: Some(Edition::EDITION_2024 as i32),
            file: files,
            error: None,
            ..Default::default()
        },
        Err(e) => CodeGeneratorResponse {
            error: Some(e.to_string()),
            ..Default::default()
        },
    };

    let mut out = Vec::new();
    response.encode(&mut out);
    io::stdout().write_all(&out)?;
    Ok(())
}

fn run(
    request: &CodeGeneratorRequest,
) -> anyhow::Result<Vec<buffa_codegen::generated::compiler::code_generator_response::File>> {
    let opts = parse_opts(request.parameter.as_deref().unwrap_or(""));
    let validators = scan::gather(request)?;
    emit::render_with_options(&validators, &opts)
}

/// Parse the `opt: [...]` parameters passed via `buf.gen.yaml`. Accepts a
/// comma-separated `key=value,flag,...` list (the format protoc / buf use
/// to invoke plugins). Unknown keys are ignored so callers can pass
/// forward-compatible options.
fn parse_opts(parameter: &str) -> emit::Options {
    let mut opts = emit::Options::default();
    for part in parameter.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=')
            && k.trim() == "proto_module"
        {
            opts.proto_module = v.trim().to_string();
        }
    }
    opts
}
