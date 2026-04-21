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
    let validators = scan::gather(request)?;
    emit::render(&validators)
}
