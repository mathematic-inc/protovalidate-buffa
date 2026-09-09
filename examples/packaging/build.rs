//! Generate both examples from the same descriptors for Buffa and validation.

use std::{env, fs, path::PathBuf, process::Command};

use buffa::Message as _;
use buffa_codegen::{
    CodeGenConfig,
    generated::{compiler::CodeGeneratorRequest, descriptor::FileDescriptorSet},
};
use protoc_gen_protovalidate_buffa::{emit, scan};

fn main() -> anyhow::Result<()> {
    let out = PathBuf::from(env::var("OUT_DIR")?);
    let schemas = "../../crates/protovalidate-buffa-protos/proto";
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed={schemas}");
    println!("cargo:rerun-if-env-changed=PROTOC");
    let sources = [
        "user.proto",
        "order.proto",
        "line_item.proto",
        "shared/currency.proto",
    ];
    let descriptors = out.join("examples.binpb");
    let status = Command::new(env::var_os("PROTOC").unwrap_or_else(|| "protoc".into()))
        .arg("-Iproto")
        .arg(format!("-I{schemas}"))
        .arg("--include_imports")
        .arg(format!("--descriptor_set_out={}", descriptors.display()))
        .args(sources)
        .status()?;
    anyhow::ensure!(
        status.success(),
        "protoc failed to compile the example schemas"
    );
    let fds = FileDescriptorSet::decode_from_slice(&fs::read(descriptors)?)?;
    let request = CodeGeneratorRequest {
        file_to_generate: sources.into_iter().map(str::to_string).collect(),
        proto_file: fds.file,
        ..Default::default()
    };

    let mut config = CodeGenConfig::default();
    config.file_per_package = true;
    // Both plugins write to one directory. The handwritten Rust modules below
    // include only each package's types and validators.
    for file in buffa_codegen::generate(&request.proto_file, &request.file_to_generate, &config)? {
        fs::write(out.join(&file.name), file.content)?;
    }
    let options = emit::Options {
        packaging: false,
        ..Default::default()
    };
    for file in emit::render_with_options(&scan::gather(&request)?, &options)? {
        fs::write(
            out.join(file.name.as_deref().expect("generated filename")),
            file.content.as_deref().expect("generated content"),
        )?;
    }
    Ok(())
}
