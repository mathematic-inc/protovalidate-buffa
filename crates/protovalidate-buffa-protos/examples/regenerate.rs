//! Regenerate the checked-in schema with the existing Buffa generator.
//! From the workspace root, using the repository's pinned protoc:
//!
//! ```sh
//! PROTOC="$(mise which protoc)" mise exec -- cargo run --locked \
//!     -p protovalidate-buffa-protos --example regenerate
//! ```
//! Only maintainers regenerating sources need protoc and its WKT includes.

#![warn(rust_2018_idioms)]

use std::{error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let protoc = PathBuf::from(
        std::env::var_os("PROTOC")
            .ok_or("set PROTOC to the absolute protoc executable, e.g. with mise which protoc")?,
    );
    let includes = protoc
        .parent()
        .and_then(|bin| bin.parent())
        .ok_or("PROTOC must have a parent installation directory")?
        .join("include");
    if !includes.join("google/protobuf/descriptor.proto").is_file() {
        return Err("PROTOC's installation must include google/protobuf/descriptor.proto".into());
    }
    buffa_build::Config::new()
        .files(&[root.join("proto/buf/validate/validate.proto")])
        .includes(&[root.join("proto"), includes])
        .out_dir(root.join("src/generated"))
        .include_file("mod.rs")
        .generate_json(true)
        .gate_impls_on_crate_features(true)
        .compile()?;
    Ok(())
}
