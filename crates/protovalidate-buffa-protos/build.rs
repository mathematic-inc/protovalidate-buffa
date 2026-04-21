//! Compiles the vendored `buf/validate/validate.proto` into Rust types via
//! `buffa-build`. The proto file lives under this crate's own `proto/`
//! directory so the crate is self-contained and does not assume any
//! particular workspace layout.

fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let proto_root = manifest.join("proto");
    let validate_proto = proto_root.join("buf/validate/validate.proto");

    println!("cargo:rerun-if-changed={}", validate_proto.display());
    println!("cargo:rerun-if-env-changed=PROTOC");

    // validate.proto imports google/protobuf/{descriptor,duration,field_mask,timestamp}.proto.
    // These well-known types are bundled with protoc. Detect the include dir by
    // locating the `protoc` binary and stepping up to its sibling `include/`.
    let protoc_path = std::env::var("PROTOC")
        .unwrap_or_else(|_| which_protoc().unwrap_or_else(|| "protoc".to_string()));
    let protoc_include = std::path::PathBuf::from(&protoc_path)
        .parent() // bin/
        .and_then(|p| p.parent()) // prefix/
        .map(|prefix| prefix.join("include"))
        .filter(|p| p.join("google/protobuf/descriptor.proto").exists());

    let mut includes = vec![proto_root.to_str().expect("utf-8 path").to_string()];
    if let Some(ref inc) = protoc_include {
        includes.push(inc.to_str().expect("utf-8 path").to_string());
    }
    let includes_str: Vec<&str> = includes.iter().map(String::as_str).collect();

    // validate.proto transitively uses FieldDescriptorProto.Type, which is not
    // in buffa_types. Compile all required google.protobuf WKTs locally.
    let mut files = vec![validate_proto.to_str().expect("utf-8 path").to_string()];
    if let Some(ref inc) = protoc_include {
        for wkt in &[
            "google/protobuf/descriptor.proto",
            "google/protobuf/duration.proto",
            "google/protobuf/field_mask.proto",
            "google/protobuf/timestamp.proto",
        ] {
            let p = inc.join(wkt);
            if p.exists() {
                files.push(p.to_str().expect("utf-8 path").to_string());
            }
        }
    }
    let files_str: Vec<&str> = files.iter().map(String::as_str).collect();

    buffa_build::Config::new()
        .files(&files_str)
        .includes(&includes_str)
        .include_file("_include.rs")
        .compile()
        .expect("buf/validate/validate.proto compilation failed");
}

/// Try to find `protoc` on PATH, returning its full path as a String.
/// Unix-only (uses `which`). Windows is not a supported build host.
fn which_protoc() -> Option<String> {
    let output = std::process::Command::new("which")
        .arg("protoc")
        .output()
        .ok()?;
    if output.status.success() {
        let path = String::from_utf8(output.stdout).ok()?.trim().to_string();
        let resolved =
            std::fs::canonicalize(&path).unwrap_or_else(|_| std::path::PathBuf::from(&path));
        Some(resolved.to_string_lossy().into_owned())
    } else {
        None
    }
}
