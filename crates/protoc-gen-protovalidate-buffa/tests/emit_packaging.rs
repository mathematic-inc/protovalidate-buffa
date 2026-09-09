//! Discussion #58: opt out of packaging without overwriting a consumer's modules.
#![warn(rust_2018_idioms)]

use std::{
    io::Write as _,
    process::{Command, Stdio},
};

use buffa::Message as _;
use buffa_codegen::generated::{
    compiler::{CodeGeneratorRequest, CodeGeneratorResponse},
    descriptor::{DescriptorProto, FileDescriptorProto},
};
use protoc_gen_protovalidate_buffa::{emit, scan};

fn request() -> CodeGeneratorRequest {
    // Neither the directory nor the filename implies the declared package.
    let sources = [
        ("elsewhere/first.proto", "example.v1", "First"),
        ("second.proto", "example.v1", "Second"),
        ("elsewhere/third.proto", "other.v1", "Third"),
    ];
    CodeGeneratorRequest {
        file_to_generate: sources.iter().map(|(file, _, _)| (*file).into()).collect(),
        proto_file: sources
            .iter()
            .map(|(file, package, name)| FileDescriptorProto {
                name: Some((*file).into()),
                package: Some((*package).into()),
                syntax: Some("proto3".into()),
                message_type: vec![DescriptorProto {
                    name: Some((*name).into()),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .collect(),
        parameter: Some("packaging=false".into()),
        ..Default::default()
    }
}

fn invoke_plugin(request: &CodeGeneratorRequest) -> CodeGeneratorResponse {
    let mut child = Command::new(env!("CARGO_BIN_EXE_protoc-gen-protovalidate-buffa"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start plugin");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&request.encode_to_vec())
        .expect("write request");
    let output = child.wait_with_output().expect("read plugin output");
    assert!(output.status.success(), "{:?}", output.stderr);
    CodeGeneratorResponse::decode_from_slice(&output.stdout).expect("decode response")
}

#[test]
fn flat_output_merges_declared_packages_and_includes_owned_and_view_impls() {
    let request = request();
    let response = invoke_plugin(&request);
    assert!(response.error.is_none(), "{:?}", response.error);
    let names: Vec<_> = response
        .file
        .iter()
        .map(|f| f.name.as_deref().unwrap())
        .collect();
    assert_eq!(names, ["example.v1.validate.rs", "other.v1.validate.rs"]);
    for (file, types) in response
        .file
        .iter()
        .zip([&["First", "Second"][..], &["Third"]])
    {
        let content = file.content.as_deref().unwrap();
        syn::parse_file(content).expect("valid Rust syntax");
        assert_eq!(content.matches("use super::*;").count(), 1);
        for name in types {
            assert!(content.contains(&format!("Validate for {name}")));
            assert!(content.contains(&format!("__buffa::view::{name}View<'_>")));
        }
    }
    let scanned = scan::gather(&request).unwrap();
    let options = emit::Options {
        packaging: false,
        ..Default::default()
    };
    assert_eq!(
        response.file,
        emit::render_with_options(&scanned, &options).unwrap()
    );
    assert_eq!(response.supported_features, Some(1 | 2));
    assert!(response.minimum_edition.is_some());
    assert!(response.maximum_edition.is_some());
}

#[test]
fn default_true_and_bare_flag_preserve_packaged_output() {
    let mut request = request();
    let expected = emit::render(&scan::gather(&request).unwrap()).unwrap();
    let names: Vec<_> = expected
        .iter()
        .map(|f| f.name.as_deref().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "elsewhere.first.rs",
            "elsewhere.third.rs",
            "second.rs",
            "elsewhere.mod.rs",
            "second.mod.rs",
            "mod.rs",
        ]
    );
    for parameter in [
        "",
        "packaging=true",
        "packaging",
        "packaging=false,packaging=true",
    ] {
        request.parameter = Some(parameter.into());
        let response = invoke_plugin(&request);
        assert!(
            response.error.is_none(),
            "{parameter}: {:?}",
            response.error
        );
        assert_eq!(response.file, expected, "{parameter}");
    }
}

#[test]
fn flat_output_ignores_proto_module_even_when_it_is_invalid() {
    let mut request = request();
    let expected = invoke_plugin(&request).file;
    request.parameter =
        Some(" proto_module = not a Rust path, packaging = false, unknown=1, ".into());
    let response = invoke_plugin(&request);
    assert!(response.error.is_none(), "{:?}", response.error);
    assert_eq!(response.file, expected);
    let options = emit::Options {
        proto_module: "not a Rust path".into(),
        packaging: false,
    };
    assert_eq!(
        emit::render_with_options(&scan::gather(&request).unwrap(), &options).unwrap(),
        expected
    );
}

#[test]
fn invalid_packaging_returns_error_without_files() {
    let mut request = request();
    for parameter in [
        "packaging=",
        "packaging=no",
        "packaging=0",
        "packaging=FALSE",
        "packaging=false,packaging=oops",
    ] {
        request.parameter = Some(parameter.into());
        let response = invoke_plugin(&request);
        assert!(
            response
                .error
                .unwrap()
                .contains("packaging must be true or false"),
            "{parameter}"
        );
        assert!(response.file.is_empty(), "{parameter}");
    }
}

#[test]
fn unnamed_package_and_rs_suffix_follow_buffa_filenames() {
    let mut request = request();
    request.proto_file[0].package = None;
    request.proto_file[1].package = Some(String::new());
    request.proto_file[2].package = Some("other.rs".into());
    let response = invoke_plugin(&request);
    assert!(response.error.is_none(), "{:?}", response.error);
    let names: Vec<_> = response
        .file
        .iter()
        .map(|f| f.name.as_deref().unwrap())
        .collect();
    assert_eq!(names, ["__buffa.validate.rs", "other.rs.validate.rs"]);
    let unnamed = response.file[0].content.as_deref().unwrap();
    assert!(unnamed.contains("Validate for First"));
    assert!(unnamed.contains("Validate for Second"));
}

#[test]
fn empty_generation_emits_no_files_in_flat_mode() {
    let mut request = request();
    request.file_to_generate.clear();
    let response = invoke_plugin(&request);
    assert!(response.error.is_none(), "{:?}", response.error);
    assert!(response.file.is_empty());
}

#[test]
fn imported_messages_are_not_emitted() {
    let mut request = request();
    request.file_to_generate = vec!["second.proto".into()];
    let response = invoke_plugin(&request);
    assert!(response.error.is_none(), "{:?}", response.error);
    assert_eq!(response.file.len(), 1);
    let file = &response.file[0];
    assert_eq!(file.name.as_deref(), Some("example.v1.validate.rs"));
    let content = file.content.as_deref().unwrap();
    assert!(content.contains("Validate for Second"));
    assert!(!content.contains("Validate for First"));
    assert!(!content.contains("Validate for Third"));
}
