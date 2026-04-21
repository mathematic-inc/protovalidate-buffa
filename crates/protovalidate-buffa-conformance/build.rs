//! Compile the conformance harness + cases protos, and generate
//! `impl Validate` blocks for the cases protos by invoking the
//! `protoc-gen-protovalidate-buffa` plugin library in-process.

use std::{collections::BTreeMap, fmt::Write as _, path::PathBuf};

use buffa::Message;
use buffa_codegen::generated::{compiler::CodeGeneratorRequest, descriptor::FileDescriptorSet};

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let proto_root = manifest.join("proto");

    println!("cargo:rerun-if-changed={}", proto_root.display());
    println!("cargo:rerun-if-env-changed=PROTOC");

    // Resolve protoc + its bundled well-known-type include dir.
    let protoc_path = std::env::var("PROTOC")
        .unwrap_or_else(|_| which_protoc().unwrap_or_else(|| "protoc".to_string()));
    let protoc_include = PathBuf::from(&protoc_path)
        .parent()
        .and_then(|p| p.parent())
        .map(|prefix| prefix.join("include"))
        .filter(|p| p.join("google/protobuf/descriptor.proto").exists())
        .expect("protoc include dir not found");

    // All .proto files we compile. Harness + validate.proto + vendored cases + WKTs.
    let mut files: Vec<PathBuf> = Vec::new();

    let harness_dir = proto_root.join("buf/validate/conformance/harness");
    for entry in std::fs::read_dir(&harness_dir).unwrap().flatten() {
        if entry.path().extension().is_some_and(|e| e == "proto") {
            files.push(entry.path());
        }
    }
    files.push(proto_root.join("buf/validate/validate.proto"));
    // Compile ALL case protos (recursive) so buffa generates types for
    // everything, even things we don't emit validators for yet (imports
    // from sibling case files).
    walk_protos(
        &proto_root.join("buf/validate/conformance/cases"),
        &mut files,
    );
    let case_files = enabled_case_files();
    // WKTs — bundled with protoc.
    for wkt in &[
        "google/protobuf/any.proto",
        "google/protobuf/descriptor.proto",
        "google/protobuf/duration.proto",
        "google/protobuf/empty.proto",
        "google/protobuf/field_mask.proto",
        "google/protobuf/timestamp.proto",
        "google/protobuf/wrappers.proto",
    ] {
        files.push(protoc_include.join(wkt));
    }

    // Build FDS via protoc.
    let fds_path = out_dir.join("conformance.fds");
    let mut cmd = std::process::Command::new(&protoc_path);
    cmd.arg(format!("--descriptor_set_out={}", fds_path.display()))
        .arg("--include_imports")
        .arg("--include_source_info")
        .arg(format!("-I{}", proto_root.display()))
        .arg(format!("-I{}", protoc_include.display()));
    for f in &files {
        cmd.arg(f);
    }
    let status = cmd.status().expect("failed to invoke protoc");
    assert!(status.success(), "protoc failed");

    let fds_bytes = std::fs::read(&fds_path).expect("read fds");
    let fds = FileDescriptorSet::decode_from_slice(&fds_bytes).expect("decode fds");

    // Invoke buffa-build with our prebuilt FDS. Use a different include filename
    // so we can write our own merging one below.
    // buffa-build resolves `files` relative to the include search path.
    let rel_files: Vec<String> = files
        .iter()
        .map(|f| {
            f.strip_prefix(&proto_root)
                .or_else(|_| f.strip_prefix(&protoc_include))
                .map_or_else(
                    |_| f.to_string_lossy().into_owned(),
                    |r| r.to_string_lossy().into_owned(),
                )
        })
        .collect();
    buffa_build::Config::new()
        .descriptor_set(&fds_path)
        .files(&rel_files)
        .includes(&[
            proto_root.to_string_lossy().into_owned(),
            protoc_include.to_string_lossy().into_owned(),
        ])
        .include_file("_buffa_include.rs")
        .compile()
        .expect("buffa-build compile failed");

    // Now run our protovalidate plugin lib over the cases files.
    let case_source_names: Vec<String> = case_files
        .iter()
        .map(|c| format!("buf/validate/conformance/cases/{c}"))
        .collect();
    let request = CodeGeneratorRequest {
        file_to_generate: case_source_names,
        proto_file: fds.file,
        ..Default::default()
    };
    let validators =
        protoc_gen_protovalidate_buffa::scan::gather(&request).expect("protovalidate scan failed");
    let emitted = protoc_gen_protovalidate_buffa::emit::render(&validators)
        .expect("protovalidate emit failed");

    // Write each emitted file under a `pv_` prefix so it doesn't collide with
    // buffa-build's output. Emitted filename is `<stem_with_dots>.rs` —
    // e.g. `buf.validate.conformance.cases.bool.rs`.
    let mut emitted_paths: Vec<(String, String)> = Vec::new(); // (package, include_filename)
    for f in &emitted {
        let name = f.name.as_deref().expect("emitted file has name");
        // Figure out the package: strip trailing `.rs`, then everything up
        // to the last `.` is the package.
        let stem = name.trim_end_matches(".rs");
        let (pkg, _file) = stem.rsplit_once('.').unwrap_or((stem, ""));
        let out_filename = format!("pv_{name}");
        std::fs::write(out_dir.join(&out_filename), f.content.as_deref().unwrap())
            .expect("write validator file");
        emitted_paths.push((pkg.to_string(), out_filename));
    }

    // Merge include file: start from buffa's tree, append our per-package
    // validator includes. Generate a new _include.rs that wraps both.
    write_merged_include(&out_dir, &emitted_paths);

    // Write a dispatch module listing all registered types (package FQN +
    // local Rust path). The runtime registry uses this.
    write_dispatch_rs(&out_dir, &validators);
}

fn walk_protos(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk_protos(&p, out);
        } else if p.extension().is_some_and(|e| e == "proto") {
            out.push(p);
        }
    }
}

fn enabled_case_files() -> Vec<String> {
    // Curated list. Expand as the plugin & runtime grow rule coverage.
    // Files we don't enable yet (broken at codegen / runtime):
    //   custom_rules/, predefined_rules_*, groups_*, messages, oneofs,
    //   kitchen_sink, wkt_*, library, ignore_*, required_field_*,
    //   filename-with-dash, other_package/, subdirectory/, yet_another_package/.
    [
        "bool.proto",
        "numbers.proto",
        "bytes.proto",
        "strings.proto",
        "enums.proto",
        "ignore_proto3.proto",
        "ignore_empty_proto3.proto",
        "library.proto",
        "wkt_wrappers.proto",
        "required_field_proto3.proto",
        "repeated.proto",
        "other_package/embed.proto",
        "yet_another_package/embed2.proto",
        "maps.proto",
        "messages.proto",
        "oneofs.proto",
        "kitchen_sink.proto",
        "filename-with-dash.proto",
        "subdirectory/in_subdirectory.proto",
        "wkt_any.proto",
        "wkt_duration.proto",
        "wkt_timestamp.proto",
        "wkt_field_mask.proto",
        "wkt_nested.proto",
        "ignore_proto2.proto",
        "ignore_empty_proto2.proto",
        "required_field_proto2.proto",
        "ignore_proto_editions.proto",
        "ignore_empty_proto_editions.proto",
        "required_field_proto_editions.proto",
        "custom_rules/custom_rules.proto",
        "predefined_rules_proto2.proto",
        "predefined_rules_proto3.proto",
        "predefined_rules_proto_editions.proto",
        "groups_proto2.proto",
        "groups_editions.proto",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn write_merged_include(out_dir: &std::path::Path, emitted: &[(String, String)]) {
    // Enumerate all buffa-generated package files: `<pkg>.<stem>.rs`. We
    // infer the package by stripping the file stem suffix from the filename.
    // Strategy: look at every `.rs` file in OUT_DIR; for any file of the
    // form `<dotted>.rs`, its package is the longest prefix matching one of
    // the known packages. But we don't have that list directly — so we
    // instead reconstruct per-package file lists from buffa's include file.
    let buffa_inc =
        std::fs::read_to_string(out_dir.join("_buffa_include.rs")).expect("read buffa include");

    // Parse `pub mod X { use super::*; include!(...); ... }` structure.
    // Simple state machine tracking the current module path.
    let mut out = String::from("// Merged include: buffa types + validator impls.\n");
    let mut pkg_stack: Vec<String> = Vec::new();
    let by_pkg: BTreeMap<String, Vec<String>> = {
        let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (pkg, file) in emitted {
            m.entry(pkg.clone()).or_default().push(file.clone());
        }
        m
    };

    for line in buffa_inc.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pub mod ") {
            if let Some(name) = rest
                .strip_suffix(" {")
                .or_else(|| rest.split_whitespace().next())
            {
                let clean = name.trim_end_matches('{').trim();
                pkg_stack.push(clean.to_string());
            }
        } else if trimmed == "}" {
            // Before closing this module, emit any validator includes for
            // the current package.
            let current_pkg = pkg_stack.join(".");
            if let Some(files) = by_pkg.get(&current_pkg) {
                for f in files {
                    writeln!(
                        out,
                        "        include!(concat!(env!(\"OUT_DIR\"), \"/{f}\"));"
                    )
                    .unwrap();
                }
            }
            pkg_stack.pop();
        }
        out.push_str(line);
        out.push('\n');
    }

    std::fs::write(out_dir.join("_include.rs"), out).expect("write include");
}

fn write_dispatch_rs(
    out_dir: &std::path::Path,
    validators: &[protoc_gen_protovalidate_buffa::scan::MessageValidators],
) {
    let mut out = String::new();
    out.push_str("// @generated by protovalidate-buffa-conformance build.rs\n");
    out.push_str("use protovalidate_buffa::Validate;\n");
    out.push_str("use buffa::Message;\n\n");
    out.push_str(
        "pub(crate) fn dispatch_known(fqn: &str, bytes: &[u8]) -> Option<CaseOutcome> {\n",
    );
    out.push_str("    match fqn {\n");

    for v in validators {
        // Proto name: fully qualified. Rust path: within `crate::generated`.
        // Lowercase every PascalCase parent segment that holds nested types
        // (buffa's convention); the leaf segment keeps its original case.
        let segs: Vec<&str> = v.proto_name.split('.').collect();
        let rust_segs: Vec<String> = segs
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let is_last = i + 1 == segs.len();
                let starts_upper = s.chars().next().is_some_and(char::is_uppercase);
                if !is_last && starts_upper {
                    snake_case(s)
                } else {
                    (*s).to_string()
                }
            })
            .collect();
        let rust_path = format!("crate::generated::{}", rust_segs.join("::"));
        writeln!(
            out,
            "        \"{fqn}\" => Some(run::<{rust}>(bytes)),",
            fqn = v.proto_name,
            rust = rust_path
        )
        .unwrap();
    }
    out.push_str("        _ => None,\n");
    out.push_str("    }\n");
    out.push_str("}\n\n");

    out.push_str("fn run<M: Message + Validate + Default>(bytes: &[u8]) -> CaseOutcome {\n");
    out.push_str("    let msg = match M::decode_from_slice(bytes) {\n");
    out.push_str("        Ok(m) => m,\n");
    out.push_str("        Err(e) => return CaseOutcome::RuntimeError(format!(\"decode: {e}\")),\n");
    out.push_str("    };\n");
    out.push_str("    match msg.validate() {\n");
    out.push_str("        Ok(()) => CaseOutcome::Valid,\n");
    out.push_str("        Err(err) => {\n");
    out.push_str("            if let Some(reason) = err.compile_error.clone() {\n");
    out.push_str("                return CaseOutcome::CompilationError(reason);\n");
    out.push_str("            }\n");
    out.push_str("            if let Some(reason) = err.runtime_error.clone() {\n");
    out.push_str("                return CaseOutcome::RuntimeError(reason);\n");
    out.push_str("            }\n");
    out.push_str("            CaseOutcome::Invalid(crate::to_harness_violations(err))\n");
    out.push_str("        }\n");
    out.push_str("    }\n");
    out.push_str("}\n");

    std::fs::write(out_dir.join("dispatch.rs"), out).expect("write dispatch");
}

/// Match buffa's `to_snake_case`: insert `_` before uppercase letters that
/// follow a lowercase letter, or before a new word after an acronym run
/// (`XMLHttp` → `x_m_l_http`). Digits do NOT trigger an underscore — `Proto3Message`
/// becomes `proto3message`.
fn snake_case(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len() + 2);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() && i > 0 {
            let prev = chars[i - 1];
            let next_is_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            if prev.is_lowercase() || (prev.is_uppercase() && next_is_lower) {
                out.push('_');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

fn which_protoc() -> Option<String> {
    let output = std::process::Command::new("which")
        .arg("protoc")
        .output()
        .ok()?;
    if output.status.success() {
        let path = String::from_utf8(output.stdout).ok()?.trim().to_string();
        let resolved = std::fs::canonicalize(&path).unwrap_or_else(|_| PathBuf::from(&path));
        Some(resolved.to_string_lossy().into_owned())
    } else {
        None
    }
}
