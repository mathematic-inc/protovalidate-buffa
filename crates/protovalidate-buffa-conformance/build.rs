//! Compile the conformance harness + cases protos, and generate
//! `impl Validate` blocks for the cases protos by invoking the
//! `protoc-gen-protovalidate-buffa` plugin library in-process.

use std::{collections::BTreeMap, fmt::Write as _, path::PathBuf};

use buffa::Message;
use buffa_codegen::generated::{compiler::CodeGeneratorRequest, descriptor::FileDescriptorSet};
use protoc_gen_protovalidate_buffa::emit::cel_compile::{
    Binding, CelType, Compiler, MapTy, RustScalar,
};

#[allow(
    clippy::too_many_lines,
    reason = "build script orchestration is sequential by nature; splitting further would just thread arguments through helpers without adding clarity"
)]
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
    //
    // The plugin also emits a top-level `mod.rs` and per-package
    // `<pkg>.mod.rs` packaging files for downstream Rust crates that just
    // want `pub mod protovalidate;` to wire everything up. The conformance
    // crate has its own merging include scheme (`write_merged_include`),
    // so skip these here.
    let mut emitted_paths: Vec<(String, String)> = Vec::new(); // (package, include_filename)
    for f in &emitted {
        let name = f.name.as_deref().expect("emitted file has name");
        if name == "mod.rs" || name.ends_with(".mod.rs") {
            continue;
        }
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

    // Run the CEL transpiler against a curated battery of expressions and
    // write the emitted tokens into a Rust source file. The `emit_compiles`
    // integration test `include!()`s that file, so the test crate's compile
    // is the verification — any token sequence that doesn't type-check
    // breaks the build.
    write_cel_emit_fixtures(&out_dir);
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

/// Spec for one CEL → Rust transpile-and-compile check.
///
/// `name` becomes the generated function name; `expr` is the CEL source;
/// `this_ty` is the static type bound to the `this` ident; `extras` are
/// additional bindings (e.g. a `rule` const for predefined-rule cases);
/// `expect_ret` is the Rust type the transpiler is expected to produce —
/// the generated function ascribes `let _: <expect_ret> = <emitted>;` so
/// the Rust compile verifies both type-correctness AND that the
/// transpiler returned the type we anticipated.
struct CelCheck {
    name: &'static str,
    expr: &'static str,
    this_ty: CelType,
    /// `(name, CelType, optional rule-const)` for additional `bind` calls.
    extras: Vec<(
        &'static str,
        CelType,
        Option<protoc_gen_protovalidate_buffa::scan::RuleConst>,
    )>,
    /// Rust type the emitted tokens evaluate to.
    expect_ret: &'static str,
}

/// Generate the integration-test fixture file. Each check becomes a
/// `pub fn _check_<name>(...)` whose body is the emitted expression
/// ascribed to its expected Rust type. The test crate must compile;
/// if any emitted token doesn't type-check, the build fails.
#[allow(clippy::too_many_lines)]
fn write_cel_emit_fixtures(out_dir: &std::path::Path) {
    let str_map = || {
        CelType::Map(Box::new(MapTy {
            key_cel: CelType::Str { owned: false },
            value_cel: CelType::Int,
            key_rust: RustScalar::Str,
            value_rust: RustScalar::I64,
        }))
    };
    let int_map = || {
        CelType::Map(Box::new(MapTy {
            key_cel: CelType::Int,
            value_cel: CelType::Str { owned: false },
            key_rust: RustScalar::I64,
            value_rust: RustScalar::Str,
        }))
    };

    let checks: Vec<CelCheck> = vec![
        // --- int/uint cross-type compare (i128 promotion path)
        CelCheck {
            name: "int_eq_uint",
            expr: "this == 1u",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "int_lt_uint",
            expr: "this < 5u",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "uint_gt_int",
            expr: "this > 0",
            this_ty: CelType::UInt,
            extras: vec![],
            expect_ret: "bool",
        },
        // --- type() reflection
        CelCheck {
            name: "type_of_int_eq_int_marker",
            expr: "type(this) == int",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "type_of_string",
            expr: "type(this) == string",
            this_ty: CelType::Str { owned: false },
            extras: vec![],
            expect_ret: "bool",
        },
        // --- dynamic duration / timestamp
        CelCheck {
            name: "duration_literal",
            expr: "this >= duration('1s')",
            this_ty: CelType::Duration,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "duration_dynamic",
            expr: "duration(this) >= duration('1s')",
            this_ty: CelType::Str { owned: false },
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "timestamp_literal",
            expr: "this > timestamp('2020-01-01T00:00:00Z')",
            this_ty: CelType::Timestamp,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "timestamp_dynamic",
            expr: "timestamp(this) > timestamp('2020-01-01T00:00:00Z')",
            this_ty: CelType::Str { owned: false },
            extras: vec![],
            expect_ret: "bool",
        },
        // --- two-variable comprehensions
        CelCheck {
            name: "two_var_map_all",
            expr: "this.all(k, v, size(k) > 0 && v > 0)",
            this_ty: str_map(),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "two_var_map_exists",
            expr: "this.exists(k, v, v == 1)",
            this_ty: str_map(),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "two_var_map_exists_one",
            expr: "this.exists_one(k, v, v == 1)",
            this_ty: str_map(),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "two_var_map_filter",
            expr: "size(this.filter(k, v, v > 0)) >= 0",
            this_ty: str_map(),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "two_var_map_map_four_arg",
            expr: "size(this.map(k, v, v > 0, v * 2)) >= 0",
            this_ty: str_map(),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "two_var_list_all",
            expr: "this.all(i, v, i >= 0 && v > 0)",
            this_ty: CelType::List(Box::new(CelType::Int)),
            extras: vec![],
            expect_ret: "bool",
        },
        // --- non-string join
        CelCheck {
            name: "join_int_list",
            expr: "this.join(',')",
            this_ty: CelType::List(Box::new(CelType::Int)),
            extras: vec![],
            expect_ret: "::std::string::String",
        },
        CelCheck {
            name: "join_double_list",
            expr: "this.join(' ')",
            this_ty: CelType::List(Box::new(CelType::Double)),
            extras: vec![],
            expect_ret: "::std::string::String",
        },
        // --- format directives
        CelCheck {
            name: "format_hex_lower",
            expr: "'%x'.format([this])",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "::std::string::String",
        },
        CelCheck {
            name: "format_hex_upper",
            expr: "'%X'.format([this])",
            this_ty: CelType::UInt,
            extras: vec![],
            expect_ret: "::std::string::String",
        },
        CelCheck {
            name: "format_octal",
            expr: "'%o'.format([this])",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "::std::string::String",
        },
        CelCheck {
            name: "format_binary",
            expr: "'%b'.format([this])",
            this_ty: CelType::UInt,
            extras: vec![],
            expect_ret: "::std::string::String",
        },
        CelCheck {
            name: "format_scientific",
            expr: "'%e'.format([this])",
            this_ty: CelType::Double,
            extras: vec![],
            expect_ret: "::std::string::String",
        },
        // --- map literals
        CelCheck {
            name: "map_literal_string_keys",
            expr: "size({'a': 1, 'b': 2}) == 2",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "map_literal_int_keys_lookup",
            expr: "{1: 'a', 2: 'b'}[1] == 'a'",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "map_literal_in_op",
            expr: "'a' in {'a': 1, 'b': 2}",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "empty_map_size",
            expr: "size({}) == 0",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        // --- list indexing
        CelCheck {
            name: "list_index_int",
            expr: "this[0] == 1",
            this_ty: CelType::List(Box::new(CelType::Int)),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "list_index_string",
            expr: "this[0] == 'foo'",
            this_ty: CelType::List(Box::new(CelType::Str { owned: false })),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "list_index_literal",
            expr: "[10, 20, 30][1] == 20",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        // --- empty list short-circuits
        CelCheck {
            name: "empty_list_all_vacuous",
            expr: "[].all(x, x > 0)",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "empty_list_exists_false",
            expr: "[].exists(x, x > 0)",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        // --- map .in / contains_key path
        CelCheck {
            name: "in_op_on_map_string_key",
            expr: "'k' in this",
            this_ty: str_map(),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "in_op_on_map_int_key",
            expr: "1 in this",
            this_ty: int_map(),
            extras: vec![],
            expect_ret: "bool",
        },
        // --- string semantics
        CelCheck {
            name: "size_string_unicode",
            expr: "size(this) >= 0",
            this_ty: CelType::Str { owned: false },
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "string_matches_literal",
            expr: "this.matches('^[a-z]+$')",
            this_ty: CelType::Str { owned: false },
            extras: vec![],
            expect_ret: "bool",
        },
        // Dynamic regex pattern.
        CelCheck {
            name: "string_matches_dynamic_pattern",
            expr: "this.matches(pat)",
            this_ty: CelType::Str { owned: false },
            extras: vec![("pat", CelType::Str { owned: false }, None)],
            expect_ret: "bool",
        },
        // --- rule-const folding
        CelCheck {
            name: "rule_const_int",
            expr: "this == rule",
            this_ty: CelType::Int,
            extras: vec![(
                "rule",
                CelType::Int,
                Some(protoc_gen_protovalidate_buffa::scan::RuleConst::Int(7)),
            )],
            expect_ret: "bool",
        },
        CelCheck {
            name: "rule_const_str",
            expr: "this == rule",
            this_ty: CelType::Str { owned: false },
            extras: vec![(
                "rule",
                CelType::Str { owned: false },
                Some(protoc_gen_protovalidate_buffa::scan::RuleConst::Str(
                    "hello".to_string(),
                )),
            )],
            expect_ret: "bool",
        },
        // --- timestamp accessors
        CelCheck {
            name: "ts_get_full_year",
            expr: "this.getFullYear() >= 2020",
            this_ty: CelType::Timestamp,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "ts_get_month",
            expr: "this.getMonth() < 12",
            this_ty: CelType::Timestamp,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "ts_get_day_of_week",
            expr: "this.getDayOfWeek() == 0",
            this_ty: CelType::Timestamp,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "ts_get_hours",
            expr: "this.getHours() < 24",
            this_ty: CelType::Timestamp,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "ts_get_minutes_milliseconds",
            expr: "this.getMinutes() < 60 && this.getMilliseconds() < 1000",
            this_ty: CelType::Timestamp,
            extras: vec![],
            expect_ret: "bool",
        },
        // --- math.* extension
        CelCheck {
            name: "math_abs_int",
            expr: "math.abs(this) > 5",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "math_abs_double",
            expr: "math.abs(this) > 0.0",
            this_ty: CelType::Double,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "math_greatest",
            expr: "math.greatest(this, 5, 10) >= 10",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "math_least",
            expr: "math.least(this, 0) <= 0",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "math_ceil",
            expr: "math.ceil(this) >= 0.0",
            this_ty: CelType::Double,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "math_floor",
            expr: "math.floor(this) <= 0.0",
            this_ty: CelType::Double,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "math_round",
            expr: "math.round(this) >= 0.0",
            this_ty: CelType::Double,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "math_sign_int",
            expr: "math.sign(this) > 0",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "math_bit_and",
            expr: "math.bitAnd(this, 5u) >= 0u",
            this_ty: CelType::UInt,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "math_bit_shift_left",
            expr: "math.bitShiftLeft(this, 2u) >= 0u",
            this_ty: CelType::UInt,
            extras: vec![],
            expect_ret: "bool",
        },
        // --- isFinite, reverse, distinct
        CelCheck {
            name: "float_is_finite",
            expr: "this.isFinite()",
            this_ty: CelType::Double,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "string_reverse",
            expr: "this.reverse() == 'olleh'",
            this_ty: CelType::Str { owned: false },
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "list_reverse",
            expr: "size(this.reverse()) >= 0",
            this_ty: CelType::List(Box::new(CelType::Int)),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "list_distinct_int",
            expr: "size(this.distinct()) >= 0",
            this_ty: CelType::List(Box::new(CelType::Int)),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "list_distinct_str",
            expr: "size(this.distinct()) >= 0",
            this_ty: CelType::List(Box::new(CelType::Str { owned: false })),
            extras: vec![],
            expect_ret: "bool",
        },
        // --- timezone-arg timestamp accessors
        CelCheck {
            name: "ts_year_in_tz",
            expr: "this.getFullYear('America/New_York') >= 2020",
            this_ty: CelType::Timestamp,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "ts_hours_in_utc",
            expr: "this.getHours('UTC') < 24",
            this_ty: CelType::Timestamp,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "ts_day_of_week_in_tz",
            expr: "this.getDayOfWeek('Europe/Berlin') < 7",
            this_ty: CelType::Timestamp,
            extras: vec![],
            expect_ret: "bool",
        },
        // --- optional types
        CelCheck {
            name: "optional_of_int_hasvalue",
            expr: "optional.of(this).hasValue()",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "optional_or_value",
            expr: "optional.of(this).orValue(-1) >= 0",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "optional_value_unwrap",
            expr: "optional.of(this).value() == 5",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "optional_of_non_zero_int",
            expr: "optional.ofNonZeroValue(this).hasValue()",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "optional_of_non_zero_string",
            expr: "optional.ofNonZeroValue(this).hasValue()",
            this_ty: CelType::Str { owned: false },
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "optional_none_unified_via_ternary",
            expr: "(this > 0 ? optional.of(this) : optional.none()).orValue(0) >= 0",
            this_ty: CelType::Int,
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "opt_index_map_string_key",
            expr: "this[?'k'].hasValue()",
            this_ty: CelType::Map(Box::new(MapTy {
                key_cel: CelType::Str { owned: false },
                value_cel: CelType::Int,
                key_rust: RustScalar::Str,
                value_rust: RustScalar::I64,
            })),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "opt_index_list_int",
            expr: "this[?0].orValue(0) >= 0",
            this_ty: CelType::List(Box::new(CelType::Int)),
            extras: vec![],
            expect_ret: "bool",
        },
        CelCheck {
            name: "opt_index_map_str_value",
            expr: "this[?'k'].orValue('') == ''",
            this_ty: CelType::Map(Box::new(MapTy {
                key_cel: CelType::Str { owned: false },
                value_cel: CelType::Str { owned: false },
                key_rust: RustScalar::Str,
                value_rust: RustScalar::Str,
            })),
            extras: vec![],
            expect_ret: "bool",
        },
    ];

    let mut body = String::new();
    body.push_str(
        "// @generated by protovalidate-buffa-conformance build.rs\n\
         // Token-emission compile checks — one fn per CEL test case.\n\
         // The integration test that include!()s this file relies on\n\
         // the Rust compiler to verify each emitted body type-checks.\n\n\
         use ::protovalidate_buffa::cel::CelScalar as _;\n\n",
    );

    for check in &checks {
        let mut compiler = Compiler::new();
        compiler.bind("this", binding_for_emit(&check.this_ty, "__this"));
        for (name, ty, rule_const) in &check.extras {
            if let Some(rc) = rule_const {
                compiler.bind_rule_const(name, rc);
            } else {
                compiler.bind(name, binding_for_emit(ty, name));
            }
        }
        let out = match compiler.compile(check.expr) {
            Ok(o) => o,
            Err(e) => panic!(
                "transpile fixture `{}` failed at codegen: {:?}",
                check.name, e
            ),
        };
        let now_prelude = if out.needs_now {
            "let now = ::protovalidate_buffa::cel::now_local();".to_string()
        } else {
            String::new()
        };
        let rust_param = rust_emit_param_type(&check.this_ty);
        let mut extras_params = String::new();
        for (name, ty, _) in check.extras.iter().filter(|(_, _, rc)| rc.is_none()) {
            let pt = rust_emit_param_type(ty);
            write!(extras_params, ", {name}: {pt}").unwrap();
        }
        let body_tokens = out.tokens.to_string();
        writeln!(
            body,
            "pub fn _check_{name}(__this: {rust_param}{extras}) -> {ret} {{\n    \
             {now_prelude}\
             let __out: {ret} = {tokens};\n    \
             __out\n\
             }}\n",
            name = check.name,
            rust_param = rust_param,
            extras = extras_params,
            ret = check.expect_ret,
            now_prelude = now_prelude,
            tokens = body_tokens,
        )
        .unwrap();
    }

    std::fs::write(out_dir.join("cel_emit_fixtures.rs"), body).expect("write cel_emit_fixtures");
}

/// Rust parameter type for binding the given CEL type as an input. The
/// transpiler's `this` access patterns assume references for compound
/// types (slices for lists / bytes, `&HashMap` for maps, `&str` for
/// strings); scalars are passed by value.
///
/// Only covers the shapes used by the fixture cases. New cases that
/// need a different `this` shape should extend this match.
fn rust_emit_param_type(ty: &CelType) -> &'static str {
    match ty {
        CelType::UInt => "u64",
        CelType::Double => "f64",
        CelType::Bool => "bool",
        CelType::Str { .. } => "&str",
        CelType::Bytes { .. } => "&[u8]",
        CelType::List(elem) => match elem.as_ref() {
            CelType::UInt => "&::std::vec::Vec<u64>",
            CelType::Double => "&::std::vec::Vec<f64>",
            CelType::Bool => "&::std::vec::Vec<bool>",
            CelType::Str { .. } => "&::std::vec::Vec<::std::string::String>",
            CelType::Bytes { .. } => "&::std::vec::Vec<::std::vec::Vec<u8>>",
            // Default: List<Int> — also covers `_` for any unmodeled
            // element type, treated as i64-bearing for the fixture.
            _ => "&::std::vec::Vec<i64>",
        },
        CelType::Map(map_ty) => match (&map_ty.key_rust, &map_ty.value_rust) {
            (RustScalar::I64, RustScalar::Str) => {
                "&::std::collections::HashMap<i64, ::std::string::String>"
            }
            (RustScalar::Bool, RustScalar::I64) => "&::std::collections::HashMap<bool, i64>",
            (RustScalar::Str, RustScalar::Str) => {
                "&::std::collections::HashMap<::std::string::String, ::std::string::String>"
            }
            // Default: Map<Str, Int>.
            _ => "&::std::collections::HashMap<::std::string::String, i64>",
        },
        CelType::Duration => "::chrono::Duration",
        CelType::Timestamp => "::chrono::DateTime<::chrono::FixedOffset>",
        // Default for Int and anything not modeled above.
        _ => "i64",
    }
}

fn binding_for_emit(ty: &CelType, ident: &str) -> Binding {
    use proc_macro2::{Ident, Span, TokenStream};
    use quote::quote;
    let id = Ident::new(ident, Span::call_site());
    let rust_expr: TokenStream = quote! { #id };
    Binding {
        rust_expr,
        ty: ty.clone(),
        constant: None,
    }
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
