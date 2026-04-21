# protovalidate-buffa-conformance

Private (`publish = false`) dispatch binary that plugs into the upstream [`protovalidate-conformance`](https://github.com/bufbuild/protovalidate/tree/main/tools/protovalidate-conformance) harness.

The harness forks this binary once per test batch, sends a `TestConformanceRequest` proto on stdin, and reads a `TestConformanceResponse` back on stdout. This crate is not part of the published release surface — it's a CI / pre-release coverage tool.

## Running

```bash
# Install the upstream harness (Go binary).
go install github.com/bufbuild/protovalidate/tools/protovalidate-conformance@latest

# Build the dispatch binary.
cargo build --release -p protovalidate-buffa-conformance

# Run the suite.
protovalidate-conformance target/release/protovalidate-buffa-conformance
# -> PASS (failed: 0, skipped: 0, passed: 2872, total: 2872)
```

Useful harness flags:

| Flag | Effect |
|---|---|
| `--verbose` | Prints one PASS / FAIL line per case. |
| `--suite <pattern>` | Narrow to a single suite (e.g. `library/is_uri`, `standard_rules/map`). |
| `--expected_failures <file>` | Accept known-failure cases listed in `<file>`; useful while iterating on a diff. |

## What `build.rs` does

1. Resolves `protoc` and its bundled well-known-types include directory.
2. Enumerates the cases proto set — the list in `enabled_case_files()` mirrors every `.proto` under `proto/buf/validate/conformance/cases/` that we've taught the codegen to handle (proto2, proto3, editions 2023).
3. Runs `protoc` once to produce a serialized `FileDescriptorSet`, feeding the harness protos plus `buf.validate.*` extension definitions alongside our cases.
4. Hands that `CodeGeneratorRequest` to `protoc_gen_protovalidate_buffa::{scan, emit}` in-process — no out-of-process plugin round-trip for validators — and writes each emitted `impl Validate` file into `$OUT_DIR`.
5. Runs `buffa-build` over the same descriptor set to produce message types for the harness and cases.
6. Stitches the two outputs together in `_include.rs` so generated validators sit in the same module as the messages they validate.
7. Writes `dispatch.rs` — a big `match` on `type_url` that decodes + validates, keyed off every message the harness cares about.

## Binary flow

`src/main.rs::main` decodes `TestConformanceRequest`, walks `request.cases`, and dispatches each case via `registry::dispatch`:

```text
Validate::validate                             │ TestResult variant
───────────────────────────────────────────────┼──────────────────────
Ok(())                                         │ Success(true)
Err { compile_error: Some(reason), .. }        │ CompilationError(reason)
Err { runtime_error: Some(reason), .. }        │ RuntimeError(reason)
Err { violations, .. }                         │ ValidationError(Violations)
unknown `type_url`                             │ UnexpectedError("unsupported message type: …")
```

Bare `google.protobuf.*` inputs (no user validator) short-circuit to `Success(true)`.

`to_harness_violations` converts our `Violation` / `FieldPath` types back to the harness's own `pb_validate::Violations` for the wire response.

## Extending

- To enable a new cases `.proto`: add it to `enabled_case_files()` in `build.rs`, rebuild, run the harness, and fix anything that fails.
- To inspect emitted validators for debugging: look under `target/release/build/protovalidate-buffa-conformance-*/out/pv_buf.validate.conformance.cases.*.rs`.
