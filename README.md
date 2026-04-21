# protovalidate-buffa

Static-codegen [protovalidate] for the [buffa] Rust protobuf runtime.

Annotate your `.proto` messages with `(buf.validate.*)` rules; a codegen plugin emits pure-Rust `impl Validate` blocks per message. Handlers call `req.validate()?` at entry (or use the `#[connect_impl]` macro to do it automatically on every handler in a service impl).

For what the rules *mean*, the full rule catalogue, CEL semantics, and design docs, read the upstream project — this crate intentionally does not duplicate that material:

- **Docs:** <https://buf.build/docs/protovalidate/>
- **Rule catalogue:** <https://buf.build/docs/protovalidate/schemas/standard-rules/>
- **Custom / predefined rules:** <https://buf.build/docs/protovalidate/schemas/custom-rules/>
- **Source of truth (`validate.proto`):** <https://github.com/bufbuild/protovalidate/blob/main/proto/protovalidate/buf/validate/validate.proto>

[protovalidate]: https://github.com/bufbuild/protovalidate
[buffa]: https://github.com/anthropics/buffa

## Status

**Conformance: 2872 / 2872 (100%)** against the upstream [`protovalidate-conformance`](https://github.com/bufbuild/protovalidate/tree/main/tools/protovalidate-conformance) harness, covering proto2, proto3, and editions 2023.

## Why a different crate?

Existing Rust implementations of protovalidate (`prost-protovalidate`, `protocheck`, `protify`) all target [prost]. buffa has a different runtime model — zero-copy views, static types, no dynamic-message reflection — so prost-based validators are incompatible. This repo fills that gap.

Compared to reflection-based implementations, the codegen approach has two characteristics:

- **No runtime descriptor lookup.** Every `validate()` is a direct struct field walk that LLVM can inline.
- **Schema-aware compile errors.** Rule / field type mismatches, malformed `message.oneof` specs, and CEL expressions that reference non-existent fields are surfaced at codegen time rather than at first-call.

[prost]: https://github.com/tokio-rs/prost

## Crates

| Crate | Purpose |
|-------|---------|
| [`protovalidate-buffa`](crates/protovalidate-buffa/) | Runtime library: `Validate` trait, structured `ValidationError` (with typed `compile_error` / `runtime_error` slots), `Violation` / `FieldPath`, rule helpers, CEL integration via `cel-interpreter`, Connect error adapter. |
| [`protovalidate-buffa-macros`](crates/protovalidate-buffa-macros/) | `#[connect_impl]` attribute macro — inserts `req.validate()?` at the top of every handler in a service `impl` block. Re-exported from the runtime crate. |
| [`protoc-gen-protovalidate-buffa`](crates/protoc-gen-protovalidate-buffa/) | Codegen plugin. Reads `(buf.validate.*)` extensions off descriptors via buffa's `ExtensionSet`, emits `impl Validate for Foo` blocks. Wire into `buf.gen.yaml`. |
| [`protovalidate-buffa-protos`](crates/protovalidate-buffa-protos/) | Compiled Rust for `buf/validate/validate.proto` (vendored under `proto/`). Consumed by the codegen plugin. |

`protovalidate-buffa-conformance` also lives in this workspace but is private (`publish = false`) — see [its README](crates/protovalidate-buffa-conformance/README.md) for the conformance test-run flow.

## Supported rules

Every rule family in the upstream [standard-rules catalogue](https://buf.build/docs/protovalidate/schemas/standard-rules/) plus [predefined rules](https://buf.build/docs/protovalidate/schemas/custom-rules/#predefined-rules) is implemented — that's what the 2872 / 2872 conformance number above is measuring. See the upstream docs for semantics; this repo doesn't maintain a parallel list.

## Quick start

For the proto-annotation side (which rules exist, how to combine them, CEL syntax), follow the upstream [protovalidate quick start](https://buf.build/docs/protovalidate/quickstart/). The Rust-specific bits are:

```bash
# Install the plugin
cargo install --git https://github.com/mathematic-inc/protovalidate-buffa protoc-gen-protovalidate-buffa
```

Add to your `buf.gen.yaml`:

```yaml
- local: protoc-gen-protovalidate-buffa
  out: gen/protovalidate
  strategy: all
```

Annotate a proto (see upstream for the full rule vocabulary):

```protobuf
syntax = "proto3";
import "buf/validate/validate.proto";

message CreateUserRequest {
  string email = 1 [(buf.validate.field).string = { min_len: 5, max_len: 254, email: true }];
  int32 age = 3 [(buf.validate.field).int32 = { gte: 13, lte: 150 }];
}
```

Use in a Connect handler:

```rust
use protovalidate_buffa::Validate;

#[protovalidate_buffa::connect_impl]
impl UserService for UserServiceImpl {
    async fn create_user(
        &self,
        ctx: Context,
        request: OwnedView<pb::CreateUserRequestView<'static>>,
    ) -> Result<(pb::CreateUserResponse, Context), ConnectError> {
        // #[connect_impl] inserts req.validate()? here automatically.
        // Body only sees already-validated requests.
    }
}
```

## Error model

`Validate::validate` returns `Result<(), ValidationError>`:

```rust
pub struct ValidationError {
    pub violations: Vec<Violation>,
    pub compile_error: Option<String>,  // schema mismatch detected at codegen time
    pub runtime_error: Option<String>,  // rule precondition failed (e.g. non-UTF-8 bytes under `pattern`)
}
```

Match on the typed fields rather than stringly-typed rule-id prefixes. `Violation` / `FieldPath` mirror the [upstream proto shape](https://github.com/bufbuild/protovalidate/blob/main/proto/protovalidate/buf/validate/validate.proto) — see those message definitions for field semantics. The `connect` feature provides `ValidationError::into_connect_error` mapping to `InvalidArgument`.

## Conformance testing

See [`crates/protovalidate-buffa-conformance/README.md`](crates/protovalidate-buffa-conformance/README.md) for how to build the dispatch binary and drive the upstream harness locally. CI runs `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` on every push; conformance is currently a local-only / pre-release check.

## License

Dual-licensed under Apache-2.0 or MIT at your option.
