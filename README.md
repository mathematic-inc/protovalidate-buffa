# protovalidate-buffa

Static-codegen [protovalidate] for the [buffa] Rust protobuf runtime.

Annotate your `.proto` messages with `(buf.validate.*)` rules; a codegen plugin
emits pure-Rust `impl Validate` blocks per message. Handlers call
`req.validate()?` at entry (or use the `#[connect_impl]` macro to do it
automatically on every handler in a service impl).

For what the rules *mean*, the full rule catalogue, CEL semantics, and design docs,
read the upstream project. This crate intentionally does not duplicate that
material:

- **Docs:** <https://protovalidate.com/>
- **Rule catalogue:** <https://protovalidate.com/schemas/standard-rules/>
- **Custom rules:** <https://protovalidate.com/schemas/custom-rules/>
- **Predefined rules:** <https://protovalidate.com/schemas/predefined-rules/>
- **Source of truth (`validate.proto`):** <https://github.com/bufbuild/protovalidate/blob/main/proto/protovalidate/buf/validate/validate.proto>

[protovalidate]: https://github.com/bufbuild/protovalidate
[buffa]: https://github.com/anthropics/buffa

## Prebuilt installation

Release archives contain the executable and install without a Rust compiler.
Install with cargo-binstall, with source compilation disabled:

```sh
cargo binstall --disable-strategies compile protoc-gen-protovalidate-buffa
```

Or declare the GitHub release directly in `mise.toml`:

```toml
[tools."github:mathematic-inc/protovalidate-buffa"]
version = "latest"
version_prefix = "protoc-gen-protovalidate-buffa-v"
```

Run `mise install` to download and activate the executable. No custom mise plugin
is required. The Cargo backend
(`cargo:protoc-gen-protovalidate-buffa`) also supports these releases;
set `cargo.binstall_only = true` to reject source compilation.

| Platform | Architectures | Archive |
| --- | --- | --- |
| macOS | x64, ARM64 | `.tar.gz` |
| Linux GNU (glibc 2.35 or newer) | x64, ARM64 | `.tar.gz` |
| Linux musl | x64, ARM64 | `.tar.gz` |
| Windows MSVC | x64, ARM64 | `.zip` |

Every archive includes SHA-256 checksums and GitHub build provenance. CI builds
all eight targets and runs the extracted executables on the matching architecture.
After publication, the release workflow installs through cargo-binstall and mise
and runs both installations. A missing prebuilt binary fails the release checks.

## Status

**Conformance: 2872 / 2872 (100%)** against the upstream
[`protovalidate-conformance`] harness, covering proto2, proto3, and editions 2023.

## Why a different crate?

Existing Rust implementations of protovalidate (`prost-protovalidate`,
`protocheck`, `protify`) all target [prost]. buffa has a different runtime model:
two-tier owned/borrowed types with zero-copy views, and static generated types
rather than descriptor-driven dynamic messages. Prost-based validators are
incompatible. This repo fills that gap.

Compared to reflection-based implementations, the codegen approach has two characteristics:

- **No runtime descriptor lookup.** Every `validate()` is a direct struct field
  walk that LLVM can inline.
- **Schema-aware compile errors.** Rule / field type mismatches, malformed
  `message.oneof` specs, and CEL expressions that reference non-existent fields
  surface at codegen time rather than at the first call.

[prost]: https://github.com/tokio-rs/prost

## Crates

| Crate | Purpose |
|-------|---------|
| [`protovalidate-buffa`](crates/protovalidate-buffa/) | Runtime library: `Validate` trait, structured `ValidationError` (with typed `compile_error` / `runtime_error` slots), `Violation` / `FieldPath`, rule helpers, `CelScalar` widening trait + Duration/Timestamp helpers, Connect error adapter. CEL rules are transpiled to native Rust at codegen time, so the runtime carries no interpreter. |
| [`protovalidate-buffa-macros`](crates/protovalidate-buffa-macros/) | `#[connect_impl]` attribute macro — inserts request validation at the top of every handler in a service `impl` block. Re-exported from the runtime crate. |
| [`protoc-gen-protovalidate-buffa`](crates/protoc-gen-protovalidate-buffa/) | Codegen plugin. Reads `(buf.validate.*)` extensions off descriptors via buffa's `ExtensionSet`, emits `impl Validate for Foo` blocks. Wire into `buf.gen.yaml`. |
| [`protovalidate-buffa-protos`](crates/protovalidate-buffa-protos/) | Checked-in Buffa types for `buf/validate/validate.proto`, shared by the codegen plugin and structured runtime errors. |

`protovalidate-buffa-conformance` also lives in this workspace but is private
(`publish = false`). See [its README] for the conformance test-run flow.

## Compatibility

This workspace currently targets **buffa 0.9.1**, **connectrpc 0.9**, and
**Rust 1.88+** (edition 2024).

The emitted validators reference buffa's generated-code shape directly (field
placement, map and view types), so the plugin and your `buffa-build` output must
agree on the buffa minor version. buffa is pre-1.0 and treats **minor bumps as
breaking**, so upgrading buffa generally means upgrading this crate in lockstep.

The `connect` feature links `connectrpc`, which itself depends on buffa `^0.9.1`.
The buffa version here must stay in step with connectrpc's. Otherwise, two
incompatible buffa versions get linked and the default `connect` feature breaks
for downstream handlers.

## Supported rules

Every rule family in the upstream [standard-rules catalogue] plus [predefined
rules] is implemented. That is what the 2872 / 2872 conformance number above
measures. See the upstream docs for semantics; this repo does not maintain a
parallel list.

## Quick start

For the proto-annotation side (which rules exist, how to combine them, CEL syntax),
follow the upstream [protovalidate quick start]. The Rust-specific bits are:

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

If buffa uses `idiomatic_field_names`, enable it on the validator plugin too:

```yaml
- local: protoc-gen-buffa
  out: gen/proto
  strategy: all
  opt: [idiomatic_field_names=true]
- local: protoc-gen-protovalidate-buffa
  out: gen/protovalidate
  strategy: all
  opt: [idiomatic_field_names=true]
```

The bare `idiomatic_field_names` flag also enables it; the default and
`idiomatic_field_names=false` preserve protobuf field spelling. Use the same
input descriptors and generation strategy for both plugins: buffa resolves
collisions across the entire request, including imports. Rust accessors follow
buffa's conversion and collision rules, while CEL expressions and validation
error paths keep the original protobuf names. Oneof enum and variant names are
unaffected.

For in-process generation, set `CodeGeneratorRequest.parameter` before calling
`scan::gather`, for example `Some("idiomatic_field_names=true".into())`. Then pass
the scanned validators to `emit::render` or `emit::render_with_options` as usual.

### Include validators beside message types

Two independent flags control the output:

- `packaging=false` omits `mod.rs` and `<package>.mod.rs` and adds a `.validate`
  infix to validator filenames. This lets you share an output directory with
  handwritten module files. The default is `true`.
- `file_per_package=true` merges validators by declared protobuf package.
  The default is `false`, which emits one file per source proto.

| `packaging` | `file_per_package` | Validator files | Module files |
| --- | --- | --- | --- |
| `true` | `false` | `<source>.rs` | Yes (default layout) |
| `false` | `false` | `<source>.validate.rs` | No |
| `true` | `true` | `<package>.rs` | Yes |
| `false` | `true` | `<package>.validate.rs` | No |

To mount one validator file beside each package's Buffa types, set both flags:

```yaml
- local: protoc-gen-buffa
  out: gen/proto
  strategy: all
  opt: [file_per_package=true]
- local: protoc-gen-protovalidate-buffa
  out: gen/proto
  strategy: all
  opt: [packaging=false, file_per_package=true]
```

For package `example.v1`, mount both generated files:

```rust
pub mod example {
    pub mod v1 {
        use crate::example;

        include!("gen/proto/example.v1.rs");
        include!("gen/proto/example.v1.validate.rs");
    }
}
```

With `file_per_package=true`, the filename follows the declared package, even
when the source directories differ. Multiple `.proto` files in a package share
one validator file; keep
`strategy: all` so each plugin sees them together. Packages with messages but
no validation annotations still get validators. Packages with only enums or
services need no validator include. The unnamed package uses
`__buffa.validate.rs`, beside Buffa's `__buffa.rs`.

Preserve the package hierarchy for cross-package references. Enum validators
use paths beginning at the top-level protobuf package, so bring those roots
into scope in each consuming module (for example, `use crate::example;`).

`proto_module` is ignored with `packaging=false`. Omitting both flags preserves
the existing output. Either bare flag means `true`; both accept explicit
`true` and `false`, and other values fail generation with an error.
When switching an existing
output directory to this mode, remove old generated packaging files once;
generation does not delete files left by previous runs.

For in-process generation, pass these options to `emit::render_with_options`:

```rust
emit::Options {
    packaging: false,
    file_per_package: true,
    ..Default::default()
}
```

Code that previously constructed `Options` with only `proto_module` must add
`..Default::default()` or set both new fields explicitly.

Two [runnable examples](examples/packaging/) demonstrate per-source output and
per-package output with an enum from another package. Both
exercise validation on owned messages and borrowed views.

### Annotate and validate a request

Annotate a proto (see upstream for the full rule vocabulary):

```protobuf
syntax = "proto3";
import "buf/validate/validate.proto";

message CreateUserRequest {
  string email = 1 [(buf.validate.field).string = {
    min_len: 5,
    max_len: 254,
    email: true
  }];
  int32 age = 3 [(buf.validate.field).int32 = { gte: 13, lte: 150 }];
}
```

Use in a Connect handler:

```rust
#[protovalidate_buffa::connect_impl]
impl UserService for UserServiceImpl {
    async fn create_user(
        &self,
        ctx: Context,
        request: connectrpc::ServiceRequest<'_, pb::CreateUserRequest>,
    ) -> Result<(pb::CreateUserResponse, Context), ConnectError> {
        // #[connect_impl] validates the request here automatically.
        // Body only sees already-validated requests.
    }
}
```

`#[connect_impl]` validates `request.view()` for `ServiceRequest` parameters
and `request.reborrow()` for `OwnedView` parameters. It uses the generated
view's `Validate` implementation without converting the request to an owned
message. Regenerate validators with the current codegen plugin to include
view implementations.

## Error model

`Validate::validate` returns `Result<(), ValidationError>`:

```rust
pub struct ValidationError {
    pub violations: Vec<Violation>,
    // Schema mismatch detected at codegen time.
    pub compile_error: Option<String>,
    // Rule precondition failed, e.g. non-UTF-8 bytes under `pattern`.
    pub runtime_error: Option<String>,
}
```

Match on the typed fields rather than stringly-typed rule-id prefixes. `Violation`
and `FieldPath` mirror the [upstream proto shape]; see those message definitions
for field semantics.

### Connect and gRPC errors

With the default `connect` feature, `ValidationError::into_connect_error()`
converts **request** failures using ConnectRPC's existing error APIs:

| Diagnostic state | RPC status | Public detail |
|---|---|---|
| One or more violations, no validator defect | `invalid_argument` | `buf.validate.Violations`, bounded as described below |
| Compilation or evaluation diagnostic, including mixed states | `internal` | None |
| Empty `ValidationError` | `internal` | None |

The presence of a compilation/evaluation diagnostic wins even if its string is
empty. The original `ValidationError` remains available through
`std::error::Error::source()` on the returned `ConnectError`; ConnectRPC does not
serialize it. Public messages are fixed strings without internal diagnostics.
The existing `#[connect_impl]` macro continues to call this conversion for
requests. It does not validate responses. If an application separately validates
a server response, return a generic `ConnectError::internal` with the diagnostic
as its source; invalid server output is not the caller's invalid argument.

The [Protovalidate schema] defines `buf.validate.Violations` with rule IDs,
structured field and rule paths, typed indexes/map keys, and `for_key`.
[Connect's Go validation adapter] and the [gRPC Go validation middleware] use this
message for Protovalidate details. The latter also distinguishes validation
failures from validator defects. These are reference choices; neither transport
requires every service to validate messages or use a particular validation policy.

[Google's `BadRequest`] is another standard detail format for request field
failures, with textual field paths and descriptions. It does not preserve
Protovalidate's full field/rule path structure. We emit the canonical
Protovalidate detail once, without a redundant `BadRequest` translation.
[`google.rpc.Status`] is the **envelope**, not a competing detail type:
ConnectRPC places our message in its `Any` details inside `grpc-status-details-bin`
for gRPC. On [Connect's wire format], it uses the bare type name and base64
protobuf value in the JSON error. The same generated message decodes both.

### Wire defaults and diagnostic fidelity

These are library defaults, not requirements of Connect or gRPC:

- Public violations omit all free-form messages and map-key values, including
  boolean and numeric keys. CEL messages can include rejected input. Schema
  field names/numbers/types, complete rule IDs, repeated indexes, and `for_key`
  remain intact. Schema names and rule IDs must be schema-authored; applications
  constructing errors manually must not put rejected data in those fields.
- A path with an omitted map selector retains its schema location and nested
  field information, but cannot locate a specific map entry. Clients must not
  interpret an absent selector as a default key or as a complete concrete path.
- One detail contains the longest prefix of whole violations that fits in
  **4096 encoded protobuf bytes**. The first violation that cannot fit and all
  subsequent violations are omitted. IDs and names are never shortened. If
  none fit, no detail is attached. The status stays `invalid_argument`; the
  message becomes `request validation failed (violation details truncated)`.
  Otherwise, the message is `request validation failed`. The schema has no
  truncation flag, so clients must always treat details as potentially partial.
- [gRPC metadata limits] commonly start at 8 KiB. A 4-KiB payload expands to at
  most 5464 base64 bytes before accounting for `Status`, `Any`, type names,
  and header overhead. This provides headroom, **not a guarantee** that a whole
  metadata block fits. Applications adding other headers or details must budget
  those separately. The same detail budget applies to Connect for consistency.

Enable `protos` to call `ValidationError::to_proto()` for an unbounded diagnostic
copy, preserving violation messages and map keys. Empty rule IDs/messages and
empty paths become absent fields, and `for_key` is present only when true;
unavailable field identity is never invented. Compile/evaluation diagnostics stay
on `ValidationError`, since the canonical detail schema has no slots for them.
This diagnostic copy and the error source may contain rejected data. Applications
that deliberately choose a different public policy can prepare the generated
message themselves and attach it with `ErrorDetail::from_message`.

### Typed client decoding

`protovalidate_buffa::proto` re-exports the existing generated `buf.validate`
module. No additional schema copy or code generator is needed. ConnectRPC 0.9
provides `ErrorDetail::from_message` but no typed decoding method, so the runtime
provides `decode_violations(&ErrorDetail)`:

```rust
use protovalidate_buffa::{DecodeViolationsError, decode_violations};

fn inspect(
    error: &connectrpc::ConnectError,
) -> Result<(), DecodeViolationsError> {
    // Interpret the RPC status independently from any attached details.
    for detail in &error.details {
        if let Some(violations) = decode_violations(detail)? {
            for violation in violations.violations {
                println!(
                    "rule: {:?}, field: {:?}",
                    violation.rule_id, violation.field
                );
            }
        }
    }
    Ok(())
}
```

The helper accepts the exact bare message name and type URLs ending in
`/buf.validate.Violations`, including the canonical `type.googleapis.com` URL.
Unrelated types return `Ok(None)`. Matching details with no value, malformed
base64/protobuf, exceeded limits, or no violations return `DecodeViolationsError`.
It ignores `debug`, accepts padded/unpadded standard base64 and unknown protobuf
fields, and preserves peer messages/keys regardless of our sender's redaction.
Receiver limits are 5464 base64 bytes before allocation, 4096 decoded bytes, and
1 MiB of repeated/map element memory; buffa's default recursion and unknown-field
limits also apply. Applications receiving larger trusted details can use their
own bounded base64 decode and the generated type's normal buffa decoding APIs.

Compatibility: the conversion signature and macro integration are unchanged,
but RPC messages are now generic, validator defects use `internal`, and typed
details are added. The optional `protos` feature is enabled by `connect` and adds
the existing generated schema dependency. Its generated Rust is checked in, so
normal downstream builds do not require `protoc`. Maintainers regenerate with the
schema crate's [existing Buffa tooling](crates/protovalidate-buffa-protos/README.md).
`default-features = false` retains the runtime without ConnectRPC, base64, or the
new schema/descriptor dependencies; `features = ["protos"]` enables diagnostic
conversion without transport integration. The opt-in `json` feature enables
`protos` plus canonical JSON support on the generated messages, including
`serde_json::to_value(buffa::json_helpers::ProtoJson(&violations))` and JSON
deserialization. It does not enable ConnectRPC JSON transport. The normal
ConnectRPC dependency keeps its JSON, client, server, compression, and TLS
features disabled.

[Protovalidate schema]: https://github.com/bufbuild/protovalidate/blob/main/proto/protovalidate/buf/validate/validate.proto
[Connect's Go validation adapter]: https://github.com/connectrpc/validate-go/blob/main/validate.go
[gRPC Go validation middleware]: https://github.com/grpc-ecosystem/go-grpc-middleware/blob/main/interceptors/protovalidate/protovalidate.go
[Google's `BadRequest`]: https://github.com/googleapis/googleapis/blob/master/google/rpc/error_details.proto
[`google.rpc.Status`]: https://github.com/googleapis/googleapis/blob/master/google/rpc/status.proto
[Connect's wire format]: https://connectrpc.com/docs/protocol/#error-and-endstreamresponse
[gRPC metadata limits]: https://grpc.io/docs/guides/metadata/

## Conformance testing

See the [conformance README] for how to build the dispatch binary and drive the
upstream harness locally. CI runs
`cargo clippy --workspace --all-targets -- -D warnings` and
`cargo test --workspace` on every push; conformance is currently a local-only /
pre-release check.

## Contributing

Please [start a Discussion] before proposing a change. If we accept the proposal,
a Mathematic maintainer or AI agent will implement it and open a pull request. We
will link the implementation pull request to the Discussion and credit the
proposal's original author. GitHub restricts pull request creation to Mathematic
maintainers and repository collaborators with write, maintain, or admin access,
plus authorized maintenance agents. See [CONTRIBUTING.md] for the full process.

## License

Dual-licensed under Apache-2.0 or MIT at your option.

[`protovalidate-conformance`]: https://github.com/bufbuild/protovalidate/tree/main/tools/protovalidate-conformance
[CONTRIBUTING.md]: CONTRIBUTING.md
[conformance README]: crates/protovalidate-buffa-conformance/README.md
[its README]: crates/protovalidate-buffa-conformance/README.md
[predefined rules]: https://protovalidate.com/schemas/predefined-rules/
[protovalidate quick start]: https://protovalidate.com/quickstart/
[standard-rules catalogue]: https://protovalidate.com/schemas/standard-rules/
[start a Discussion]: https://github.com/mathematic-inc/protovalidate-buffa/discussions/new
[upstream proto shape]: https://github.com/bufbuild/protovalidate/blob/main/proto/protovalidate/buf/validate/validate.proto
