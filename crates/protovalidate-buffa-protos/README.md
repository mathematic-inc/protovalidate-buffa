# protovalidate-buffa-protos

Compiled Rust types for `buf/validate/validate.proto`, generated via `buffa-build`
at build time. [`protoc-gen-protovalidate-buffa`] consumes them to read
`(buf.validate.*)` options off proto descriptors at codegen time.

The `validate.proto` schema is vendored under `proto/` so this crate is self-contained.

This crate is not intended for direct use. Depend on [`protovalidate-buffa`] for
the runtime API.

[`protoc-gen-protovalidate-buffa`]: ../protoc-gen-protovalidate-buffa/
[`protovalidate-buffa`]: ../protovalidate-buffa/
