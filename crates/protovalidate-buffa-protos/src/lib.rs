//! Compiled Rust types for `buf/validate/validate.proto`, used by
//! `protoc-gen-protovalidate-buffa` to read `(buf.validate.*)` options off
//! `FieldOptions` / `MessageOptions` / `OneofOptions`.
//!
//! The body of this file is entirely `buffa-build` output; we disable the
//! workspace's strict lints for it so upstream codegen style doesn't block CI.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction,
    reason = "buffa-build generated code — upstream codegen style; do not police"
)]
#![allow(
    warnings,
    reason = "generated code may emit unused-imports/dead-code warnings"
)]

include!(concat!(env!("OUT_DIR"), "/_include.rs"));
