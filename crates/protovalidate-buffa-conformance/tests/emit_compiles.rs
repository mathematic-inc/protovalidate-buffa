//! End-to-end compile check for the CEL → Rust transpiler.
//!
//! The build script (`build.rs`) runs the transpiler against a curated
//! battery of CEL expressions covering features the conformance suite
//! doesn't exercise (two-variable comprehensions, `type()`, dynamic
//! `duration()` / `timestamp()`, format directives `%e` / `%x` / `%o` /
//! `%b`, map literals, list indexing, `int`/`uint` cross-type compare,
//! empty-list short-circuits, dynamic regex, `rule`-const folding) and
//! emits each result as a `pub fn _check_<name>(...) -> <Type>` function
//! ascribed to its expected Rust return type. This file `include!()`s
//! that fixture so the test binary's compile is the verification — if
//! any emitted body fails to type-check, the test crate fails to build
//! and CI catches it.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    unused_variables,
    unused_imports,
    unused_parens,
    clippy::unnecessary_cast,
    reason = "generated transpiler-emit fixtures — the goal is type-check, not style"
)]

include!(concat!(env!("OUT_DIR"), "/cel_emit_fixtures.rs"));

#[test]
fn fixtures_compile() {
    // The test passes by virtue of the fixture file having compiled.
    // Calling one of the generated fns just keeps the linker honest.
    let _ = _check_empty_map_size(0);
}
