//! Dispatch table from proto fully-qualified name to a parse+validate
//! function. The `dispatch_known` function is generated at build time from
//! the set of compiled cases protos.

use crate::pb_validate;

pub(crate) enum CaseOutcome {
    Valid,
    Invalid(pb_validate::Violations),
    RuntimeError(String),
    CompilationError(String),
    Unsupported,
}

#[expect(
    clippy::too_many_lines,
    clippy::redundant_pub_crate,
    reason = "generated dispatch table: one match arm per registered message type"
)]
mod dispatch_impl {
    use super::CaseOutcome;
    include!(concat!(env!("OUT_DIR"), "/dispatch.rs"));
}
use dispatch_impl::dispatch_known;

pub(crate) fn dispatch(fqn: &str, bytes: &[u8]) -> CaseOutcome {
    dispatch_known(fqn, bytes).unwrap_or(CaseOutcome::Unsupported)
}
