//! Confirms `#[connect_impl]` injects `validate()` before user code. A
//! fake service impl uses a mock trait and a mock View — the macro still
//! inserts the decode + validate because it recognizes `OwnedView<_>` in
//! the signature.

// The generated macro output names `::buffa_protovalidate` paths that aren't
// reachable from this test crate; we re-expose them under the expected
// path via `extern crate self as buffa_protovalidate;`. Not part of the
// public API — just test scaffolding.
//
// `clippy::result_large_err` fires on the fake trait because
// `connectrpc::ConnectError` is a hefty type; the test doesn't care.
#![allow(
    clippy::result_large_err,
    clippy::used_underscore_binding,
    reason = "test scaffolding: fake connectrpc trait signature + macro-expanded bindings named _var"
)]

use std::cell::Cell;

use protovalidate_buffa::{connect_impl, FieldPath, Validate, ValidationError, Violation};

struct FakeOwned {
    valid: bool,
}

impl Validate for FakeOwned {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.valid {
            Ok(())
        } else {
            Err(ValidationError {
                violations: vec![Violation {
                    field: FieldPath::default(),
                    rule: FieldPath::default(),
                    rule_id: "fake".into(),
                    message: "fake fails".into(),
                    for_key: false,
                }],
                ..Default::default()
            })
        }
    }
}

struct FakeView {
    valid: bool,
}

impl FakeView {
    const fn to_owned_message(&self) -> FakeOwned {
        FakeOwned { valid: self.valid }
    }
}

struct OwnedView<T>(T);

impl<T> std::ops::Deref for OwnedView<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

trait FakeService {
    fn handle(&self, request: OwnedView<FakeView>) -> Result<(), ::connectrpc::ConnectError>;
}

struct Impl {
    called: Cell<bool>,
}

#[connect_impl]
impl FakeService for Impl {
    fn handle(&self, _request: OwnedView<FakeView>) -> Result<(), ::connectrpc::ConnectError> {
        self.called.set(true);
        Ok(())
    }
}

#[test]
fn injects_validate_and_short_circuits_on_failure() {
    let svc = Impl {
        called: Cell::new(false),
    };
    let err = svc
        .handle(OwnedView(FakeView { valid: false }))
        .unwrap_err();
    assert_eq!(err.code, ::connectrpc::ErrorCode::InvalidArgument);
    assert!(!svc.called.get(), "body must not run when validate fails");
}

#[test]
fn injects_validate_and_runs_body_on_success() {
    let svc = Impl {
        called: Cell::new(false),
    };
    svc.handle(OwnedView(FakeView { valid: true })).unwrap();
    assert!(svc.called.get(), "body must run when validate passes");
}
