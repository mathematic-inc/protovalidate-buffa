//! Confirms `#[connect_impl]` injects `validate()` before user code. A
//! fake service impl uses a mock trait and a mock View — the macro still
//! inserts the decode + validate because it recognizes `OwnedView<_>` in
//! the signature.

#![cfg(feature = "connect")]
// `clippy::result_large_err` fires on the fake trait because
// `connectrpc::ConnectError` is a hefty type; the test doesn't care.
#![allow(
    clippy::result_large_err,
    clippy::used_underscore_binding,
    reason = "test scaffolding: fake connectrpc trait signature + macro-expanded bindings named _var"
)]

use std::cell::Cell;

use protovalidate_buffa::{FieldPath, Validate, ValidationError, Violation, connect_impl};

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

// connectrpc 0.7 hands handlers a `ServiceRequest<'_, _>` rather than an
// `OwnedView<_>`; the macro must recognize it too (both expose
// `to_owned_message()`), else `#[connect_impl]` silently no-ops under 0.7.
struct ServiceRequest<'a, T>(&'a T);

impl<T> ServiceRequest<'_, T> {
    fn to_owned_message(&self) -> FakeOwned
    where
        T: AsRef<FakeView>,
    {
        self.0.as_ref().to_owned_message()
    }
}

impl AsRef<FakeView> for FakeView {
    fn as_ref(&self) -> &FakeView {
        self
    }
}

trait FakeService07 {
    fn handle(&self, request: ServiceRequest<'_, FakeView>) -> Result<(), ::connectrpc::ConnectError>;
}

struct Impl07 {
    called: Cell<bool>,
}

#[connect_impl]
impl FakeService07 for Impl07 {
    fn handle(
        &self,
        _request: ServiceRequest<'_, FakeView>,
    ) -> Result<(), ::connectrpc::ConnectError> {
        self.called.set(true);
        Ok(())
    }
}

#[test]
fn injects_validate_for_service_request_0_7() {
    let svc = Impl07 {
        called: Cell::new(false),
    };
    let bad = FakeView { valid: false };
    let err = svc.handle(ServiceRequest(&bad)).unwrap_err();
    assert_eq!(err.code, ::connectrpc::ErrorCode::InvalidArgument);
    assert!(!svc.called.get(), "body must not run when validate fails");

    let svc = Impl07 {
        called: Cell::new(false),
    };
    let good = FakeView { valid: true };
    svc.handle(ServiceRequest(&good)).unwrap();
    assert!(svc.called.get(), "body must run when validate passes");
}
