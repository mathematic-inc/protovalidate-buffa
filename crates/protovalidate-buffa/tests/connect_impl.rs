//! Confirms `#[connect_impl]` injects `validate()` before user code. A
//! fake service impls use mock traits and mock views — the macro still
//! inserts the decode + validate because it recognizes `OwnedView<_>` and
//! `ServiceRequest<'_, _>` in the signature.

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

struct ServiceRequest<'a, T>(&'a T);

impl ServiceRequest<'_, FakeView> {
    const fn to_owned_message(&self) -> FakeOwned {
        self.0.to_owned_message()
    }
}

trait FakeService {
    fn handle(&self, request: OwnedView<FakeView>) -> Result<(), ::connectrpc::ConnectError>;
}

trait FakeServiceRequestService {
    fn handle(
        &self,
        request: ServiceRequest<'_, FakeView>,
    ) -> Result<(), ::connectrpc::ConnectError>;
}

struct OwnedViewImpl {
    called: Cell<bool>,
}

struct ServiceRequestImpl {
    called: Cell<bool>,
}

#[connect_impl]
impl FakeService for OwnedViewImpl {
    fn handle(&self, _request: OwnedView<FakeView>) -> Result<(), ::connectrpc::ConnectError> {
        self.called.set(true);
        Ok(())
    }
}

#[connect_impl]
impl FakeServiceRequestService for ServiceRequestImpl {
    fn handle(
        &self,
        _request: ServiceRequest<'_, FakeView>,
    ) -> Result<(), ::connectrpc::ConnectError> {
        self.called.set(true);
        Ok(())
    }
}

#[test]
fn injects_validate_for_owned_view_and_short_circuits_on_failure() {
    let svc = OwnedViewImpl {
        called: Cell::new(false),
    };
    let err = svc
        .handle(OwnedView(FakeView { valid: false }))
        .unwrap_err();
    assert_eq!(err.code, ::connectrpc::ErrorCode::InvalidArgument);
    assert!(!svc.called.get(), "body must not run when validate fails");
}

#[test]
fn injects_validate_for_owned_view_and_runs_body_on_success() {
    let svc = OwnedViewImpl {
        called: Cell::new(false),
    };
    svc.handle(OwnedView(FakeView { valid: true })).unwrap();
    assert!(svc.called.get(), "body must run when validate passes");
}

#[test]
fn injects_validate_for_service_request_and_short_circuits_on_failure() {
    let svc = ServiceRequestImpl {
        called: Cell::new(false),
    };
    let view = FakeView { valid: false };
    let err = svc.handle(ServiceRequest(&view)).unwrap_err();
    assert_eq!(err.code, ::connectrpc::ErrorCode::InvalidArgument);
    assert!(!svc.called.get(), "body must not run when validate fails");
}

#[test]
fn injects_validate_for_service_request_and_runs_body_on_success() {
    let svc = ServiceRequestImpl {
        called: Cell::new(false),
    };
    let view = FakeView { valid: true };
    svc.handle(ServiceRequest(&view)).unwrap();
    assert!(svc.called.get(), "body must run when validate passes");
}
