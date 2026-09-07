//! Confirms `#[connect_impl]` validates views before user code. The request
//! doubles expose only borrowed view accessors and have no owned-message
//! conversion, so an expansion that materializes an owned message fails to
//! compile.

#![warn(rust_2018_idioms)]
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

struct FakeView {
    valid: bool,
}

impl Validate for FakeView {
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

struct OwnedView<T>(T);

impl<T> OwnedView<T> {
    const fn reborrow(&self) -> &T {
        &self.0
    }
}

struct ServiceRequest<'a, T>(&'a T);

impl<T> ServiceRequest<'_, T> {
    const fn view(&self) -> &T {
        self.0
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
        let OwnedView(view) = _request;
        assert!(view.valid, "body receives the validated request");
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
        assert!(_request.view().valid, "body receives the validated request");
        self.called.set(true);
        Ok(())
    }
}

#[connect_impl]
impl OwnedViewImpl {
    fn helper(&self, value: usize) -> usize {
        self.called.set(true);
        value
    }
}

#[test]
fn leaves_non_handler_methods_unchanged() {
    let svc = OwnedViewImpl {
        called: Cell::new(false),
    };
    assert_eq!(svc.helper(42), 42);
    assert!(svc.called.get());
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
    let details = protovalidate_buffa::decode_violations(&err.details[0])
        .unwrap()
        .unwrap();
    assert_eq!(details.violations[0].rule_id.as_deref(), Some("fake"));
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
    let details = protovalidate_buffa::decode_violations(&err.details[0])
        .unwrap()
        .unwrap();
    assert_eq!(details.violations[0].rule_id.as_deref(), Some("fake"));
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
