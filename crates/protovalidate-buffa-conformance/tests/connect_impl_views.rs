//! Exercise `connect_impl` with real request wrappers and generated validators.

#![warn(rust_2018_idioms)]

use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};

use buffa::{Message as _, MessageView as _, bytes::Bytes};
use protovalidate_buffa::connect_impl;

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    elided_lifetimes_in_paths,
    non_camel_case_types,
    unused_imports,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_html_tags,
    reason = "buffa-build generated code — upstream codegen style; do not police"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/_include.rs"));
}

use generated::buf::validate::conformance::cases::{__buffa::view::StringConstView, StringConst};

#[derive(Default)]
struct Service {
    called: AtomicBool,
}

#[connect_impl]
impl Service {
    async fn owned(
        &self,
        request: buffa::OwnedView<StringConstView<'static>>,
    ) -> Result<buffa::OwnedView<StringConstView<'static>>, connectrpc::ConnectError> {
        self.called.store(true, Ordering::Relaxed);
        yield_once().await;
        Ok(request)
    }

    async fn borrowed<'a>(
        &self,
        request: connectrpc::ServiceRequest<'a, StringConst>,
    ) -> Result<connectrpc::ServiceRequest<'a, StringConst>, connectrpc::ConnectError> {
        self.called.store(true, Ordering::Relaxed);
        yield_once().await;
        Ok(request)
    }
}

async fn yield_once() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

fn message(value: &str) -> StringConst {
    StringConst {
        val: value.to_owned(),
        ..Default::default()
    }
}

/// The handler yields exactly once before returning the request by value,
/// proving that validation releases its borrow before an async suspension.
fn complete_handler<F: Future + Send>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    let Poll::Ready(result) = future.as_mut().poll(&mut cx) else {
        panic!("handler must complete after its single suspension");
    };
    result
}

/// Invalid requests must return before the handler's first suspension.
fn reject_handler<F: Future + Send>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready(result) = future.as_mut().poll(&mut cx) else {
        panic!("validation must reject the request before entering the handler");
    };
    result
}

#[test]
fn valid_owned_views_remain_usable_after_handler_suspends() {
    let message = message("foo");
    let body = Bytes::from(message.encode_to_vec());
    for request in [
        buffa::OwnedView::<StringConstView<'static>>::decode(body).unwrap(),
        buffa::OwnedView::<StringConstView<'static>>::from_owned(&message).unwrap(),
    ] {
        let service = Service::default();
        let original_bytes = request.bytes().as_ptr();
        let original_value = request.reborrow().val.as_ptr();

        let returned = complete_handler(service.owned(request)).unwrap();

        assert!(service.called.load(Ordering::Relaxed));
        assert_eq!(returned.reborrow().val, "foo");
        assert_eq!(returned.bytes().as_ptr(), original_bytes);
        assert_eq!(returned.reborrow().val.as_ptr(), original_value);
    }
}

#[test]
fn invalid_owned_views_skip_handler_and_return_invalid_argument() {
    let message = message("invalid");
    let body = Bytes::from(message.encode_to_vec());
    for request in [
        buffa::OwnedView::<StringConstView<'static>>::decode(body).unwrap(),
        buffa::OwnedView::<StringConstView<'static>>::from_owned(&message).unwrap(),
    ] {
        let service = Service::default();

        let error = reject_handler(service.owned(request)).unwrap_err();

        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
        assert!(!service.called.load(Ordering::Relaxed));
    }
}

#[test]
fn valid_service_request_remains_borrowed_after_handler_suspends() {
    let body = Bytes::from(message("foo").encode_to_vec());
    let view = StringConstView::decode_view(&body).unwrap();
    let request = connectrpc::ServiceRequest::<StringConst>::from_parts(&view, &body);
    let service = Service::default();

    let returned = complete_handler(service.borrowed(request)).unwrap();

    assert!(service.called.load(Ordering::Relaxed));
    assert_eq!(returned.val, "foo");
    assert!(std::ptr::eq(returned.view(), &raw const view));
    assert!(std::ptr::eq(returned.bytes(), &raw const body));
}

#[test]
fn invalid_service_request_skips_handler_and_returns_invalid_argument() {
    let body = Bytes::from(message("invalid").encode_to_vec());
    let view = StringConstView::decode_view(&body).unwrap();
    let request = connectrpc::ServiceRequest::<StringConst>::from_parts(&view, &body);
    let service = Service::default();

    let error = reject_handler(service.borrowed(request)).unwrap_err();

    assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
    assert!(!service.called.load(Ordering::Relaxed));
}
