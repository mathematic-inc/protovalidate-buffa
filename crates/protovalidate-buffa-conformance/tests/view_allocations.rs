#![warn(rust_2018_idioms)]
#![allow(
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

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use buffa::{Message as _, MessageView as _};
use protovalidate_buffa::Validate as _;

pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/_include.rs"));
}

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// SAFETY: every allocation operation is forwarded to `System` with its
// arguments unchanged; the side counter is safe thread-local state.
unsafe impl GlobalAlloc for CountingAllocator {
    /// # Safety
    ///
    /// `layout` must satisfy [`GlobalAlloc::alloc`]'s contract.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: `layout` is forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    /// # Safety
    ///
    /// `layout` must satisfy [`GlobalAlloc::alloc_zeroed`]'s contract.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: `layout` is forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    /// # Safety
    ///
    /// `ptr` and `layout` must satisfy [`GlobalAlloc::dealloc`]'s contract.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` and `layout` came from the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    /// # Safety
    ///
    /// The arguments must satisfy [`GlobalAlloc::realloc`]'s contract.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: `ptr` and `layout` came from the system allocator and
        // `new_size` is forwarded unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

fn record_allocation() {
    if TRACK_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCATION_COUNT.try_with(|count| count.set(count.get() + 1));
    }
}

fn allocations_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATION_COUNT.with(|count| count.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    let result = f();
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    let count = ALLOCATION_COUNT.with(Cell::get);
    (result, count)
}

/// # Design
///
/// Decoding happens before allocation tracking because Buffa's repeated and
/// map views intentionally own index vectors. The assertion covers only the
/// public `Validate::validate` call on already-decoded borrowed views.
#[test]
fn valid_borrowed_views_allocate_nothing_during_validation() {
    use generated::{
        buf::validate::conformance::cases::{
            __buffa::view::{FieldMaskConstView, StringConstView},
            FieldMaskConst, StringConst,
        },
        google::protobuf::FieldMask,
    };

    let mut string_bytes = Vec::new();
    StringConst {
        val: "foo".to_owned(),
        ..Default::default()
    }
    .encode(&mut string_bytes);
    let string_view = StringConstView::decode_view(&string_bytes).expect("decode string view");
    let (result, allocations) = allocations_during(|| string_view.validate());
    assert!(result.is_ok());
    assert_eq!(allocations, 0);

    let mut field_mask_bytes = Vec::new();
    FieldMaskConst {
        val: FieldMask {
            paths: vec!["a".to_owned()],
            ..Default::default()
        }
        .into(),
        ..Default::default()
    }
    .encode(&mut field_mask_bytes);
    let field_mask_view =
        FieldMaskConstView::decode_view(&field_mask_bytes).expect("decode field-mask view");
    let (result, allocations) = allocations_during(|| field_mask_view.validate());
    assert!(result.is_ok());
    assert_eq!(allocations, 0);
}

#[test]
fn valid_borrowed_map_validation_is_allocation_free() {
    use generated::buf::validate::conformance::cases::{__buffa::view::MapMinView, MapMin};

    let mut message = MapMin::default();
    message.val.insert(1, 1.0);
    message.val.insert(2, 2.0);
    let mut bytes = Vec::new();
    message.encode(&mut bytes);
    let view = MapMinView::decode_view(&bytes).expect("decode map view");

    let (result, allocations) = allocations_during(|| view.validate());
    assert!(result.is_ok());
    assert_eq!(allocations, 0);
}

#[test]
fn duplicate_borrowed_values_fail_unique_validation() {
    use generated::buf::validate::conformance::cases::{
        __buffa::view::RepeatedUniqueView, RepeatedUnique,
    };

    let mut bytes = Vec::new();
    RepeatedUnique {
        val: vec!["duplicate".to_owned(), "duplicate".to_owned()],
        ..Default::default()
    }
    .encode(&mut bytes);
    let view = RepeatedUniqueView::decode_view(&bytes).expect("decode repeated view");

    assert!(view.validate().is_err());
}
