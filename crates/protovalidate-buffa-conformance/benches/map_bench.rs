//! What validating a view costs relative to the owned message, measured
//! through the real generated validators.
//!
//! Two groups, because they answer different questions:
//!
//! - `map_field` isolates the overhead the view body pays on a map field. A
//!   `MapView` is the raw wire entry list, so the view has to rebuild the
//!   canonical last-wins map the owned decoder already built. This is the one
//!   place the view is slower, and how much depends on how heavy the per-entry
//!   rule is — `MapValues` carries a `min_len` check, `MapKeysPattern` a regex
//!   that amortizes the index build.
//! - `decode_validate` is the comparison that decides whether views are worth
//!   using: decode plus validate, end to end, where the view skips building the
//!   owned message entirely.

use buffa::{Message, MessageView};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use protovalidate_buffa::Validate;
use protovalidate_buffa_conformance::generated::buf::validate::conformance::cases::{
    __buffa::view::{MapKeysPatternView, MapValuesView, RepeatedItemPatternView},
    MapKeysPattern, MapValues, RepeatedItemPattern,
};
use std::hint::black_box;

const SIZES: [usize; 5] = [16, 64, 256, 1024, 4096];

fn entries(n: usize) -> Vec<(String, String)> {
    (0..n)
        .map(|i| (format!("key{i:07}"), format!("value{i:07}")))
        .collect()
}

fn map_field(c: &mut Criterion) {
    let mut group = c.benchmark_group("map_field");
    for n in SIZES {
        let pairs = entries(n);

        let mut owned = MapValues::default();
        let mut owned_re = MapKeysPattern::default();
        for (k, v) in &pairs {
            owned.val.insert(k.clone(), v.clone());
            owned_re.val.insert(k.clone(), v.clone());
        }
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let view = MapValuesView {
            val: borrowed.iter().copied().collect(),
            ..Default::default()
        };
        let view_re = MapKeysPatternView {
            val: borrowed.iter().copied().collect(),
            ..Default::default()
        };

        group.bench_with_input(BenchmarkId::new("owned/min_len", n), &owned, |b, m| {
            b.iter(|| black_box(m).validate().is_ok());
        });
        group.bench_with_input(BenchmarkId::new("view/min_len", n), &view, |b, m| {
            b.iter(|| black_box(m).validate().is_ok());
        });
        group.bench_with_input(BenchmarkId::new("owned/regex", n), &owned_re, |b, m| {
            b.iter(|| black_box(m).validate().is_ok());
        });
        group.bench_with_input(BenchmarkId::new("view/regex", n), &view_re, |b, m| {
            b.iter(|| black_box(m).validate().is_ok());
        });
    }
    group.finish();
}

fn decode_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_validate");
    for n in [8usize, 64, 512] {
        let mut msg = RepeatedItemPattern::default();
        for i in 0..n {
            msg.val.push(format!("item{i:07}"));
        }
        let mut bytes = Vec::new();
        msg.encode(&mut bytes);

        group.bench_with_input(BenchmarkId::new("owned", n), &bytes, |b, buf| {
            b.iter(|| {
                let m = RepeatedItemPattern::decode_from_slice(black_box(buf))
                    .expect("fixture decodes");
                m.validate().is_ok()
            });
        });
        group.bench_with_input(BenchmarkId::new("view", n), &bytes, |b, buf| {
            b.iter(|| {
                let v =
                    RepeatedItemPatternView::decode_view(black_box(buf)).expect("fixture decodes");
                v.validate().is_ok()
            });
        });
    }
    group.finish();
}

criterion_group!(benches, map_field, decode_validate);
criterion_main!(benches);
