//! Cost of validating a map field on each shape, using the real generated
//! validators for `buf.validate.conformance.cases.MapValues`
//! (`map<string, string>` carrying `map.values.string.min_len`).

use std::hint::black_box;
use std::time::Instant;

use protovalidate_buffa::Validate;

mod generated {
    #![allow(
        clippy::all,
        clippy::pedantic,
        clippy::nursery,
        dead_code,
        non_camel_case_types,
        unused_imports,
        rustdoc::broken_intra_doc_links,
        rustdoc::invalid_html_tags,
        reason = "buffa-build generated code — upstream codegen style; do not police"
    )]
    include!(concat!(env!("OUT_DIR"), "/_include.rs"));
}

use generated::buf::validate::conformance::cases::{
    __buffa::view::{MapKeysPatternView, MapValuesView},
    MapKeysPattern, MapValues,
};

fn main() {
    println!(
        "{:>7}  {:>11}  {:>11}  {:>7}  |  {:>11}  {:>11}  {:>7}",
        "entries", "owned", "view", "ratio", "owned/re", "view/re", "ratio"
    );
    for n in [16usize, 64, 256, 1024, 4096] {
        let keys: Vec<String> = (0..n).map(|i| format!("key{i:07}")).collect();
        let vals: Vec<String> = (0..n).map(|i| format!("value{i:07}")).collect();

        let mut owned = MapValues::default();
        for (k, v) in keys.iter().zip(&vals) {
            owned.val.insert(k.clone(), v.clone());
        }
        let view = MapValuesView {
            val: keys
                .iter()
                .zip(&vals)
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
            ..Default::default()
        };

        let reps = if n > 2048 { 500u32 } else { 5000 };

        let t = Instant::now();
        for _ in 0..reps {
            black_box(black_box(&owned).validate().is_ok());
        }
        let o = t.elapsed() / reps;

        let t = Instant::now();
        for _ in 0..reps {
            black_box(black_box(&view).validate().is_ok());
        }
        let v = t.elapsed() / reps;

        // Same field shape, but the per-entry rule is a regex rather than a
        // length check — heavier rule work amortizes the index build.
        let mut owned_re = MapKeysPattern::default();
        for (k, val) in keys.iter().zip(&vals) {
            owned_re.val.insert(k.clone(), val.clone());
        }
        let view_re = MapKeysPatternView {
            val: keys
                .iter()
                .zip(&vals)
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
            ..Default::default()
        };
        let t = Instant::now();
        for _ in 0..reps {
            black_box(black_box(&owned_re).validate().is_ok());
        }
        let ore = t.elapsed() / reps;
        let t = Instant::now();
        for _ in 0..reps {
            black_box(black_box(&view_re).validate().is_ok());
        }
        let vre = t.elapsed() / reps;

        println!(
            "{n:>7}  {o:>11.2?}  {v:>11.2?}  {:>6.2}x  |  {ore:>11.2?}  {vre:>11.2?}  {:>6.2}x",
            v.as_secs_f64() / o.as_secs_f64(),
            vre.as_secs_f64() / ore.as_secs_f64()
        );
    }
}
