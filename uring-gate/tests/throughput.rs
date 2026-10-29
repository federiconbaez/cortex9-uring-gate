//! Throughput acceptance: the restricted ring must keep >= 85% of native
//! io_uring throughput (vs 0% if io_uring were banned). Uses a modest
//! iteration count so CI stays quick; the README reports a larger run.

use uring_gate::bench;

#[test]
fn restricted_ring_keeps_85_percent() {
    // Median of three short runs to damp scheduler noise on shared CI.
    let mut ratios: Vec<f64> = (0..3)
        .map(|_| bench::run(100_000).expect("bench").ratio())
        .collect();
    ratios.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = ratios[1];
    assert!(
        median >= 0.85,
        "restricted-ring throughput ratio {median:.4} below 0.85 (ratios {ratios:?})"
    );
}
