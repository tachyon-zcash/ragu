//! Serial fallback behavior of the accelerated backends.

// Cargo can enable this crate's multicore feature independently of a
// downstream crate's flag, so the fallback test belongs with this feature.
#![cfg(not(feature = "multicore"))]

use core::sync::atomic::{AtomicUsize, Ordering};

use ragu_acceleration::{AcceleratedBackend, AcceleratedProver};
use ragu_backend::Backend;

#[test]
fn serial_map_prepares_one_input_at_a_time() {
    fn check<B: Backend>() {
        let completed = AtomicUsize::new(0);
        let inputs = (0..5).inspect(|&index| {
            assert_eq!(completed.load(Ordering::Relaxed), index);
        });
        let results = B::map(inputs, |index| {
            completed.fetch_add(1, Ordering::Relaxed);
            index * 7
        });
        assert_eq!(completed.load(Ordering::Relaxed), 0);
        assert_eq!(results.collect::<Vec<_>>(), [0, 7, 14, 21, 28]);
        assert_eq!(completed.load(Ordering::Relaxed), 5);
    }
    check::<AcceleratedBackend>();
    check::<AcceleratedProver>();
}
