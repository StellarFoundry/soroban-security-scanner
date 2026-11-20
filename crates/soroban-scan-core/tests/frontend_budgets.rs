//! Frontend performance budgets (#388).
//!
//! The conformance fixture is tiny, so these budgets are deliberately generous:
//! they catch a regression that makes loading dramatically slower or larger,
//! not normal CI variance. Time is wall-clock in the debug test profile; memory
//! is peak allocated bytes from the counting allocator below, which is
//! deterministic across operating systems and does not need `/proc` or RSS.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use soroban_scan_core::discovery::DiscoveryOptions;
use soroban_scan_core::frontend::{default_frontend, Frontend};

/// Maximum wall-clock time for one load of `fixtures/projects/soroban-confirmed`.
pub const TIME_BUDGET: Duration = Duration::from_secs(2);

/// Maximum peak allocated bytes for one load of the same fixture (32 MiB).
pub const PEAK_ALLOCATION_BUDGET: usize = 32 * 1024 * 1024;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            record_allocation(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            record_allocation(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            if new_size >= layout.size() {
                record_allocation(new_size - layout.size());
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn record_allocation(size: usize) {
    let current = CURRENT.fetch_add(size, Ordering::SeqCst) + size;
    PEAK.fetch_max(current, Ordering::SeqCst);
}

fn reset_peak() {
    PEAK.store(CURRENT.load(Ordering::SeqCst), Ordering::SeqCst);
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/projects/soroban-confirmed")
}

#[test]
fn conformance_fixture_meets_frontend_budgets() {
    let frontend = default_frontend();
    let root = fixture();
    let opts = DiscoveryOptions::default();

    // Warm up caches and the allocator before measuring.
    frontend.load(&root, &opts).expect("warm-up load");

    reset_peak();
    let start = Instant::now();
    let loaded = frontend.load(&root, &opts).expect("measured load");
    let elapsed = start.elapsed();
    let peak = PEAK.load(Ordering::SeqCst);
    println!("frontend load: {elapsed:?}, peak allocations: {peak} bytes");

    assert!(
        !loaded.sources.is_empty(),
        "budget fixture loaded no sources; the measurement is not meaningful"
    );
    assert!(
        elapsed <= TIME_BUDGET,
        "frontend load of fixtures/projects/soroban-confirmed took {elapsed:?}, \
which exceeds the {TIME_BUDGET:?} time budget; profile the frontend before \
raising the budget"
    );
    assert!(
        peak <= PEAK_ALLOCATION_BUDGET,
        "frontend load of fixtures/projects/soroban-confirmed allocated {peak} \
bytes at peak, which exceeds the {PEAK_ALLOCATION_BUDGET}-byte budget; find the \
allocation regression before raising the budget"
    );
}
