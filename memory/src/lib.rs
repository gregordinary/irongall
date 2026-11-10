//! A counting allocator, with which `tests/memory.rs` measures what reading
//! irongall's input allocates.
//!
//! It is a crate of its own because implementing an allocator takes
//! `unsafe`, which the library forbids.

#![deny(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// The system allocator, counting the octets requested of it: those held
/// now, and the most held at once since a [`measure`](Self::measure) began.
///
/// What is counted is the sizes requested, not what an allocator spends on
/// each, so the counts are the same whichever allocator serves them. A
/// reallocation counts as the change in its size, as one that grows or
/// shrinks in place spends.
#[derive(Debug)]
pub struct Counting {
    held: AtomicUsize,
    peak: AtomicUsize,
}

/// What a [`measure`](Counting::measure) found: the octets held beyond what
/// was held before it began.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measured {
    /// Held when the measured work returned, by what it returned.
    pub held: usize,
    /// The most held at once while it ran.
    pub peak: usize,
}

impl Counting {
    /// A counting allocator, with nothing counted yet.
    #[must_use]
    pub const fn new() -> Counting {
        Counting {
            held: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    /// Runs `work`, and returns what it returns with what it allocated.
    ///
    /// The counts are the process's, so nothing else may allocate while
    /// `work` runs.
    pub fn measure<T>(&self, work: impl FnOnce() -> T) -> (T, Measured) {
        let before = self.held.load(Ordering::SeqCst);
        self.peak.store(before, Ordering::SeqCst);
        let result = work();
        let measured = Measured {
            held: self.held.load(Ordering::SeqCst).saturating_sub(before),
            peak: self.peak.load(Ordering::SeqCst).saturating_sub(before),
        };
        (result, measured)
    }

    fn grow(&self, size: usize) {
        let held = self
            .held
            .fetch_add(size, Ordering::SeqCst)
            .saturating_add(size);
        self.peak.fetch_max(held, Ordering::SeqCst);
    }

    fn shrink(&self, size: usize) {
        self.held.fetch_sub(size, Ordering::SeqCst);
    }
}

impl Default for Counting {
    fn default() -> Counting {
        Counting::new()
    }
}

#[expect(
    unsafe_code,
    reason = "an allocator is an `unsafe` trait; each method passes its \
              arguments to the system allocator unchanged, so the caller's \
              obligations are the system allocator's, and counts only what \
              succeeded"
)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let allocated = unsafe { System.alloc(layout) };
        if !allocated.is_null() {
            self.grow(layout.size());
        }
        allocated
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let allocated = unsafe { System.alloc_zeroed(layout) };
        if !allocated.is_null() {
            self.grow(layout.size());
        }
        allocated
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        self.shrink(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let reallocated = unsafe { System.realloc(ptr, layout, new_size) };
        if !reallocated.is_null() {
            match new_size.checked_sub(layout.size()) {
                Some(grown) => self.grow(grown),
                None => self.shrink(layout.size().saturating_sub(new_size)),
            }
        }
        reallocated
    }
}
