//! Safe access to FRE's audited exact-allocation and thread-owner primitives.

#![deny(unsafe_code)]

use core::{
    alloc::Layout,
    cell::UnsafeCell,
    fmt,
    marker::PhantomData,
    mem::{align_of, size_of},
    ops::{Deref, DerefMut},
    panic::{RefUnwindSafe, UnwindSafe},
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::alloc::{alloc, alloc_zeroed};

const THREAD_OWNER_UNOWNED: usize = 0;
const THREAD_OWNER_IN_USE: usize = 1;

static NEXT_THREAD_OWNER_ID: AtomicUsize = AtomicUsize::new(2);

std::thread_local! {
    static THREAD_OWNER_ID: usize = NEXT_THREAD_OWNER_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| current.checked_add(1))
        .expect("FRE thread-owner ID space exhausted");
}

fn thread_owner_id() -> usize {
    THREAD_OWNER_ID.with(|id| *id)
}

/// One reusable value reserved for the thread that first checks it out.
///
/// The owner thread avoids a mutex and borrows the retained value in place.
/// Other threads must use a caller-provided fallback pool. A checkout guard
/// discards its value by default; callers explicitly commit only after a
/// successful transaction. This makes unwind and error paths fail closed.
pub struct ThreadOwnerSlot<T> {
    owner: AtomicUsize,
    value: UnsafeCell<Option<T>>,
}

/// Exclusive access to a [`ThreadOwnerSlot`] value.
///
/// Dropping this guard discards the value and releases ownership. Call
/// [`Self::commit`] to retain a successfully used value for the same owner.
/// A guard can move to another thread when `T: Send`, but it cannot be shared
/// there unless `T: Sync`:
///
/// ```compile_fail
/// use core::cell::Cell;
/// use fre_exact_alloc::ThreadOwnerGuard;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<ThreadOwnerGuard<'static, Cell<u8>>>();
/// ```
pub struct ThreadOwnerGuard<'a, T> {
    slot: &'a ThreadOwnerSlot<T>,
    owner: usize,
    committed: bool,
    // A guard may move when T is Send, but sharing the guard requires T: Sync
    // because `value` can project a shared reference to T.
    marker: PhantomData<T>,
}

// The guard contains only a reference, an owner ID, and transaction state;
// moving it never moves or projects the slot's retained `T`.
impl<T> Unpin for ThreadOwnerGuard<'_, T> {}

#[allow(
    unsafe_code,
    reason = "the atomic owner state gives exactly one thread access to the owner-only cell"
)]
// SAFETY: `value` is accessed only while `owner == THREAD_OWNER_IN_USE`, and
// only the unique thread whose ID matched the prior owner can make that state
// transition without synchronization. Non-owner threads never access the
// cell. A guard may move threads, but it retains the original owner ID and
// keeps the state in-use until commit or drop.
unsafe impl<T: Send> Sync for ThreadOwnerSlot<T> {}

impl<T: UnwindSafe> UnwindSafe for ThreadOwnerSlot<T> {}
impl<T: RefUnwindSafe> RefUnwindSafe for ThreadOwnerSlot<T> {}

impl<T> ThreadOwnerSlot<T> {
    /// Create an unowned empty slot without allocating.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owner: AtomicUsize::new(THREAD_OWNER_UNOWNED),
            value: UnsafeCell::new(None),
        }
    }

    /// Create an unowned slot containing one reusable value.
    ///
    /// The first successful checkout becomes the fast-path owner. Moving this
    /// slot before that checkout therefore cannot strand the value on the
    /// construction thread.
    #[must_use]
    pub const fn with_value(value: T) -> Self {
        Self {
            owner: AtomicUsize::new(THREAD_OWNER_UNOWNED),
            value: UnsafeCell::new(Some(value)),
        }
    }

    /// Create a populated slot already reserved for the current thread.
    ///
    /// This is useful when a fallibly built owner is about to be published
    /// and its constructing invocation must retain the initial checkout. A
    /// slot that might move without an immediate checkout should use
    /// [`Self::with_value`] instead.
    #[must_use]
    pub fn with_current_owner(value: T) -> Self {
        Self {
            owner: AtomicUsize::new(thread_owner_id()),
            value: UnsafeCell::new(Some(value)),
        }
    }

    /// Check out the owner value without locking.
    ///
    /// The first populated commit establishes the fast-path owner. Calls from
    /// a different thread, and reentrant calls while a guard is live, return
    /// `None` without touching the value. Discarding the value releases the
    /// empty slot so a later caller may become its new owner.
    #[must_use]
    pub fn try_checkout(&self) -> Option<ThreadOwnerGuard<'_, T>> {
        let caller = thread_owner_id();
        let owner = self.owner.load(Ordering::Acquire);
        if owner == caller {
            // Only the thread with this never-reused ID can enter this branch.
            // Non-owners never CAS an established owner ID, so this owner-only
            // load/store shape cannot race another access to `value`.
            self.owner.store(THREAD_OWNER_IN_USE, Ordering::Release);
        } else if owner == THREAD_OWNER_UNOWNED {
            self.owner
                .compare_exchange(
                    THREAD_OWNER_UNOWNED,
                    THREAD_OWNER_IN_USE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .ok()?;
        } else {
            return None;
        }
        Some(ThreadOwnerGuard {
            slot: self,
            owner: caller,
            committed: false,
            marker: PhantomData,
        })
    }

    /// Recover the retained value when the slot has never been published.
    ///
    /// Consuming the slot provides exclusive access and needs no atomic state
    /// transition. This is used only to recover ownership after a failed
    /// fallible publication.
    #[must_use]
    pub fn into_value(self) -> Option<T> {
        self.value.into_inner()
    }
}

impl<T> Default for ThreadOwnerSlot<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> fmt::Debug for ThreadOwnerSlot<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreadOwnerSlot")
            .field("owner_state", &self.owner.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<T> ThreadOwnerGuard<'_, T> {
    /// Borrow the retained value, or `None` for a newly claimed empty slot.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "the live guard is the unique accessor to the owner-only cell"
    )]
    pub fn value(&self) -> Option<&T> {
        // SAFETY: this guard exclusively owns the in-use state. Shared access
        // here cannot overlap mutation except through this same guard.
        unsafe { (&*self.slot.value.get()).as_ref() }
    }

    /// Mutably borrow the retained value, or `None` for an empty slot.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "the live guard is the unique mutable accessor to the owner-only cell"
    )]
    pub fn value_mut(&mut self) -> Option<&mut T> {
        // SAFETY: no other guard can exist while the atomic state is in-use.
        unsafe { (&mut *self.slot.value.get()).as_mut() }
    }

    /// Install the value for this exclusive checkout.
    ///
    /// Returns `Err(value)` if the slot already contains a value.
    pub fn try_insert(&mut self, value: T) -> Result<(), T> {
        if self.value().is_some() {
            return Err(value);
        }
        // `value_mut` proved this guard's unique access, but it projects the
        // inner value rather than the surrounding option.
        self.replace_value(Some(value));
        Ok(())
    }

    /// Move the retained value out while keeping this checkout exclusive.
    ///
    /// This is intended for an existing owning API that must temporarily
    /// carry `T` by value. The guard remains the return token: insert the
    /// successfully used value and commit, or drop the guard to release an
    /// empty slot.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "the live guard exclusively takes the owner-only cell value"
    )]
    pub fn take(&mut self) -> Option<T> {
        // SAFETY: the guard is the sole accessor while the state is in-use.
        unsafe { (&mut *self.slot.value.get()).take() }
    }

    /// Discard any current value but keep the guard live and exclusive.
    pub fn clear(&mut self) {
        self.replace_value(None);
    }

    /// Retain the current value and restore the fast-path owner.
    pub fn commit(mut self) {
        let owner = if self.value().is_some() {
            self.owner
        } else {
            THREAD_OWNER_UNOWNED
        };
        self.committed = true;
        self.slot.owner.store(owner, Ordering::Release);
    }

    #[allow(
        unsafe_code,
        reason = "the live guard exclusively replaces the owner-only cell value"
    )]
    fn replace_value(&mut self, value: Option<T>) {
        // SAFETY: the guard is the sole accessor while the state is in-use.
        // `ptr::replace` installs a valid new option before dropping the old
        // value, so even a panicking destructor cannot leave stale bits in
        // the cell to be dropped a second time.
        let old = unsafe { ptr::replace(self.slot.value.get(), value) };
        drop(old);
    }
}

impl<T> Drop for ThreadOwnerGuard<'_, T> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Discard before publishing an empty, unowned slot. If T's destructor
        // panics, the slot remains permanently in-use and therefore fails
        // closed instead of exposing partially destroyed state.
        self.clear();
        self.slot
            .owner
            .store(THREAD_OWNER_UNOWNED, Ordering::Release);
    }
}

impl<T: fmt::Debug> fmt::Debug for ThreadOwnerGuard<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreadOwnerGuard")
            .field("owner", &self.owner)
            .field("value", &self.value())
            .finish()
    }
}

/// Failure to copy bytes into an exact-capacity allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyError {
    /// The requested byte count cannot be represented as an allocation layout.
    LayoutOverflow,
    /// The global allocator rejected the exact layout.
    AllocationFailed,
}

impl fmt::Display for CopyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LayoutOverflow => formatter.write_str("exact allocation layout overflow"),
            Self::AllocationFailed => formatter.write_str("exact allocation failed"),
        }
    }
}

impl std::error::Error for CopyError {}

/// One word containing either an inline `usize` or one fallibly allocated
/// initialized value.
///
/// Even words encode the integer shifted left by one. Odd words own an
/// aligned allocation whose exposed address has its otherwise-zero low bit
/// set. This lets object-neutral compiler plans retain a large optional proof
/// without invoking Rust's infallible allocation-error handler.
pub struct ExactBoxOrUsize<T> {
    encoded: usize,
    marker: PhantomData<T>,
}

/// Fallibly allocate exactly one `T` while returning ownership on failure.
///
/// Construction transactions use this form when a failed final-owner
/// allocation must still publish receipts derived from the unpublished value.
pub fn try_box_preserve<T>(value: T) -> Result<Box<T>, (CopyError, T)> {
    exact_box_preserve_with(value, false)
}

impl<T> ExactBoxOrUsize<T> {
    /// Retain an inline integer when its one-bit tag shift is representable.
    pub fn try_from_usize(value: usize) -> Result<Self, CopyError> {
        value
            .checked_mul(2)
            .map(|encoded| Self {
                encoded,
                marker: PhantomData,
            })
            .ok_or(CopyError::LayoutOverflow)
    }

    /// Allocate exactly one `T` and retain it behind the tagged word.
    pub fn try_from_boxed(value: T) -> Result<Self, CopyError> {
        exact_box_or_usize_with(value, false)
    }

    /// Return the inline integer, or `None` when this word owns a value.
    #[must_use]
    pub const fn as_usize(&self) -> Option<usize> {
        if self.encoded & 1 == 0 {
            Some(self.encoded >> 1)
        } else {
            None
        }
    }

    /// Borrow the owned value, or `None` when this word contains an integer.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "the tagged word recovers only the exposed provenance of its live owned allocation"
    )]
    pub fn boxed(&self) -> Option<&T> {
        if self.encoded & 1 == 0 {
            return None;
        }
        let address = self.encoded & !1;
        // SAFETY: the odd variant is created only from the exposed address of
        // a live, aligned `Box<T>` allocation retained exclusively by `self`.
        unsafe { ptr::with_exposed_provenance::<T>(address).as_ref() }
    }

    /// Mutably borrow the owned value, or `None` when this word contains an
    /// integer.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "the exclusive handle borrow recovers only the exposed provenance of its live exclusively owned allocation"
    )]
    pub fn boxed_mut(&mut self) -> Option<&mut T> {
        if self.encoded & 1 == 0 {
            return None;
        }
        let address = self.encoded & !1;
        // SAFETY: the odd variant exclusively owns this live allocation and
        // `&mut self` prevents any overlapping borrow through the handle.
        unsafe { ptr::with_exposed_provenance_mut::<T>(address).as_mut() }
    }
}

impl<T: fmt::Debug> fmt::Debug for ExactBoxOrUsize<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.as_usize(), self.boxed()) {
            (Some(value), None) => formatter.debug_tuple("Usize").field(&value).finish(),
            (None, Some(value)) => formatter.debug_tuple("Boxed").field(value).finish(),
            _ => formatter.write_str("InvalidExactBoxOrUsize"),
        }
    }
}

impl<T> Drop for ExactBoxOrUsize<T> {
    #[allow(
        unsafe_code,
        reason = "the tagged word reconstructs its uniquely owned exact allocation for one drop"
    )]
    fn drop(&mut self) {
        if self.encoded & 1 == 0 {
            return;
        }
        let address = self.encoded & !1;
        // SAFETY: this object uniquely owns the allocation encoded by the odd
        // variant, and Drop runs exactly once.
        unsafe {
            drop(Box::from_raw(ptr::with_exposed_provenance_mut::<T>(
                address,
            )));
        }
    }
}

/// Fallible, exact-layout storage for incrementally initialized values.
///
/// Capacity is exactly the requested element count. `try_push` refuses rather
/// than reallocating, so callers may charge the complete allocation before it
/// occurs and retain the storage without a conversion copy.
#[derive(Clone)]
pub struct ExactVec<T> {
    inner: Vec<T>,
}

impl<T> Default for ExactVec<T> {
    fn default() -> Self {
        Self { inner: Vec::new() }
    }
}

impl<T> ExactVec<T> {
    /// Create empty storage without allocating.
    #[must_use]
    pub const fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Allocate exactly `capacity` elements without initializing them.
    pub fn try_with_capacity(capacity: usize) -> Result<Self, CopyError> {
        exact_vec_with_capacity(capacity, false)
    }

    /// Number of initialized elements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether no elements have been initialized.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Exact element capacity selected at allocation.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Initialize the next element, refusing instead of reallocating when full.
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        if self.inner.len() == self.inner.capacity() {
            return Err(value);
        }
        self.inner.push(value);
        Ok(())
    }

    /// Remove and return the final initialized element.
    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop()
    }

    /// Drop every initialized element without changing exact capacity.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Borrow all initialized elements.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    /// Mutably borrow all initialized elements.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.inner.as_mut_slice()
    }

    /// Transfer the exact-capacity allocation into the standard vector
    /// representation without reallocating or copying initialized elements.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.inner
    }
}

impl<T: fmt::Debug> fmt::Debug for ExactVec<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.as_slice()).finish()
    }
}

impl<T: PartialEq> PartialEq for ExactVec<T> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Eq> Eq for ExactVec<T> {}

impl<T> Deref for ExactVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T> DerefMut for ExactVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<'a, T> IntoIterator for &'a ExactVec<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<'a, T> IntoIterator for &'a mut ExactVec<T> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_mut_slice().iter_mut()
    }
}

#[allow(
    unsafe_code,
    reason = "this reviewed function owns FRE's exact-layout single-value allocation boundary"
)]
fn exact_box_or_usize_with<T>(
    value: T,
    force_failure: bool,
) -> Result<ExactBoxOrUsize<T>, CopyError> {
    if size_of::<T>() == 0 || align_of::<T>() < 2 {
        return Err(CopyError::LayoutOverflow);
    }
    let layout = Layout::new::<T>();
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc(layout) }
    };
    if allocation.is_null() {
        return Err(CopyError::AllocationFailed);
    }
    // SAFETY: `alloc` returned a fresh allocation for exactly one `T`.
    // Writing initializes that object. Its exposed address retains recoverable
    // provenance, and alignment proves the low tag bit was zero.
    unsafe {
        let typed = allocation.cast::<T>();
        typed.write(value);
        Ok(ExactBoxOrUsize {
            encoded: typed.expose_provenance() | 1,
            marker: PhantomData,
        })
    }
}

#[allow(
    unsafe_code,
    reason = "this reviewed function owns FRE's exact-layout single-value allocation boundary"
)]
fn exact_box_preserve_with<T>(value: T, force_failure: bool) -> Result<Box<T>, (CopyError, T)> {
    if size_of::<T>() == 0 {
        return Err((CopyError::LayoutOverflow, value));
    }
    let layout = Layout::new::<T>();
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc(layout) }
    };
    if allocation.is_null() {
        return Err((CopyError::AllocationFailed, value));
    }
    // SAFETY: `alloc` returned a fresh allocation for exactly one `T`; the
    // write initializes it and transfers unique ownership to the returned Box.
    unsafe {
        let typed = allocation.cast::<T>();
        typed.write(value);
        Ok(Box::from_raw(typed))
    }
}

#[allow(
    unsafe_code,
    reason = "this reviewed function owns FRE's exact-layout typed allocation boundary"
)]
fn exact_vec_with_capacity<T>(
    capacity: usize,
    force_failure: bool,
) -> Result<ExactVec<T>, CopyError> {
    if size_of::<T>() == 0 {
        return Err(CopyError::LayoutOverflow);
    }
    if capacity == 0 {
        return Ok(ExactVec { inner: Vec::new() });
    }
    let layout = Layout::array::<T>(capacity).map_err(|_| CopyError::LayoutOverflow)?;
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc(layout) }
    };
    if allocation.is_null() {
        return Err(CopyError::AllocationFailed);
    }
    // SAFETY: `alloc` returned exactly `layout`; a zero-length Vec owns the
    // uninitialized spare capacity and later deallocates with the same layout.
    let inner = unsafe { Vec::from_raw_parts(allocation.cast::<T>(), 0, capacity) };
    Ok(ExactVec { inner })
}

/// Copy `bytes` into a fallible allocation with `capacity == len`.
///
/// An empty input needs no allocation and returns an empty vector. For a
/// nonempty input, allocation failure is reported without invoking the
/// infallible allocation-error handler.
pub fn copy_exact(bytes: &[u8]) -> Result<Vec<u8>, CopyError> {
    copy_exact_with(bytes, false)
}

/// Allocate and initialize exactly `len` zero bytes with `capacity == len`.
///
/// An empty request needs no allocation. Callers can therefore charge the
/// exact retained/temporary byte count before this function performs either
/// allocation or zero initialization.
pub fn zeroed_exact(len: usize) -> Result<Vec<u8>, CopyError> {
    zeroed_exact_with(len, false)
}

#[allow(
    unsafe_code,
    reason = "this reviewed function owns FRE's exact-layout zero-initialization boundary"
)]
fn zeroed_exact_with(len: usize, force_failure: bool) -> Result<Vec<u8>, CopyError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let layout = Layout::array::<u8>(len).map_err(|_| CopyError::LayoutOverflow)?;
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc_zeroed(layout) }
    };
    if allocation.is_null() {
        return Err(CopyError::AllocationFailed);
    }

    // SAFETY: `alloc_zeroed` returned a fresh allocation for exactly `layout`
    // and initialized every byte. With `len == capacity`, `Vec` later uses the
    // identical layout for deallocation.
    unsafe { Ok(Vec::from_raw_parts(allocation, len, len)) }
}

#[allow(
    unsafe_code,
    reason = "this one reviewed function owns FRE's exact-layout allocation boundary"
)]
fn copy_exact_with(bytes: &[u8], force_failure: bool) -> Result<Vec<u8>, CopyError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let layout = Layout::array::<u8>(bytes.len()).map_err(|_| CopyError::LayoutOverflow)?;
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc(layout) }
    };
    if allocation.is_null() {
        return Err(CopyError::AllocationFailed);
    }

    // SAFETY: `alloc` returned a fresh global allocation for exactly `layout`.
    // Every `u8` alignment is valid, the allocation is disjoint from the input,
    // and the copy initializes all `len` bytes. No panicking operation occurs
    // between successful allocation and `Vec` ownership. Since `len == capacity`,
    // `Vec` later deallocates with the same layout.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), allocation, bytes.len());
        Ok(Vec::from_raw_parts(allocation, bytes.len(), bytes.len()))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe, RefUnwindSafe, UnwindSafe},
        rc::Rc,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier,
        },
        thread,
    };

    use super::{
        copy_exact, copy_exact_with, exact_box_or_usize_with, exact_box_preserve_with,
        exact_vec_with_capacity, try_box_preserve, zeroed_exact, zeroed_exact_with, CopyError,
        ExactBoxOrUsize, ExactVec, ThreadOwnerSlot,
    };

    #[derive(Debug)]
    struct DropSpy(Rc<Cell<usize>>);

    struct PanicDrop(Arc<AtomicUsize>);

    impl Drop for DropSpy {
        fn drop(&mut self) {
            self.0
                .set(self.0.get().checked_add(1).expect("two test drops fit"));
        }
    }

    impl Drop for PanicDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("test destructor panic");
        }
    }

    #[test]
    fn thread_owner_reuses_mutation_without_locking() {
        let slot = ThreadOwnerSlot::with_value(String::from("cold"));
        let mut first = slot.try_checkout().unwrap();
        first.value_mut().unwrap().push_str("-warm");
        assert!(slot.try_checkout().is_none(), "reentrant checkout aliases");
        first.commit();

        let second = slot.try_checkout().unwrap();
        assert_eq!(second.value().map(String::as_str), Some("cold-warm"));
        second.commit();
    }

    #[test]
    fn thread_owner_guard_restores_captured_owner_after_moving_threads() {
        let slot = ThreadOwnerSlot::with_value(7_usize);
        let guard = slot.try_checkout().unwrap();
        thread::scope(|scope| {
            scope
                .spawn(move || {
                    let mut guard = guard;
                    *guard.value_mut().unwrap() = 11;
                    guard.commit();
                })
                .join()
                .unwrap();
        });
        let restored = slot.try_checkout().unwrap();
        assert_eq!(restored.value(), Some(&11));
        restored.commit();
    }

    #[test]
    fn moved_guard_excludes_original_owner_until_handoff() {
        let slot = ThreadOwnerSlot::with_value(7_usize);
        let guard = slot.try_checkout().unwrap();
        let live = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        thread::scope(|scope| {
            let worker_live = Arc::clone(&live);
            let worker_release = Arc::clone(&release);
            let worker = scope.spawn(move || {
                worker_live.wait();
                worker_release.wait();
                guard.commit();
            });
            live.wait();
            assert!(slot.try_checkout().is_none());
            release.wait();
            worker.join().unwrap();
        });
        let restored = slot.try_checkout().unwrap();
        assert_eq!(restored.value(), Some(&7));
        restored.commit();
    }

    #[test]
    fn simultaneous_first_claim_has_exactly_one_owner() {
        const THREADS: usize = 8;
        let slot = Arc::new(ThreadOwnerSlot::with_value(7_usize));
        let barrier = Arc::new(Barrier::new(THREADS + 1));
        let winners = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                let slot = Arc::clone(&slot);
                let barrier = Arc::clone(&barrier);
                let winners = Arc::clone(&winners);
                thread::spawn(move || {
                    barrier.wait();
                    if let Some(guard) = slot.try_checkout() {
                        assert_eq!(guard.value(), Some(&7));
                        winners.fetch_add(1, Ordering::SeqCst);
                        guard.commit();
                    }
                })
            })
            .collect();
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(winners.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn thread_owner_auto_traits_match_exclusive_value_access() {
        fn require_send<T: Send>() {}
        fn require_sync<T: Sync>() {}
        fn require_unpin<T: Unpin>() {}
        fn require_unwind<T: UnwindSafe + RefUnwindSafe>() {}

        require_send::<super::ThreadOwnerGuard<'static, Cell<u8>>>();
        require_sync::<super::ThreadOwnerGuard<'static, usize>>();
        require_unpin::<super::ThreadOwnerGuard<'static, core::marker::PhantomPinned>>();
        require_unwind::<super::ThreadOwnerGuard<'static, usize>>();
        require_send::<ThreadOwnerSlot<Cell<u8>>>();
        require_sync::<ThreadOwnerSlot<Cell<u8>>>();
        require_unwind::<ThreadOwnerSlot<usize>>();
    }

    #[test]
    fn thread_owner_drop_and_unwind_discard_before_reclaim() {
        let slot = ThreadOwnerSlot::with_value(String::from("partial"));
        let panicked = catch_unwind(AssertUnwindSafe(|| {
            let mut guard = slot.try_checkout().unwrap();
            guard.value_mut().unwrap().push_str("-mutation");
            panic!("transaction failed");
        }));
        assert!(panicked.is_err());

        let mut reclaimed = slot.try_checkout().unwrap();
        assert!(reclaimed.value().is_none());
        reclaimed.try_insert(String::from("complete")).unwrap();
        reclaimed.commit();
        let retained = slot.try_checkout().unwrap();
        assert_eq!(retained.value().map(String::as_str), Some("complete"));
        retained.commit();
    }

    #[test]
    fn empty_commit_releases_slot_for_a_different_thread() {
        let slot = Arc::new(ThreadOwnerSlot::<usize>::new());
        slot.try_checkout().unwrap().commit();
        let other = Arc::clone(&slot);
        let value = thread::spawn(move || {
            let mut guard = other.try_checkout().unwrap();
            assert!(guard.value().is_none());
            guard.try_insert(23).unwrap();
            guard.commit();
            23
        })
        .join()
        .unwrap();
        assert_eq!(value, 23);
        assert!(slot.try_checkout().is_none());
    }

    #[test]
    fn populated_slot_is_owned_by_its_first_checkout_thread() {
        let slot = Arc::new(ThreadOwnerSlot::with_value(7_usize));
        let worker = Arc::clone(&slot);
        thread::spawn(move || {
            let guard = worker.try_checkout().unwrap();
            assert_eq!(guard.value(), Some(&7));
            guard.commit();
        })
        .join()
        .unwrap();

        assert!(slot.try_checkout().is_none());
        assert_eq!(ThreadOwnerSlot::with_value(11).into_value(), Some(11));
        assert_eq!(ThreadOwnerSlot::<u8>::new().into_value(), None);
    }

    #[test]
    fn panicking_value_drop_cannot_be_observed_or_dropped_twice() {
        let drops = Arc::new(AtomicUsize::new(0));
        let slot = ThreadOwnerSlot::with_value(PanicDrop(Arc::clone(&drops)));
        let guard = slot.try_checkout().unwrap();
        let panicked = catch_unwind(AssertUnwindSafe(|| drop(guard)));
        assert!(panicked.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(
            slot.try_checkout().is_none(),
            "a destructor panic leaves the empty slot fail-closed in-use",
        );
        drop(slot);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn non_copy_single_value_uses_one_fallible_exact_allocation() {
        assert_eq!(
            size_of::<ExactBoxOrUsize<[usize; 64]>>(),
            size_of::<usize>()
        );
        let inline = ExactBoxOrUsize::<DropSpy>::try_from_usize(17).unwrap();
        assert_eq!(inline.as_usize(), Some(17));
        assert!(inline.boxed().is_none());
        let mut mutable = ExactBoxOrUsize::try_from_boxed(17_usize).unwrap();
        *mutable.boxed_mut().unwrap() = 23;
        assert_eq!(mutable.boxed(), Some(&23));
        let drops = Rc::new(Cell::new(0));
        let value = ExactBoxOrUsize::try_from_boxed(DropSpy(Rc::clone(&drops))).unwrap();
        assert!(value.as_usize().is_none());
        assert!(value.boxed().is_some());
        assert_eq!(drops.get(), 0);
        drop(value);
        assert_eq!(drops.get(), 1);
        assert!(matches!(
            exact_box_or_usize_with(DropSpy(Rc::clone(&drops)), true),
            Err(CopyError::AllocationFailed)
        ));
        assert_eq!(drops.get(), 2);
        assert!(matches!(
            ExactBoxOrUsize::try_from_boxed(()),
            Err(CopyError::LayoutOverflow)
        ));
    }

    #[test]
    fn plain_box_preserves_value_on_fallible_exact_allocation() {
        let drops = Rc::new(Cell::new(0));
        let value = DropSpy(Rc::clone(&drops));
        let (source, value) = exact_box_preserve_with(value, true).unwrap_err();
        assert_eq!(source, CopyError::AllocationFailed);
        assert_eq!(drops.get(), 0);
        drop(value);
        assert_eq!(drops.get(), 1);
        let value = String::from("preserved");
        let (source, value) = exact_box_preserve_with(value, true).unwrap_err();
        assert_eq!(source, CopyError::AllocationFailed);
        assert_eq!(value, "preserved");
        assert_eq!(*try_box_preserve(17_u64).unwrap(), 17);
    }

    #[test]
    fn non_copy_values_use_exact_fallible_storage_and_drop_once() {
        let drops = Rc::new(Cell::new(0));
        let mut values = ExactVec::try_with_capacity(1).unwrap();
        values.try_push(DropSpy(Rc::clone(&drops))).unwrap();
        let rejected = values
            .try_push(DropSpy(Rc::clone(&drops)))
            .expect_err("full exact storage must return ownership");
        drop(rejected);
        assert_eq!(drops.get(), 1);
        assert_eq!(values.len(), 1);
        assert_eq!(values.capacity(), 1);
        drop(values);
        assert_eq!(drops.get(), 2);
        assert!(matches!(
            exact_vec_with_capacity::<String>(1, true),
            Err(CopyError::AllocationFailed)
        ));
    }

    #[test]
    fn typed_exact_storage_never_overallocates_or_grows() {
        for capacity in [0_usize, 1, 2, 3, 7, 16, 255, 4096] {
            let mut values = ExactVec::try_with_capacity(capacity).unwrap();
            assert_eq!(values.capacity(), capacity);
            assert!(values.is_empty());
            for value in 0..capacity {
                values.try_push(value).unwrap();
                assert_eq!(values.capacity(), capacity);
            }
            assert_eq!(values.as_slice(), (0..capacity).collect::<Vec<_>>());
            assert_eq!(values.try_push(capacity), Err(capacity));
            assert_eq!(values.capacity(), capacity);
            if capacity > 0 {
                assert_eq!(values.pop(), Some(capacity - 1));
                assert_eq!(values.capacity(), capacity);
            }
            values.clear();
            assert!(values.is_empty());
            assert_eq!(values.capacity(), capacity);
            if capacity > 0 {
                values.try_push(7).unwrap();
                assert_eq!(values.as_slice(), &[7]);
            }
            let standard = values.into_vec();
            assert_eq!(standard.capacity(), capacity);
            if capacity == 0 {
                assert!(standard.is_empty());
            } else {
                assert_eq!(standard.as_slice(), &[7]);
            }
        }
        assert!(matches!(
            exact_vec_with_capacity::<u32>(1, true),
            Err(CopyError::AllocationFailed)
        ));
        assert!(matches!(
            ExactVec::<u64>::try_with_capacity(usize::MAX),
            Err(CopyError::LayoutOverflow)
        ));
        assert!(matches!(
            ExactVec::<()>::try_with_capacity(0),
            Err(CopyError::LayoutOverflow)
        ));
        assert!(matches!(
            ExactVec::<()>::try_with_capacity(1),
            Err(CopyError::LayoutOverflow)
        ));
    }

    #[test]
    fn empty_and_nonempty_copies_have_exact_capacity() {
        let empty = copy_exact(b"").unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.capacity(), 0);

        for len in [1_usize, 2, 3, 7, 8, 15, 16, 31, 32, 255, 256, 4096] {
            let source: Vec<u8> = (0_u8..=u8::MAX).cycle().take(len).collect();
            let copied = copy_exact(&source).unwrap();
            assert_eq!(copied, source);
            assert_eq!(copied.len(), len);
            assert_eq!(copied.capacity(), len);
        }

        assert_eq!(
            copy_exact_with(b"forced allocation failure", true),
            Err(CopyError::AllocationFailed)
        );
    }

    #[test]
    fn empty_and_nonempty_zeroing_has_exact_capacity() {
        for len in [0_usize, 1, 2, 3, 7, 8, 31, 256, 4096] {
            let zeroed = zeroed_exact(len).unwrap();
            assert_eq!(zeroed.len(), len);
            assert_eq!(zeroed.capacity(), len);
            assert!(zeroed.iter().all(|&byte| byte == 0));
        }
        assert_eq!(zeroed_exact_with(1, true), Err(CopyError::AllocationFailed));
    }
}
