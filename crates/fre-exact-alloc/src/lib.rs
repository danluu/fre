//! Safe access to FRE's single exact-layout allocation primitive.

#![deny(unsafe_code)]

use core::{
    alloc::Layout,
    fmt,
    marker::PhantomData,
    mem::{align_of, size_of},
    ops::{Deref, DerefMut},
    ptr,
};
use std::alloc::{alloc, alloc_zeroed};

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
    use std::{cell::Cell, rc::Rc};

    use super::{
        CopyError, ExactBoxOrUsize, ExactVec, copy_exact, copy_exact_with, exact_box_or_usize_with,
        exact_box_preserve_with, exact_vec_with_capacity, try_box_preserve, zeroed_exact,
        zeroed_exact_with,
    };

    #[derive(Debug)]
    struct DropSpy(Rc<Cell<usize>>);

    impl Drop for DropSpy {
        fn drop(&mut self) {
            self.0
                .set(self.0.get().checked_add(1).expect("two test drops fit"));
        }
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
