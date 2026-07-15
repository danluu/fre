//! Safe access to FRE's single exact-layout allocation primitive.

#![deny(unsafe_code)]

use core::{alloc::Layout, fmt, ptr};
use std::alloc::alloc;

/// Failure to copy bytes into an exact-capacity allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyError {
    /// The requested byte count cannot be represented as an allocation layout.
    LayoutOverflow,
    /// The global allocator rejected the exact layout.
    AllocationFailed,
}

/// Failure to create a vector with exactly the requested element capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityError {
    /// The requested element count cannot be represented as an allocation layout.
    LayoutOverflow,
    /// Exact capacity has no meaningful representation for a zero-sized type.
    ZeroSizedType,
    /// The global allocator rejected the exact layout.
    AllocationFailed,
}

impl fmt::Display for CapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LayoutOverflow => formatter.write_str("exact capacity layout overflow"),
            Self::ZeroSizedType => formatter.write_str("exact capacity rejects zero-sized types"),
            Self::AllocationFailed => formatter.write_str("exact capacity allocation failed"),
        }
    }
}

impl std::error::Error for CapacityError {}

/// Allocate an empty vector whose capacity is exactly `capacity`.
///
/// This is the fallible policy boundary used when allocator capacity rounding
/// would make a post-allocation limit check too late. Zero-sized element types
/// are rejected because `Vec` represents their capacity as `usize::MAX`.
pub fn vec_with_exact_capacity<T>(capacity: usize) -> Result<Vec<T>, CapacityError> {
    if capacity == 0 {
        return Ok(Vec::new());
    }
    if core::mem::size_of::<T>() == 0 {
        return Err(CapacityError::ZeroSizedType);
    }
    vec_with_exact_capacity_nonzero(capacity)
}

#[allow(
    unsafe_code,
    reason = "this reviewed function owns FRE's generic exact-layout vector allocation boundary"
)]
fn vec_with_exact_capacity_nonzero<T>(capacity: usize) -> Result<Vec<T>, CapacityError> {
    let layout = Layout::array::<T>(capacity).map_err(|_| CapacityError::LayoutOverflow)?;
    let allocation = unsafe { alloc(layout) }.cast::<T>();
    if allocation.is_null() {
        return Err(CapacityError::AllocationFailed);
    }

    // SAFETY: `alloc` returned a fresh allocation with the exact layout for
    // `capacity` values of `T`. The vector owns no initialized elements yet,
    // and its eventual deallocation uses the identical layout.
    unsafe { Ok(Vec::from_raw_parts(allocation, 0, capacity)) }
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

/// Copy `bytes` into a fallible allocation with `capacity == len`.
///
/// An empty input needs no allocation and returns an empty vector. For a
/// nonempty input, allocation failure is reported without invoking the
/// infallible allocation-error handler.
pub fn copy_exact(bytes: &[u8]) -> Result<Vec<u8>, CopyError> {
    copy_exact_with(bytes, false)
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
    use super::{CapacityError, CopyError, copy_exact, copy_exact_with, vec_with_exact_capacity};

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
    fn generic_vectors_have_exact_capacity_before_initialization() {
        let empty = vec_with_exact_capacity::<u64>(0).unwrap();
        assert_eq!(empty.capacity(), 0);
        let mut values = vec_with_exact_capacity::<u64>(17).unwrap();
        assert_eq!(values.capacity(), 17);
        values.extend(0..17);
        assert_eq!(values.len(), 17);
        assert_eq!(
            vec_with_exact_capacity::<()>(1),
            Err(CapacityError::ZeroSizedType)
        );
    }
}
