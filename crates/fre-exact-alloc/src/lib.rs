//! Safe access to FRE's single exact-layout allocation primitive.

#![deny(unsafe_code)]

use core::{alloc::Layout, fmt, ptr};
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
    use super::{CopyError, copy_exact, copy_exact_with, zeroed_exact, zeroed_exact_with};

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
