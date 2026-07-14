//! Stable logical-to-AAPCS64 ABI mapping.

/// One architectural general-purpose register.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Register(u8);

impl Register {
    pub(crate) const fn new(number: u8) -> Self {
        Self(number)
    }

    /// Architectural register number.
    #[must_use]
    pub const fn number(self) -> u8 {
        self.0
    }
}

/// Stable v1 AAPCS64 register assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aapcs64V1;

impl Aapcs64V1 {
    /// `x0`: base of the readable haystack.
    pub const HAYSTACK_BASE: Register = Register::new(0);
    /// `x1`: total haystack byte length.
    pub const HAYSTACK_LEN: Register = Register::new(1);
    /// `x2`: inclusive start of the checked search window.
    pub const WINDOW_START: Register = Register::new(2);
    /// `x3`: exclusive end of the checked search window.
    pub const WINDOW_END: Register = Register::new(3);
    /// `x4`: pointer to a writable [`NativeResult`].
    pub const RESULT_SLOT: Register = Register::new(4);
    /// `w0`: zero for no match and one for a match.
    pub const STATUS: Register = Register::new(0);
}

/// Result memory shared by all v1 output contracts.
///
/// Existence-only kernels do not touch it. Selected-end kernels initialize
/// only `end`; span kernels initialize both fields.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct NativeResult {
    pub start: usize,
    pub end: usize,
}

/// Auditable byte layout of [`NativeResult`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultLayout {
    pub size: u8,
    pub alignment: u8,
    pub start_offset: u8,
    pub end_offset: u8,
}

impl ResultLayout {
    /// Layout for a 64-bit `AArch64` target.
    pub const AARCH64: Self = Self {
        size: 16,
        alignment: 8,
        start_offset: 0,
        end_offset: 8,
    };
}

/// Stable v1 whole-haystack aggregate AAPCS64 register assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateAapcs64V1;

impl AggregateAapcs64V1 {
    /// `x0`: base of the readable haystack.
    pub const HAYSTACK_BASE: Register = Register::new(0);
    /// `x1`: total haystack byte length.
    pub const HAYSTACK_LEN: Register = Register::new(1);
    /// `x2`: pointer to a writable [`NativeAggregateResult`].
    pub const RESULT_SLOT: Register = Register::new(2);
    /// `w0`: zero for success; nonzero is a typed backend fault.
    pub const STATUS: Register = Register::new(0);
}

/// Result memory for the distinct whole-haystack aggregate ABI.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct NativeAggregateResult {
    pub value: u64,
}

/// Auditable byte layout of [`NativeAggregateResult`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateResultLayout {
    pub size: u8,
    pub alignment: u8,
    pub value_offset: u8,
}

impl AggregateResultLayout {
    /// Layout for a 64-bit `AArch64` target.
    pub const AARCH64: Self = Self {
        size: 8,
        alignment: 8,
        value_offset: 0,
    };
}
