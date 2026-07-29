//! Static final-image adoption for optimizing Count-v3.

use core::marker::PhantomData;
use core::{mem, ptr, slice};
use std::rc::Rc;

use fre_aot_aarch64::{
    AotCountCpuFeatures, AotCountMappedMetadataV3, CountAuditReportV3, CountEmitLimitsV3,
    audit_count_mapped_code_v3,
};
use fre_aot_count_contract::v3::CountObjectFormatV3;
use fre_aot_count_contract::v3::{
    ClaimedCountMetadataV3, CountGeneralEligibilityTupleV3, METADATA_BYTES_V3,
    STATIC_COUNT_EXPECTATION_BYTES_V3, inspect_count_metadata_v3,
};
use fre_aot_optimizer::decode_count_recipe_v3;
use fre_kernel_ir::{
    AggregateExecutionLimits, AggregateOutput, Count, ValidateLimits, build_exact_aggregate,
    preflight_exact_aggregate,
};
use sha2::{Digest, Sha256};

use crate::{
    StaticCountCallErrorV3, StaticCountContractFieldV3, StaticCountVerifyErrorV3,
    expected_v3::ExpectedStaticCountV3, support_v3,
};
use crate::{StaticCountSveCallErrorV3, StaticCountSveThreadContractErrorV3};

#[cfg(all(
    feature = "linked-count-v3",
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod macos_aarch64;
#[cfg(all(
    feature = "linked-count-v3",
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
use macos_aarch64 as platform;

#[cfg(all(
    feature = "linked-count-v3",
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod linux_aarch64;
#[cfg(all(
    feature = "linked-count-v3",
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
use linux_aarch64 as platform;

#[cfg(not(any(
    all(
        feature = "linked-count-v3",
        target_arch = "aarch64",
        target_os = "macos",
        target_pointer_width = "64",
        target_endian = "little"
    ),
    all(
        feature = "linked-count-v3",
        target_arch = "aarch64",
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    )
)))]
mod unavailable;
#[cfg(not(any(
    all(
        feature = "linked-count-v3",
        target_arch = "aarch64",
        target_os = "macos",
        target_pointer_width = "64",
        target_endian = "little"
    ),
    all(
        feature = "linked-count-v3",
        target_arch = "aarch64",
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    )
)))]
use unavailable as platform;

const POISONED_COUNT_RESULT_V3: u64 = u64::MAX;
const HARD_MAX_MAPPED_PAYLOAD_BYTES_V3: usize = 4 << 20;
static EMPTY_HAYSTACK_SENTINEL_V3: u8 = 0;
/// Native Count-v3 production evidence covers only long-running inputs.
///
/// Safe automatic facades route shorter inputs through their retained portable
/// owner. Low-level production handles reject them before the native entry.
pub const STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3: usize = 4_096;

/// Raw result slot fixed by Count call ABI schema 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
#[doc(hidden)]
pub struct RawAggregateResultV3 {
    pub value: u64,
}

/// Raw entry type retained only after final mapped-code verification.
#[allow(
    unsafe_code,
    reason = "the type describes the audited three-argument native ABI"
)]
#[doc(hidden)]
pub type StaticAggregateEntryV3 =
    unsafe extern "C" fn(*const u8, usize, *mut RawAggregateResultV3) -> u64;

const _: () = assert!(mem::size_of::<StaticAggregateEntryV3>() == mem::size_of::<usize>());
const _: () = assert!(mem::size_of::<RawAggregateResultV3>() == 8);
const _: () = assert!(mem::align_of::<RawAggregateResultV3>() == 8);

/// Untrusted process-lifetime addresses for the production adopter.
///
/// Constructing this inert value reads nothing. The unsafe adopter owns all
/// immutable-range, fixed-record, target, digest, KIR, recipe, and code checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticCountLinkedAddressesV3 {
    addresses: LinkedAddressesV3,
}

impl StaticCountLinkedAddressesV3 {
    #[must_use]
    pub const fn from_exposed_addresses(
        expectation: usize,
        payload: usize,
        metadata: usize,
        entry: usize,
    ) -> Self {
        Self {
            addresses: LinkedAddressesV3 {
                expectation,
                payload,
                metadata,
                entry,
            },
        }
    }
}

/// Untrusted process-lifetime addresses for the production SVE/SVE2 adopter.
///
/// The expected full eligibility tuple is supplied independently of the image
/// addresses. The adopter checks that tuple against source authority before it
/// reads any address, then proves that the inspected image carries that exact
/// tuple before a callable can exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticCountSveLinkedAddressesV3 {
    addresses: LinkedAddressesV3,
    expected_eligibility_tuple: CountGeneralEligibilityTupleV3,
}

/// Borrowed fixed-policy facade proof for production SVE/SVE2 adoption.
///
/// This type is disjoint from both movable ASIMD production and private SVE
/// qualification bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticCountSveFacadeBindingV3<'a> {
    literal: &'a [u8],
    semantic_binding_identity: [u8; 32],
    planning_receipt_identity: [u8; 32],
}

impl<'a> StaticCountSveFacadeBindingV3<'a> {
    #[must_use]
    pub const fn new(
        literal: &'a [u8],
        semantic_binding_identity: [u8; 32],
        planning_receipt_identity: [u8; 32],
    ) -> Self {
        Self {
            literal,
            semantic_binding_identity,
            planning_receipt_identity,
        }
    }
}

impl StaticCountSveLinkedAddressesV3 {
    #[must_use]
    pub const fn from_exposed_addresses(
        expectation: usize,
        payload: usize,
        metadata: usize,
        entry: usize,
        expected_eligibility_tuple: CountGeneralEligibilityTupleV3,
    ) -> Self {
        Self {
            addresses: LinkedAddressesV3 {
                expectation,
                payload,
                metadata,
                entry,
            },
            expected_eligibility_tuple,
        }
    }
}

/// Qualification-only address carrier, intentionally type-disjoint from the
/// production adopter.
#[cfg(feature = "count-v3-qualification-private")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct StaticCountQualificationLinkedAddressesV3 {
    addresses: LinkedAddressesV3,
}

/// Borrowed facade proof supplied to the qualification-only adopter.
///
/// The adopter compares all three values after complete byte/code inspection
/// and before private authority is granted. Production has no analogous
/// caller-supplied authority input.
#[cfg(feature = "count-v3-qualification-private")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct StaticCountQualificationFacadeBindingV3<'a> {
    literal: &'a [u8],
    semantic_binding_identity: [u8; 32],
    planning_receipt_identity: [u8; 32],
}

/// SVE/SVE2 qualification address carrier. It cannot select either the
/// production adopter or the movable ASIMD qualification adopter.
#[cfg(feature = "count-v3-qualification-private")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct StaticCountSveQualificationLinkedAddressesV3 {
    addresses: LinkedAddressesV3,
}

/// Fixed-policy facade proof for the SVE/SVE2-only qualification adopter.
#[cfg(feature = "count-v3-qualification-private")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct StaticCountSveQualificationFacadeBindingV3<'a> {
    literal: &'a [u8],
    semantic_binding_identity: [u8; 32],
    planning_receipt_identity: [u8; 32],
}

#[cfg(feature = "count-v3-qualification-private")]
impl<'a> StaticCountSveQualificationFacadeBindingV3<'a> {
    #[must_use]
    pub const fn new(
        literal: &'a [u8],
        semantic_binding_identity: [u8; 32],
        planning_receipt_identity: [u8; 32],
    ) -> Self {
        Self {
            literal,
            semantic_binding_identity,
            planning_receipt_identity,
        }
    }
}

#[cfg(feature = "count-v3-qualification-private")]
impl<'a> StaticCountQualificationFacadeBindingV3<'a> {
    #[must_use]
    pub const fn new(
        literal: &'a [u8],
        semantic_binding_identity: [u8; 32],
        planning_receipt_identity: [u8; 32],
    ) -> Self {
        Self {
            literal,
            semantic_binding_identity,
            planning_receipt_identity,
        }
    }
}

#[cfg(feature = "count-v3-qualification-private")]
impl StaticCountQualificationLinkedAddressesV3 {
    #[must_use]
    pub const fn from_exposed_addresses(
        expectation: usize,
        payload: usize,
        metadata: usize,
        entry: usize,
    ) -> Self {
        Self {
            addresses: LinkedAddressesV3 {
                expectation,
                payload,
                metadata,
                entry,
            },
        }
    }
}

#[cfg(feature = "count-v3-qualification-private")]
impl StaticCountSveQualificationLinkedAddressesV3 {
    #[must_use]
    pub const fn from_exposed_addresses(
        expectation: usize,
        payload: usize,
        metadata: usize,
        entry: usize,
    ) -> Self {
        Self {
            addresses: LinkedAddressesV3 {
                expectation,
                payload,
                metadata,
                entry,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinkedAddressesV3 {
    expectation: usize,
    payload: usize,
    metadata: usize,
    entry: usize,
}

/// Cold-path inspection accounting retained by every authenticated handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticCountInspectionAccountingV3 {
    pub expectation_bytes_copied: u32,
    pub metadata_bytes_copied: u32,
    pub payload_bytes_hashed: u32,
    pub vm_query_input_bytes_upper_bound: u32,
    pub vm_regions_checked: u32,
    pub audit: CountAuditReportV3,
}

#[derive(Debug)]
struct VerifiedCoreV3 {
    entry: StaticAggregateEntryV3,
    literal_manifest: [u8; 32],
    literal_bytes: u8,
    semantic_binding_identity: [u8; 32],
    planning_receipt_identity: [u8; 32],
    expectation_identity: [u8; 32],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    eligibility_tuple: CountGeneralEligibilityTupleV3,
    accounting: StaticCountInspectionAccountingV3,
}

/// Production-only callable Count-v3 handle.
///
/// Its fields are private and the production adopter can construct it only
/// after an exact source-row match. The currently empty production table means
/// no ordinary build can yet obtain this value. This movable handle remains
/// ASIMD-only; SVE evidence promotion requires a separate source-authorized
/// production same-thread handle/session.
#[derive(Debug)]
pub struct VerifiedStaticCountV3 {
    core: VerifiedCoreV3,
}

/// Production-only fixed-VL SVE/SVE2 callable handle.
///
/// The handle exposes no direct count method and is deliberately neither
/// `Send` nor `Sync`: Linux SVE vector length is mutable per thread. Calls
/// require a borrowed [`StaticCountSveSessionV3`].
///
/// ```compile_fail,E0277
/// use fre_aot_static_runtime::VerifiedStaticCountSveV3;
///
/// fn require_send<T: Send>() {}
/// require_send::<VerifiedStaticCountSveV3>();
/// ```
///
/// ```compile_fail,E0277
/// use fre_aot_static_runtime::VerifiedStaticCountSveV3;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<VerifiedStaticCountSveV3>();
/// ```
///
/// ```compile_fail,E0599
/// use fre_aot_static_runtime::VerifiedStaticCountSveV3;
///
/// fn direct_count(handle: &VerifiedStaticCountSveV3) {
///     let _ = handle.count();
/// }
/// ```
#[derive(Debug)]
pub struct VerifiedStaticCountSveV3 {
    core: VerifiedCoreV3,
    thread_bound: PhantomData<Rc<()>>,
}

/// Current-thread production SVE/SVE2 invocation session.
///
/// Session creation checks exact VL16 and every native call checks it again
/// immediately before branching to the authenticated entry.
#[derive(Debug)]
pub struct StaticCountSveSessionV3<'handle> {
    handle: &'handle VerifiedStaticCountSveV3,
    thread_bound: PhantomData<Rc<()>>,
}

/// Qualification-only callable handle.
///
/// This distinct type cannot be passed where production evidence is required.
#[cfg(feature = "count-v3-qualification-private")]
#[derive(Debug)]
#[doc(hidden)]
pub struct VerifiedStaticCountQualificationV3 {
    core: VerifiedCoreV3,
}

/// Qualification-only SVE/SVE2 handle.
///
/// Both this handle and sessions borrowed from it are deliberately neither
/// `Send` nor `Sync`: Linux SVE VL is mutable per thread. The handle exposes no
/// direct count method.
///
/// ```compile_fail,E0277
/// use fre_aot_static_runtime::VerifiedStaticCountSveQualificationV3;
///
/// fn require_send<T: Send>() {}
/// require_send::<VerifiedStaticCountSveQualificationV3>();
/// ```
///
/// ```compile_fail,E0277
/// use fre_aot_static_runtime::VerifiedStaticCountSveQualificationV3;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<VerifiedStaticCountSveQualificationV3>();
/// ```
///
/// A verified SVE handle deliberately has no direct call surface:
///
/// ```compile_fail,E0599
/// use fre_aot_static_runtime::VerifiedStaticCountSveQualificationV3;
///
/// fn direct_count(handle: &VerifiedStaticCountSveQualificationV3) {
///     let _ = handle.count();
/// }
/// ```
#[cfg(feature = "count-v3-qualification-private")]
#[derive(Debug)]
#[doc(hidden)]
pub struct VerifiedStaticCountSveQualificationV3 {
    core: VerifiedCoreV3,
    thread_bound: PhantomData<Rc<()>>,
}

/// Current-thread SVE/SVE2 invocation session.
///
/// Session creation checks exact VL16 and every call checks it again
/// immediately before the native branch.
#[cfg(feature = "count-v3-qualification-private")]
#[derive(Debug)]
#[doc(hidden)]
pub struct StaticCountSveQualificationSessionV3<'handle> {
    handle: &'handle VerifiedStaticCountSveQualificationV3,
    thread_bound: PhantomData<Rc<()>>,
}

macro_rules! verified_accessors_v3 {
    ($type:ty, production_floor = $production_floor:expr) => {
        impl $type {
            /// Invoke the already-verified whole-haystack non-overlapping
            /// counter. This path performs one value preflight and one direct
            /// native call; it performs no lookup, compilation, allocation,
            /// target selection, recipe decoding, or code audit.
            #[inline]
            pub fn count(
                &self,
                haystack: &[u8],
                limits: AggregateExecutionLimits,
            ) -> Result<u64, StaticCountCallErrorV3> {
                if $production_floor
                    && haystack.len() < STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3
                {
                    return Err(StaticCountCallErrorV3::ProductionRouteBelowEvidenceFloor {
                        required_bytes: STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3,
                        actual_bytes: haystack.len(),
                    });
                }
                self.core.count(haystack, limits)
            }

            #[must_use]
            pub fn literal(&self) -> &[u8] {
                &self.core.literal_manifest[..usize::from(self.core.literal_bytes)]
            }

            #[must_use]
            pub const fn semantic_binding_identity(&self) -> &[u8; 32] {
                &self.core.semantic_binding_identity
            }

            #[must_use]
            pub const fn planning_receipt_identity(&self) -> &[u8; 32] {
                &self.core.planning_receipt_identity
            }

            #[must_use]
            pub const fn expectation_identity(&self) -> &[u8; 32] {
                &self.core.expectation_identity
            }

            #[must_use]
            pub const fn compile_identity(&self) -> &[u8; 32] {
                &self.core.compile_identity
            }

            #[must_use]
            pub const fn object_identity(&self) -> &[u8; 32] {
                &self.core.object_identity
            }

            #[must_use]
            pub const fn eligibility_tuple(&self) -> CountGeneralEligibilityTupleV3 {
                self.core.eligibility_tuple
            }

            #[must_use]
            pub const fn inspection_accounting(&self) -> StaticCountInspectionAccountingV3 {
                self.core.accounting
            }
        }
    };
}

verified_accessors_v3!(VerifiedStaticCountV3, production_floor = true);
#[cfg(feature = "count-v3-qualification-private")]
verified_accessors_v3!(VerifiedStaticCountQualificationV3, production_floor = false);

impl VerifiedStaticCountSveV3 {
    #[must_use]
    pub fn literal(&self) -> &[u8] {
        &self.core.literal_manifest[..usize::from(self.core.literal_bytes)]
    }

    #[must_use]
    pub const fn semantic_binding_identity(&self) -> &[u8; 32] {
        &self.core.semantic_binding_identity
    }

    #[must_use]
    pub const fn planning_receipt_identity(&self) -> &[u8; 32] {
        &self.core.planning_receipt_identity
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> &[u8; 32] {
        &self.core.expectation_identity
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.core.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> &[u8; 32] {
        &self.core.object_identity
    }

    #[must_use]
    pub const fn eligibility_tuple(&self) -> CountGeneralEligibilityTupleV3 {
        self.core.eligibility_tuple
    }

    #[must_use]
    pub const fn inspection_accounting(&self) -> StaticCountInspectionAccountingV3 {
        self.core.accounting
    }

    /// Begin a current-thread session after checking exact SVE VL16.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<StaticCountSveSessionV3<'_>, StaticCountSveThreadContractErrorV3> {
        platform::require_current_thread_sve_target_v3(
            self.core.eligibility_tuple.required_isa_id,
            self.core.eligibility_tuple.actual_features,
            self.core.eligibility_tuple.sve_vector_length_bytes,
        )?;
        Ok(StaticCountSveSessionV3 {
            handle: self,
            thread_bound: PhantomData,
        })
    }
}

impl StaticCountSveSessionV3<'_> {
    /// Invoke after repeating the exact VL16 check immediately before the
    /// native call.
    #[inline]
    pub fn count(
        &self,
        haystack: &[u8],
        limits: AggregateExecutionLimits,
    ) -> Result<u64, StaticCountSveCallErrorV3> {
        if haystack.len() < STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3 {
            return Err(StaticCountCallErrorV3::ProductionRouteBelowEvidenceFloor {
                required_bytes: STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3,
                actual_bytes: haystack.len(),
            }
            .into());
        }
        self.handle.core.count_sve(haystack, limits)
    }

    #[must_use]
    pub const fn handle(&self) -> &VerifiedStaticCountSveV3 {
        self.handle
    }
}

#[cfg(feature = "count-v3-qualification-private")]
impl VerifiedStaticCountSveQualificationV3 {
    #[must_use]
    pub fn literal(&self) -> &[u8] {
        &self.core.literal_manifest[..usize::from(self.core.literal_bytes)]
    }

    #[must_use]
    pub const fn semantic_binding_identity(&self) -> &[u8; 32] {
        &self.core.semantic_binding_identity
    }

    #[must_use]
    pub const fn planning_receipt_identity(&self) -> &[u8; 32] {
        &self.core.planning_receipt_identity
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> &[u8; 32] {
        &self.core.expectation_identity
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.core.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> &[u8; 32] {
        &self.core.object_identity
    }

    #[must_use]
    pub const fn eligibility_tuple(&self) -> CountGeneralEligibilityTupleV3 {
        self.core.eligibility_tuple
    }

    #[must_use]
    pub const fn inspection_accounting(&self) -> StaticCountInspectionAccountingV3 {
        self.core.accounting
    }

    /// Begin a current-thread session after checking exact SVE VL16.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<StaticCountSveQualificationSessionV3<'_>, StaticCountSveThreadContractErrorV3> {
        platform::require_current_thread_sve_target_v3(
            self.core.eligibility_tuple.required_isa_id,
            self.core.eligibility_tuple.actual_features,
            self.core.eligibility_tuple.sve_vector_length_bytes,
        )?;
        Ok(StaticCountSveQualificationSessionV3 {
            handle: self,
            thread_bound: PhantomData,
        })
    }
}

#[cfg(feature = "count-v3-qualification-private")]
impl StaticCountSveQualificationSessionV3<'_> {
    /// Invoke after repeating the exact VL16 check immediately before the
    /// native call.
    #[inline]
    pub fn count(
        &self,
        haystack: &[u8],
        limits: AggregateExecutionLimits,
    ) -> Result<u64, StaticCountSveCallErrorV3> {
        self.handle.core.count_sve(haystack, limits)
    }

    #[must_use]
    pub const fn handle(&self) -> &VerifiedStaticCountSveQualificationV3 {
        self.handle
    }
}

impl VerifiedCoreV3 {
    #[allow(
        unsafe_code,
        reason = "the private entry exists only after complete static mapped-code verification"
    )]
    #[inline]
    fn count(
        &self,
        haystack: &[u8],
        limits: AggregateExecutionLimits,
    ) -> Result<u64, StaticCountCallErrorV3> {
        let literal_len = usize::from(self.literal_bytes);
        let upper =
            preflight_exact_aggregate(haystack.len(), literal_len, AggregateOutput::Count, limits)?;
        let haystack_pointer = if haystack.is_empty() {
            ptr::addr_of!(EMPTY_HAYSTACK_SENTINEL_V3)
        } else {
            haystack.as_ptr()
        };
        let mut result = RawAggregateResultV3 {
            value: POISONED_COUNT_RESULT_V3,
        };
        // SAFETY: this entry exists only after exact mapped-code audit and the
        // slices/result slot satisfy the fixed three-argument ABI.
        let status =
            unsafe { (self.entry)(haystack_pointer, haystack.len(), ptr::addr_of_mut!(result)) };
        decode_count_result_v3(
            status,
            result.value,
            upper.count,
            haystack.len(),
            literal_len,
        )
    }

    #[allow(
        unsafe_code,
        reason = "the SVE entry was exactly audited and current-thread VL16 is rechecked immediately before invocation"
    )]
    #[inline]
    fn count_sve(
        &self,
        haystack: &[u8],
        limits: AggregateExecutionLimits,
    ) -> Result<u64, StaticCountSveCallErrorV3> {
        let literal_len = usize::from(self.literal_bytes);
        let upper =
            preflight_exact_aggregate(haystack.len(), literal_len, AggregateOutput::Count, limits)
                .map_err(StaticCountCallErrorV3::from)?;
        let haystack_pointer = if haystack.is_empty() {
            ptr::addr_of!(EMPTY_HAYSTACK_SENTINEL_V3)
        } else {
            haystack.as_ptr()
        };
        let mut result = RawAggregateResultV3 {
            value: POISONED_COUNT_RESULT_V3,
        };
        platform::require_current_thread_sve_target_v3(
            self.eligibility_tuple.required_isa_id,
            self.eligibility_tuple.actual_features,
            self.eligibility_tuple.sve_vector_length_bytes,
        )?;
        // SAFETY: no operation intervenes between the exact current-thread VL
        // check and this branch; the entry and result ABI were authenticated.
        let status =
            unsafe { (self.entry)(haystack_pointer, haystack.len(), ptr::addr_of_mut!(result)) };
        decode_count_result_v3(
            status,
            result.value,
            upper.count,
            haystack.len(),
            literal_len,
        )
        .map_err(Into::into)
    }
}

/// Adopt one production-linked image.
///
/// The empty production table is checked before any supplied address is read.
///
/// # Safety
///
/// Every address must name the exact process-lifetime final-image symbol
/// described by the linked expectation, without interposition, unload, remap,
/// or mutation for the lifetime of the returned handle.
#[allow(
    unsafe_code,
    reason = "this is the sole production raw-address adoption boundary"
)]
pub unsafe fn adopt_linked_static_count_v3(
    linked: StaticCountLinkedAddressesV3,
) -> Result<VerifiedStaticCountV3, StaticCountVerifyErrorV3> {
    support_v3::require_nonempty_production_authority()?;
    if !cfg!(feature = "linked-count-v3") {
        return Err(StaticCountVerifyErrorV3::LinkedCountV3FeatureDisabled);
    }
    // SAFETY: forwarded caller contract; `adopt_core_v3` performs every check
    // before the address-to-function conversion.
    let core = unsafe { adopt_core_v3(linked.addresses, AuthorityV3::Production)? };
    Ok(VerifiedStaticCountV3 { core })
}

/// Adopt one source-authorized production Linux SVE/SVE2 image.
///
/// The caller-supplied full eligibility tuple is matched against production
/// source authority before any image address is read. Complete inspection then
/// proves that the image carries that exact tuple and fixed-policy facade
/// binding. The returned handle has no direct call method and is neither
/// `Send` nor `Sync`.
///
/// # Safety
///
/// Every exposed address must name the exact process-lifetime final-image
/// symbol described by the linked expectation, without interposition, unload,
/// remap, or mutation. `facade` must have been projected from the live
/// fixed-policy owner that will be retained by every safe call facade.
#[allow(
    unsafe_code,
    reason = "sole raw-address boundary for the disjoint production SVE handle"
)]
pub unsafe fn adopt_linked_static_count_sve_v3(
    linked: StaticCountSveLinkedAddressesV3,
    facade: StaticCountSveFacadeBindingV3<'_>,
) -> Result<VerifiedStaticCountSveV3, StaticCountVerifyErrorV3> {
    // This exact source-authority lookup deliberately precedes every read from
    // the untrusted final-image addresses.
    support_v3::require_production_tuple(linked.expected_eligibility_tuple)?;
    if !cfg!(feature = "linked-count-v3") {
        return Err(StaticCountVerifyErrorV3::LinkedCountV3FeatureDisabled);
    }
    // SAFETY: forwarded caller contract; `adopt_core_v3` rechecks the exact
    // tuple, facade binding, target, host, mapped bytes, and entry address.
    let core = unsafe {
        adopt_core_v3(
            linked.addresses,
            AuthorityV3::SveProduction {
                facade,
                expected_eligibility_tuple: linked.expected_eligibility_tuple,
            },
        )?
    };
    Ok(VerifiedStaticCountSveV3 {
        core,
        thread_bound: PhantomData,
    })
}

/// Adopt one image solely for qualification evidence gathering.
///
/// This symbol, address type, authority mode, and returned handle are all
/// disjoint from production. The exact full eligibility tuple is retained on
/// the handle but is never inserted into the production table.
///
/// # Safety
///
/// The same process-lifetime final-image contract as
/// [`adopt_linked_static_count_v3`] applies. In addition, `facade` must have
/// been projected from the live fixed-policy planned candidate that will own
/// every use of the returned qualification handle, and that owner must remain
/// alive and immutable for those uses. The safe FRE qualification wrapper
/// retains this owner and repeats the complete binding check.
#[cfg(feature = "count-v3-qualification-private")]
#[doc(hidden)]
#[allow(
    unsafe_code,
    reason = "this is the sole qualification-private raw-address adoption boundary"
)]
pub unsafe fn adopt_linked_static_count_qualification_v3(
    linked: StaticCountQualificationLinkedAddressesV3,
    facade: StaticCountQualificationFacadeBindingV3<'_>,
) -> Result<VerifiedStaticCountQualificationV3, StaticCountVerifyErrorV3> {
    // SAFETY: forwarded caller contract; authority remains private.
    let core = unsafe { adopt_core_v3(linked.addresses, AuthorityV3::Qualification { facade })? };
    Ok(VerifiedStaticCountQualificationV3 { core })
}

/// Adopt one Linux SVE/SVE2 image solely for qualification.
///
/// The returned handle has no direct call method and is neither `Send` nor
/// `Sync`. Configure this same thread to VL16 before adoption, then create a
/// same-thread session. Each session call repeats the VL16 check.
///
/// # Safety
///
/// The complete process-lifetime image and live planned-facade obligations of
/// [`adopt_linked_static_count_qualification_v3`] apply.
#[cfg(feature = "count-v3-qualification-private")]
#[doc(hidden)]
#[allow(
    unsafe_code,
    reason = "sole raw-address boundary for the disjoint SVE qualification handle"
)]
pub unsafe fn adopt_linked_static_count_sve_qualification_v3(
    linked: StaticCountSveQualificationLinkedAddressesV3,
    facade: StaticCountSveQualificationFacadeBindingV3<'_>,
) -> Result<VerifiedStaticCountSveQualificationV3, StaticCountVerifyErrorV3> {
    // SAFETY: forwarded caller contract; exact SVE target and thread checks
    // precede the sole address-to-function conversion.
    let core =
        unsafe { adopt_core_v3(linked.addresses, AuthorityV3::SveQualification { facade })? };
    Ok(VerifiedStaticCountSveQualificationV3 {
        core,
        thread_bound: PhantomData,
    })
}

/// Set this Linux AArch64 thread to SVE VL16, then independently read it back.
///
/// This qualification-only mutation has no inherit/on-exec flag and grants no
/// production authority.
#[cfg(feature = "count-v3-qualification-private")]
#[doc(hidden)]
pub fn configure_current_thread_sve_vl16_for_count_v3_qualification()
-> Result<u16, StaticCountSveThreadContractErrorV3> {
    platform::configure_current_thread_sve_vl16_v3()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityV3<'a> {
    Production,
    SveProduction {
        facade: StaticCountSveFacadeBindingV3<'a>,
        expected_eligibility_tuple: CountGeneralEligibilityTupleV3,
    },
    #[cfg(feature = "count-v3-qualification-private")]
    Qualification {
        facade: StaticCountQualificationFacadeBindingV3<'a>,
    },
    #[cfg(feature = "count-v3-qualification-private")]
    SveQualification {
        facade: StaticCountSveQualificationFacadeBindingV3<'a>,
    },
}

#[allow(
    unsafe_code,
    reason = "copies and views happen only after platform range verification under the caller's process-lifetime contract"
)]
unsafe fn adopt_core_v3(
    linked: LinkedAddressesV3,
    authority: AuthorityV3<'_>,
) -> Result<VerifiedCoreV3, StaticCountVerifyErrorV3> {
    let expectation_regions = platform::verify_range(
        linked.expectation,
        STATIC_COUNT_EXPECTATION_BYTES_V3,
        platform::RegionPurposeV3::Expectation,
    )?;
    // SAFETY: the exact fixed range is verified read-only and process-lifetime.
    let expectation_bytes =
        unsafe { copy_fixed_array::<STATIC_COUNT_EXPECTATION_BYTES_V3>(linked.expectation) };
    let expected = ExpectedStaticCountV3::inspect(&expectation_bytes)?;

    let metadata_regions = platform::verify_range(
        linked.metadata,
        METADATA_BYTES_V3,
        platform::RegionPurposeV3::Metadata,
    )?;
    // SAFETY: the exact fixed range is verified read-only and process-lifetime.
    let metadata_bytes = unsafe { copy_fixed_array::<METADATA_BYTES_V3>(linked.metadata) };
    let metadata = inspect_count_metadata_v3(&metadata_bytes)?;

    let payload_bytes = bounded_payload_bytes_v3(metadata.payload_bytes())?;
    let payload_regions = platform::verify_range(
        linked.payload,
        payload_bytes,
        platform::RegionPurposeV3::Payload,
    )?;
    let entry_offset = usize::try_from(metadata.entry_offset())
        .map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    require_entry_address_v3(linked.payload, entry_offset, linked.entry)?;
    match authority {
        AuthorityV3::SveProduction { .. } => {
            require_sve_handle_contract_v3(metadata)?;
            platform::require_sve_host_contract(
                metadata.actual_features(),
                metadata.required_isa_id(),
                metadata.sve_vector_length_bytes(),
            )?;
        }
        #[cfg(feature = "count-v3-qualification-private")]
        AuthorityV3::SveQualification { .. } => {
            require_sve_handle_contract_v3(metadata)?;
            platform::require_sve_host_contract(
                metadata.actual_features(),
                metadata.required_isa_id(),
                metadata.sve_vector_length_bytes(),
            )?;
        }
        AuthorityV3::Production => {
            require_thread_safe_asimd_handle_v3(
                metadata.actual_features(),
                metadata.sve_vector_length_bytes(),
            )?;
            platform::require_asimd_host_contract(
                metadata.actual_features(),
                metadata.sve_vector_length_bytes(),
            )?;
        }
        #[cfg(feature = "count-v3-qualification-private")]
        AuthorityV3::Qualification { .. } => {
            require_thread_safe_asimd_handle_v3(
                metadata.actual_features(),
                metadata.sve_vector_length_bytes(),
            )?;
            platform::require_asimd_host_contract(
                metadata.actual_features(),
                metadata.sve_vector_length_bytes(),
            )?;
        }
    }

    // SAFETY: the complete nonempty range is verified RX and the unsafe caller
    // promises stable process-lifetime provenance.
    let payload = unsafe {
        slice::from_raw_parts(
            ptr::with_exposed_provenance::<u8>(linked.payload),
            payload_bytes,
        )
    };
    let inert = inspect_inert_candidate_v3(expected, metadata, payload)?;

    let eligibility_tuple = inert.eligibility_tuple;
    match authority {
        AuthorityV3::Production => support_v3::require_production_tuple(eligibility_tuple)?,
        AuthorityV3::SveProduction {
            facade,
            expected_eligibility_tuple,
        } => {
            if eligibility_tuple != expected_eligibility_tuple {
                return Err(StaticCountVerifyErrorV3::EligibilityTupleNotAuthorized);
            }
            require(
                facade.literal == inert.literal(),
                StaticCountContractFieldV3::Literal,
            )?;
            require(
                facade.semantic_binding_identity == *expected.semantic_binding_identity(),
                StaticCountContractFieldV3::SemanticBindingIdentity,
            )?;
            require(
                facade.planning_receipt_identity == *expected.planning_receipt_identity(),
                StaticCountContractFieldV3::PlanningReceiptIdentity,
            )?;
        }
        #[cfg(feature = "count-v3-qualification-private")]
        AuthorityV3::Qualification { facade } => {
            require(
                facade.literal == inert.literal(),
                StaticCountContractFieldV3::Literal,
            )?;
            require(
                facade.semantic_binding_identity == *expected.semantic_binding_identity(),
                StaticCountContractFieldV3::SemanticBindingIdentity,
            )?;
            require(
                facade.planning_receipt_identity == *expected.planning_receipt_identity(),
                StaticCountContractFieldV3::PlanningReceiptIdentity,
            )?;
            if !support_v3::qualification_accepts_inspected_tuple(eligibility_tuple) {
                return Err(StaticCountVerifyErrorV3::EligibilityTupleNotAuthorized);
            }
        }
        #[cfg(feature = "count-v3-qualification-private")]
        AuthorityV3::SveQualification { facade } => {
            require(
                facade.literal == inert.literal(),
                StaticCountContractFieldV3::Literal,
            )?;
            require(
                facade.semantic_binding_identity == *expected.semantic_binding_identity(),
                StaticCountContractFieldV3::SemanticBindingIdentity,
            )?;
            require(
                facade.planning_receipt_identity == *expected.planning_receipt_identity(),
                StaticCountContractFieldV3::PlanningReceiptIdentity,
            )?;
            if !support_v3::qualification_accepts_inspected_tuple(eligibility_tuple) {
                return Err(StaticCountVerifyErrorV3::EligibilityTupleNotAuthorized);
            }
        }
    }

    let vm_regions_checked = expectation_regions
        .checked_add(metadata_regions)
        .and_then(|regions| regions.checked_add(payload_regions))
        .and_then(|regions| u32::try_from(regions).ok())
        .ok_or(StaticCountVerifyErrorV3::InspectionAccountingOverflow)?;
    // SAFETY: this is deliberately last, after immutable-range, ABI, exact
    // entry offset, host, digest, semantic, recipe, code, and authority checks.
    let entry = unsafe { entry_from_verified_address(linked.entry) };
    Ok(VerifiedCoreV3 {
        entry,
        literal_manifest: inert.literal_manifest,
        literal_bytes: inert.literal_bytes,
        semantic_binding_identity: *expected.semantic_binding_identity(),
        planning_receipt_identity: *expected.planning_receipt_identity(),
        expectation_identity: *expected.expectation_identity(),
        compile_identity: *expected.compile_identity(),
        object_identity: *expected.object_identity(),
        eligibility_tuple,
        accounting: StaticCountInspectionAccountingV3 {
            expectation_bytes_copied: u32::try_from(STATIC_COUNT_EXPECTATION_BYTES_V3)
                .expect("fixed expectation width"),
            metadata_bytes_copied: u32::try_from(METADATA_BYTES_V3).expect("fixed metadata width"),
            payload_bytes_hashed: u32::try_from(payload_bytes)
                .map_err(|_| StaticCountVerifyErrorV3::InspectionAccountingOverflow)?,
            vm_query_input_bytes_upper_bound: platform::VM_QUERY_INPUT_BYTES_UPPER_BOUND_V3,
            vm_regions_checked,
            audit: inert.audit,
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InertInspectionV3 {
    literal_manifest: [u8; 32],
    literal_bytes: u8,
    eligibility_tuple: CountGeneralEligibilityTupleV3,
    audit: CountAuditReportV3,
}

impl InertInspectionV3 {
    fn literal(&self) -> &[u8] {
        &self.literal_manifest[..usize::from(self.literal_bytes)]
    }
}

/// Complete byte-level validation shared by mapped adoption and inert
/// mutation tests. It creates no callable and consults no authority table.
fn inspect_inert_candidate_v3(
    expected: ExpectedStaticCountV3,
    metadata: ClaimedCountMetadataV3,
    payload: &[u8],
) -> Result<InertInspectionV3, StaticCountVerifyErrorV3> {
    require(
        metadata == expected.metadata(),
        StaticCountContractFieldV3::Metadata,
    )?;
    require(
        metadata.compile_identity() == expected.compile_identity(),
        StaticCountContractFieldV3::CompileIdentity,
    )?;
    if payload.len() != bounded_payload_bytes_v3(metadata.payload_bytes())? {
        return Err(StaticCountVerifyErrorV3::ContractMismatch {
            field: StaticCountContractFieldV3::MappedCode,
        });
    }
    let payload_digest: [u8; 32] = Sha256::digest(payload).into();
    if &payload_digest != metadata.payload_sha256() {
        return Err(StaticCountVerifyErrorV3::PayloadDigestMismatch);
    }
    let code_bytes = usize::try_from(metadata.code_bytes())
        .map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    let mapped_code =
        payload
            .get(..code_bytes)
            .ok_or(StaticCountVerifyErrorV3::ContractMismatch {
                field: StaticCountContractFieldV3::MappedCode,
            })?;
    if payload[code_bytes..].iter().any(|byte| *byte != 0) {
        return Err(StaticCountVerifyErrorV3::ContractMismatch {
            field: StaticCountContractFieldV3::MappedCode,
        });
    }

    let literal_len = usize::try_from(metadata.literal_bytes())
        .map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    let literal = metadata.literal_manifest().get(..literal_len).ok_or(
        StaticCountVerifyErrorV3::ContractMismatch {
            field: StaticCountContractFieldV3::Literal,
        },
    )?;
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())?;
    require(
        program.cache_identity().as_bytes() == metadata.program_identity(),
        StaticCountContractFieldV3::ProgramIdentity,
    )?;
    // Decode explicitly before the independent mapped-code auditor performs
    // its own closed decode/regeneration pass.
    let recipe = decode_count_recipe_v3(&program, metadata.canonical_recipe())?;
    require(
        recipe.identity().as_bytes() == metadata.recipe_identity(),
        StaticCountContractFieldV3::Recipe,
    )?;
    let mapped_metadata = mapped_metadata_v3(metadata)?;
    let audit = audit_count_mapped_code_v3(
        &program,
        metadata.canonical_recipe(),
        mapped_code,
        mapped_metadata,
        CountEmitLimitsV3::default(),
    )?;

    let literal_bytes =
        u8::try_from(literal_len).map_err(|_| StaticCountVerifyErrorV3::ContractMismatch {
            field: StaticCountContractFieldV3::Literal,
        })?;
    let mut literal_manifest = [0_u8; 32];
    literal_manifest[..literal_len].copy_from_slice(literal);
    Ok(InertInspectionV3 {
        literal_manifest,
        literal_bytes,
        eligibility_tuple: expected.eligibility_tuple(),
        audit,
    })
}

fn mapped_metadata_v3(
    metadata: ClaimedCountMetadataV3,
) -> Result<AotCountMappedMetadataV3, StaticCountVerifyErrorV3> {
    AotCountMappedMetadataV3::from_wire_parts(
        metadata.backend_version(),
        metadata.algorithm_version(),
        metadata.kir_semantics_version(),
        metadata.kir_abi_version(),
        metadata.output_kind(),
        metadata.architecture(),
        metadata.little_endian(),
        metadata.pointer_width(),
        metadata.target_abi(),
        metadata.actual_features(),
        metadata.allowed_features(),
        metadata.max_literal_bytes(),
        metadata.candidate_block_starts(),
        metadata.vector_bytes(),
        metadata.sve_vector_length_bytes(),
        *metadata.program_identity(),
        metadata.literal_bytes(),
        *metadata.recipe_identity(),
        *metadata.artifact_identity(),
        metadata.code_bytes(),
    )
    .ok_or(StaticCountVerifyErrorV3::ContractMismatch {
        field: StaticCountContractFieldV3::Metadata,
    })
}

/// This handle is freely movable between threads. Linux SVE VL is a mutable
/// per-thread property, so SVE/SVE2 production uses the separately
/// source-authorized [`VerifiedStaticCountSveV3`] and
/// [`StaticCountSveSessionV3`] instead of broadening this check.
fn require_thread_safe_asimd_handle_v3(
    actual_features: u64,
    sve_vector_length_bytes: u16,
) -> Result<(), StaticCountVerifyErrorV3> {
    let features = AotCountCpuFeatures::from_bits(actual_features)
        .ok_or(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable)?;
    if features.contains(AotCountCpuFeatures::SVE)
        || features.contains(AotCountCpuFeatures::SVE2)
        || sve_vector_length_bytes != 0
    {
        Err(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable)
    } else {
        Ok(())
    }
}

fn require_sve_handle_contract_v3(
    metadata: ClaimedCountMetadataV3,
) -> Result<(), StaticCountVerifyErrorV3> {
    if exact_sve_target_contract_fields_v3(
        metadata.required_isa_id(),
        metadata.register_plan_id(),
        metadata.actual_features(),
        metadata.allowed_features(),
        metadata.object_format(),
        metadata.vector_bytes(),
        metadata.sve_vector_length_bytes(),
    ) {
        Ok(())
    } else {
        Err(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable)
    }
}

fn exact_sve_target_contract_fields_v3(
    required_isa_id: u8,
    register_plan_id: u8,
    actual_features: u64,
    allowed_features: u64,
    object_format: CountObjectFormatV3,
    vector_bytes: u16,
    sve_vector_length_bytes: u16,
) -> bool {
    let sve = AotCountCpuFeatures::SVE.bits();
    let sve2 = AotCountCpuFeatures::SVE
        .union(AotCountCpuFeatures::SVE2)
        .bits();
    let exact_recipe_target = match required_isa_id {
        2 => register_plan_id == 2 && actual_features == sve && allowed_features == sve,
        3 => register_plan_id == 3 && actual_features == sve2 && allowed_features == sve2,
        _ => false,
    };
    exact_recipe_target
        && object_format == CountObjectFormatV3::Elf64Aarch64
        && vector_bytes == 16
        && sve_vector_length_bytes == 16
}

fn bounded_payload_bytes_v3(claimed: u32) -> Result<usize, StaticCountVerifyErrorV3> {
    let claimed =
        usize::try_from(claimed).map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    if claimed == 0 || claimed > HARD_MAX_MAPPED_PAYLOAD_BYTES_V3 {
        Err(StaticCountVerifyErrorV3::MappedPayloadExtentOutOfBounds {
            claimed,
            hard_maximum: HARD_MAX_MAPPED_PAYLOAD_BYTES_V3,
        })
    } else {
        Ok(claimed)
    }
}

fn require_entry_address_v3(
    payload: usize,
    entry_offset: usize,
    entry: usize,
) -> Result<(), StaticCountVerifyErrorV3> {
    let expected = payload
        .checked_add(entry_offset)
        .ok_or(StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    if expected == entry {
        Ok(())
    } else {
        Err(StaticCountVerifyErrorV3::EntryAddressMismatch)
    }
}

fn require(
    condition: bool,
    field: StaticCountContractFieldV3,
) -> Result<(), StaticCountVerifyErrorV3> {
    if condition {
        Ok(())
    } else {
        Err(StaticCountVerifyErrorV3::ContractMismatch { field })
    }
}

#[allow(
    unsafe_code,
    reason = "caller first verifies the exact immutable fixed-size mapping"
)]
unsafe fn copy_fixed_array<const BYTES: usize>(address: usize) -> [u8; BYTES] {
    let mut bytes = [0_u8; BYTES];
    // SAFETY: upheld by this function's caller.
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::with_exposed_provenance::<u8>(address),
            bytes.as_mut_ptr(),
            BYTES,
        );
    }
    bytes
}

#[allow(
    unsafe_code,
    reason = "called only after complete mapped-image and authority verification"
)]
unsafe fn entry_from_verified_address(address: usize) -> StaticAggregateEntryV3 {
    let pointer = ptr::with_exposed_provenance::<()>(address);
    // SAFETY: the complete entry proof precedes this sole conversion.
    unsafe { mem::transmute::<*const (), StaticAggregateEntryV3>(pointer) }
}

fn decode_count_result_v3(
    status: u64,
    value: u64,
    admitted_count_upper_bound: u64,
    haystack_len: usize,
    literal_len: usize,
) -> Result<u64, StaticCountCallErrorV3> {
    if status != 0 && value != POISONED_COUNT_RESULT_V3 {
        return Err(StaticCountCallErrorV3::NativeResultChangedOnFault { status, value });
    }
    match status {
        0 => {}
        1 => return Err(StaticCountCallErrorV3::BackendArithmeticOverflow),
        status => return Err(StaticCountCallErrorV3::BackendFault { status }),
    }
    if value == POISONED_COUNT_RESULT_V3 {
        return Err(StaticCountCallErrorV3::PoisonedNativeResult);
    }
    if value > admitted_count_upper_bound {
        return Err(StaticCountCallErrorV3::InvalidNativeCount {
            value,
            haystack_len,
            literal_len,
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre_aot_count_compiler::{
        CountCompileLimitsV3, CountCompileRequestV3, CountCompileTargetV3, CountObjectFormatV3,
        CountObjectLimitsV3, CountSemanticCandidateV3, FocusedCompiledCountV3, compile_count_v3,
        inspect_count_implementation_object_v3,
    };
    use fre_aot_optimizer::{CountV3RequiredIsa, CountV3TuningClass};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn compiled_fixture_v3() -> FocusedCompiledCountV3 {
        compile_count_v3(
            CountCompileRequestV3 {
                literal: b"needle",
                semantic_candidate: CountSemanticCandidateV3 {
                    manifest_identity: [1; 32],
                    policy_limits_identity: [2; 32],
                    semantic_binding_identity: [3; 32],
                    planning_receipt_identity: [4; 32],
                    object_binding_identity: [5; 32],
                    claimed_receipt_identity: [6; 32],
                    claimed_resource_receipt_identity: [7; 32],
                },
                target: CountCompileTargetV3 {
                    object_format: CountObjectFormatV3::MachOArm64,
                    tuning_class: CountV3TuningClass::AppleMSeries,
                    required_isa: CountV3RequiredIsa::Aarch64Neon128,
                },
            },
            CountCompileLimitsV3::default(),
        )
        .expect("inert optimizing Count-v3 fixture")
    }

    static DIRECT_ENTRY_CALLS_V3: AtomicUsize = AtomicUsize::new(0);

    #[allow(
        unsafe_code,
        reason = "ABI-compatible inert entry used only by the private call-shape test"
    )]
    unsafe extern "C" fn counted_dummy_entry_v3(
        _haystack: *const u8,
        _haystack_len: usize,
        result: *mut RawAggregateResultV3,
    ) -> u64 {
        DIRECT_ENTRY_CALLS_V3.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the private caller supplies its initialized result slot.
        unsafe {
            (*result).value = 2;
        }
        0
    }

    fn counted_dummy_core_v3() -> VerifiedCoreV3 {
        let compiled = compiled_fixture_v3();
        let expected = ExpectedStaticCountV3::inspect(compiled.expectation()).unwrap();
        let mut literal_manifest = [0_u8; 32];
        literal_manifest[..6].copy_from_slice(b"needle");
        VerifiedCoreV3 {
            entry: counted_dummy_entry_v3,
            literal_manifest,
            literal_bytes: 6,
            semantic_binding_identity: [1; 32],
            planning_receipt_identity: [2; 32],
            expectation_identity: [3; 32],
            compile_identity: [4; 32],
            object_identity: [5; 32],
            eligibility_tuple: expected.eligibility_tuple(),
            accounting: StaticCountInspectionAccountingV3 {
                expectation_bytes_copied: 0,
                metadata_bytes_copied: 0,
                payload_bytes_hashed: 0,
                vm_query_input_bytes_upper_bound: 0,
                vm_regions_checked: 0,
                audit: CountAuditReportV3::default(),
            },
        }
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "source-empty authority proves refusal precedes address use"
    )]
    fn production_refuses_before_reading_any_address() {
        let linked = StaticCountLinkedAddressesV3::from_exposed_addresses(1, 2, 3, 4);
        // SAFETY: source-empty production authority must return before any
        // supplied address is inspected.
        assert_eq!(
            unsafe { adopt_linked_static_count_v3(linked) }.unwrap_err(),
            StaticCountVerifyErrorV3::NoProductionAuthority
        );
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "source-empty SVE authority proves exact-tuple refusal precedes address use"
    )]
    fn production_sve_refuses_authority_before_reading_any_address() {
        let compiled = compiled_fixture_v3();
        let expected = ExpectedStaticCountV3::inspect(compiled.expectation()).unwrap();
        let linked = StaticCountSveLinkedAddressesV3::from_exposed_addresses(
            1,
            2,
            3,
            4,
            expected.eligibility_tuple(),
        );
        let facade = StaticCountSveFacadeBindingV3::new(b"needle", [3; 32], [4; 32]);
        // SAFETY: the empty production table must refuse the independently
        // supplied tuple before dereferencing any sentinel address.
        assert_eq!(
            unsafe { adopt_linked_static_count_sve_v3(linked, facade) }.unwrap_err(),
            StaticCountVerifyErrorV3::NoProductionAuthority
        );
    }

    #[test]
    fn result_decoder_is_strict() {
        assert_eq!(decode_count_result_v3(0, 3, 3, 9, 3), Ok(3));
        assert!(matches!(
            decode_count_result_v3(0, 4, 3, 9, 3),
            Err(StaticCountCallErrorV3::InvalidNativeCount { .. })
        ));
        assert_eq!(
            decode_count_result_v3(7, 2, 3, 9, 3),
            Err(StaticCountCallErrorV3::NativeResultChangedOnFault {
                status: 7,
                value: 2
            })
        );
    }

    #[test]
    fn movable_handle_remains_closed_to_sve_and_sve2() {
        let sve = AotCountCpuFeatures::SVE.bits();
        let sve2 = AotCountCpuFeatures::SVE
            .union(AotCountCpuFeatures::SVE2)
            .bits();
        assert_eq!(
            require_thread_safe_asimd_handle_v3(sve, 16),
            Err(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable)
        );
        assert_eq!(
            require_thread_safe_asimd_handle_v3(sve2, 16),
            Err(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable)
        );
    }

    #[test]
    fn sve_production_and_qualification_target_fields_are_exact_and_closed() {
        let sve = AotCountCpuFeatures::SVE.bits();
        let sve2 = AotCountCpuFeatures::SVE
            .union(AotCountCpuFeatures::SVE2)
            .bits();
        let neon = AotCountCpuFeatures::ASIMD.bits();
        assert!(exact_sve_target_contract_fields_v3(
            2,
            2,
            sve,
            sve,
            CountObjectFormatV3::Elf64Aarch64,
            16,
            16,
        ));
        assert!(exact_sve_target_contract_fields_v3(
            3,
            3,
            sve2,
            sve2,
            CountObjectFormatV3::Elf64Aarch64,
            16,
            16,
        ));
        assert!(!exact_sve_target_contract_fields_v3(
            2,
            2,
            sve | neon,
            sve | neon,
            CountObjectFormatV3::Elf64Aarch64,
            16,
            16,
        ));
        assert!(!exact_sve_target_contract_fields_v3(
            3,
            3,
            sve2,
            sve2,
            CountObjectFormatV3::MachOArm64,
            16,
            16,
        ));
        assert!(!exact_sve_target_contract_fields_v3(
            3,
            2,
            sve2,
            sve2,
            CountObjectFormatV3::Elf64Aarch64,
            16,
            16,
        ));
        assert!(!exact_sve_target_contract_fields_v3(
            3,
            3,
            sve2,
            sve2,
            CountObjectFormatV3::Elf64Aarch64,
            32,
            16,
        ));
        assert!(!exact_sve_target_contract_fields_v3(
            3,
            3,
            AotCountCpuFeatures::SVE2.bits(),
            AotCountCpuFeatures::SVE2.bits(),
            CountObjectFormatV3::Elf64Aarch64,
            16,
            16,
        ));
        assert!(!exact_sve_target_contract_fields_v3(
            3,
            3,
            sve2,
            sve,
            CountObjectFormatV3::Elf64Aarch64,
            16,
            16,
        ));
        assert!(!exact_sve_target_contract_fields_v3(
            2,
            2,
            sve,
            sve,
            CountObjectFormatV3::Elf64Aarch64,
            16,
            0,
        ));
        assert!(!exact_sve_target_contract_fields_v3(
            2,
            3,
            sve,
            sve,
            CountObjectFormatV3::Elf64Aarch64,
            16,
            16,
        ));
    }

    #[test]
    fn every_expectation_byte_mutation_is_refused() {
        let compiled = compiled_fixture_v3();
        let original = *compiled.expectation();
        for index in 0..original.len() {
            let mut changed = original;
            changed[index] ^= 1;
            assert!(
                ExpectedStaticCountV3::inspect(&changed).is_err(),
                "mutated expectation byte {index} was accepted"
            );
        }
    }

    #[test]
    fn metadata_and_payload_tampering_fail_before_a_callable() {
        let compiled = compiled_fixture_v3();
        let expected = ExpectedStaticCountV3::inspect(compiled.expectation()).unwrap();
        let inspection = inspect_count_implementation_object_v3(
            compiled.implementation_object().as_bytes(),
            CountObjectLimitsV3::default(),
        )
        .unwrap();
        let metadata = inspect_count_metadata_v3(inspection.metadata_bytes()).unwrap();
        assert!(inspect_inert_candidate_v3(expected, metadata, inspection.payload()).is_ok());

        let mut changed_payload = inspection.payload().to_vec();
        changed_payload[0] ^= 1;
        assert_eq!(
            inspect_inert_candidate_v3(expected, metadata, &changed_payload).unwrap_err(),
            StaticCountVerifyErrorV3::PayloadDigestMismatch
        );

        let mut changed_metadata = *inspection.metadata_bytes();
        // This lies within the canonical recipe. Whether the strict metadata
        // decoder or the exact expectation comparison rejects first, no code
        // audit or callable can be reached.
        changed_metadata[160] ^= 1;
        match inspect_count_metadata_v3(&changed_metadata) {
            Err(_) => {}
            Ok(changed) => assert!(matches!(
                inspect_inert_candidate_v3(expected, changed, inspection.payload()),
                Err(StaticCountVerifyErrorV3::ContractMismatch {
                    field: StaticCountContractFieldV3::Metadata
                })
            )),
        }
    }

    #[test]
    fn production_value_path_enforces_floor_before_one_direct_entry_call() {
        let verified = VerifiedStaticCountV3 {
            core: counted_dummy_core_v3(),
        };
        DIRECT_ENTRY_CALLS_V3.store(0, Ordering::SeqCst);
        assert_eq!(
            verified.count(b"............", AggregateExecutionLimits::unlimited()),
            Err(StaticCountCallErrorV3::ProductionRouteBelowEvidenceFloor {
                required_bytes: STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3,
                actual_bytes: 12,
            })
        );
        assert_eq!(DIRECT_ENTRY_CALLS_V3.load(Ordering::SeqCst), 0);
        let long_haystack = [b'.'; STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3];
        assert_eq!(
            verified.count(&long_haystack, AggregateExecutionLimits::unlimited()),
            Ok(2)
        );
        assert_eq!(DIRECT_ENTRY_CALLS_V3.load(Ordering::SeqCst), 1);
        assert_eq!(verified.core.accounting.payload_bytes_hashed, 0);
    }

    #[test]
    fn production_sve_session_enforces_floor_before_target_or_native_call() {
        let verified = VerifiedStaticCountSveV3 {
            core: counted_dummy_core_v3(),
            thread_bound: PhantomData,
        };
        let session = StaticCountSveSessionV3 {
            handle: &verified,
            thread_bound: PhantomData,
        };
        DIRECT_ENTRY_CALLS_V3.store(0, Ordering::SeqCst);
        assert_eq!(
            session.count(b"short", AggregateExecutionLimits::unlimited()),
            Err(StaticCountSveCallErrorV3::Count(
                StaticCountCallErrorV3::ProductionRouteBelowEvidenceFloor {
                    required_bytes: STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3,
                    actual_bytes: 5,
                }
            ))
        );
        assert_eq!(DIRECT_ENTRY_CALLS_V3.load(Ordering::SeqCst), 0);
    }
}
