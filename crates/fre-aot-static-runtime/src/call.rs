use crate::CallError;

pub(crate) const POISONED_COUNT_RESULT_V2: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawAggregateCallV2 {
    pub(crate) status: u64,
    pub(crate) value: u64,
}

#[inline]
pub(crate) fn decode_count_v2(
    raw: RawAggregateCallV2,
    admitted_count_upper_bound: u64,
    haystack_len: usize,
    literal_len: usize,
) -> Result<u64, CallError> {
    if raw.status != 0 && raw.value != POISONED_COUNT_RESULT_V2 {
        return Err(CallError::NativeResultChangedOnFault {
            status: raw.status,
            value: raw.value,
        });
    }
    match raw.status {
        0 => {}
        1 => return Err(CallError::BackendArithmeticOverflow),
        status => return Err(CallError::BackendFault { status }),
    }
    if raw.value == POISONED_COUNT_RESULT_V2 {
        return Err(CallError::PoisonedNativeResult);
    }

    if raw.value > admitted_count_upper_bound {
        return Err(CallError::InvalidNativeCount {
            value: raw.value,
            haystack_len,
            literal_len,
        });
    }
    Ok(raw.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn success(value: u64) -> RawAggregateCallV2 {
        RawAggregateCallV2 { status: 0, value }
    }

    #[test]
    fn status_result_and_count_bounds_are_all_strict() {
        assert_eq!(decode_count_v2(success(3), 3, 9, 3), Ok(3));
        assert_eq!(decode_count_v2(success(4), 4, 3, 0), Ok(4));
        assert!(matches!(
            decode_count_v2(success(4), 3, 9, 3),
            Err(CallError::InvalidNativeCount { .. })
        ));
        assert!(matches!(
            decode_count_v2(success(5), 4, 3, 0),
            Err(CallError::InvalidNativeCount { .. })
        ));
        assert_eq!(
            decode_count_v2(
                RawAggregateCallV2 {
                    status: 1,
                    value: u64::MAX,
                },
                1,
                0,
                0,
            ),
            Err(CallError::BackendArithmeticOverflow)
        );
        assert_eq!(
            decode_count_v2(
                RawAggregateCallV2 {
                    status: 7,
                    value: u64::MAX,
                },
                1,
                0,
                0,
            ),
            Err(CallError::BackendFault { status: 7 })
        );
        assert_eq!(
            decode_count_v2(success(u64::MAX), u64::MAX, usize::MAX, 1),
            Err(CallError::PoisonedNativeResult)
        );
        for (status, value) in [(1, 0), (2, 5), (9, 7), (u64::MAX, 11)] {
            assert_eq!(
                decode_count_v2(RawAggregateCallV2 { status, value }, 1, 0, 0,),
                Err(CallError::NativeResultChangedOnFault { status, value })
            );
        }
    }

    #[test]
    fn empty_haystack_empty_literal_count_bound_is_one() {
        assert_eq!(decode_count_v2(success(1), 1, 0, 0), Ok(1));
        assert!(matches!(
            decode_count_v2(success(2), 1, 0, 0),
            Err(CallError::InvalidNativeCount { .. })
        ));
    }

    #[test]
    fn decoder_reuses_the_exact_admitted_preflight_bound() {
        assert_eq!(decode_count_v2(success(2), 2, 5, 2), Ok(2));
        assert!(matches!(
            decode_count_v2(success(3), 2, 5, 2),
            Err(CallError::InvalidNativeCount { .. })
        ));
        assert_eq!(decode_count_v2(success(4), 4, 12, 3), Ok(4));
        assert!(matches!(
            decode_count_v2(success(5), 4, 12, 3),
            Err(CallError::InvalidNativeCount { .. })
        ));
    }
}
