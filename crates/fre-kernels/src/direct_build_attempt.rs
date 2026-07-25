use core::fmt;

/// Exact effects observed while constructing one direct kernel plan.
///
/// The counters describe successful reservations and writes, rather than
/// preflight bounds. On a terminal error, `live_persistent_bytes` is zero
/// after the unpublished buffers have been released; `peak_bytes` retains the
/// largest co-live allocation observed before that release.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectBuildAttemptActual {
    pub work: u64,
    pub allocations: usize,
    pub allocated_bytes: usize,
    pub copied_bytes: usize,
    pub initialized_bytes: usize,
    pub live_persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Successful direct-plan construction plus its exact observed effects.
#[derive(Debug)]
pub struct DirectBuildAttempt<P> {
    plan: P,
    actual: DirectBuildAttemptActual,
}

impl<P> DirectBuildAttempt<P> {
    pub(crate) const fn new(plan: P, actual: DirectBuildAttemptActual) -> Self {
        Self { plan, actual }
    }

    #[must_use]
    pub const fn actual(&self) -> DirectBuildAttemptActual {
        self.actual
    }

    #[must_use]
    pub fn into_parts(self) -> (P, DirectBuildAttemptActual) {
        (self.plan, self.actual)
    }

    #[must_use]
    pub fn into_plan(self) -> P {
        self.plan
    }
}

/// Terminal direct-plan construction error with allocation-free partial
/// accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectBuildAttemptError<E> {
    source: E,
    actual: DirectBuildAttemptActual,
}

impl<E> DirectBuildAttemptError<E> {
    pub(crate) const fn new(source: E, actual: DirectBuildAttemptActual) -> Self {
        Self { source, actual }
    }

    #[must_use]
    pub const fn actual(&self) -> DirectBuildAttemptActual {
        self.actual
    }

    #[must_use]
    pub const fn source(&self) -> &E {
        &self.source
    }

    #[must_use]
    pub fn into_source(self) -> E {
        self.source
    }
}

impl<E: fmt::Display> fmt::Display for DirectBuildAttemptError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl<E: std::error::Error + 'static> std::error::Error for DirectBuildAttemptError<E> {}
