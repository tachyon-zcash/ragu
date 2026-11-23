//! Test-only capture of a compressed verifier run, after zakura-common's
//! Halo2 verifier fingerprints.
//!
//! During a test capture, the cycle transcript records every point and
//! scalar it absorbs and every challenge it squeezes, and each IPA [`MSM`]
//! the verifier evaluates records its terms and whether it was the identity.
//! The fuse fixtures pin these, so a change to how the verifier reads a proof
//! shows even when its verdict does not.
//!
//! Recording is per thread. The recorder and event encoding compile only
//! for tests; production observation helpers are inline no-ops.
//!
//! [`MSM`]: super::MSM

#[cfg(test)]
pub(crate) use recorder::{Event, capture};
pub(crate) use recorder::{record_challenge, record_msm, record_point, record_scalar};

#[cfg(not(test))]
mod recorder {
    use udon::{curve::Affine, field::Field};

    #[inline]
    pub(crate) fn record_point<P: Affine>(_point: &P) {}

    #[inline]
    pub(crate) fn record_scalar<F: Field>(_scalar: &F) {}

    #[inline]
    pub(crate) fn record_challenge<F: Field>(_challenge: &F) {}

    #[inline]
    pub(crate) fn record_msm<P: Affine>(
        _scalars: &[P::Scalar],
        _bases: &[P],
        _proof_dependent_bases: usize,
        _identity: bool,
    ) {
    }
}

#[cfg(test)]
mod recorder {
    use alloc::vec::Vec;
    use core::cell::RefCell;

    use udon::{curve::Affine, field::Field};

    /// One step of a verifier run.
    pub(crate) enum Event {
        /// A point the transcript absorbed: a nested-curve point directly, or the
        /// bridge commitment of host-curve coordinates or nested-curve scalars.
        Point(Vec<u8>),
        /// A circuit-field scalar the transcript absorbed directly.
        Scalar(Vec<u8>),
        /// A challenge the transcript squeezed, in the circuit field.
        Challenge(Vec<u8>),
        /// An IPA MSM the verifier evaluated: its scalars in evaluation order,
        /// the proof-dependent bases they multiply, and whether it was the
        /// identity. The fixed generators are left out; their scalars' positions
        /// pin them.
        Msm {
            scalars: Vec<Vec<u8>>,
            bases: Vec<Vec<u8>>,
            identity: bool,
        },
    }

    std::thread_local! {
        static LOG: RefCell<Option<Vec<Event>>> = const { RefCell::new(None) };
    }

    /// Records an event if a capture is running on this thread.
    fn record(event: impl FnOnce() -> Event) {
        LOG.with(|log| {
            if let Some(log) = log.borrow_mut().as_mut() {
                log.push(event());
            }
        });
    }

    /// Runs `run`, returning its output and the events it recorded.
    pub(crate) fn capture<T>(run: impl FnOnce() -> T) -> (T, Vec<Event>) {
        LOG.with(|log| *log.borrow_mut() = Some(Vec::new()));
        let output = run();
        let events = LOG.with(|log| log.borrow_mut().take()).unwrap_or_default();
        (output, events)
    }

    pub(crate) fn record_point<P: Affine>(value: &P) {
        record(|| Event::Point(point(value)));
    }

    pub(crate) fn record_scalar<F: Field>(value: &F) {
        record(|| Event::Scalar(field(value)));
    }

    pub(crate) fn record_challenge<F: Field>(value: &F) {
        record(|| Event::Challenge(field(value)));
    }

    /// Records the MSM's scalars and the proof-dependent prefix of its bases.
    pub(crate) fn record_msm<P: Affine>(
        scalars: &[P::Scalar],
        bases: &[P],
        proof_dependent_bases: usize,
        identity: bool,
    ) {
        record(|| Event::Msm {
            scalars: scalars.iter().map(field).collect(),
            bases: bases[..proof_dependent_bases].iter().map(point).collect(),
            identity,
        });
    }

    fn field<F: Field>(value: &F) -> Vec<u8> {
        value.to_bytes().as_ref().to_vec()
    }

    fn point<P: Affine>(value: &P) -> Vec<u8> {
        value.to_bytes().as_ref().to_vec()
    }
}
