//! Sealed selection of the computational backend.
//!
//! The sealed mapping below decides which backends an application may select
//! and which kernels the verifier consults for each of them; nothing else in
//! `ragu_pcd` makes either choice. The builder's default backend,
//! [`AcceleratedBackend`](ragu_acceleration::AcceleratedBackend), is named in
//! the crate root.

use ragu_backend::Backend;

mod sealed {
    use ragu_acceleration::{AcceleratedBackend, AcceleratedProver};
    use ragu_backend::ReferenceBackend;

    use super::SelectableBackend;

    pub trait Sealed {
        type Verifier: SelectableBackend;
    }

    // Reference kernels for both proving and verification.
    impl Sealed for ReferenceBackend {
        type Verifier = ReferenceBackend;
    }

    // Accelerated kernels for both proving and verification.
    impl Sealed for AcceleratedBackend {
        type Verifier = AcceleratedBackend;
    }

    // Accelerated proving, with verification routed directly to the reference backend.
    impl Sealed for AcceleratedProver {
        type Verifier = ReferenceBackend;
    }
}

#[cfg(test)]
pub(crate) use sealed::Sealed as TestSealed;

/// A Ragu-owned computational backend.
///
/// This trait is sealed: applications may select one of Ragu's supported
/// implementations, but cannot provide their own backend implementation.
/// Each selectable backend also fixes [`Verifier`](Self::Verifier), the
/// backend whose kernels
/// [`Application::verify_compressed`](crate::Application::verify_compressed)
/// (and, under `test-utils`, `Application::verify_uncompressed`) consult.
/// The builder's default, `AcceleratedBackend`, verifies with the accelerated
/// kernels. An application keeps verification on the reference kernels by
/// selecting `AcceleratedProver`, which still proves with the accelerated
/// ones, or `ReferenceBackend`. Either way it chooses among Ragu's kernels:
/// it cannot supply the code that decides acceptance.
///
/// # Trust
///
/// The prover's kernels are outside the soundness trust base. The verifier
/// checks every proof independently, so a prover kernel that computed a
/// wrong value could only make an honest proof fail to verify or change its
/// bytes; it could not make a false statement verify. The verifier's kernels
/// are inside it.
///
/// Every accelerated kernel must return exactly what the reference kernel
/// returns: the accelerated verifier computes the same values as the
/// reference one, only faster. Their agreement is tested rather than
/// proven. The backend-equivalence tests compare each accelerated kernel
/// with its reference, and the fuse fixtures require both verifiers to
/// reproduce the committed fingerprints, on each fixture's honest proof and
/// on a random string. That is evidence on those inputs, not on every input
/// an adversary could choose. A disagreement on some input would let a proof
/// be accepted by one verifier and rejected by the other, so parties that
/// must agree on acceptance should verify with the same backend. A party
/// that wants the reference verifier selects `AcceleratedProver` or
/// `ReferenceBackend`.
pub trait SelectableBackend: Backend + sealed::Sealed {
    /// The backend whose kernels the verifier consults.
    ///
    /// `ReferenceBackend` and `AcceleratedBackend` verify with their own
    /// kernels; `AcceleratedProver` proves with the accelerated kernels
    /// and verifies with the reference ones.
    type Verifier: SelectableBackend;
}

impl<T: Backend + sealed::Sealed> SelectableBackend for T {
    type Verifier = <T as sealed::Sealed>::Verifier;
}
