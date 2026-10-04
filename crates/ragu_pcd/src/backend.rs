//! Sealed selection of the computational backend.
//!
//! This is the only file in `ragu_pcd` that names `ragu_acceleration`: the
//! sealed mapping below decides which backends an application may select and
//! which kernels the verifier consults for each of them.

use ragu_backend::Backend;

mod sealed {
    use ragu_acceleration::{AcceleratedBackend, AcceleratedProver};
    use ragu_backend::ReferenceBackend;

    use super::SelectableBackend;

    pub trait Sealed {
        type Verifier: SelectableBackend;
    }

    impl Sealed for ReferenceBackend {
        type Verifier = ReferenceBackend;
    }

    impl Sealed for AcceleratedBackend {
        type Verifier = AcceleratedBackend;
    }

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
/// backend whose kernels [`Application::verify`](crate::Application::verify)
/// and [`Application::verify_compressed`](crate::Application::verify_compressed)
/// consult, so accelerating verification is an explicit choice rather than a
/// consequence of accelerating proving.
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
