//! Verifier-consulted kernels.
//!
//! The [`Backend`](ragu_backend::Backend) trait has a single set of methods,
//! and the prover uses all of them. The verifiers also use polynomial and
//! registry evaluations, commitments, and MSMs through the selected backend's
//! `Verifier`. This includes the compressed verifier's transcript bridges,
//! batch commitments, and IPA checks. `AcceleratedBackend` selects its own
//! kernels for verification; `AcceleratedProver` selects `ReferenceBackend`.
//! Overrides of verifier-consulted kernels belong in this module and are
//! reached from the `Backend` impl in the crate root by delegation, so code
//! that can influence an acceptance decision can be reviewed and tested here.
//!
//! Nothing is overridden here yet; [`AcceleratedBackend`](crate::AcceleratedBackend)
//! verifies with the reference kernels until the first override lands.
