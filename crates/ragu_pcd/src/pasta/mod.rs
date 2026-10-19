//! Ragu's fixed generators for the Pasta cycle.
//!
//! The `baked` feature derives generators at build time, using `pasta_curves`
//! only for hash-to-curve. Udon checks the resulting points, and Bento writes
//! and embeds their typed representations. `baked()` assembles Udon's parameter
//! containers once on first access. Generation and loading are owned here;
//! runtime arithmetic, cycle types, and Poseidon constants come from Udon.

pub use ragu_core::pasta::{Pasta, PastaParams};

/// Log2 of the number of Pallas generators: enough for the aggregator rank.
/// The vector generators are derived by index, so a proof at a lower rank
/// uses the same first generators it always did. The build script's
/// derivation carries its own copy of these counts; Bento checks the
/// artifact lengths against the consumer's array types at compile time.
pub const DEFAULT_EP_K: usize = 15;
/// Log2 of the number of Vesta generators.
pub const DEFAULT_EQ_K: usize = 15;

#[cfg(feature = "baked")]
mod baked;
#[cfg(feature = "baked")]
pub use baked::baked;

#[cfg(all(test, feature = "baked"))]
mod tests {
    use ragu_core::{Cycle, FixedGenerators};
    use udon::curve::Affine;

    use super::*;
    use crate::ipa::IpaCycle;

    #[test]
    fn baked_parameters_have_the_expected_shape() {
        let params = baked();
        let pallas = Pasta::nested_generators(params);
        let vesta = Pasta::host_generators(params);

        assert_eq!(pallas.g().len(), 1 << DEFAULT_EP_K);
        assert_eq!(vesta.g().len(), 1 << DEFAULT_EQ_K);

        // Hash-to-curve outputs: never the identity, and no two alike.
        assert!(!pallas.h().is_identity());
        assert!(!vesta.h().is_identity());
        assert!(pallas.g().iter().all(|point| !point.is_identity()));
        assert!(vesta.g().iter().all(|point| !point.is_identity()));
        assert!(!pallas.g().contains(pallas.h()));
        assert!(!vesta.g().contains(vesta.h()));
        assert_ne!(pallas.g()[0], pallas.g()[1]);
        assert_ne!(vesta.g()[0], vesta.g()[1]);

        // The IPA's generator: a further hash-to-curve output on each curve.
        let (pallas_u, vesta_u) = (Pasta::nested_u(params), Pasta::host_u(params));
        assert!(!pallas_u.is_identity());
        assert!(!vesta_u.is_identity());
        assert_ne!(pallas_u, pallas.h());
        assert_ne!(vesta_u, vesta.h());
        assert!(!pallas.g().contains(pallas_u));
        assert!(!vesta.g().contains(vesta_u));
    }
}
