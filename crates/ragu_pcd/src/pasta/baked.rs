//! Embeds Udon affine points and binds them to the Pasta parameter containers.

use alloc::vec::Vec;

use lazy_static::lazy_static;
use ragu_core::Cycle;
use udon::{
    curve::{
        AffineAdapter, AffinePoint, Pallas, PallasAffine, PastaCurve, Point, Vesta, VestaAffine,
    },
    cycle::{Generators, Pasta},
};

use super::{DEFAULT_EP_K, DEFAULT_EQ_K, PastaParams};
use crate::ipa::IpaCycle;

bento::embed_array! {
    static PALLAS: [PallasAffine; (1 << DEFAULT_EP_K) + 2] =
        concat!(env!("OUT_DIR"), "/pallas-generators-v1-", udon::stored_form!(), ".bin");
}
bento::embed_array! {
    static VESTA: [VestaAffine; (1 << DEFAULT_EQ_K) + 2] =
        concat!(env!("OUT_DIR"), "/vesta-generators-v1-", udon::stored_form!(), ".bin");
}

/// The artifact's points as the vector generators and the blinding
/// generator, leaving the IPA's generator to [`ipa_generator`].
pub(super) fn generators<C: PastaCurve>(points: &'static [AffinePoint<C>]) -> Generators<C> {
    let (_, points) = points
        .split_last()
        .expect("the artifact includes the IPA's generator");
    let (h, g) = points
        .split_last()
        .expect("the artifact includes a blinding generator");
    // Udon's parameter containers take identity-capable Point slices. Adapt
    // the embedded nonidentity points once, without coordinate decoding or
    // another curve-validation pass.
    let g: Vec<_> = g.iter().map(AffinePoint::to_point).collect();
    Generators::new(g.leak(), h.to_point())
}

/// The artifact's last point, the IPA's generator, as Udon's identity-capable
/// point.
fn ipa_generator<C: PastaCurve>(points: &'static [AffinePoint<C>]) -> Point<C> {
    points
        .last()
        .expect("the artifact includes the IPA's generator")
        .to_point()
}

lazy_static! {
    static ref PASTA_PARAMETERS: PastaParams =
        PastaParams::new(generators(PALLAS), generators(VESTA));
    static ref PALLAS_U: Point<Pallas> = ipa_generator(PALLAS);
    static ref VESTA_U: Point<Vesta> = ipa_generator(VESTA);
}

/// The IPA's generators are bound to the baked artifact, the only parameters
/// this crate provides.
impl IpaCycle for Pasta {
    fn host_u(_: &PastaParams) -> &<Pasta as Cycle>::HostCurve {
        AffineAdapter::from_ref(&VESTA_U)
    }

    fn nested_u(_: &PastaParams) -> &<Pasta as Cycle>::NestedCurve {
        AffineAdapter::from_ref(&PALLAS_U)
    }
}

/// Returns Ragu's fixed generators bound to Udon's Pasta cycle.
///
/// The embedded points require no decoding. Parameter slices are assembled
/// once and retained for the lifetime of the program.
///
/// These tables stop at the Standard rank, short of the positions
/// compression bridges a proof's values at: an application that compresses
/// needs `baked_aggregator()`, under the `baked-aggregator` feature.
pub fn baked() -> &'static PastaParams {
    &PASTA_PARAMETERS
}
