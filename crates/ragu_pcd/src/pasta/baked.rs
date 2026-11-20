//! Embeds Udon affine points and binds them to the Pasta parameter containers.

use alloc::vec::Vec;

use lazy_static::lazy_static;
use ragu_circuits::polynomials::{AggregatorRank, Rank};
use ragu_core::{Cycle, FixedGenerators};
use udon::{
    curve::{
        AffineAdapter, AffinePoint, Pallas, PallasAffine, PastaCurve, Point, Vesta, VestaAffine,
    },
    cycle::{Generators, Pasta},
};

use super::{DEFAULT_EP_K, DEFAULT_EQ_K, PastaParams, STAGE_REACH};
use crate::ipa::IpaCycle;

bento::embed_array! {
    static PALLAS: [PallasAffine; (1 << DEFAULT_EP_K) + 2] =
        concat!(env!("OUT_DIR"), "/pallas-generators-v1-", udon::stored_form!(), ".bin");
}
bento::embed_array! {
    static VESTA: [VestaAffine; (1 << DEFAULT_EQ_K) + 2] =
        concat!(env!("OUT_DIR"), "/vesta-generators-v1-", udon::stored_form!(), ".bin");
}
bento::embed_array! {
    static PALLAS_STAGES: [PallasAffine; 2 * STAGE_REACH] =
        concat!(env!("OUT_DIR"), "/pallas-generators-stages-v1-", udon::stored_form!(), ".bin");
}

/// The aggregator rank's $n$: a stage trace at that rank lands the even
/// wire of gate $g$ at degree $2n - 1 - g$ and the odd at $4n - 1 - g$.
const STAGE_N: usize = 1 << (AggregatorRank::RANK - 2);

/// The nested generator at `index` among the stage reach's: the artifact
/// holds the even wires' of the first [`STAGE_REACH`] gates after the
/// SYSTEM gate, then the odd wires', each range in ascending index.
fn stage_generator(index: usize) -> Option<Point<Pallas>> {
    let even = 2 * STAGE_N - 1 - STAGE_REACH..2 * STAGE_N - 1;
    let odd = 4 * STAGE_N - 1 - STAGE_REACH..4 * STAGE_N - 1;
    let position = if even.contains(&index) {
        index - even.start
    } else if odd.contains(&index) {
        STAGE_REACH + index - odd.start
    } else {
        return None;
    };
    Some(PALLAS_STAGES[position].to_point())
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

    /// The table's generator where it reaches, and past it the stage
    /// reach's, which the aggregator table holds too: a Standard application
    /// compresses over `baked()` and its aggregator decompresses over
    /// `baked_aggregator()`, at the same generators.
    fn nested_generator(
        params: &PastaParams,
        index: usize,
    ) -> Option<<Pasta as Cycle>::NestedCurve> {
        if let Some(generator) = Pasta::nested_generators(params).g().get(index) {
            return Some(*generator);
        }
        stage_generator(index).map(|point| *AffineAdapter::from_ref(&point))
    }
}

/// Returns Ragu's fixed generators bound to Udon's Pasta cycle.
///
/// The embedded points require no decoding. Parameter slices are assembled
/// once and retained for the lifetime of the program.
pub fn baked() -> &'static PastaParams {
    &PASTA_PARAMETERS
}
