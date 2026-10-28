//! Additional generators reaching the aggregator rank, for its extensions and
//! for compression.

use lazy_static::lazy_static;
use udon::curve::{PallasAffine, VestaAffine};

use super::{AGGREGATOR_EP_K, AGGREGATOR_EQ_K, PastaParams, baked::generators};

bento::embed_array! {
    static PALLAS: [PallasAffine; (1 << AGGREGATOR_EP_K) + 2] =
        concat!(env!("OUT_DIR"), "/pallas-generators-aggregator-v1-", udon::stored_form!(), ".bin");
}
bento::embed_array! {
    static VESTA: [VestaAffine; (1 << AGGREGATOR_EQ_K) + 2] =
        concat!(env!("OUT_DIR"), "/vesta-generators-aggregator-v1-", udon::stored_form!(), ".bin");
}

lazy_static! {
    static ref PARAMETERS: PastaParams = PastaParams::new(generators(PALLAS), generators(VESTA));
}

/// Returns the optional larger parameters, which reach the aggregator rank.
///
/// Each curve has $2^{15}$ vector generators, the aggregator rank's (see
/// [`AggregatorRank`](ragu_circuits::polynomials::AggregatorRank)). Their
/// $2^{13}$-point prefix, blinding generator and IPA generator are the
/// Standard parameters' originals.
///
/// An application at the aggregator rank needs them, and so does any
/// application that compresses, whatever its profile: compression bridges a
/// proof's values at their positions in the decompression's stages at the
/// aggregator rank, past the end of the original tables.
///
/// Requires the `baked-aggregator` feature. Only calling this function loads
/// these larger tables; [`super::baked()`] always loads the original tables.
pub fn baked_aggregator() -> &'static PastaParams {
    &PARAMETERS
}
