//! Additional generators reaching rank 15, past the aggregator rank's, which
//! is the wallet's.

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

/// Returns the optional larger parameters, which reach rank 15.
///
/// Each curve has $2^{15}$ vector generators. Their $2^{14}$-point prefix,
/// blinding generator and IPA generator are the Standard parameters'
/// originals.
///
/// An application at rank 15 needs them. A Standard application does not,
/// compressing included, and neither does one at the aggregator rank (see
/// [`AggregatorRank`](ragu_circuits::polynomials::AggregatorRank)), which
/// is the wallet's.
///
/// Requires the `baked-aggregator` feature. Only calling this function loads
/// these larger tables; [`super::baked()`] always loads the original tables.
pub fn baked_aggregator() -> &'static PastaParams {
    &PARAMETERS
}
