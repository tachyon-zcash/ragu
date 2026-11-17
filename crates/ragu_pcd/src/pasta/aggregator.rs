//! Additional generators for Aggregator extensions above the Standard rank.

use lazy_static::lazy_static;
use udon::curve::{PallasAffine, VestaAffine};

use crate::pasta::{AGGREGATOR_EP_K, AGGREGATOR_EQ_K, PastaParams, baked::generators};

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

/// Returns the optional larger parameters for Aggregator extensions.
///
/// Each curve has $2^{14}$ vector generators, supporting `R<14>` extension
/// tests. Their $2^{13}$-point prefix, blinding generator and IPA generator
/// are the Standard parameters' originals. This capacity does not fix the
/// production Aggregator rank before its decompression circuits land.
///
/// Requires the `baked-aggregator` feature. Only calling this function loads
/// these larger tables; [`crate::pasta::baked()`] always loads the original tables.
pub fn baked_aggregator() -> &'static PastaParams {
    &PARAMETERS
}
