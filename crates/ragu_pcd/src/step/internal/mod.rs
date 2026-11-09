pub(crate) mod adapter;
pub(crate) mod bootstrap;
pub(crate) mod decompress;
pub(crate) mod padded;
pub(crate) mod rerandomize;

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, GadgetExt};

use super::{Oracles, Slot};
use crate::header::HEADER_POLYNOMIALS;

/// Opens each output slot at $\zeta$ and holds it to one: the padding an
/// internal step's output proof carries, which a prover cannot replace
/// with a polynomial of its choosing.
pub(crate) fn pin_output_slots<'dr, D: Driver<'dr>>(
    dr: &mut D,
    oracles: &mut Oracles<'_, 'dr, D>,
) -> Result<()> {
    let zeta = oracles.zeta().clone();
    for i in 0..HEADER_POLYNOMIALS {
        let value = oracles.query(dr, Slot::output(i), &zeta)?;
        value.enforce_equal(dr, &Element::one())?;
    }
    Ok(())
}
