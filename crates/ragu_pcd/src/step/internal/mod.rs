pub(crate) mod adapter;
pub(crate) mod bootstrap;
pub(crate) mod decompress;
pub(crate) mod padded;
pub(crate) mod rerandomize;

use ragu_core::{Cycle, Result, drivers::Driver};
use ragu_primitives::{Element, GadgetExt};

use super::{Oracles, Step};
use crate::{header::NUM_ONLINE_POLYNOMIALS, internal::online::Slot};

/// Opens each output slot at $\zeta$ and holds it to one: the padding an
/// internal step's output proof carries, which a prover cannot replace
/// with a polynomial of its choosing. The adapter pins every output slot
/// a step leaves unopened the same way; the internal steps pin by hand so
/// that their wiring does not depend on where the adapter does it.
pub(crate) fn pin_output_slots<'dr, D: Driver<'dr>, C: Cycle, S: Step<C>>(
    dr: &mut D,
    oracles: &mut Oracles<'_, 'dr, D, C, S>,
) -> Result<()> {
    let zeta = oracles.zeta().clone();
    for i in 0..NUM_ONLINE_POLYNOMIALS {
        let value = oracles.query(dr, Slot::output(i), &zeta)?;
        value.enforce_equal(dr, &Element::one())?;
    }
    Ok(())
}
