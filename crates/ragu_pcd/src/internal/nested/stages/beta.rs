//! Beta stage for nested fuse operations: the nested $\beta$ as a
//! scalar-field wire.
//!
//! The lift of `pre_beta`, at the $a$-wire of one gate with the $d$-wire
//! zero, committed **unblinded** like the [`challenges`](super::challenges)
//! stage. `pre_beta` is squeezed only after the native `eval` stage is
//! committed, so its lift cannot ride with the other challenges; its binding
//! is checked by the parent instead (see the native `bind_beta` circuit),
//! which holds this proof's `pre_beta` and this stage's commitment. A nested
//! circuit consuming the endoscalar bits can also lift them and enforce
//! equality with this wire, which binds the bits through it.

use core::marker::PhantomData;

use ragu_arithmetic::{CurveAffine, ff::Field};
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, io::Write};

/// The lift of `pre_beta`.
#[derive(Clone, Copy)]
pub struct Witness<F> {
    pub lift: F,
}

/// Prover-internal output gadget for this stage: the lift and its trailing
/// zero.
///
/// This is stage communication data, not part of any circuit's public
/// instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub lift: Element<'dr, D>,
    #[ragu(gadget)]
    pub zero: Element<'dr, D>,
}

#[derive(Default)]
pub struct Stage<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = super::challenges::Stage<C, R>;
    type Witness<'source> = Witness<C::Base>;
    type OutputKind = Kind![C::Base; Output<'_, _>];

    fn values() -> usize {
        // The lift at an a-wire, and the zero that pads its gate.
        2
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let allocator = &mut ();
        Ok(Output {
            lift: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.lift))?,
            zero: Element::alloc(dr, allocator, witness.as_ref().map(|_| C::Base::ZERO))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<EqAffine, R>::default());
    }
}
