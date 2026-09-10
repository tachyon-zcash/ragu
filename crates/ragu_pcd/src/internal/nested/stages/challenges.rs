//! Challenge stage for nested fuse operations: the nested challenges as
//! scalar-field wires.
//!
//! The nested side squeezes nothing; every challenge it uses is the lift
//! ([`challenge`]) of a native one. This stage holds those lifts, one per
//! native challenge, at the $a$-wire of consecutive gates with the $d$-wire
//! zero, and is committed **unblinded** (alpha zero). Its commitment is then
//! a fixed linear combination of the nested-curve generators,
//!
//! $$C_s = \sum_i \mathrm{lift}(\mathrm{ch}_i) \cdot G_{\mathrm{idx}(i)},$$
//!
//! with `idx` given by [`StageExt::generator_index_for_a`]. A native circuit
//! can recompute exactly that point from the transcript challenges by
//! endoscaling each generator by the challenge's bits, which is the only
//! statement about a scalar-field value a circuit-field circuit can make. That
//! recomputation, spread over the `bind_challenges` circuits, is what ties
//! the nested challenges to the transcript. The stage holds the ten
//! challenges squeezed before `pre_beta`, so that it is committed before the
//! native `eval` stage carries its commitment; $\beta$ has its own
//! [`beta`](super::beta) stage.
//!
//! [`challenge`]: crate::internal::nested::challenge
//! [`StageExt::generator_index_for_a`]: ragu_circuits::staging::StageExt::generator_index_for_a

use core::marker::PhantomData;

use ragu_arithmetic::{
    CurveAffine,
    ff::{Field, PrimeField},
};
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    io::Write,
    vec::{ConstLen, FixedVec},
};

/// The native challenges this stage holds the lifts of, in order: `w, y, z,
/// mu, nu, mu_prime, nu_prime, x, alpha, u`.
pub const NUM: usize = 10;

/// Length type for the challenge lifts.
pub type Len = ConstLen<NUM>;

/// The lifts, in stage order.
#[derive(Clone)]
pub struct Witness<F> {
    pub lifts: FixedVec<F, Len>,
}

impl<F: PrimeField> Witness<F> {
    /// The lifts of the given native challenges, in stage order.
    pub fn new(lifts: [F; NUM]) -> Self {
        Self {
            lifts: FixedVec::new(lifts.into()).expect("NUM lifts"),
        }
    }
}

/// Prover-internal output gadget for this stage: each lift followed by the
/// zero that keeps the next lift at an $a$-wire.
///
/// This is stage communication data, not part of any circuit's public
/// instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub pairs: FixedVec<Pair<'dr, D>, Len>,
}

/// One lift and its trailing zero.
#[derive(Gadget, Write)]
pub struct Pair<'dr, D: Driver<'dr>> {
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
    type Parent = super::eval::Stage<C, R>;
    type Witness<'source> = &'source Witness<C::Base>;
    type OutputKind = Kind![C::Base; Output<'_, _>];

    fn values() -> usize {
        // One lift and one zero per challenge: each lift at an a-wire.
        NUM * 2
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
        let pairs = FixedVec::try_from_fn(|i| {
            Ok(Pair {
                lift: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.lifts[i]))?,
                zero: Element::alloc(dr, allocator, witness.as_ref().map(|_| C::Base::ZERO))?,
            })
        })?;
        Ok(Output { pairs })
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
