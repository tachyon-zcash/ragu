//! Challenge stage for nested fuse operations: the nested challenges as
//! scalar-field wires.
//!
//! The nested side squeezes nothing; every challenge it uses is the lift
//! ([`challenge`]) of a native one. This stage holds those lifts, one per
//! native challenge, then the base-case sign and the lift of `pre_beta`, at
//! the $a$-wire of consecutive gates with the $d$-wire zero, and is committed
//! **unblinded** (alpha zero). Its commitment is then a fixed linear
//! combination of the nested-curve generators,
//!
//! $$C_s = \sum_i \mathrm{lift}(\mathrm{ch}_i) \cdot G_{\mathrm{idx}(i)},$$
//!
//! with `idx` given by [`StageExt::generator_index_for_a`]. A native circuit
//! can recompute exactly that point from the transcript challenges by
//! endoscaling each generator by the challenge's bits, which is the only
//! statement about a scalar-field value a circuit-field circuit can make.
//! That recomputation is split between the proof's own `bind_challenges`
//! circuits, which cover the ten challenges squeezed before `pre_beta` and
//! the sign and export their sum through the unified instance, and the
//! parent's `bind_beta`, which adds `pre_beta`'s term and holds the result
//! against the commitment it walks: `pre_beta` is squeezed after the native
//! `eval` stage carrying the binders' partials is committed.
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

/// The native challenges this stage holds the lifts of before the sign and
/// $\beta$, in order: `w, y, z, mu, nu, mu_prime, nu_prime, x, alpha, u`.
pub const NUM: usize = 10;

/// The position of the lift of $w$.
pub const W: usize = 0;
/// The position of the lift of $y$.
pub const Y: usize = 1;
/// The position of the lift of $z$.
pub const Z: usize = 2;
/// The position of the lift of $\mu$.
pub const MU: usize = 3;
/// The position of the lift of $\nu$.
pub const NU: usize = 4;
/// The position of the lift of $\mu'$.
pub const MU_PRIME: usize = 5;
/// The position of the lift of $\nu'$.
pub const NU_PRIME: usize = 6;
/// The position of the lift of $x$.
pub const X: usize = 7;
/// The position of the lift of $\alpha$.
pub const ALPHA: usize = 8;
/// The position of the lift of $u$.
pub const U: usize = 9;
/// The position of the base-case sign.
pub const SIGN_INDEX: usize = NUM;
/// The position of the lift of `pre_beta`, $\beta$.
pub const BETA_INDEX: usize = NUM + 1;

/// Length type for the challenge lifts before the sign and $\beta$.
pub type Len = ConstLen<NUM>;

/// The lifts, in stage order, the base-case sign and the lift of `pre_beta`.
#[derive(Clone)]
pub struct Witness<F> {
    pub lifts: FixedVec<F, Len>,
    /// $+1$ when both children of this step are trivial proofs, $-1$
    /// otherwise: the native side's base-case verdict, carried as a sign so
    /// the last binding circuit can add or subtract one generator.
    pub base_case_sign: F,
    /// The lift of `pre_beta`.
    pub beta: F,
}

impl<F: PrimeField> Witness<F> {
    /// The lifts of the given native challenges, in stage order, the
    /// base-case sign and the lift of `pre_beta`.
    pub fn new(lifts: [F; NUM], is_base_case: bool, beta: F) -> Self {
        Self {
            lifts: FixedVec::new(lifts.into()).expect("NUM lifts"),
            base_case_sign: base_case_sign(is_base_case),
            beta,
        }
    }
}

/// The sign the stage carries for the given base-case verdict.
pub fn base_case_sign<F: PrimeField>(is_base_case: bool) -> F {
    if is_base_case { F::ONE } else { -F::ONE }
}

/// Prover-internal output gadget for this stage: each lift followed by the
/// zero that keeps the next lift at an $a$-wire, then the base-case sign and
/// $\beta$ with theirs.
///
/// This is stage communication data, not part of any circuit's public
/// instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub pairs: FixedVec<Pair<'dr, D>, Len>,
    #[ragu(gadget)]
    pub base_case: Pair<'dr, D>,
    #[ragu(gadget)]
    pub beta: Pair<'dr, D>,
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
        // One lift and one zero per challenge, then the base-case sign and
        // beta with theirs: every value at an a-wire.
        (NUM + 2) * 2
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
        let mut pair = |dr: &mut D, value: DriverValue<D, C::Base>| {
            Ok::<_, ragu_core::Error>(Pair {
                lift: Element::alloc(dr, allocator, value)?,
                zero: Element::alloc(dr, allocator, witness.as_ref().map(|_| C::Base::ZERO))?,
            })
        };
        let pairs = FixedVec::try_from_fn(|i| pair(dr, witness.as_ref().map(|w| w.lifts[i])))?;
        let base_case = pair(dr, witness.as_ref().map(|w| w.base_case_sign))?;
        let beta = pair(dr, witness.as_ref().map(|w| w.beta))?;
        Ok(Output {
            pairs,
            base_case,
            beta,
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
