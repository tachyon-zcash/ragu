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
//! endoscaling each generator by the challenge's bits.
//! That recomputation is split between the proof's own `bind_challenges`
//! circuits, which cover the challenges squeezed before `pre_beta` and
//! the sign and export their sum through the unified instance, and the
//! parent's `bind_beta`, which adds `pre_beta`'s term and holds the result
//! against the commitment it walks: `pre_beta` is squeezed after the native
//! `eval` stage carrying the binders' partials is committed.
//!
//! ## Binding
//!
//! The nested circuits load this stage unenforced, and none of them derives
//! its contents: the nested side sees neither the transcript nor the headers.
//! The polynomial a step's nested claims are checked against is fixed from
//! the native side, by the step's parent.
//!
//! - The commitment the parent walks for the stage is the recomputed point.
//!   `bind_beta` enforces the two equal on the [`BindingStage`]'s copy, and
//!   the sign in that point is the one the step's last `bind_challenges`
//!   circuit derived from the step's input headers.
//! - The parent's endoscaling steps fold that same copy into its $P_n$, the
//!   commitment its nested batch opens. The batch opens the stage polynomial
//!   at the parent's $x_n z_n$, with the step's other rx polynomials
//!   ([`Batch::queries`]).
//! - The parent's nested `compute_v` adds the opened evaluation to each of
//!   the step's export, collapse and compute-v claims, and holds the fold of
//!   its children's claims against its own $A_n(x_n z_n)$.
//!
//! The stage is unblinded and the commitment scheme is binding, so the only
//! polynomial that opens the walked point holds the transcript's lifts and
//! the header-derived sign. A step whose prover traced its nested circuits
//! against a different sign or lift fails those claims in its parent's fold.
//! The root has no parent: the decider rederives the root's stage polynomial
//! from its headers and challenges, and compares coefficients.
//!
//! [`challenge`]: crate::internal::nested::challenge
//! [`StageExt::generator_index_for_a`]: ragu_circuits::staging::StageExt::generator_index_for_a
//! [`BindingStage`]: crate::internal::native::stages::points::BindingStage
//! [`Batch::queries`]: crate::internal::nested::pcs::Batch::queries

use core::marker::PhantomData;

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
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use crate::profile::Profile;

/// The native challenges this stage holds the lifts of before the sign and
/// $\beta$, in order: `w, y, z, mu, mu_prime, x, alpha, u`.
pub const NUM: usize = 8;

/// The position of the lift of $w$.
pub const W: usize = 0;
/// The position of the lift of $y$.
pub const Y: usize = 1;
/// The position of the lift of $z$.
pub const Z: usize = 2;
/// The position of the lift of $\mu$.
pub const MU: usize = 3;
/// The position of the lift of $\mu'$.
pub const MU_PRIME: usize = MU + 1;
/// The position of the lift of $x$.
pub const X: usize = MU_PRIME + 1;
/// The position of the lift of $\alpha$.
pub const ALPHA: usize = X + 1;
/// The position of the lift of $u$.
pub const U: usize = ALPHA + 1;
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
    /// $+1$ when this step declares the internal `Dummy` header for both inputs, $-1$
    /// otherwise: the native side's base-case verdict, carried as a sign so
    /// the last binding circuit can add or subtract one generator.
    pub base_case_sign: F,
    /// The lift of `pre_beta`.
    pub beta: F,
}

impl<F: Field> Witness<F> {
    /// Creates the witness from the lifts and the children's native output
    /// headers. The sign mirrors the native preamble's base-case predicate;
    /// the last native binding circuit derives that predicate independently
    /// from its header wires. The beta lift is filled once `pre_beta` is known.
    pub fn new<N: Field, const HEADER_SIZE: usize>(
        lifts: [F; NUM],
        left_header: &[N],
        right_header: &[N],
        beta: F,
    ) -> Self {
        let dummy_suffix =
            N::from(<crate::header::Dummy as crate::header::Header<N>>::SUFFIX.get());
        let is_dummy =
            |header: &[N]| header.len() == HEADER_SIZE && header.last() == Some(&dummy_suffix);
        Self {
            lifts: FixedVec::new(lifts.into()).expect("NUM lifts"),
            base_case_sign: if is_dummy(left_header) && is_dummy(right_header) {
                F::ONE
            } else {
                -F::ONE
            },
            beta,
        }
    }
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
pub struct Stage<C: Affine, R, P> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R, P> {
    type Parent = super::eval::Stage<C, R, P>;
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
    use alloc::vec::Vec;

    use ragu_circuits::{
        polynomials::ProductionRank,
        staging::{StageExt, StageReader, stage_wire_indices, wires_of},
    };
    use ragu_core::pasta::EqAffine;

    use super::*;
    use crate::{
        internal::tests::{R, assert_stage_values},
        profile::Standard,
    };

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<EqAffine, R, Standard>::default());
    }

    /// The challenge stage's lifts read back off its rx polynomial are the
    /// lifts it was built from, at the indices its gadget names.
    #[test]
    fn stage_values_read_back() -> Result<()> {
        type R = ProductionRank;
        type F = ragu_core::pasta::Fq;
        let lifts: [F; NUM] = core::array::from_fn(|i| F::from(3 + i as u64));
        let beta = F::from(99);
        let header = [ragu_core::pasta::Fp::from(crate::header::Suffix::new(0).get()); 4];
        let witness = Witness::new::<_, 4>(lifts, &header, &header, beta);
        let rx = <Stage<EqAffine, R, Standard> as StageExt<F, R>>::rx(F::from(11), &witness)?;
        let reader = StageReader::<F, R>::new(&rx);

        let indices = stage_wire_indices::<F, R, Stage<EqAffine, R, Standard>>(|out| {
            let mut wires = Vec::new();
            for pair in out.pairs.iter() {
                wires.extend(wires_of(&pair.lift)?);
            }
            wires.extend(wires_of(&out.base_case.lift)?);
            wires.extend(wires_of(&out.beta.lift)?);
            Ok(wires)
        })?;
        for (i, lift) in lifts.iter().enumerate() {
            assert_eq!(reader.read(indices[i]), *lift, "lift {i}");
        }
        assert_eq!(reader.read(indices[SIGN_INDEX]), -F::ONE);
        assert_eq!(reader.read(indices[BETA_INDEX]), beta);
        Ok(())
    }
}
