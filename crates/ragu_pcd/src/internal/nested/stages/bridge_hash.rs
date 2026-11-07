//! Bridge-hash stage for nested fuse operations: the step's own second
//! online commitment, `O1`, alone in a stage whose commitment is its digest.
//!
//! The stage sits between the endoscalar stage, whose size the endoscalar
//! encoding fixes, and the points stage, so its gates do not move when the
//! walk or the preamble grows. It is committed unblinded under a
//! [canonical mask](ragu_circuits::staging::StageExt::canonical_mask), which
//! holds every wire but the point's two coordinates to zero: the stage
//! polynomial is then a function of the point, and so is its commitment,
//! $H^{bridge}(O_1) = x \cdot G_i + y \cdot G_j$ for two fixed generators.
//! The nested collapse circuit holds the point to the step's own `O1` in
//! the preamble, which $w$ absorbs, so the digest is fixed before $w$
//! without being absorbed itself. The unified instance carries it, the
//! parent binds it to the stage it folds, and the step's application
//! instance carries it too (see [`digest`]).

use core::marker::PhantomData;

use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
};
use ragu_primitives::{Point, io::Write};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use crate::internal::endoscalar::EndoscalarStage;

/// Prover-internal output gadget for this bridge stage.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    /// The step's own second online commitment.
    #[ragu(gadget)]
    pub o1: Point<'dr, D, C>,
}

#[derive(Default)]
pub struct Stage<C: Affine> {
    _marker: PhantomData<C>,
}

impl<C: Affine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C> {
    type Parent = EndoscalarStage;
    type Witness<'source> = C;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
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
        Ok(Output {
            o1: Point::alloc(dr, witness)?,
        })
    }
}

/// The stage polynomial of `o1`: unblinded, so that the canonical mask
/// accepts it and its commitment is [`digest`].
///
/// # Errors
///
/// Fails only if the stage does not fit the rank.
pub fn rx<C: Affine, R: Rank>(
    o1: C,
) -> Result<ragu_circuits::polynomials::sparse::Polynomial<C::Base, R>> {
    <Stage<C> as StageExt<C::Base, R>>::rx(C::Base::ZERO, o1)
}

/// $H^{bridge}(o_1)$, the commitment of the stage holding `o1`, under the
/// nested generators: what a step's application instance carries as
/// `h_O1`, and what an application computes outside the circuit, for
/// instance to recompute an anchor that hashes a polynomial commitment.
///
/// It depends on the rank, which fixes where the stage's wires sit, and
/// on the nested generators; backend `B` computes the commitment.
///
/// # Errors
///
/// Fails only if the stage does not fit the rank.
pub fn digest<B, C, N, R, G>(o1: C, generators: &G) -> Result<N>
where
    B: ragu_backend::Backend,
    C: Affine,
    N: udon::curve::Affine<Scalar = C::Base>,
    R: Rank,
    G: ragu_core::FixedGenerators<N>,
{
    Ok(B::sparse_commit_to_affine(&rx::<C, R>(o1)?, generators))
}
