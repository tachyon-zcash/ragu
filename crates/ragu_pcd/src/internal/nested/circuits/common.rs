//! What the nested internal circuits share: the witness of every stage a
//! fuse step commits, and the loading of all of them.
//!
//! The nested stages form one chain, from the endoscalar stage to the
//! challenge stage. The [`collapse`](super::collapse) and
//! [`compute_v`](super::compute_v) circuits both end on its last stage,
//! so each reserves the whole chain and
//! loads it here. Every stage is loaded unenforced: output contracts are not
//! emitted here, though each wire still holds a coefficient of its committed
//! stage polynomial. The collapse circuit enforces curve membership of the
//! points stage and the hoisted endoscalar stage's contract, boolean bits
//! with product wires the products of those bits, once for all consuming
//! circuits.

use ragu_circuits::{polynomials::Rank, staging::StageBuilder};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{HoistedEndoscalar, Uendo, vec::FixedVec};
use udon::curve::EndomorphismAffine as Affine;

use crate::{
    internal::{
        endoscalar::EndoscalarStage,
        nested::{LinksStage, Points, PointsStage, WalkWitness, stages, unified},
    },
    profile::{
        Profile,
        online::stages::{Nested, Present},
    },
};

/// The witnesses of every stage a nested circuit reserves, and the nested
/// unified instance the circuit outputs.
pub struct Witness<'a, C: Affine, P: Profile> {
    pub instance: unified::Instance<C>,
    /// The online helper's two sums, exported by compute-v to the same targets.
    pub online_fold: FixedVec<C::Base, Present<P, Nested, 2>>,
    pub endoscalar: Uendo,
    pub bridge_hash: C,
    pub walk: &'a WalkWitness<C, P>,
    pub preamble: &'a stages::preamble::Witness<C, P>,
    pub s_prime: &'a stages::s_prime::Witness<C, P>,
    pub inner_error: &'a stages::inner_error::Witness<C, P>,
    pub outer_error: &'a stages::outer_error::Witness<C, P>,
    pub ab: &'a stages::ab::Witness<C, P>,
    pub query: &'a stages::query::Witness<C, P>,
    pub f: &'a stages::f::Witness<C>,
    pub eval: &'a stages::eval::Witness<C, P>,
    pub challenges: &'a stages::challenges::Witness<C::Base>,
}

/// The output gadgets of the stages a circuit reads, once loaded.
pub struct Loaded<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    pub endoscalar: HoistedEndoscalar<'dr, D>,
    pub bridge_hash: stages::bridge_hash::Output<'dr, D, C>,
    pub points: Points<'dr, D, C, P>,
    pub preamble: stages::preamble::Output<'dr, D, C, P>,
    pub s_prime: stages::s_prime::Output<'dr, D, C, P>,
    pub inner_error: stages::inner_error::Output<'dr, D, C, P>,
    pub outer_error: stages::outer_error::Output<'dr, D, C, P>,
    pub ab: stages::ab::Output<'dr, D, C, P>,
    pub query: stages::query::Output<'dr, D, C, P>,
    pub f: stages::f::Output<'dr, D, C>,
    pub eval: stages::eval::Output<'dr, D, C, P>,
    pub challenges: stages::challenges::Output<'dr, D>,
}

/// Reserves the whole stage chain and loads every stage, unenforced.
///
/// The chain is the layout of a profile whose walk is in one points stage,
/// and whose links stage is then empty. A profile that cuts its walk into
/// groups lays its stages side by side and loads them with
/// [`paged`](super::paged).
pub fn load_all<'a, 'dr, 'source: 'dr, D, C, R, P>(
    dr: StageBuilder<'a, 'dr, D, R, (), stages::challenges::Stage<C, R, P>>,
    witness: &DriverValue<D, Witness<'source, C, P>>,
) -> Result<(&'a mut D, Loaded<'dr, D, C, P>)>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    R: Rank,
    P: Profile,
{
    let (endoscalar, dr) = dr.add_stage::<EndoscalarStage>()?;
    let (bridge_hash, dr) = dr.add_stage::<stages::bridge_hash::Stage<C>>()?;
    let (points, dr) = dr.add_stage::<PointsStage<C, P>>()?;
    // The links stage of a walk in one points stage holds nothing.
    let dr = dr.skip_stage::<LinksStage<C, P>>()?;
    let (preamble, dr) = dr.add_stage::<stages::preamble::Stage<C, R, P>>()?;
    let (s_prime, dr) = dr.add_stage::<stages::s_prime::Stage<C, R, P>>()?;
    let (inner_error, dr) = dr.add_stage::<stages::inner_error::Stage<C, R, P>>()?;
    let (outer_error, dr) = dr.add_stage::<stages::outer_error::Stage<C, R, P>>()?;
    let (ab, dr) = dr.add_stage::<stages::ab::Stage<C, R, P>>()?;
    let (query, dr) = dr.add_stage::<stages::query::Stage<C, R, P>>()?;
    let (f, dr) = dr.add_stage::<stages::f::Stage<C, R, P>>()?;
    let (eval, dr) = dr.add_stage::<stages::eval::Stage<C, R, P>>()?;
    let (challenges, dr) = dr.add_stage::<stages::challenges::Stage<C, R, P>>()?;
    let dr = dr.finish();

    let loaded = Loaded {
        endoscalar: endoscalar.unenforced(dr, witness.as_ref().map(|w| w.endoscalar))?,
        bridge_hash: bridge_hash.unenforced(dr, witness.as_ref().map(|w| w.bridge_hash))?,
        points: points.unenforced(dr, witness.as_ref().map(|w| &w.walk.groups[0]))?,
        preamble: preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble))?,
        s_prime: s_prime.unenforced(dr, witness.as_ref().map(|w| w.s_prime))?,
        inner_error: inner_error.unenforced(dr, witness.as_ref().map(|w| w.inner_error))?,
        outer_error: outer_error.unenforced(dr, witness.as_ref().map(|w| w.outer_error))?,
        ab: ab.unenforced(dr, witness.as_ref().map(|w| w.ab))?,
        query: query.unenforced(dr, witness.as_ref().map(|w| w.query))?,
        f: f.unenforced(dr, witness.as_ref().map(|w| w.f))?,
        eval: eval.unenforced(dr, witness.as_ref().map(|w| w.eval))?,
        challenges: challenges.unenforced(dr, witness.as_ref().map(|w| w.challenges))?,
    };
    Ok((dr, loaded))
}
