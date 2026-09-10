//! What the nested internal circuits share: the witness of every stage a
//! fuse step commits, and the loading of all of them.
//!
//! The nested stages form one chain, from the endoscalar stage to the beta
//! stage, and the [`export`](super::export), [`collapse`](super::collapse)
//! and [`compute_v`](super::compute_v) circuits all end on its last stage,
//! so each reserves the whole chain and loads it here. Every stage is loaded
//! unenforced: these circuits relate wires, and the contracts the walk
//! rests on, curve membership of the points stage and booleanity of the
//! endoscalar stage, are emitted once, by the export circuit.

use ragu_arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging::StageBuilder};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::Endoscalar;

use crate::internal::{
    endoscalar::{EndoscalarStage, Points, PointsStage, PointsWitness},
    nested::{NUM_ENDOSCALING_POINTS, stages, unified},
};

/// The witnesses of every stage a nested circuit reserves, and the nested
/// unified instance the circuit outputs.
pub struct Witness<'a, C: CurveAffine> {
    pub instance: unified::Instance<C>,
    pub endoscalar: u128,
    pub points: &'a PointsWitness<C, NUM_ENDOSCALING_POINTS>,
    pub preamble: &'a stages::preamble::Witness<C>,
    pub s_prime: &'a stages::s_prime::Witness<C>,
    pub inner_error: &'a stages::inner_error::Witness<C>,
    pub outer_error: &'a stages::outer_error::Witness<C>,
    pub ab: &'a stages::ab::Witness<C>,
    pub query: &'a stages::query::Witness<C>,
    pub f: &'a stages::f::Witness<C>,
    pub eval: &'a stages::eval::Witness<C>,
    pub challenges: &'a stages::challenges::Witness<C::Base>,
    pub beta: stages::beta::Witness<C::Base>,
}

/// The output gadgets of the stages a circuit reads, once loaded. The
/// `s_prime` and `f` bridge stages hold nothing a circuit here reads and
/// are loaded and dropped.
pub struct Loaded<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    pub endoscalar: Endoscalar<'dr, D>,
    pub points: Points<'dr, D, C, NUM_ENDOSCALING_POINTS>,
    pub preamble: stages::preamble::Output<'dr, D, C>,
    pub inner_error: stages::inner_error::Output<'dr, D, C>,
    pub outer_error: stages::outer_error::Output<'dr, D, C>,
    pub ab: stages::ab::Output<'dr, D, C>,
    pub query: stages::query::Output<'dr, D, C>,
    pub eval: stages::eval::Output<'dr, D, C>,
    pub challenges: stages::challenges::Output<'dr, D>,
    pub beta: stages::beta::Output<'dr, D>,
}

/// Reserves the whole stage chain and loads every stage, unenforced.
pub fn load_all<'a, 'dr, 'source: 'dr, D, C, R>(
    dr: StageBuilder<'a, 'dr, D, R, (), stages::beta::Stage<C, R>>,
    witness: &DriverValue<D, Witness<'source, C>>,
) -> Result<(&'a mut D, Loaded<'dr, D, C>)>
where
    D: Driver<'dr, F = C::Base>,
    C: CurveAffine,
    R: Rank,
{
    let (endoscalar, dr) = dr.add_stage::<EndoscalarStage>()?;
    let (points, dr) = dr.add_stage::<PointsStage<C, NUM_ENDOSCALING_POINTS>>()?;
    let (preamble, dr) = dr.add_stage::<stages::preamble::Stage<C, R>>()?;
    let (s_prime, dr) = dr.add_stage::<stages::s_prime::Stage<C, R>>()?;
    let (inner_error, dr) = dr.add_stage::<stages::inner_error::Stage<C, R>>()?;
    let (outer_error, dr) = dr.add_stage::<stages::outer_error::Stage<C, R>>()?;
    let (ab, dr) = dr.add_stage::<stages::ab::Stage<C, R>>()?;
    let (query, dr) = dr.add_stage::<stages::query::Stage<C, R>>()?;
    let (f, dr) = dr.add_stage::<stages::f::Stage<C, R>>()?;
    let (eval, dr) = dr.add_stage::<stages::eval::Stage<C, R>>()?;
    let (challenges, dr) = dr.add_stage::<stages::challenges::Stage<C, R>>()?;
    let (beta, dr) = dr.add_stage::<stages::beta::Stage<C, R>>()?;
    let dr = dr.finish();

    let loaded = Loaded {
        endoscalar: endoscalar.unenforced(dr, witness.as_ref().map(|w| w.endoscalar))?,
        points: points.unenforced(dr, witness.as_ref().map(|w| w.points))?,
        preamble: preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble))?,
        inner_error: inner_error.unenforced(dr, witness.as_ref().map(|w| w.inner_error))?,
        outer_error: outer_error.unenforced(dr, witness.as_ref().map(|w| w.outer_error))?,
        ab: ab.unenforced(dr, witness.as_ref().map(|w| w.ab))?,
        query: query.unenforced(dr, witness.as_ref().map(|w| w.query))?,
        eval: eval.unenforced(dr, witness.as_ref().map(|w| w.eval))?,
        challenges: challenges.unenforced(dr, witness.as_ref().map(|w| w.challenges))?,
        beta: beta.unenforced(dr, witness.as_ref().map(|w| w.beta))?,
    };
    let _ = s_prime.unenforced(dr, witness.as_ref().map(|w| w.s_prime))?;
    let _ = f.unenforced(dr, witness.as_ref().map(|w| w.f))?;
    Ok((dr, loaded))
}
