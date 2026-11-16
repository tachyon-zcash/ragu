//! The independent private opening fold, with explicit public challenge inputs.

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Endoscalar, EndoscalarChallenge,
    io::Write,
    vec::{ConstLen, FixedVec},
};
use udon::field::Field;

use super::{
    batch::{Challenges, Queries},
    stages::{EvalStage, InputStage, InputsLen, PolynomialsLen, QueryStage, QueryWitness, Side},
};
use crate::profile::Profile;

/// Public values shared by the batch helper and the fuse's `compute_v` target.
#[derive(Clone, Debug)]
pub struct Instance<F> {
    /// The authenticated enclosing-step challenges. On the native side `beta`
    /// carries raw `pre_beta`; on the nested side it is the effective lift.
    pub challenges: Challenges<F>,
    /// The quotient and polynomial-evaluation sums, in that order.
    pub sums: [F; 2],
}

/// The helper's public output, before the extension's zero suffix.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>> {
    /// `w`, `y`, `x`, `alpha`, `u`, and the side's `beta` input, in order.
    #[ragu(gadget)]
    pub challenges: FixedVec<Element<'dr, D>, ConstLen<6>>,
    /// The quotient and evaluation sums.
    #[ragu(gadget)]
    pub sums: FixedVec<Element<'dr, D>, ConstLen<2>>,
}

/// The three committed stage witnesses and the authenticated challenge inputs.
pub struct Witness<'a, F: Field, P: Profile, S: Side> {
    /// Input values committed before `w`.
    pub inputs: &'a FixedVec<F, InputsLen<P, S>>,
    /// Opening points and claims committed before `alpha`.
    pub query: &'a QueryWitness<F, P, S>,
    /// One value at `u` per polynomial, committed before `pre_beta`.
    pub eval: &'a FixedVec<F, PolynomialsLen<P, S>>,
    /// Public challenge inputs fixed by the parent or terminal verifier.
    pub challenges: Challenges<F>,
}

/// Computes the two private-batch sums without loading the fuse preamble.
pub struct Circuit<P: Profile, S: Side>(PhantomData<(P, S)>);
impl<P: Profile, S: Side> Default for Circuit<P, S> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<F: Field, R: Rank, P: Profile, S: Side> MultiStageCircuit<F, R> for Circuit<P, S> {
    type Last = EvalStage<P, S>;
    type Instance<'source> = &'source Instance<F>;
    type Witness<'source> = Witness<'source, F, P, S>;
    type Output = Kind![F; Output<'_, _>];
    type Aux<'source> = [F; 2];

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let challenges = allocate_challenges(dr, instance.as_ref().map(|i| &i.challenges))?;
        let sums = FixedVec::try_from_fn(|j| {
            Element::alloc(dr, &mut (), instance.as_ref().map(|i| i.sums[j]))
        })?;
        Ok(Output { challenges, sums })
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (inputs, builder) = builder.add_stage::<InputStage<P, S>>()?;
        let (query, builder) = builder.add_stage::<QueryStage<P, S>>()?;
        let (eval, builder) = builder.add_stage::<EvalStage<P, S>>()?;
        let dr = builder.finish();
        let inputs = inputs.unenforced(dr, witness.as_ref().map(|w| w.inputs))?;
        let query = query.unenforced(dr, witness.as_ref().map(|w| w.query))?;
        let eval = eval.unenforced(dr, witness.as_ref().map(|w| w.eval))?;
        let public = allocate_challenges(dr, witness.as_ref().map(|w| &w.challenges))?;
        let beta = if S::NATIVE {
            let challenge = EndoscalarChallenge::from_element(dr, &mut (), public[5].clone())?;
            Endoscalar::extract(challenge).lift(dr)?
        } else {
            public[5].clone()
        };
        let challenges = Challenges {
            w: public[0].clone(),
            y: public[1].clone(),
            x: public[2].clone(),
            alpha: public[3].clone(),
            u: public[4].clone(),
            beta,
        };
        let query = Queries {
            inputs: inputs.to_vec(),
            points: query.points.to_vec(),
            values: query.values.to_vec(),
        };
        let (f, e) = S::layout::<P>().fold(dr, &query, &eval, &challenges)?;
        let sums = FixedVec::new(alloc::vec![f, e])?;
        let values = D::just(|| [*sums[0].value().take(), *sums[1].value().take()]);
        Ok(WithAux::new(
            Output {
                challenges: public,
                sums,
            },
            values,
        ))
    }
}

fn allocate_challenges<'dr, D: Driver<'dr>>(
    dr: &mut D,
    challenges: DriverValue<D, &Challenges<D::F>>,
) -> Result<FixedVec<Element<'dr, D>, ConstLen<6>>> {
    FixedVec::try_from_fn(|i| {
        Element::alloc(
            dr,
            &mut (),
            challenges
                .as_ref()
                .map(|c| [c.w, c.y, c.x, c.alpha, c.u, c.beta][i]),
        )
    })
}
