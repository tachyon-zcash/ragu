//! The circuit registered in `compute_v`'s place when the opening program
//! runs in chunks.
//!
//! [`compute_v`](super::compute_v) recomputes $v$ and covers the unified
//! instance's $v$ slot. In a profile whose opening program runs in chunks
//! ([`Chunking`](crate::profile::Chunking)), the [`open`](super::open)
//! circuits recompute it between them, and this circuit does what is left
//! of `compute_v`:
//!
//! - It enforces the preamble's contracts, as `compute_v` does.
//! - It computes what the chunks share and holds the
//!   [`carry`](super::super::stages::open) stage to it: the effective
//!   $\beta$, extracted from `pre_beta` and lifted; $t(xz)$; and the second
//!   layer's interpolation weights at $\mu'$. It holds the stage's copies of
//!   the online helper's sums to the ones it exports.
//! - It takes $v$ from the program's state after the last chunk and
//!   provides it to the instance.
//! - It exports what `compute_v` exports for the profile's online batches.
//!   The values of the `query` and `eval` stages among them it reads from
//!   its own band, as the chunks read theirs.
//!
//! ## Staging
//!
//! The circuit ends on the band stage, after the binding stage (loaded as
//! `compute_v` loads it), the preamble and the carry stage.
//!
//! ## Instance
//!
//! `compute_v`'s: the unified instance followed by what the profile's
//! online batches export and the zero suffix ([`Output`]).

use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::{Rank, txz::Evaluate},
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Endoscalar, EndoscalarChallenge, GadgetExt, WithSuffix,
    allocator::Standard,
    vec::{FixedVec, Len},
};

use super::{
    super::{
        NumFoldGroups,
        open::{EvalValue, Input, QueryValue, Schedule},
        stages::{
            open::{BandStage, Carry, CarryStage},
            points::{BindingStage, BindingWitness},
            preamble as native_preamble,
        },
        unified::{self, OutputBuilder},
    },
    compute_v::Output,
};
use crate::{
    internal::revdot,
    profile::{
        Profile, ProfiledCycle,
        online::stages::{Native, Present},
    },
};

/// The circuit that stages what the chunks of an opening program share and
/// takes $v$ from the last.
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize> {
    schedule: Arc<Schedule>,
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Circuit<C, R, HEADER_SIZE> {
    /// Creates the circuit for the program `schedule` shares.
    pub fn new(schedule: Arc<Schedule>) -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            schedule,
            _marker: PhantomData,
        })
    }
}

/// Witness for the circuit.
pub struct Witness<'a, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> {
    /// The unified instance containing challenges and accumulated coverage.
    pub unified: unified::Instance<C>,
    /// Common sums supplied by the independent online helper.
    pub online_fold: FixedVec<C::CircuitField, Present<C::Profile, Native, 2>>,
    /// Holds the nested online input-stage commitment fixed before w.
    pub binding: &'a BindingWitness<C::NestedCurve, C::Profile>,
    /// Witness for the preamble stage.
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// The carry stage's values.
    pub carry: &'a [C::CircuitField],
    /// The values of the circuit's own band.
    pub band: &'a [C::CircuitField],
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> MultiStageCircuit<C::CircuitField, R>
    for Circuit<C, R, HEADER_SIZE>
{
    type Last = BandStage<C, R, HEADER_SIZE>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE>;
    type Output = Kind![C::CircuitField; WithSuffix<'_, _, Output<'_, _, C>>];
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        // The binding stage is loaded under the condition `compute_v`
        // loads it under.
        let (binding, builder) = if C::Profile::NESTED_ONLINE.is_empty() {
            (
                None,
                builder.skip_stage::<BindingStage<C::NestedCurve, C::Profile>>()?,
            )
        } else {
            let (binding, builder) =
                builder.add_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
            (Some(binding), builder)
        };
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (carry, builder) = builder.add_stage::<CarryStage<C, R, HEADER_SIZE>>()?;
        let (band, builder) = builder.add_stage::<BandStage<C, R, HEADER_SIZE>>()?;
        let dr = builder.finish();
        let binding = match binding {
            Some(binding) => Some(binding.unenforced(dr, witness.as_ref().map(|w| w.binding))?),
            None => None,
        };

        // The preamble is enforced here, as in `compute_v`: it holds child
        // proof data that must be validated.
        let preamble = preamble.enforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let carry = carry.unenforced(dr, witness.as_ref().map(|w| w.carry))?;
        let band = band.unenforced(dr, witness.as_ref().map(|w| w.band))?;
        let carry = Carry::<_, C::Profile>::new(&carry[..]);

        // The circuit's own band holds its copies of the two stages'
        // values, after the chunks' bands.
        let slots = self.schedule.slots(self.schedule.chunks());
        let copy = |input: Input| {
            band[*slots
                .get(&input)
                .expect("the circuit's band holds every value it exports")]
            .clone()
        };

        // Export deadline-bound copies of the online helper chain, as
        // `compute_v` does.
        let mut input_coordinates = Vec::new();
        if let Some(binding) = &binding {
            binding.online_input[0].write(dr, &mut input_coordinates)?;
        }
        let online_stages = FixedVec::from_fn(|i| match i {
            0 | 1 => input_coordinates[i].clone(),
            2 | 3 => copy(Input::Query(QueryValue::OnlineStage(i - 2))),
            _ => copy(Input::Eval(EvalValue::OnlineStage(i - 4))),
        });
        let online_auxiliaries =
            FixedVec::from_fn(|i| copy(Input::Query(QueryValue::OnlineAuxiliary(i))));

        let allocator = &mut Standard::new();
        let online_fold = FixedVec::<_, Present<C::Profile, Native, 2>>::try_from_fn(|i| {
            Element::alloc(dr, allocator, witness.as_ref().map(|w| w.online_fold[i]))
        })?;
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        // The effective beta the chunks weigh the evaluations with.
        let pre_beta = unified_output.pre_beta.read(dr, allocator)?;
        let pre_beta = EndoscalarChallenge::from_element(dr, allocator, pre_beta)?;
        let effective_beta = Endoscalar::extract(pre_beta).lift(dr)?;
        effective_beta.enforce_equal(dr, carry.beta())?;

        // t(xz), the vanishing polynomial evaluated at xz.
        let z = unified_output.z.read(dr, allocator)?;
        let x = unified_output.x.read(dr, allocator)?;
        let x = x.enforce_invertible(dr)?;
        let z = z.enforce_invertible(dr)?;
        let txz = dr.routine(Evaluate::<R>::new(), (x, z))?;
        txz.enforce_equal(dr, carry.txz())?;

        // The second layer's interpolation weights.
        let mu_prime = unified_output.mu_prime.read(dr, allocator)?;
        let outer = revdot::basis_weights(dr, &mu_prime, NumFoldGroups::<C::Profile>::len())?;
        for (computed, staged) in outer.iter().zip(carry.outer()) {
            computed.enforce_equal(dr, staged)?;
        }

        // The online helper's sums the chunks fold are the ones exported.
        for (exported, staged) in online_fold.iter().zip(carry.online_fold()) {
            exported.enforce_equal(dr, staged)?;
        }

        // v is where the program ends.
        unified_output
            .v
            .provide(carry.after(self.schedule.chunks() - 1).v);

        // The online batches' exports join the instance for the parent.
        let (unified, aux) = unified_output.finish_no_suffix(dr, allocator)?;
        let output = Output {
            unified,
            online_fold,
            online_stages,
            online_auxiliaries,
            inherited_coordinates: FixedVec::from_fn(|i| {
                [
                    &preamble.left.unified.x,
                    &preamble.left.unified.y,
                    &preamble.right.unified.x,
                    &preamble.right.unified.y,
                ][i]
                    .clone()
            }),
            inherited_points: FixedVec::from_fn(|i| {
                [&preamble.left, &preamble.right][i].online_points
                    [C::Profile::NESTED_MESH.expect("mesh present").outgoing]
                    .clone()
            }),
        };
        let zero = Element::zero(dr);
        Ok(WithAux::new(WithSuffix::new(output, zero), aux))
    }
}
