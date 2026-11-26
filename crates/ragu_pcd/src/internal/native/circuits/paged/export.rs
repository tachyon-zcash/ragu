//! The circuit that exposes the compute-v circuit's public output for a
//! profile with a native program.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt as _, WithSuffix, allocator::Standard, vec::FixedVec};

use super::{Batch, Challenges, Inputs, Stages, Witness, cells, effective_beta};
use crate::{
    internal::{
        native::{
            MemoryStage,
            circuits::compute_v::Output,
            stages::{
                eval as native_eval,
                points::{BindingStage, BindingWitness},
                preamble as native_preamble, query as native_query,
            },
            unified::{self, OutputBuilder},
        },
        program::{Memory, Program as _},
    },
    profile::{Profile, ProfiledCycle},
};

/// Circuit in the compute-v circuit's place for a profile with a native
/// program: it exposes that circuit's public output ([`Output`]).
///
/// - It reads the challenges off the unified instance, derives $\beta$
///   from `pre_beta`, and stores them in the memory for the steps
///   ([`Step::Challenges`](super::Step::Challenges)).
/// - It provides the instance's $v$ from the cell the last
///   [`Evaluations`](super::Step::Evaluations) page stored.
/// - It enforces the `preamble` stage's contracts, as the compute-v
///   circuit does for every circuit that loads the stage.
/// - It exposes the online helper's two sums from the cells the prover
///   supplied to the steps that add them, and the other online exports
///   from the stages, which it loads.
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Circuit<C, R, HEADER_SIZE> {
    pub fn new() -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Witness of the export circuit: the unified instance, the binding
/// stage's and a step circuit's.
pub struct ExportWitness<'a, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> {
    pub unified: unified::Instance<C>,
    pub binding: &'a BindingWitness<C::NestedCurve, C::Profile>,
    pub stages: Witness<'a, C, R, HEADER_SIZE>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> MultiStageCircuit<C::CircuitField, R>
    for Circuit<C, R, HEADER_SIZE>
{
    type Last = native_eval::Stage<C, R, HEADER_SIZE>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = ExportWitness<'source, C, R, HEADER_SIZE>;
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
        type Binding<C, P> = BindingStage<C, P>;
        let (binding, builder) = if C::Profile::NESTED_ONLINE.is_empty() {
            (
                None,
                builder.skip_stage::<Binding<C::NestedCurve, C::Profile>>()?,
            )
        } else {
            let (binding, builder) = builder.add_stage::<Binding<C::NestedCurve, C::Profile>>()?;
            (Some(binding), builder)
        };
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (memory, builder) = builder.add_stage::<MemoryStage<C, R, HEADER_SIZE>>()?;
        let (query, builder) = builder.add_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
        let (eval, builder) = builder.add_stage::<native_eval::Stage<C, R, HEADER_SIZE>>()?;
        let dr = builder.finish();
        let binding = match binding {
            Some(binding) => Some(binding.unenforced(dr, witness.as_ref().map(|w| w.binding))?),
            None => None,
        };
        let stage = witness.as_ref().map(|w| w.stages);

        // Preamble is enforced because it contains child proof data that must
        // be validated (Points, Booleans, etc.).
        let preamble = preamble.enforced(dr, stage.as_ref().map(|w| w.preamble_witness))?;
        let memory = memory.unenforced(dr, stage.as_ref().map(|w| w.memory))?;
        let query = query.unenforced(dr, stage.as_ref().map(|w| w.query_witness))?;
        let eval = eval.unenforced(dr, stage.as_ref().map(|w| w.eval_witness))?;

        // Export deadline-bound copies of the online helper chain, as the
        // compute-v circuit does.
        let mut input_coordinates = Vec::new();
        if let Some(binding) = &binding {
            binding.online_input[0].write(dr, &mut input_coordinates)?;
        }
        let online_stages = FixedVec::from_fn(|i| match i {
            0 | 1 => input_coordinates[i].clone(),
            2 | 3 => query.online_stage[i - 2].clone(),
            _ => eval.online_stage[i - 4].clone(),
        });
        let online_auxiliaries = query.online_auxiliaries.clone();
        let stages = Stages {
            preamble,
            query: Some(query),
            eval: Some(eval),
        };
        let preamble = &stages.preamble;

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        // The challenges, off the unified instance, in the order the
        // compute-v circuit reads them: `pre_beta` first, whose Boolean
        // gates donate their spare wires to the reads that follow.
        let pre_beta = unified_output.pre_beta.read(dr, allocator)?;
        let beta = effective_beta(dr, allocator, pre_beta)?;
        let challenges = Challenges {
            w: unified_output.w.read(dr, allocator)?,
            y: unified_output.y.read(dr, allocator)?,
            z: unified_output.z.read(dr, allocator)?,
            x: unified_output.x.read(dr, allocator)?,
            mu: unified_output.mu.read(dr, allocator)?,
            mu_prime: unified_output.mu_prime.read(dr, allocator)?,
            alpha: unified_output.alpha.read(dr, allocator)?,
            u: unified_output.u.read(dr, allocator)?,
            beta,
        };

        // The program's first step: the challenges into the memory.
        let cells = cells::<C::Profile>();
        let inputs = Inputs {
            stages: &stages,
            memory: Memory::loaded(&memory),
            challenges: Some(&challenges),
            online_fold: stage.as_ref().map(|w| w.online_fold),
        };
        Batch::<C, R, HEADER_SIZE>::new().step(0, dr, &inputs)?;

        // v, as the last page of the evaluations stored it, and the online
        // helper's sums, as the steps that add them took them.
        let v = inputs.memory.load_element(
            dr,
            *cells
                .evaluations
                .last()
                .expect("the evaluations have a page"),
        )?;
        unified_output.v.provide(v);
        let online_fold =
            FixedVec::try_from_fn(|i| inputs.memory.load_element(dr, cells.online_fold[i]))?;

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
