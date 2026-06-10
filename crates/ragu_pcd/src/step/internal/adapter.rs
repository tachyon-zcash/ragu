use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_arithmetic::{Coeff, Cycle};
use ragu_circuits::{Circuit, WithAux, polynomials::Rank, staging::InducedStages};
use ragu_core::{
    Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, Kind},
    maybe::{Empty, Maybe},
};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use super::super::{Step, StepCtx};
use crate::{
    Header,
    framework_hooks::{FrameworkHookOutputs, FrameworkHooks},
};

/// Represents triple a length determined at compile time.
pub struct TripleConstLen<const N: usize>;

impl<const N: usize> Len for TripleConstLen<N> {
    fn len() -> usize {
        N * 3
    }
}

/// Discovers the induced stage layout of `step` by dry-running its witness
/// body once, with an [`Empty`] witness on a counting emulator and the hooks
/// in discovery mode.
///
/// Each [`derive_challenge`](StepCtx::derive_challenge) call records its
/// gadget's wire width; the widths in call order *are* the layout. This is
/// sound because circuit structure must be witness-independent: the same body
/// runs with `Empty` witnesses for wiring extraction and metrics, so the call
/// sequence cannot differ between this dry run and real synthesis. (A body
/// that violates that requirement is caught at synthesis time by the
/// determinism guard in
/// [`FrameworkHooks::derive_challenge`].)
pub(crate) fn discover_induced_stages<C: Cycle, S: Step<C>, const HEADER_SIZE: usize>(
    step: &S,
) -> Result<InducedStages> {
    let mut dr: Emulator<Wireless<Empty, C::CircuitField>> = Emulator::counter();
    let mut hooks = FrameworkHooks::<_, C::NestedCurve>::new();
    {
        let mut ctx = StepCtx::new(&mut dr, &mut hooks);
        step.witness::<_, HEADER_SIZE>(&mut ctx, Empty, Empty, Empty)?;
    }

    Ok(InducedStages::new(
        hooks
            .into_outputs()
            .derived_challenges
            .iter()
            .map(|stage| stage.num_wires)
            .collect(),
    ))
}

/// Auxiliary data produced by [`Adapter::witness`]: the two input headers, the
/// output data carried by the resulting PCD, the inner step's own aux, and the
/// polynomial-query claims raised by the step (surfaced for later fuse-time
/// processing — see [`FrameworkHooks`]).
pub(crate) struct AdapterAux<'source, C: Cycle, S: Step<C>, const HEADER_SIZE: usize> {
    pub left_header: FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
    pub right_header: FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
    pub output_data: <S::Output as Header<C::CircuitField>>::Data,
    pub step_aux: S::Aux<'source>,
    // TODO: surface these for fuse-time polynomial-query verification.
    #[allow(dead_code)]
    pub claims: Vec<(C::NestedCurve, C::CircuitField, C::CircuitField)>,
    // Note: the stages induced by `derive_challenge` do not travel here. Their
    // geometry is deterministic ([`Adapter::induced_stages`]), and the binding
    // constraints emitted during synthesis tie each reserved head-of-trace
    // region to its gadget's wires, so fuse can carve each stage's slice out
    // of the trace positionally. Committing those slices and resolving the
    // deferred (point, challenge) outputs is future fuse-side work.
}

pub(crate) struct Adapter<C, S, R, const HEADER_SIZE: usize> {
    step: S,
    /// The induced stage layout discovered from the step's witness body at
    /// construction time; see [`discover_induced_stages`].
    induced: InducedStages,
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize> Adapter<C, S, R, HEADER_SIZE> {
    /// Wraps `step`, discovering its induced stage layout with a dry run of
    /// the witness body (see [`discover_induced_stages`]).
    pub fn new(step: S) -> Result<Self> {
        let induced = discover_induced_stages::<C, S, HEADER_SIZE>(&step)?;
        Ok(Adapter {
            step,
            induced,
            _marker: PhantomData,
        })
    }

    /// The stage layout induced by the step's
    /// [`derive_challenge`](StepCtx::derive_challenge) calls.
    pub fn induced_stages(&self) -> &InducedStages {
        &self.induced
    }
}

impl<C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize> Circuit<C::CircuitField>
    for Adapter<C, S, R, HEADER_SIZE>
{
    type Instance<'source> = (
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        <S::Output as Header<C::CircuitField>>::Data,
    );
    type Witness<'source> = (
        <S::Left as Header<C::CircuitField>>::Data,
        <S::Right as Header<C::CircuitField>>::Data,
        S::Witness<'source>,
    );
    type Output = Kind![C::CircuitField; FixedVec<Element<'_, _>, TripleConstLen<HEADER_SIZE>>];
    type Aux<'source> = AdapterAux<'source, C, S, HEADER_SIZE>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        unreachable!("k(Y) is computed manually for ragu_pcd circuit implementations")
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (left, right, witness) = witness.cast();

        // Reserve the induced stage regions at the head of the trace (gates
        // 1.. — the SYSTEM gate is allocated by orchestration) so their
        // geometry depends only on the discovered widths, mirroring
        // `StageBuilder::configure_stage`. The final trace is zero here; each
        // stage polynomial carries the actual values.
        let mut reserved = Vec::with_capacity(self.induced.len());
        {
            let allocator = &mut Standard::new();
            for stage in 0..self.induced.len() {
                let width = self.induced.width(stage);
                let mut wires = Vec::with_capacity(width);
                for _ in 0..width {
                    wires.push(allocator.alloc(dr, || Ok(Coeff::Zero))?);
                }
                // Pad to a whole number of gates so consecutive stages tile
                // disjoint gate ranges.
                for _ in width..(2 * self.induced.num_gates(stage)) {
                    allocator.alloc(dr, || Ok(Coeff::Zero))?;
                }
                reserved.push(wires);
            }
        }

        let mut hooks = FrameworkHooks::with_reserved(reserved);
        let ((left, right, output), output_data, step_aux) = {
            let mut ctx = StepCtx::new(dr, &mut hooks);
            self.step
                .witness::<_, HEADER_SIZE>(&mut ctx, witness, left, right)?
        };
        let FrameworkHookOutputs {
            poly_query_claims: claims,
            derived_challenges,
        } = hooks.into_outputs();

        // Determinism guard, complementing the per-call checks inside
        // `derive_challenge`: every reserved region must have been consumed,
        // or a stage polynomial would commit to a slice nothing was bound to.
        if derived_challenges.len() != self.induced.len() {
            return Err(ragu_core::Error::InvalidWitness(
                "derive_challenge called fewer times than the discovered stage layout; \
                 circuit structure must not depend on witness values"
                    .into(),
            ));
        }

        let mut elements = Vec::with_capacity(HEADER_SIZE * 3);
        left.write(dr, &mut elements)?;
        right.write(dr, &mut elements)?;
        output.write(dr, &mut elements)?;

        let adapter_aux = D::try_just(|| {
            let left_header = elements[0..HEADER_SIZE]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            let right_header = elements[HEADER_SIZE..HEADER_SIZE * 2]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            Ok(AdapterAux {
                left_header,
                right_header,
                output_data: output_data.take(),
                step_aux: step_aux.take(),
                claims: claims.take(),
            })
        })?;

        Ok(WithAux::new(FixedVec::try_from(elements)?, adapter_aux))
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::TestRank;
    use ragu_core::{
        drivers::emulator::Emulator,
        gadgets::{Bound, Kind},
        maybe::{Always, Maybe, MaybeKind},
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::allocator::{Allocator, Standard};

    use super::*;
    use crate::{
        header::{Header, Suffix},
        step::{Encoded, Index, Step},
    };

    type TestR = TestRank;
    const HEADER_SIZE: usize = 4;

    struct TestHeader;

    impl Header<Fp> for TestHeader {
        const SUFFIX: Suffix = Suffix::new(50);
        type Data = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            dr: &mut D,
            allocator: &mut A,
            witness: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, allocator, witness)
        }
    }

    struct TestStep;

    impl Step<Pasta> for TestStep {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = TestHeader;
        type Right = TestHeader;
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            ctx: &mut StepCtx<'_, 'dr, D, <Pasta as ragu_arithmetic::Cycle>::NestedCurve>, // the type for user-supplied polynomial commitments
            _: DriverValue<D, ()>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let dr = &mut *ctx.dr;
            let allocator = &mut Standard::new();
            // Allocate elements for left and right
            let left_elem = Element::alloc(dr, allocator, left)?;
            let right_elem = Element::alloc(dr, allocator, right)?;

            // Output is sum of left and right
            let output_elem = left_elem.add(dr, &right_elem);
            let output_val = output_elem.value().map(|v| *v);

            let left_enc = Encoded::from_gadget(left_elem);
            let right_enc = Encoded::from_gadget(right_elem);
            let output_enc = Encoded::from_gadget(output_elem);

            Ok(((left_enc, right_enc, output_enc), output_val, D::unit()))
        }
    }

    /// Like [`TestStep`], but derives a challenge from a two-element gadget,
    /// inducing one stage of width 2.
    struct ChallengeStep;

    impl Step<Pasta> for ChallengeStep {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = TestHeader;
        type Right = TestHeader;
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            ctx: &mut StepCtx<'_, 'dr, D, <Pasta as ragu_arithmetic::Cycle>::NestedCurve>,
            _: DriverValue<D, ()>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut Standard::new();
            let left_elem = Element::alloc(ctx.dr, allocator, left)?;
            let right_elem = Element::alloc(ctx.dr, allocator, right)?;

            // Derive a challenge bound to both inputs: induces a stage of
            // width 2. The outputs are deferred; only the wires are used.
            let (_point, challenge) =
                ctx.derive_challenge((left_elem.clone(), right_elem.clone()))?;

            // Output = left + right + challenge, so the deferred challenge
            // wire participates in downstream circuit structure.
            let sum = left_elem.add(ctx.dr, &right_elem);
            let output_elem = sum.add(ctx.dr, &challenge);
            let output_val = output_elem.value().map(|v| *v);

            Ok((
                (
                    Encoded::from_gadget(left_elem),
                    Encoded::from_gadget(right_elem),
                    Encoded::from_gadget(output_elem),
                ),
                output_val,
                D::unit(),
            ))
        }
    }

    #[test]
    fn triple_const_len_returns_3n() {
        assert_eq!(TripleConstLen::<1>::len(), 3);
        assert_eq!(TripleConstLen::<4>::len(), 12);
        assert_eq!(TripleConstLen::<10>::len(), 30);
    }

    #[test]
    fn adapter_witness_produces_correct_output_size() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep)
            .expect("discovery should succeed");
        let witness = Always::maybe_just(|| (Fp::from(10u64), Fp::from(20u64), ()));

        let output = adapter
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_output();

        // Output should have 3 * HEADER_SIZE elements (left + right + output headers)
        assert_eq!(output.len(), HEADER_SIZE * 3);
    }

    #[test]
    fn adapter_witness_extracts_aux_correctly() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep)
            .expect("discovery should succeed");
        let witness = Always::maybe_just(|| (Fp::from(10u64), Fp::from(20u64), ()));

        let aux = adapter
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_aux();

        let AdapterAux {
            left_header,
            right_header,
            output_data,
            step_aux: _,
            claims: _,
        } = aux.take();

        // Left header should start with 10
        assert_eq!(left_header[0], Fp::from(10u64));
        // Right header should start with 20
        assert_eq!(right_header[0], Fp::from(20u64));
        // Step aux should be 10 + 20 = 30
        assert_eq!(output_data, Fp::from(30u64));
    }

    /// A step without `derive_challenge` calls discovers an empty layout.
    #[test]
    fn discovery_finds_no_stages_for_plain_step() {
        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep)
            .expect("discovery should succeed");
        assert!(adapter.induced_stages().is_empty());
    }

    /// Each `derive_challenge` call induces one stage whose width is the
    /// gadget's wire count.
    #[test]
    fn discovery_finds_induced_stage() {
        let adapter = Adapter::<Pasta, ChallengeStep, TestR, HEADER_SIZE>::new(ChallengeStep)
            .expect("discovery should succeed");
        let induced = adapter.induced_stages();
        assert_eq!(induced.len(), 1);
        // Two `Element`s -> width 2, one gate right after the SYSTEM gate.
        assert_eq!(induced.width(0), 2);
        assert_eq!(induced.skip_gates(0), 1);
        assert_eq!(induced.num_gates(0), 1);
        assert_eq!(induced.final_skip_gates(), 2);
    }

    /// The full adapter synthesis (reservation + binding + deferred output
    /// allocation) completes on a structure-only driver for a step that
    /// derives a challenge.
    #[test]
    fn adapter_witness_synthesizes_induced_stage_structure() {
        // A counting driver: no witness values, so the deferred output value
        // closures never run.
        let mut dr: Emulator<Wireless<Empty, Fp>> = Emulator::counter();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, ChallengeStep, TestR, HEADER_SIZE>::new(ChallengeStep)
            .expect("discovery should succeed");

        let output = adapter
            .witness(dr, Empty)
            .expect("structure-only synthesis should succeed")
            .into_output();

        assert_eq!(output.len(), HEADER_SIZE * 3);
    }
}
