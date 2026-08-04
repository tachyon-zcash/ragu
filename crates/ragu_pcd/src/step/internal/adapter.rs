use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_circuits::{Circuit, WithAux, polynomials::Rank};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use super::super::{Step, StepCtx};
use crate::{
    Header,
    framework_hooks::{FrameworkAux, FrameworkHooks, HookConfig},
};

/// Three headers plus the hooks' instance regions.
pub struct AdapterLen<const HEADER_SIZE: usize, J: HookConfig>(PhantomData<J>);

impl<const HEADER_SIZE: usize, J: HookConfig> Len for AdapterLen<HEADER_SIZE, J> {
    fn len() -> usize {
        HEADER_SIZE * 3 + J::layout().poly_query_instance_len()
    }
}

/// Auxiliary data produced by [`Adapter::witness`]: the input headers, the
/// output data, the inner step's own aux, and the framework hooks' outputs.
pub(crate) struct AdapterAux<'source, C: Cycle, S: Step<C>, const HEADER_SIZE: usize> {
    pub left_header: FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
    pub right_header: FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
    pub output_data: <S::Output as Header<C::CircuitField>>::Data,
    pub step_aux: S::Aux<'source>,
    /// Every framework hook's output; see [`FrameworkAux`].
    pub framework: FrameworkAux<C>,
}

pub(crate) struct Adapter<'params, C: Cycle, S, R: Rank, const HEADER_SIZE: usize, J: HookConfig> {
    step: S,
    /// Held for the hooks; a [`Step`] never sees these.
    params: &'params C::Params,
    _marker: PhantomData<(C, R, J)>,
}

impl<'params, C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize, J: HookConfig>
    Adapter<'params, C, S, R, HEADER_SIZE, J>
{
    /// Wraps `step`; the layout comes from `J`. A step that asks for more than
    /// it allows overruns [`AdapterLen`], which is what refuses it.
    pub fn new(step: S, params: &'params C::Params) -> Self {
        Adapter {
            step,
            params,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize, J: HookConfig>
    Circuit<C::CircuitField> for Adapter<'_, C, S, R, HEADER_SIZE, J>
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
    type Output = Kind![
        C::CircuitField;
        FixedVec<
            Element<'_, _>,
            AdapterLen<HEADER_SIZE, J>,
        >
    ];
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

        let mut hooks = FrameworkHooks::new(J::layout(), self.params);
        let ((left, right, output), output_data, step_aux) = {
            let mut ctx = StepCtx::<'_, '_, _, C>::new(dr, &mut hooks);
            self.step
                .witness::<_, HEADER_SIZE>(&mut ctx, witness, left, right)?
        };
        // Fill what the body left over, through the same hooks it used.
        hooks.pad_to_layout::<R>(dr)?;

        let mut elements = Vec::with_capacity(AdapterLen::<HEADER_SIZE, J>::len());
        left.write(dr, &mut elements)?;
        right.write(dr, &mut elements)?;
        output.write(dr, &mut elements)?;
        // Same types `ProofInputs::application_ky` folds into k(Y), so neither
        // side spells the order out.
        for poly in hooks.witnessed_polys() {
            poly.write(dr, &mut elements)?;
        }

        // Read every hook's wires back out as values for the fuse.
        let framework = hooks.into_values()?;

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
                framework: framework.take(),
            })
        })?;

        Ok(WithAux::new(FixedVec::try_from(elements)?, adapter_aux))
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::Circuit;
    use ragu_core::{
        drivers::emulator::Emulator,
        gadgets::{Bound, Kind},
        maybe::{Always, Maybe, MaybeKind},
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::allocator::{Allocator, Standard};

    use super::*;
    use crate::{
        NoHooks,
        header::{Header, Suffix},
        step::{Encoded, Index, Step},
    };

    // The per-polynomial bridge stages need a rank fitting
    // `skip_gates + num_gates` (~177); `TestRank` (n = 32) is too small.
    type TestR = ragu_circuits::polynomials::ProductionRank;
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
            ctx: &mut StepCtx<'_, 'dr, D, Pasta>,
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

    #[test]
    fn adapter_witness_extracts_aux_correctly() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter =
            Adapter::<Pasta, TestStep, TestR, HEADER_SIZE, NoHooks>::new(TestStep, Pasta::baked());
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
            framework: _,
        } = aux.take();

        // Left header should start with 10
        assert_eq!(left_header[0], Fp::from(10u64));
        // Right header should start with 20
        assert_eq!(right_header[0], Fp::from(20u64));
        // Step aux should be 10 + 20 = 30
        assert_eq!(output_data, Fp::from(30u64));
    }
}
