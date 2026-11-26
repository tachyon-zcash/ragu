use alloc::vec;
use std::sync::Mutex;

use ragu_circuits::{
    Circuit, CircuitExt, WithAux,
    registry::CircuitIndex,
    staging::{MultiStage, MultiStageCircuit, Stage, StageBuilder, StageExt},
};
use ragu_core::{
    Coeff, FixedGenerators,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Boolean, Element, NonzeroBank, Point, allocator,
    vec::{ConstLen, FixedVec},
};
use udon::curve::EndomorphismAffine as Affine;

use super::*;
use crate::{
    internal::ky,
    step::{Encoded, Index, Oracles, Step},
};

/// A step with unit headers and no witness.
pub(crate) struct UnitStep;

impl<C: Cycle> Step<C> for UnitStep {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, C, Self>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, (), HEADER_SIZE>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut allocator::Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        Ok((
            (left, right, Encoded::from_gadget(())),
            D::unit(),
            D::unit(),
        ))
    }
}

/// A second profile with the standard profile's shape and no extension:
/// the setup separation tests hold two profiles of one shape apart by
/// their tags alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Twin;

impl Profile for Twin {
    const NAME: &'static str = "twin";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
}

/// The standard profile's circuits with the nested walk cut into groups of
/// eight steps: a links stage, a points stage polynomial per group and a
/// check circuit per group beside the fuse's own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Grouped;

impl Profile for Grouped {
    const NAME: &'static str = "grouped";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NESTED_WALK_GROUP: usize = 8;
    const NESTED_STEPS: usize = 7;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
}

/// `NATIVE` native and `NESTED` nested [`Trivial`] circuits and no stage,
/// in a paged profile whose nested walk is in groups of thirty-two steps
/// and whose nested program pins `STEPS` steps: a profile with as many
/// polynomials as an extension the size of the aggregator's adds, for the
/// tests that measure the nested program's steps at that size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Sized<const NATIVE: usize, const NESTED: usize, const STEPS: usize>;

impl<const NATIVE: usize, const NESTED: usize, const STEPS: usize> Profile
    for Sized<NATIVE, NESTED, STEPS>
{
    const NAME: &'static str = "sized";
    const NATIVE_EXTENSION: usize = NATIVE;
    const NESTED_EXTENSION: usize = NESTED;
    const NESTED_WALK_GROUP: usize = 32;
    const NESTED_STEPS: usize = STEPS;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    fn native_extension() -> Extension {
        Extension {
            circuits: vec![vec![]; NATIVE],
            stages: 0,
            final_masks: vec![],
            statement: None,
            binding: None,
        }
    }

    fn nested_extension() -> Extension {
        Extension {
            circuits: vec![vec![]; NESTED],
            stages: 0,
            final_masks: vec![],
            statement: None,
            binding: None,
        }
    }

    fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert!(circuit < NATIVE);
        slot.register(Trivial::<Base::CircuitField>::new())
    }

    fn register_nested_circuit<'params, Base, R: Rank>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::ScalarField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert!(circuit < NESTED);
        slot.register(Trivial::<Base::ScalarField>::new())
    }
}

/// Two native circuits over two stages, each under its last stage's
/// final mask, and one nested circuit over one stage under one final
/// mask, declared but without hooks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Wider;

impl Profile for Wider {
    const NAME: &'static str = "wider";
    const NATIVE_EXTENSION: usize = 4;
    const NESTED_EXTENSION: usize = 2;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    fn native_extension() -> Extension {
        Extension {
            circuits: vec![vec![0], vec![0, 1]],
            stages: 2,
            final_masks: vec![vec![0], vec![1]],
            statement: None,
            binding: None,
        }
    }

    fn nested_extension() -> Extension {
        Extension {
            circuits: vec![vec![0]],
            stages: 1,
            final_masks: vec![vec![0]],
            statement: None,
            binding: None,
        }
    }
}

/// [`Wider`]'s native side with its second circuit declared the
/// statement circuit, so that the profile registers the statement step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Stated;

impl Profile for Stated {
    const NAME: &'static str = "stated";
    const NATIVE_EXTENSION: usize = 4;
    const NESTED_EXTENSION: usize = 0;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    fn native_extension() -> Extension {
        Extension {
            circuits: vec![vec![0], vec![0, 1]],
            stages: 2,
            final_masks: vec![vec![0], vec![1]],
            statement: Some(1),
            binding: None,
        }
    }
}

/// Declares one rx polynomial and no extension.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Mismatched;

impl Profile for Mismatched {
    const NAME: &'static str = "mismatched";
    const NATIVE_EXTENSION: usize = 1;
    const NESTED_EXTENSION: usize = 0;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
}

/// `CIRCUITS` native circuits and one nested circuit, each side's over
/// one stage under one final mask, with hooks that register a one-stage
/// test circuit ([`DigitsCircuit`]) and its stage as stand-ins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Hooked<const CIRCUITS: usize = 1>;

impl<const CIRCUITS: usize> Profile for Hooked<CIRCUITS> {
    const NAME: &'static str = "hooked";
    const NATIVE_EXTENSION: usize = CIRCUITS + 1;
    const NESTED_EXTENSION: usize = 2;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    fn native_extension() -> Extension {
        Extension {
            circuits: vec![vec![0]; CIRCUITS],
            stages: 1,
            final_masks: vec![(0..CIRCUITS as u32).collect()],
            statement: None,
            binding: None,
        }
    }

    fn nested_extension() -> Extension {
        Extension {
            circuits: vec![vec![0]],
            stages: 1,
            final_masks: vec![vec![0]],
            statement: None,
            binding: None,
        }
    }

    fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert!(circuit < CIRCUITS);
        slot.register_staged(MultiStage::new(DigitsCircuit::<Base::CircuitField, R>(
            PhantomData,
        )))
    }

    fn register_native_mask<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        mask: usize,
        slot: MaskSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        match mask {
            0 => slot.register_stage_mask::<DigitsStage<Base::CircuitField, R>>(),
            1 => slot.register_final_mask::<DigitsStage<Base::CircuitField, R>>(),
            _ => unreachable!("two masks"),
        }
    }

    fn register_nested_circuit<'params, Base, R: Rank>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::ScalarField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert_eq!(circuit, 0);
        slot.register_staged(MultiStage::new(DigitsCircuit::<Base::ScalarField, R>(
            PhantomData,
        )))
    }

    fn register_nested_mask<'params, Base, R: Rank>(
        mask: usize,
        slot: MaskSlot<'params, Base::ScalarField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        match mask {
            0 => slot.register_stage_mask::<DigitsStage<Base::ScalarField, R>>(),
            1 => slot.register_final_mask::<DigitsStage<Base::ScalarField, R>>(),
            _ => unreachable!("two masks"),
        }
    }
}

/// One boolean wire: a circuit over any field, with no instance, that
/// [`Proving`]'s hooks register on each side.
pub(crate) struct Trivial<F>(PhantomData<fn() -> F>);

impl<F> Trivial<F> {
    pub(crate) const fn new() -> Self {
        Trivial(PhantomData)
    }
}

impl<F: Field> Circuit<F> for Trivial<F> {
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (bit, square) = Element::alloc_square(dr, D::just(|| F::ONE))?;
        bit.add_coeff(dr, &square, Coeff::NegativeOne)
            .enforce_zero(dr)?;
        Ok(WithAux::new((), D::unit()))
    }
}

/// The rx polynomial of a [`Trivial`] circuit at `circuit` in
/// `registry`, as an extension's only polynomial.
fn trivial_rxs<F: Field, R: Rank>(
    registry: &Registry<'_, F, R>,
    circuit: CircuitIndex,
    rng: &mut impl CryptoRng,
) -> Result<ExtensionRxs<F, R>> {
    let (trace, ()) = Trivial::<F>::new().trace(())?.into_parts();
    Ok(ExtensionRxs {
        circuits: vec![registry.assemble(&trace, circuit, rng)?],
        stages: Vec::new(),
    })
}

/// A statement circuit for the tests of the decompression step: its
/// public output is the header it is given, `HEADER_SIZE` elements
/// whose suffix it holds nonzero, standing in for the output header of
/// the compressed proof a decompression extension verifies, then the
/// step binding it is given, which it leaves unconstrained.
pub(crate) struct StatementCircuit<F, const HEADER_SIZE: usize>(PhantomData<fn() -> F>);

impl<F, const HEADER_SIZE: usize> StatementCircuit<F, HEADER_SIZE> {
    pub(crate) const fn new() -> Self {
        StatementCircuit(PhantomData)
    }
}

impl<F: Field, const HEADER_SIZE: usize> Circuit<F> for StatementCircuit<F, HEADER_SIZE> {
    /// The header, then the step binding.
    type Instance<'source> = &'source [F];
    type Witness<'source> = &'source [F];
    type Output = Kind![F; (
        FixedVec<Element<'_, _>, ConstLen<HEADER_SIZE>>,
        FixedVec<Element<'_, _>, ConstLen<STEP_BINDING>>,
    )];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let header = FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), instance.as_ref().map(|values| values[i]))
        })?;
        let step = FixedVec::try_from_fn(|i| {
            Element::alloc(
                dr,
                &mut (),
                instance.as_ref().map(|values| values[HEADER_SIZE + i]),
            )
        })?;
        Ok((header, step))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let header: FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>> =
            FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|values| values[i]))
            })?;
        let step: FixedVec<Element<'dr, D>, ConstLen<STEP_BINDING>> = FixedVec::try_from_fn(|i| {
            Element::alloc(
                dr,
                &mut (),
                witness.as_ref().map(|values| values[HEADER_SIZE + i]),
            )
        })?;
        // One check stands in for what a decompression verifies of its
        // statement: a header's suffix is never zero.
        header[HEADER_SIZE - 1].clone().enforce_nonzero(dr)?;
        Ok(WithAux::new((header, step), D::unit()))
    }
}

/// What [`Decompressing`]'s prover holds: the header its statement
/// circuit exposes in the proofs made next, or none for the unit
/// header, which the circuit must expose for every step but the
/// decompression step (see [`statement_ky`]). A test sets it before
/// proving, as a decompression prover would be handed the compressed
/// proof to verify.
///
/// [`statement_ky`]: crate::internal::native::stages::preamble::ProofInputs::statement_ky
pub(crate) struct StatementContext<F> {
    header: Mutex<Option<Vec<F>>>,
    /// Values that replace the step binding's as the circuit exposes
    /// them, by position; see [`expose_binding`](Self::expose_binding).
    binding: Mutex<[Option<F>; STEP_BINDING]>,
}

impl<F> ProverContext for StatementContext<F> {
    type Source = core::convert::Infallible;
}

impl<F> Default for StatementContext<F> {
    fn default() -> Self {
        StatementContext {
            header: Mutex::new(None),
            binding: Mutex::new(core::array::from_fn(|_| None)),
        }
    }
}

impl<F: Field> StatementContext<F> {
    /// Exposes `header` from now on, or the unit header for `None`.
    pub(crate) fn expose(&self, header: Option<Vec<F>>) {
        *self.header.lock().unwrap() = header;
    }

    /// Replaces, from now on, each value of the step binding the
    /// statement circuit exposes that `binding` sets: the flag and the
    /// digest, in that order. A test
    /// exposes a binding its step did not make this way; all `None`
    /// restores the step's own.
    pub(crate) fn expose_binding(&self, binding: [Option<F>; STEP_BINDING]) {
        *self.binding.lock().unwrap() = binding;
    }

    /// What the statement circuit exposes: the header set, then the
    /// step binding of a decompression that staged `digest`; or the unit header
    /// padded to `HEADER_SIZE`, then the binding of any other step,
    /// all zero.
    fn statement<C: Cycle<CircuitField = F>, const HEADER_SIZE: usize>(
        &self,
        digest: F,
    ) -> Result<Vec<F>> {
        let (mut header, binding) = match self.header.lock().unwrap().clone() {
            Some(header) => (header, [F::ONE, digest]),
            None => (
                ky::output_header::<C, (), HEADER_SIZE>(())?,
                [F::ZERO; STEP_BINDING],
            ),
        };
        let replaced = *self.binding.lock().unwrap();
        header.extend(
            binding
                .into_iter()
                .zip(replaced)
                .map(|(own, replaced)| replaced.unwrap_or(own)),
        );
        Ok(header)
    }
}

/// One statement circuit and no stage on the native side, exposing the
/// header its context holds: the profile that registers the
/// decompression step, so that the step and the statement claim's
/// binding of its output header prove and verify without decompression
/// circuits. Proves at a rank above the wallet's, as [`Proving`]
/// does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Decompressing;

impl Profile for Decompressing {
    const NAME: &'static str = "decompressing";
    const NATIVE_EXTENSION: usize = 1;
    const NESTED_EXTENSION: usize = 0;

    type Context<'params, Base, R, B>
        = StatementContext<Base::CircuitField>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    fn native_extension() -> Extension {
        Extension {
            circuits: vec![vec![]],
            stages: 0,
            final_masks: vec![],
            statement: Some(0),
            binding: None,
        }
    }

    fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert_eq!(circuit, 0);
        slot.register(StatementCircuit::<Base::CircuitField, HEADER_SIZE>::new())
    }

    fn native_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        _: Option<&core::convert::Infallible>,
        online_openings: &[[Base::CircuitField; 2]; 3 * crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::CircuitField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        use crate::step::internal::decompress::DIGEST_SLOT;
        let header = context.statement::<Base, HEADER_SIZE>(online_openings[DIGEST_SLOT][0])?;
        let (trace, ()) = StatementCircuit::<Base::CircuitField, HEADER_SIZE>::new()
            .trace(header.as_slice())?
            .into_parts();
        let circuit = native::InternalCircuitIndex::ExtensionCircuit(0);
        Ok(ExtensionRxs {
            circuits: vec![registry.assemble(&trace, circuit.circuit_index::<Self>(), rng)?],
            stages: Vec::new(),
        })
    }
}

/// One [`Trivial`] circuit and no stage on each side, with the hooks
/// that register and prove it: the profile whose extension proves, at a
/// rank above the wallet's, where the fuse has room for its two
/// polynomials.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Proving;

impl Profile for Proving {
    const NAME: &'static str = "proving";
    const NATIVE_EXTENSION: usize = 1;
    const NESTED_EXTENSION: usize = 1;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    fn native_extension() -> Extension {
        Extension {
            circuits: vec![vec![]],
            stages: 0,
            final_masks: vec![],
            statement: None,
            binding: None,
        }
    }

    fn nested_extension() -> Extension {
        Self::native_extension()
    }

    fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert_eq!(circuit, 0);
        slot.register(Trivial::<Base::CircuitField>::new())
    }

    fn register_nested_circuit<'params, Base, R: Rank>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::ScalarField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert_eq!(circuit, 0);
        slot.register(Trivial::<Base::ScalarField>::new())
    }

    fn native_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        _: &Self::Context<'params, Base, R, B>,
        _: Option<&core::convert::Infallible>,
        _: &[[Base::CircuitField; 2]; 3 * crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::CircuitField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let circuit = native::InternalCircuitIndex::ExtensionCircuit(0);
        trivial_rxs(registry, circuit.circuit_index::<Self>(), rng)
    }

    fn nested_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        _: &Self::Context<'params, Base, R, B>,
        _: Option<&core::convert::Infallible>,
        _: &[Base::HostCurve; crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::ScalarField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let circuit = nested::InternalCircuitIndex::ExtensionCircuit(0);
        trivial_rxs(registry, circuit.circuit_index::<Self>(), rng)
    }
}

/// The digits [`Crossing`] sends across the cycle: few, so that summing
/// their generators is a few gates.
pub(crate) const DIGITS: usize = 4;

/// The nested side's one stage under [`Crossing`]: the signed digits,
/// each $\pm 1$.
pub(crate) struct DigitsStage<F, R>(PhantomData<fn() -> (F, R)>);

impl<F, R> Default for DigitsStage<F, R> {
    fn default() -> Self {
        DigitsStage(PhantomData)
    }
}

impl<F: Field, R: Rank> Stage<F, R> for DigitsStage<F, R> {
    type Parent = ();
    type Witness<'source> = &'source [F; DIGITS];
    type OutputKind = Kind![F; FixedVec<Element<'_, _>, ConstLen<DIGITS>>];

    fn values() -> usize {
        DIGITS
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), witness.as_ref().map(|digits| digits[i]))
        })
    }
}

/// The nested side's one circuit under [`Crossing`]: over the digits
/// stage, holding each digit to $\pm 1$.
pub(crate) struct DigitsCircuit<F, R>(PhantomData<fn() -> (F, R)>);

impl<F: Field, R: Rank> MultiStageCircuit<F, R> for DigitsCircuit<F, R> {
    type Last = DigitsStage<F, R>;
    type Instance<'source> = ();
    type Witness<'source> = &'source [F; DIGITS];
    type Output = Kind![F; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (digits, dr) = dr.add_stage::<DigitsStage<F, R>>()?;
        let dr = dr.finish();
        let digits = digits.unenforced(dr, witness)?;
        for digit in digits.iter() {
            digit
                .square(dr)?
                .add_coeff(dr, &Element::one(), Coeff::NegativeOne)
                .enforce_zero(dr)?;
        }
        Ok(WithAux::new((), D::unit()))
    }
}

/// The binding circuit under [`Crossing`] and [`CrossingBack`], on the
/// side without the digits stage: its public output is the digits
/// stage's commitment recomputed from the bits it is given, the digits'
/// generators summed by sign, as the other side's digit $2b - 1$ scales
/// its generator.
pub(crate) struct BitsCircuit<P> {
    /// Each digit's generator: the digits stage's commitment with that
    /// digit one and the others zero.
    generators: Vec<P>,
}

impl<P: Affine> BitsCircuit<P> {
    /// The circuit over the digits stage's generators at rank `R`, the
    /// stage committed with `generators`: the other side's, the nested
    /// ones for a native circuit and the host ones for a nested one.
    fn new<R: Rank>(generators: &impl FixedGenerators<P>) -> Result<Self> {
        let zeros = [P::Scalar::ZERO; DIGITS];
        let commit = |digits: &[P::Scalar; DIGITS]| {
            DigitsStage::<P::Scalar, R>::rx(P::Scalar::ZERO, digits)
                .map(|rx| rx.commit_to_affine(generators))
        };
        assert!(
            commit(&zeros)?.coordinates().is_none(),
            "the digits stage has no term beyond the digits"
        );
        let generators = (0..DIGITS)
            .map(|i| {
                let mut digits = zeros;
                digits[i] = P::Scalar::ONE;
                commit(&digits)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(BitsCircuit { generators })
    }
}

impl<P: Affine> Circuit<P::Base> for BitsCircuit<P> {
    type Instance<'source> = P;
    type Witness<'source> = &'source [bool; DIGITS];
    type Output = Kind![P::Base; Point<'_, _, P>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = P::Base>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Point::alloc(dr, instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = P::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let sum = NonzeroBank::scope(dr, |dr, bank| {
            let mut sum: Option<Point<'dr, D, P>> = None;
            for (i, &generator) in self.generators.iter().enumerate() {
                let bit = Boolean::alloc(dr, &mut (), witness.as_ref().map(|bits| bits[i]))?;
                let negate = bit.not(dr);
                let term = Point::constant(dr, generator)?.conditional_negate(dr, &negate)?;
                sum = Some(match sum {
                    None => term,
                    Some(sum) => sum.add_incomplete(dr, &term, bank)?,
                });
            }
            sum.ok_or_else(|| Error::InvalidWitness("a digit".into()))
        })?;
        Ok(WithAux::new(sum, D::unit()))
    }
}

/// What [`Crossing`]'s prover holds: the parameters, for the digits'
/// generators, and each side's bits, so that a test can hand the two
/// sides different values.
pub(crate) struct CrossingContext<'params, Base: Cycle> {
    pub(crate) params: &'params Base::Params,
    pub(crate) native: [bool; DIGITS],
    pub(crate) nested: [bool; DIGITS],
}

impl<Base: Cycle> ProverContext for CrossingContext<'_, Base> {
    type Source = core::convert::Infallible;
}

/// The signed digits of `bits`: $2b - 1$ each.
fn signed<F: Field>(bits: &[bool; DIGITS]) -> [F; DIGITS] {
    bits.map(|bit| if bit { F::ONE } else { -F::ONE })
}

/// One binding circuit and no stage on the native side, exposing the
/// digits stage's commitment recomputed from the native bits, and one
/// circuit over the digits stage on the nested side, holding the
/// nested bits' signed digits: the profile whose two sides a test can
/// make agree or disagree, at a rank above the wallet's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Crossing;

impl Profile for Crossing {
    const NAME: &'static str = "crossing";
    const NATIVE_EXTENSION: usize = 1;
    const NESTED_EXTENSION: usize = 2;

    type Context<'params, Base, R, B>
        = CrossingContext<'params, Base>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    fn native_extension() -> Extension {
        Extension {
            circuits: vec![vec![]],
            stages: 0,
            final_masks: vec![],
            statement: None,
            binding: Some(Binding {
                circuit: 0,
                stages: vec![0],
                online: vec![],
                batch: Vec::new(),
            }),
        }
    }

    fn nested_extension() -> Extension {
        Extension {
            circuits: vec![vec![0]],
            stages: 1,
            final_masks: vec![vec![0]],
            statement: None,
            binding: None,
        }
    }

    fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::CircuitField, R>,
        params: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert_eq!(circuit, 0);
        let generators = Base::nested_generators(params);
        slot.register(BitsCircuit::<Base::NestedCurve>::new::<R>(generators)?)
    }

    fn register_nested_circuit<'params, Base, R: Rank>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::ScalarField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert_eq!(circuit, 0);
        slot.register_staged(MultiStage::new(DigitsCircuit::<Base::ScalarField, R>(
            PhantomData,
        )))
    }

    fn register_nested_mask<'params, Base, R: Rank>(
        mask: usize,
        slot: MaskSlot<'params, Base::ScalarField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        match mask {
            0 => slot.register_stage_mask::<DigitsStage<Base::ScalarField, R>>(),
            1 => slot.register_final_mask::<DigitsStage<Base::ScalarField, R>>(),
            _ => unreachable!("two masks"),
        }
    }

    fn native_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        _: Option<&core::convert::Infallible>,
        _: &[[Base::CircuitField; 2]; 3 * crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::CircuitField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let generators = Base::nested_generators(context.params);
        let (trace, ()) = BitsCircuit::<Base::NestedCurve>::new::<R>(generators)?
            .trace(&context.native)?
            .into_parts();
        let circuit = native::InternalCircuitIndex::ExtensionCircuit(0);
        Ok(ExtensionRxs {
            circuits: vec![registry.assemble(&trace, circuit.circuit_index::<Self>(), rng)?],
            stages: Vec::new(),
        })
    }

    fn nested_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        _: Option<&core::convert::Infallible>,
        _: &[Base::HostCurve; crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::ScalarField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let digits = signed::<Base::ScalarField>(&context.nested);
        let (trace, ()) = MultiStage::new(DigitsCircuit::<Base::ScalarField, R>(PhantomData))
            .trace(&digits)?
            .into_parts();
        let circuit = nested::InternalCircuitIndex::ExtensionCircuit(0);
        Ok(ExtensionRxs {
            circuits: vec![registry.assemble(&trace, circuit.circuit_index::<Self>(), rng)?],
            // A zero alpha, so that the native side can recompute it.
            stages: vec![DigitsStage::<Base::ScalarField, R>::rx(
                Base::ScalarField::ZERO,
                &digits,
            )?],
        })
    }
}

/// [`Crossing`] the other way round: one circuit over the digits stage
/// on the native side, holding the native bits' signed digits, and one
/// binding circuit and no stage on the nested side, exposing that
/// stage's commitment recomputed from the nested bits, so that the
/// nested side binds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CrossingBack;

impl Profile for CrossingBack {
    const NAME: &'static str = "crossing back";
    const NATIVE_EXTENSION: usize = 2;
    const NESTED_EXTENSION: usize = 1;

    type Context<'params, Base, R, B>
        = CrossingContext<'params, Base>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    fn native_extension() -> Extension {
        Extension {
            circuits: vec![vec![0]],
            stages: 1,
            final_masks: vec![vec![0]],
            statement: None,
            binding: None,
        }
    }

    fn nested_extension() -> Extension {
        Extension {
            circuits: vec![vec![]],
            stages: 0,
            final_masks: vec![],
            statement: None,
            binding: Some(Binding {
                circuit: 0,
                stages: vec![0],
                online: vec![],
                batch: Vec::new(),
            }),
        }
    }

    fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert_eq!(circuit, 0);
        slot.register_staged(MultiStage::new(DigitsCircuit::<Base::CircuitField, R>(
            PhantomData,
        )))
    }

    fn register_native_mask<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        mask: usize,
        slot: MaskSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        match mask {
            0 => slot.register_stage_mask::<DigitsStage<Base::CircuitField, R>>(),
            1 => slot.register_final_mask::<DigitsStage<Base::CircuitField, R>>(),
            _ => unreachable!("two masks"),
        }
    }

    fn register_nested_circuit<'params, Base, R: Rank>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::ScalarField, R>,
        params: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert_eq!(circuit, 0);
        let generators = Base::host_generators(params);
        slot.register(BitsCircuit::<Base::HostCurve>::new::<R>(generators)?)
    }

    fn native_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        _: Option<&core::convert::Infallible>,
        _: &[[Base::CircuitField; 2]; 3 * crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::CircuitField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let digits = signed::<Base::CircuitField>(&context.native);
        let (trace, ()) = MultiStage::new(DigitsCircuit::<Base::CircuitField, R>(PhantomData))
            .trace(&digits)?
            .into_parts();
        let circuit = native::InternalCircuitIndex::ExtensionCircuit(0);
        Ok(ExtensionRxs {
            circuits: vec![registry.assemble(&trace, circuit.circuit_index::<Self>(), rng)?],
            // A zero alpha, so that the nested side can recompute it.
            stages: vec![DigitsStage::<Base::CircuitField, R>::rx(
                Base::CircuitField::ZERO,
                &digits,
            )?],
        })
    }

    fn nested_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        _: Option<&core::convert::Infallible>,
        _: &[Base::HostCurve; crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::ScalarField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let generators = Base::host_generators(context.params);
        let (trace, ()) = BitsCircuit::<Base::HostCurve>::new::<R>(generators)?
            .trace(&context.nested)?
            .into_parts();
        let circuit = nested::InternalCircuitIndex::ExtensionCircuit(0);
        Ok(ExtensionRxs {
            circuits: vec![registry.assemble(&trace, circuit.circuit_index::<Self>(), rng)?],
            stages: Vec::new(),
        })
    }
}
