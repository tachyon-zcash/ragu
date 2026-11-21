//! Profiles with extensions, for the tests of the extension's plumbing.

use alloc::{vec, vec::Vec};
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
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use super::*;
use crate::{
    protocol::ky,
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

/// One online Fq polynomial per step and no extension: the standard
/// layout with the slot on, which proves at the production rank.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Opening;

impl Profile for Opening {
    const NAME: &'static str = "opening";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const ONLINE_FQ_POLYS: usize = 1;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
}

/// `CIRCUITS` native circuits and one nested circuit, each side's over
/// one stage under one final mask, with hooks that register the fuse's
/// own circuits and stages as stand-ins.
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
        slot.register(crate::fuse::circuits::native::bind_endoscalar::Circuit::<
            Base,
            R,
        >::new())
    }

    fn register_native_bonding<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        bonding: usize,
        slot: BondingSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        type Stage<C, R, const H: usize> = crate::protocol::native::stages::eval::Stage<C, R, H>;
        let mask = match bonding {
            0 => Stage::<Base, R, HEADER_SIZE>::mask()?,
            1 => Stage::<Base, R, HEADER_SIZE>::final_mask()?,
            _ => unreachable!("two bondings"),
        };
        Ok(slot.register(mask))
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
        let circuit =
            crate::fuse::circuits::nested::collapse::Circuit::<Base::HostCurve, R, Standard>::new();
        slot.register(MultiStage::new(circuit))
    }

    fn register_nested_bonding<'params, Base, R: Rank>(
        bonding: usize,
        slot: BondingSlot<'params, Base::ScalarField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        type Stage<C, R> =
            crate::protocol::nested::stages::eval::Stage<<C as Cycle>::HostCurve, R, Standard>;
        let mask = match bonding {
            0 => Stage::<Base, R>::mask()?,
            1 => Stage::<Base, R>::final_mask()?,
            _ => unreachable!("two bondings"),
        };
        Ok(slot.register(mask))
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
/// the compressed proof a decompression extension verifies.
pub(crate) struct StatementCircuit<F, const HEADER_SIZE: usize>(PhantomData<fn() -> F>);

impl<F, const HEADER_SIZE: usize> StatementCircuit<F, HEADER_SIZE> {
    pub(crate) const fn new() -> Self {
        StatementCircuit(PhantomData)
    }
}

impl<F: Field, const HEADER_SIZE: usize> Circuit<F> for StatementCircuit<F, HEADER_SIZE> {
    type Instance<'source> = &'source [F];
    type Witness<'source> = &'source [F];
    type Output = Kind![F; FixedVec<Element<'_, _>, ConstLen<HEADER_SIZE>>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), instance.as_ref().map(|header| header[i]))
        })
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let header: FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>> =
            FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|header| header[i]))
            })?;
        // One check stands in for what a decompression verifies of its
        // statement: a header's suffix is never zero.
        header[HEADER_SIZE - 1].clone().enforce_nonzero(dr)?;
        Ok(WithAux::new(header, D::unit()))
    }
}

/// What [`Decompressing`]'s prover holds: the header its statement
/// circuit exposes in the proofs made next, or none for the unit
/// header, which the circuit must expose for every step but the
/// decompression step (see [`statement_ky`]). A test sets it before
/// proving, as a decompression prover would be handed the compressed
/// proof to verify.
///
/// [`statement_ky`]: crate::protocol::native::stages::preamble::ProofInputs::statement_ky
pub(crate) struct StatementContext<F> {
    header: Mutex<Option<Vec<F>>>,
}

impl<F> Default for StatementContext<F> {
    fn default() -> Self {
        StatementContext {
            header: Mutex::new(None),
        }
    }
}

impl<F: Field> StatementContext<F> {
    /// Exposes `header` from now on, or the unit header for `None`.
    pub(crate) fn expose(&self, header: Option<Vec<F>>) {
        *self.header.lock().unwrap() = header;
    }

    /// The header the statement circuit exposes: the one set, or the
    /// unit header padded to `HEADER_SIZE`.
    fn header<C: Cycle<CircuitField = F>, const HEADER_SIZE: usize>(&self) -> Result<Vec<F>> {
        match self.header.lock().unwrap().clone() {
            Some(header) => Ok(header),
            None => ky::output_header::<C, (), HEADER_SIZE>(()),
        }
    }
}

/// One statement circuit and no stage on the native side, exposing the
/// header its context holds: the profile that registers the
/// decompression step, so that the step and the statement claim's
/// binding of its output header prove and verify without decompression
/// circuits. Proves at a rank above the production one, as [`Proving`]
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
        registry: &Registry<'params, Base::CircuitField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let header = context.header::<Base, HEADER_SIZE>()?;
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
/// that register and prove it, and one online Fq polynomial per step:
/// the profile whose extension proves, at a rank above the production
/// one, where the fuse has room for its two polynomials.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Proving;

impl Profile for Proving {
    const NAME: &'static str = "proving";
    const NATIVE_EXTENSION: usize = 1;
    const NESTED_EXTENSION: usize = 1;
    const ONLINE_FQ_POLYS: usize = 1;

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

/// The signed digits of `bits`: $2b - 1$ each.
fn signed<F: Field>(bits: &[bool; DIGITS]) -> [F; DIGITS] {
    bits.map(|bit| if bit { F::ONE } else { -F::ONE })
}

/// One binding circuit and no stage on the native side, exposing the
/// digits stage's commitment recomputed from the native bits, and one
/// circuit over the digits stage on the nested side, holding the
/// nested bits' signed digits: the profile whose two sides a test can
/// make agree or disagree, at a rank above the production one.
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
        slot.register(MultiStage::new(DigitsCircuit::<Base::ScalarField, R>(
            PhantomData,
        )))
    }

    fn register_nested_bonding<'params, Base, R: Rank>(
        bonding: usize,
        slot: BondingSlot<'params, Base::ScalarField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let mask = match bonding {
            0 => DigitsStage::<Base::ScalarField, R>::mask()?,
            1 => DigitsStage::<Base::ScalarField, R>::final_mask()?,
            _ => unreachable!("two bondings"),
        };
        Ok(slot.register(mask))
    }

    fn native_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
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
            // Unblinded, so that the native side can recompute it.
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
        slot.register(MultiStage::new(DigitsCircuit::<Base::CircuitField, R>(
            PhantomData,
        )))
    }

    fn register_native_bonding<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        bonding: usize,
        slot: BondingSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let mask = match bonding {
            0 => DigitsStage::<Base::CircuitField, R>::mask()?,
            1 => DigitsStage::<Base::CircuitField, R>::final_mask()?,
            _ => unreachable!("two bondings"),
        };
        Ok(slot.register(mask))
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
            // Unblinded, so that the nested side can recompute it.
            stages: vec![DigitsStage::<Base::CircuitField, R>::rx(
                Base::CircuitField::ZERO,
                &digits,
            )?],
        })
    }

    fn nested_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
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
