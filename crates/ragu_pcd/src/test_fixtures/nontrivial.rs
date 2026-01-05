//! Nontrivial test fixtures with Poseidon hashing.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::polynomials::R;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, poseidon::Sponge};

use crate::{
    Application, ApplicationBuilder,
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};

/// A leaf node header containing a single hashed field element.
pub struct LeafNode;

impl<F: Field> Header<F> for LeafNode {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data<'source> = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)
    }
}

/// An internal node header containing a single hashed field element.
pub struct InternalNode;

impl<F: Field> Header<F> for InternalNode {
    const SUFFIX: Suffix = Suffix::new(1);
    type Data<'source> = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)
    }
}

/// A leaf step that hashes a witness value: witness -> LeafNode
pub struct WitnessLeafStep<'params, C: Cycle> {
    /// Poseidon parameters for hashing.
    pub poseidon: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for WitnessLeafStep<'_, C> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = C::CircuitField;
    type Aux<'source> = C::CircuitField;
    type Left = ();
    type Right = ();
    type Output = LeafNode;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let elem = Element::alloc(dr, witness)?;
        let mut sponge = Sponge::new(dr, self.poseidon);
        sponge.absorb(dr, &elem)?;
        let output = sponge.squeeze(dr)?;
        let output_value = output.value().map(|v| *v);

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(output),
            ),
            output_value,
        ))
    }
}

/// A merge step that hashes two leaf headers: (LeafNode, LeafNode) -> InternalNode
pub struct WitnessMergeStep<'params, C: Cycle> {
    /// Poseidon parameters for hashing.
    pub poseidon: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for WitnessMergeStep<'_, C> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = C::CircuitField;
    type Left = LeafNode;
    type Right = LeafNode;
    type Output = InternalNode;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, C::CircuitField>,
        right: DriverValue<D, C::CircuitField>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left = Encoded::new(dr, left)?;
        let right = Encoded::new(dr, right)?;

        let mut sponge = Sponge::new(dr, self.poseidon);
        sponge.absorb(dr, left.as_gadget())?;
        sponge.absorb(dr, right.as_gadget())?;
        let output = sponge.squeeze(dr)?;
        let output_value = output.value().map(|v| *v);

        Ok(((left, right, Encoded::from_gadget(output)), output_value))
    }
}

pub fn build_app<C: Cycle>(params: &C::Params) -> Application<'_, C, R<13>, 4> {
    ApplicationBuilder::<C, R<13>, 4>::new()
        .register(WitnessLeafStep {
            poseidon: C::circuit_poseidon(params),
        })
        .unwrap()
        .register(WitnessMergeStep {
            poseidon: C::circuit_poseidon(params),
        })
        .unwrap()
        .finalize(params)
        .unwrap()
}
