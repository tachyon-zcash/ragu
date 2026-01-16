//! Test for the `#[define_application]` macro.

use ragu_arithmetic::Cycle;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
    maybe::Maybe,
};
use ragu_pasta::Pasta;
use ragu_pcd::step::{Encoded, Encoder};
use ragu_primitives::{Element, poseidon::Sponge};

// Define the application using the macro
#[ragu_macros::define_application]
pub mod test_app {
    use super::*;

    #[header(data = F, output = Element<'_, _>)]
    pub struct LeafNode;

    #[step(witness = C::CircuitField, aux = C::CircuitField, left = (), right = (), output = LeafNode)]
    pub struct WitnessLeaf<'params, C: Cycle> {
        pub poseidon_params: &'params C::CircuitPoseidon,
    }

    #[header(data = F, output = Element<'_, _>)]
    pub struct InternalNode;

    #[step(witness = (), aux = C::CircuitField, left = LeafNode, right = LeafNode, output = InternalNode)]
    pub struct Hash2<'params, C: Cycle> {
        pub poseidon_params: &'params C::CircuitPoseidon,
    }
}

// User-defined implementations

impl test_app::LeafNode {
    pub fn encode<'dr, 'source: 'dr, F: Field, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, F>,
    ) -> Result<<ragu_core::gadgets::Kind![F; Element<'_, _>] as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)
    }
}

impl test_app::InternalNode {
    pub fn encode<'dr, 'source: 'dr, F: Field, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, F>,
    ) -> Result<<ragu_core::gadgets::Kind![F; Element<'_, _>] as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)
    }
}

impl<'params, C: Cycle> test_app::WitnessLeaf<'params, C> {
    pub fn new(params: &'params C::Params) -> Self {
        Self {
            poseidon_params: C::circuit_poseidon(params),
        }
    }

    pub fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        (dr, witness, _left, _right): (
            &mut D,
            DriverValue<D, C::CircuitField>,
            Encoder<'dr, 'source, D, (), HEADER_SIZE>,
            Encoder<'dr, 'source, D, (), HEADER_SIZE>,
        ),
    ) -> Result<(
        (
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, test_app::LeafNode, HEADER_SIZE>,
        ),
        DriverValue<D, C::CircuitField>,
    )>
    where
        Self: 'dr,
    {
        let leaf = Element::alloc(dr, witness)?;
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, &leaf)?;
        let leaf = sponge.squeeze(dr)?;
        let leaf_value = leaf.value().map(|v| *v);
        let leaf_encoded = Encoded::from_gadget(leaf);

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                leaf_encoded,
            ),
            leaf_value,
        ))
    }
}

impl<'params, C: Cycle> test_app::Hash2<'params, C> {
    pub fn new(params: &'params C::Params) -> Self {
        Self {
            poseidon_params: C::circuit_poseidon(params),
        }
    }

    pub fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        (dr, _witness, left, right): (
            &mut D,
            DriverValue<D, ()>,
            Encoder<'dr, 'source, D, test_app::LeafNode, HEADER_SIZE>,
            Encoder<'dr, 'source, D, test_app::LeafNode, HEADER_SIZE>,
        ),
    ) -> Result<(
        (
            Encoded<'dr, D, test_app::LeafNode, HEADER_SIZE>,
            Encoded<'dr, D, test_app::LeafNode, HEADER_SIZE>,
            Encoded<'dr, D, test_app::InternalNode, HEADER_SIZE>,
        ),
        DriverValue<D, C::CircuitField>,
    )>
    where
        Self: 'dr,
    {
        let left = left.encode(dr)?;
        let right = right.encode(dr)?;

        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, left.as_gadget())?;
        sponge.absorb(dr, right.as_gadget())?;
        let output = sponge.squeeze(dr)?;
        let output_value = output.value().map(|v| *v);
        let output = Encoded::from_gadget(output);

        Ok(((left, right, output), output_value))
    }
}

// ============================================================================
// Test with implicit defaults
// ============================================================================

// This module uses the implicit default resolution:
// - output defaults to the next header after the step
// - left/right default to previous step's output (or () for first step)
#[ragu_macros::define_application]
pub mod implicit_app {
    use super::*;

    // Step 0: WitnessLeaf
    // - left/right: () (no previous step)
    // - output: LeafNode (next header)
    #[step(witness = C::CircuitField, aux = C::CircuitField)]
    pub struct WitnessLeaf<'params, C: Cycle> {
        pub poseidon_params: &'params C::CircuitPoseidon,
    }

    #[header(data = F, output = Element<'_, _>)]
    pub struct LeafNode;

    // Step 1: Hash2
    // - left/right: LeafNode (previous step's output)
    // - output: InternalNode (next header)
    #[step(witness = (), aux = C::CircuitField)]
    pub struct Hash2<'params, C: Cycle> {
        pub poseidon_params: &'params C::CircuitPoseidon,
    }

    #[header(data = F, output = Element<'_, _>)]
    pub struct InternalNode;
}

impl implicit_app::LeafNode {
    pub fn encode<'dr, 'source: 'dr, F: Field, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, F>,
    ) -> Result<<ragu_core::gadgets::Kind![F; Element<'_, _>] as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)
    }
}

impl implicit_app::InternalNode {
    pub fn encode<'dr, 'source: 'dr, F: Field, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, F>,
    ) -> Result<<ragu_core::gadgets::Kind![F; Element<'_, _>] as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)
    }
}

impl<'params, C: Cycle> implicit_app::WitnessLeaf<'params, C> {
    pub fn new(params: &'params C::Params) -> Self {
        Self {
            poseidon_params: C::circuit_poseidon(params),
        }
    }

    pub fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        (dr, witness, _left, _right): (
            &mut D,
            DriverValue<D, C::CircuitField>,
            Encoder<'dr, 'source, D, (), HEADER_SIZE>,
            Encoder<'dr, 'source, D, (), HEADER_SIZE>,
        ),
    ) -> Result<(
        (
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, implicit_app::LeafNode, HEADER_SIZE>,
        ),
        DriverValue<D, C::CircuitField>,
    )>
    where
        Self: 'dr,
    {
        let leaf = Element::alloc(dr, witness)?;
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, &leaf)?;
        let leaf = sponge.squeeze(dr)?;
        let leaf_value = leaf.value().map(|v| *v);
        let leaf_encoded = Encoded::from_gadget(leaf);

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                leaf_encoded,
            ),
            leaf_value,
        ))
    }
}

impl<'params, C: Cycle> implicit_app::Hash2<'params, C> {
    pub fn new(params: &'params C::Params) -> Self {
        Self {
            poseidon_params: C::circuit_poseidon(params),
        }
    }

    pub fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        (dr, _witness, left, right): (
            &mut D,
            DriverValue<D, ()>,
            Encoder<'dr, 'source, D, implicit_app::LeafNode, HEADER_SIZE>,
            Encoder<'dr, 'source, D, implicit_app::LeafNode, HEADER_SIZE>,
        ),
    ) -> Result<(
        (
            Encoded<'dr, D, implicit_app::LeafNode, HEADER_SIZE>,
            Encoded<'dr, D, implicit_app::LeafNode, HEADER_SIZE>,
            Encoded<'dr, D, implicit_app::InternalNode, HEADER_SIZE>,
        ),
        DriverValue<D, C::CircuitField>,
    )>
    where
        Self: 'dr,
    {
        let left = left.encode(dr)?;
        let right = right.encode(dr)?;

        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, left.as_gadget())?;
        sponge.absorb(dr, right.as_gadget())?;
        let output = sponge.squeeze(dr)?;
        let output_value = output.value().map(|v| *v);
        let output = Encoded::from_gadget(output);

        Ok(((left, right, output), output_value))
    }
}

#[test]
fn test_implicit_defaults() -> Result<()> {
    use rand::{SeedableRng, rngs::StdRng};
    use ragu_circuits::polynomials::R;
    use ragu_pasta::Fp;

    // Verify the constants are correct
    assert_eq!(implicit_app::LeafNode::HEADER_SUFFIX, 0);
    assert_eq!(implicit_app::InternalNode::HEADER_SUFFIX, 1);
    assert_eq!(implicit_app::WitnessLeaf::<Pasta>::STEP_INDEX, 0);
    assert_eq!(implicit_app::Hash2::<Pasta>::STEP_INDEX, 1);

    // Build and use the application
    let pasta = Pasta::baked();
    let app = implicit_app::build::<Pasta, R<13>, 4>(pasta)?;

    let mut rng = StdRng::seed_from_u64(5678);

    let leaf1 = app.seed(
        &mut rng,
        implicit_app::WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(100u64),
    )?;
    let leaf1 = leaf1.0.carry(leaf1.1);
    assert!(app.verify(&leaf1, &mut rng)?);

    let leaf2 = app.seed(
        &mut rng,
        implicit_app::WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(200u64),
    )?;
    let leaf2 = leaf2.0.carry(leaf2.1);

    let merged = app.fuse(
        &mut rng,
        implicit_app::Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        (),
        leaf1,
        leaf2,
    )?;
    let merged = merged.0.carry::<implicit_app::InternalNode>(merged.1);
    assert!(app.verify(&merged, &mut rng)?);

    Ok(())
}

// ============================================================================
// Original tests with explicit parameters
// ============================================================================

#[test]
fn test_generated_constants() {
    // Check that the generated constants are correct
    assert_eq!(test_app::LeafNode::HEADER_SUFFIX, 0);
    assert_eq!(test_app::InternalNode::HEADER_SUFFIX, 1);
    assert_eq!(test_app::WitnessLeaf::<Pasta>::STEP_INDEX, 0);
    assert_eq!(test_app::Hash2::<Pasta>::STEP_INDEX, 1);
}

#[test]
fn test_build_and_use_application() -> Result<()> {
    use rand::{SeedableRng, rngs::StdRng};
    use ragu_circuits::polynomials::R;
    use ragu_pasta::Fp;

    let pasta = Pasta::baked();
    let app = test_app::build::<Pasta, R<13>, 4>(pasta)?;

    let mut rng = StdRng::seed_from_u64(1234);

    // Create two leaf proofs
    let leaf1 = app.seed(
        &mut rng,
        test_app::WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;
    let leaf1 = leaf1.0.carry(leaf1.1);
    assert!(app.verify(&leaf1, &mut rng)?);

    let leaf2 = app.seed(
        &mut rng,
        test_app::WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(43u64),
    )?;
    let leaf2 = leaf2.0.carry(leaf2.1);
    assert!(app.verify(&leaf2, &mut rng)?);

    // Merge the two leaves
    let merged = app.fuse(
        &mut rng,
        test_app::Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        (),
        leaf1,
        leaf2,
    )?;
    let merged = merged.0.carry::<test_app::InternalNode>(merged.1);
    assert!(app.verify(&merged, &mut rng)?);

    Ok(())
}
