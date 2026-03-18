//! Merkle tree PCD example.
//!
//! Demonstrates the core Ragu PCD workflow: defining Headers, implementing
//! Steps, building an Application, and creating/verifying proofs.
//!
//! Run with:
//!   cargo run -p ragu_pcd --example merkle_tree --features=""
//!
//! (Uses dev-dependencies: ragu_pasta with baked feature)

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{
    ApplicationBuilder,
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};
use ragu_primitives::{Element, poseidon::Sponge};
use rand::{SeedableRng, rngs::StdRng};

// ---------------------------------------------------------------------------
// Headers: define what data flows through the proof tree
// ---------------------------------------------------------------------------

struct LeafNode;

impl<F: Field> Header<F> for LeafNode {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data<'source> = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, witness)
    }
}

struct InternalNode;

impl<F: Field> Header<F> for InternalNode {
    const SUFFIX: Suffix = Suffix::new(1);
    type Data<'source> = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, witness)
    }
}

// ---------------------------------------------------------------------------
// Steps: define computations that produce proofs
// ---------------------------------------------------------------------------

/// Creates a leaf proof by hashing a single witness value.
struct WitnessLeaf<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for WitnessLeaf<'_, C> {
    const INDEX: Index = Index::new(0);

    type Witness<'source> = C::CircuitField;
    type Left = ();
    type Right = ();
    type Output = LeafNode;
    type Aux<'source> = ();

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
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data<'source>>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let leaf = Element::alloc(dr, witness)?;
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, &leaf)?;
        let leaf = sponge.squeeze(dr)?;
        let leaf_data = leaf.value().map(|v| *v);
        let leaf_encoded = Encoded::from_gadget(leaf);

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                leaf_encoded,
            ),
            leaf_data,
            D::unit(),
        ))
    }
}

/// Combines two leaf proofs by hashing their headers together.
struct Hash2<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for Hash2<'_, C> {
    const INDEX: Index = Index::new(1);

    type Witness<'source> = ();
    type Left = LeafNode;
    type Right = LeafNode;
    type Output = InternalNode;
    type Aux<'source> = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, C::CircuitField>,
        right: DriverValue<D, C::CircuitField>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data<'source>>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left = Encoded::new(dr, left)?;
        let right = Encoded::new(dr, right)?;

        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, left.as_gadget())?;
        sponge.absorb(dr, right.as_gadget())?;
        let output = sponge.squeeze(dr)?;
        let output_data = output.value().map(|v| *v);
        let output = Encoded::from_gadget(output);

        Ok(((left, right, output), output_data, D::unit()))
    }
}

// ---------------------------------------------------------------------------
// Main: build application, create proofs, verify
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let pasta = Pasta::baked();
    let mut rng = StdRng::seed_from_u64(12345);

    // Build application
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .register(Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .finalize(pasta)?;

    println!("Application built.");

    // Create leaf proofs
    let (leaf1, _) = app.seed(
        &mut rng,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(100u64),
    )?;
    assert!(app.verify(&leaf1, &mut rng)?);
    println!("Leaf 1 verified (value: 100)");

    let (leaf2, _) = app.seed(
        &mut rng,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(200u64),
    )?;
    assert!(app.verify(&leaf2, &mut rng)?);
    println!("Leaf 2 verified (value: 200)");

    // Combine into internal node
    let (node, _) = app.fuse(
        &mut rng,
        Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        (),
        leaf1,
        leaf2,
    )?;
    assert!(app.verify(&node, &mut rng)?);
    println!("Internal node verified!");

    println!();
    println!("Tree structure:");
    println!("       node");
    println!("      /    \\");
    println!("  leaf1   leaf2");
    println!("  (100)   (200)");

    Ok(())
}
