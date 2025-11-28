use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::polynomials::R;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{
    ApplicationBuilder,
    header::{Header, Suffix},
    step::{Encoded, Encoder, Index, Step},
};
use ragu_primitives::Element;
use ragu_primitives::poseidon::Sponge;
use rand::{SeedableRng, rngs::StdRng};

/// Leaf node header: carries a single field element.
struct LeafNode;

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

/// Internal node header: carries a single field element.
struct InternalNode;

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

/// Creating a leaf from witness data by hashing it.
struct CreateLeaf<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<'params, C: Cycle> Step<C> for CreateLeaf<'params, C> {
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
        _: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        _: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
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

/// Combining two leaves by hashing them together.
struct CombineNodes<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<'params, C: Cycle> Step<C> for CombineNodes<'params, C> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = C::CircuitField;
    type Left = LeafNode;
    type Right = LeafNode;
    type Output = InternalNode;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
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

fn main() -> Result<()> {
    println!("=== Rerandomization Example ===\n");

    let pasta = Pasta::baked();
    let mut rng = StdRng::seed_from_u64(12345);

    println!("Building application...");
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(CreateLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .register(CombineNodes {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .finalize(pasta)?;
    println!("Application ready\n");

    println!("Building original proof...");
    let leaf1 = app.seed(
        &mut rng,
        CreateLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(100u64),
    )?;
    let leaf1 = leaf1.0.carry(leaf1.1);

    let leaf2 = app.seed(
        &mut rng,
        CreateLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(200u64),
    )?;
    let leaf2 = leaf2.0.carry(leaf2.1);

    let root = app.fuse(
        &mut rng,
        CombineNodes {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        (),
        leaf1,
        leaf2,
    )?;
    let root = root.0.carry::<InternalNode>(root.1);
    println!("Original proof created\n");

    println!("Verifying original proof...");
    assert!(app.verify(&root, &mut rng)?);
    println!("✓ Original proof verified\n");

    let original_data = root.data.clone();

    println!("Rerandomizing proof...");
    let rerand = app.rerandomize(root.clone(), &mut rng)?;
    println!("Rerandomized proof created\n");

    println!("Verifying rerandomized proof...");
    assert!(app.verify(&rerand, &mut rng)?);
    println!("✓ Rerandomized proof verified\n");

    println!("Comparing proofs:");
    println!("- Same header data: {}", original_data == rerand.data);
    println!("- Both verify successfully: true");
    println!();

    // Internally, the underlying proof object has different randomness,
    // but here we only rely on the public API:
    //   - same header data
    //   - both proofs verifying successfully

    println!("Creating multiple rerandomizations...");
    let rerand1 = app.rerandomize(root.clone(), &mut rng)?;
    let rerand2 = app.rerandomize(root.clone(), &mut rng)?;
    let rerand3 = app.rerandomize(root.clone(), &mut rng)?;

    assert!(app.verify(&rerand1, &mut rng)?);
    assert!(app.verify(&rerand2, &mut rng)?);
    assert!(app.verify(&rerand3, &mut rng)?);

    println!("✓ Created 3 independent rerandomizations");
    println!("✓ All verify successfully");
    println!("✓ Each proves the same statement with fresh randomness\n");

    Ok(())
}
