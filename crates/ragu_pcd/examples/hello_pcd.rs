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
    header::{Header, Prefix},
    step::{Encoded, Encoder, Index, Step},
};
use ragu_primitives::{Element, Sponge};
use rand::{SeedableRng, rngs::StdRng};

struct LeafNode;

impl<F: Field> Header<F> for LeafNode {
    const PREFIX: Prefix = Prefix::new(0);
    type Data<'source> = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)
    }
}

struct InternalNode;

impl<F: Field> Header<F> for InternalNode {
    const PREFIX: Prefix = Prefix::new(1);
    type Data<'source> = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)
    }
}

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
    println!("=== Hello PCD: Merkle-Tree Example ===\n");

    let pasta = Pasta::baked();
    let mut rng = StdRng::seed_from_u64(12345);

    println!("Building application...");
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(CreateLeaf {
            poseidon_params: pasta.circuit_poseidon(),
        })?
        .register(CombineNodes {
            poseidon_params: pasta.circuit_poseidon(),
        })?
        .finalize(&pasta)?;
    println!("Registered CreateLeaf and CombineNodes\n");

    println!("Creating trivial proof...");
    let trivial = app.trivial().carry::<()>(());
    assert!(app.verify(&trivial, &mut rng)?);
    println!("Trivial proof verified\n");

    println!("Creating leaves...");
    let leaf1 = app.merge(
        &mut rng,
        CreateLeaf {
            poseidon_params: pasta.circuit_poseidon(),
        },
        Fp::from(100u64),
        trivial.clone(),
        trivial.clone(),
    )?;
    let leaf1 = leaf1.0.carry(leaf1.1);
    assert!(app.verify(&leaf1, &mut rng)?);

    let leaf2 = app.merge(
        &mut rng,
        CreateLeaf {
            poseidon_params: pasta.circuit_poseidon(),
        },
        Fp::from(200u64),
        trivial.clone(),
        trivial.clone(),
    )?;
    let leaf2 = leaf2.0.carry(leaf2.1);
    assert!(app.verify(&leaf2, &mut rng)?);
    println!("Created and verified leaf1 and leaf2\n");

    println!("Combining leaves...");
    let node1 = app.merge(
        &mut rng,
        CombineNodes {
            poseidon_params: pasta.circuit_poseidon(),
        },
        (),
        leaf1,
        leaf2,
    )?;
    let node1 = node1.0.carry::<InternalNode>(node1.1);
    assert!(app.verify(&node1, &mut rng)?);
    println!("Combined and verified internal node\n");

    println!("Tree structure:");
    println!("       node1");
    println!("      /     \\");
    println!("  leaf1   leaf2");
    println!("   (100)    (200)");
    println!("\nAll proofs verified successfully!\n");

    Ok(())
}
