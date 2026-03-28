//! End-to-end regression for the d-wire alloc-pairing path.
//!
//! PR #606 changed `alloc()` pairing from `(a, b, 0, 0)` to `(0, b, 0, d)`,
//! placing the second allocation in each pair on the d-wire. This test
//! verifies that d-wire values survive the full proof lifecycle:
//! seed → fuse → verify.
//!
//! The leaf step allocates four witness-derived values in sequence.
//! Consecutive allocs pair into the `(0, b, 0, d)` gate layout, so the
//! second and fourth values land on the d-wire. All four values are hashed
//! into the output header, making the proof's public output transitively
//! depend on the d-wire region of r(X).

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, emulator::Emulator},
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
use rand::SeedableRng;
use rand::rngs::StdRng;

type Sim = Emulator<ragu_core::drivers::emulator::Wireless<ragu_core::maybe::Always<()>, Fp>>;

/// Compute the expected leaf hash: Poseidon(w, w+1, w², w³).
fn expected_leaf_hash(poseidon: &<Pasta as Cycle>::CircuitPoseidon, w: Fp) -> Result<Fp> {
    let mut dr = Sim::execute();
    let v1 = Element::constant(&mut dr, w);
    let v2 = Element::constant(&mut dr, w + Fp::ONE);
    let v3 = Element::constant(&mut dr, w.square());
    let v4 = Element::constant(&mut dr, w.square() * w);

    let mut sponge = Sponge::new(&mut dr, poseidon);
    sponge.absorb(&mut dr, &v1)?;
    sponge.absorb(&mut dr, &v2)?;
    sponge.absorb(&mut dr, &v3)?;
    sponge.absorb(&mut dr, &v4)?;
    Ok(*sponge.squeeze(&mut dr)?.value().take())
}

/// Compute the expected fuse hash: Poseidon(left, right).
fn expected_fuse_hash(
    poseidon: &<Pasta as Cycle>::CircuitPoseidon,
    left: Fp,
    right: Fp,
) -> Result<Fp> {
    let mut dr = Sim::execute();
    let left = Element::constant(&mut dr, left);
    let right = Element::constant(&mut dr, right);

    let mut sponge = Sponge::new(&mut dr, poseidon);
    sponge.absorb(&mut dr, &left)?;
    sponge.absorb(&mut dr, &right)?;
    Ok(*sponge.squeeze(&mut dr)?.value().take())
}

struct DWireHeader;

impl<F: Field> Header<F> for DWireHeader {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, witness)
    }
}

struct DWireInternalHeader;

impl<F: Field> Header<F> for DWireInternalHeader {
    const SUFFIX: Suffix = Suffix::new(1);
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, witness)
    }
}

/// Leaf step that exercises d-wire alloc pairing.
///
/// Allocates four witness-derived values. With the post-#606 alloc pairing,
/// these group into two gates:
///
///   Gate 0: `(0, w,       0, w+1)`  — w on b-wire, w+1 on d-wire
///   Gate 1: `(0, w*w,     0, w^3)`  — w² on b-wire, w³ on d-wire
///
/// All four values are hashed into the output, so the header depends on
/// the d-wire-paired values.
struct DWireLeaf<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for DWireLeaf<'_, C> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = C::CircuitField;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = DWireHeader;

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
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        // Derive four distinct values from the witness.
        let w1 = witness.clone();
        let w2 = witness.clone().map(|w| w + C::CircuitField::ONE);
        let w3 = witness.clone().map(|w| w.square());
        let w4 = witness.map(|w| w.square() * w);

        // Allocate all four — consecutive allocs pair into (0, b, 0, d):
        //   alloc(w1) → b-wire of gate 0
        //   alloc(w2) → d-wire of gate 0
        //   alloc(w3) → b-wire of gate 1
        //   alloc(w4) → d-wire of gate 1
        let v1 = Element::alloc(dr, w1)?;
        let v2 = Element::alloc(dr, w2)?;
        let v3 = Element::alloc(dr, w3)?;
        let v4 = Element::alloc(dr, w4)?;

        // Hash all four — output transitively depends on d-wire values (v2, v4).
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, &v1)?;
        sponge.absorb(dr, &v2)?;
        sponge.absorb(dr, &v3)?;
        sponge.absorb(dr, &v4)?;
        let output = sponge.squeeze(dr)?;
        let output_data = output.value().map(|v| *v);
        let output = Encoded::from_gadget(output);

        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            output_data,
            D::unit(),
        ))
    }
}

/// Fuse step that hashes two d-wire leaf headers together.
struct DWireFuse<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for DWireFuse<'_, C> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = DWireHeader;
    type Right = DWireHeader;
    type Output = DWireInternalHeader;

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
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
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

/// Seed two leaves that exercise d-wire alloc pairing, fuse them, and
/// verify the fused proof. If the d-wire region of r(X) is incorrectly
/// assembled, committed, or evaluated, verification will fail.
#[test]
fn d_wire_alloc_pairing_survives_fuse() -> Result<()> {
    let pasta = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);

    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(DWireLeaf {
            poseidon_params: poseidon,
        })?
        .register(DWireFuse {
            poseidon_params: poseidon,
        })?
        .finalize(pasta)?;

    let mut rng = StdRng::seed_from_u64(606);

    let w1 = Fp::from(7u64);
    let w2 = Fp::from(13u64);

    // Seed two leaves with distinct witness values.
    let (leaf1, _) = app.seed(
        &mut rng,
        DWireLeaf {
            poseidon_params: poseidon,
        },
        w1,
    )?;
    assert!(app.verify(&leaf1, &mut rng)?, "seeded leaf1 should verify");

    let (leaf2, _) = app.seed(
        &mut rng,
        DWireLeaf {
            poseidon_params: poseidon,
        },
        w2,
    )?;
    assert!(app.verify(&leaf2, &mut rng)?, "seeded leaf2 should verify");

    // Verify public outputs match the expected Poseidon hashes.
    // This proves the d-wire-paired values (w+1, w³) contributed correctly
    // to the output — not just that the proof is self-consistent.
    let expected_leaf1 = expected_leaf_hash(poseidon, w1)?;
    let expected_leaf2 = expected_leaf_hash(poseidon, w2)?;
    assert_eq!(*leaf1.data(), expected_leaf1, "leaf1 header mismatch");
    assert_eq!(*leaf2.data(), expected_leaf2, "leaf2 header mismatch");

    // Fuse and verify — exercises d-wire through the full proof pipeline.
    let (fused, _) = app.fuse(
        &mut rng,
        DWireFuse {
            poseidon_params: poseidon,
        },
        (),
        leaf1,
        leaf2,
    )?;
    assert!(
        app.verify(&fused, &mut rng)?,
        "fused proof with d-wire-paired allocs should verify"
    );

    let expected_fused = expected_fuse_hash(poseidon, expected_leaf1, expected_leaf2)?;
    assert_eq!(*fused.data(), expected_fused, "fused header mismatch");

    Ok(())
}
