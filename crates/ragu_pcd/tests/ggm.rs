//! End-to-end GGM PRF tree example.
//!
//! Two tests over the same `Application`/`DEPTH`:
//!
//! * `epoch_distinctness` — one note, two epochs. Asserts that the
//!   leaves verify, agree with the native reference walk, share a
//!   `delegation_id`, encode the correct epoch in the field, and
//!   produce **distinct** nullifiers (different epoch-bit paths).
//! * `note_distinctness` — two notes, the same epoch. Asserts that
//!   both leaves verify and agree with the native walk, that
//!   `delegation_id`s differ between notes, and that nullifiers also
//!   differ (so a different note isn't somehow folded back into the
//!   same nullifier slot).

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
use ragu_testing::pcd::ggm::{
    GgmFirstStep, GgmLeaf, GgmSeed, GgmStep, MasterHeader, NullifierHeader, native_ggm_walk,
};
use rand::{SeedableRng, rngs::StdRng};

// Tight to the widest header: DelegationHeader carries 4 field elements,
// and the slot at HEADER_SIZE-1 is reserved for the suffix tag.
const HEADER_SIZE: usize = 5;
const DEPTH: u8 = 6;

type App<'p> = Application<'p, Pasta, ProductionRank, HEADER_SIZE>;

struct Note {
    pk: Fp,
    value: Fp,
    psi: Fp,
    rcm: Fp,
}

impl Note {
    fn sample(rng: &mut StdRng) -> Self {
        Note {
            pk: Fp::random(&mut *rng),
            value: Fp::from(100_000_000u64),
            psi: Fp::random(&mut *rng),
            rcm: Fp::random(&mut *rng),
        }
    }
}

fn build_app(pasta: &'static <Pasta as Cycle>::Params) -> Result<App<'static>> {
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .register(GgmSeed::<Pasta> { poseidon_params })?
        .register(GgmFirstStep::<Pasta> { poseidon_params })?
        .register(GgmStep::<Pasta, DEPTH> { poseidon_params })?
        .register(GgmLeaf::<DEPTH>)?
        .finalize(pasta)
}

fn seed(
    app: &App<'_>,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    nk: Fp,
    note: &Note,
    trap: Fp,
) -> Result<Pcd<Pasta, ProductionRank, MasterHeader>> {
    let (master, _) = app.seed(
        rng,
        GgmSeed::<Pasta> { poseidon_params },
        (nk, note.pk, note.value, note.psi, note.rcm, trap),
    )?;
    Ok(master)
}

/// Walks from `master` down to a leaf at `epoch`. Panics if `epoch` does
/// not fit in `DEPTH` bits.
fn walk_to(
    app: &App<'_>,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    master: Pcd<Pasta, ProductionRank, MasterHeader>,
    epoch: u32,
) -> Result<Pcd<Pasta, ProductionRank, NullifierHeader>> {
    assert!(
        (epoch as u64) < (1u64 << DEPTH),
        "epoch {epoch:#x} must fit in DEPTH={DEPTH} bits",
    );

    let msb = (epoch >> (DEPTH - 1)) & 1 != 0;
    let trivial = app.seeded_trivial_pcd(rng);
    let (mut pcd, _) = app.fuse(
        rng,
        GgmFirstStep::<Pasta> { poseidon_params },
        msb,
        master,
        trivial,
    )?;

    for d in (0..DEPTH - 1).rev() {
        let bit = (epoch >> d) & 1 != 0;
        let trivial = app.seeded_trivial_pcd(rng);
        let (next, _) = app.fuse(
            rng,
            GgmStep::<Pasta, DEPTH> { poseidon_params },
            bit,
            pcd,
            trivial,
        )?;
        pcd = next;
    }

    let trivial = app.seeded_trivial_pcd(rng);
    let (leaf, _) = app.fuse(rng, GgmLeaf::<DEPTH>, (), pcd, trivial)?;
    Ok(leaf)
}

/// Native expected `(nullifier, epoch, delegation_id)` for a
/// `(nk, note, trap)` tuple at `epoch`.
fn expected(
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    nk: Fp,
    note: &Note,
    trap: Fp,
    epoch: u32,
) -> Result<(Fp, Fp, Fp)> {
    native_ggm_walk::<Pasta>(
        poseidon_params,
        (nk, note.pk, note.value, note.psi, note.rcm, trap),
        epoch,
        DEPTH,
    )
}

#[test]
fn epoch_distinctness() -> Result<()> {
    let pasta = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);
    let app = build_app(pasta)?;

    let mut rng = StdRng::seed_from_u64(1234);
    let nk = Fp::random(&mut rng);
    let note = Note::sample(&mut rng);
    let trap = Fp::random(&mut rng);

    // Seed once. `cm`, `mk`, and `delegation_id` are all derived
    // in-circuit from `(nk, note, trap)`.
    let master = seed(&app, &mut rng, poseidon, nk, &note, trap)?;
    assert!(app.verify(&master, &mut rng)?);

    // Walk to two distinct epochs with near-maximal bit-path divergence.
    let epoch_a: u32 = 0b00_0011;
    let epoch_b: u32 = 0b11_1100;
    assert_ne!(epoch_a, epoch_b);

    let leaf_a = walk_to(&app, &mut rng, poseidon, master.clone(), epoch_a)?;
    let leaf_b = walk_to(&app, &mut rng, poseidon, master, epoch_b)?;

    assert!(app.verify(&leaf_a, &mut rng)?);
    assert!(app.verify(&leaf_b, &mut rng)?);

    let (nf_a, ep_a, did_a) = *leaf_a.data();
    let (nf_b, ep_b, did_b) = *leaf_b.data();

    // Each walk agrees with the native reference.
    assert_eq!(
        (nf_a, ep_a, did_a),
        expected(poseidon, nk, &note, trap, epoch_a)?,
        "leaf A disagrees with native walk",
    );
    assert_eq!(
        (nf_b, ep_b, did_b),
        expected(poseidon, nk, &note, trap, epoch_b)?,
        "leaf B disagrees with native walk",
    );

    // delegation_id depends only on the note, not on the epoch walked.
    assert_eq!(did_a, did_b, "same note must yield same delegation_id");

    // The header's `epoch` slot equals the walked epoch, lifted into the field.
    assert_eq!(ep_a, Fp::from(epoch_a as u64));
    assert_eq!(ep_b, Fp::from(epoch_b as u64));

    // Different epoch-bit paths produce different GGM leaf values.
    assert_ne!(
        nf_a, nf_b,
        "distinct epochs on the same note must produce distinct nullifiers",
    );

    Ok(())
}

#[test]
fn note_distinctness() -> Result<()> {
    let pasta = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);
    let app = build_app(pasta)?;

    let mut rng = StdRng::seed_from_u64(4321);
    // One user's `nk`, two distinct notes (different psi/rcm), two
    // distinct delegation trapdoors.
    let nk = Fp::random(&mut rng);
    let note_a = Note::sample(&mut rng);
    let note_b = Note::sample(&mut rng);
    let trap_a = Fp::random(&mut rng);
    let trap_b = Fp::random(&mut rng);

    let master_a = seed(&app, &mut rng, poseidon, nk, &note_a, trap_a)?;
    let master_b = seed(&app, &mut rng, poseidon, nk, &note_b, trap_b)?;

    // Walk both notes to the same epoch.
    let epoch: u32 = 0b01_0101;
    let leaf_a = walk_to(&app, &mut rng, poseidon, master_a, epoch)?;
    let leaf_b = walk_to(&app, &mut rng, poseidon, master_b, epoch)?;

    assert!(app.verify(&leaf_a, &mut rng)?);
    assert!(app.verify(&leaf_b, &mut rng)?);

    let (nf_a, ep_a, did_a) = *leaf_a.data();
    let (nf_b, ep_b, did_b) = *leaf_b.data();

    assert_eq!(
        (nf_a, ep_a, did_a),
        expected(poseidon, nk, &note_a, trap_a, epoch)?,
        "leaf A disagrees with native walk",
    );
    assert_eq!(
        (nf_b, ep_b, did_b),
        expected(poseidon, nk, &note_b, trap_b, epoch)?,
        "leaf B disagrees with native walk",
    );

    // Same epoch on both walks; the field encoding is identical.
    assert_eq!(ep_a, Fp::from(epoch as u64));
    assert_eq!(ep_a, ep_b);

    // Different notes must yield different delegation_ids.
    assert_ne!(
        did_a, did_b,
        "distinct notes must yield distinct delegation_ids",
    );

    // Different notes at the same epoch must yield different nullifiers
    // (no collision back into the same nullifier slot).
    assert_ne!(
        nf_a, nf_b,
        "distinct notes at the same epoch must produce distinct nullifiers",
    );

    Ok(())
}
