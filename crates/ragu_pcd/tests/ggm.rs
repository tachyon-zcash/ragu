use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
use ragu_testing::pcd::ggm::{
    GGM_ARITY, GGM_CHUNK_SIZE, GGM_DEPTH, GGM_MAX, GgmBlindStep, GgmDelegateHeader,
    GgmDelegateStep, GgmIndex, GgmMasterHeader, GgmMasterSeed, GgmMasterStep, GgmNodeStep,
    GgmNullifierHeader, GgmNullifierStep, GgmPrivateHeader, HEADER_SIZE, native_ggm,
};
use rand::{SeedableRng, rngs::StdRng};

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

fn build_app<const CHUNK_SIZE: u8, const DEPTH: u8>(
    pasta: &'static <Pasta as Cycle>::Params,
) -> Result<App<'static>> {
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .register(GgmMasterSeed::<Pasta> { poseidon_params })?
        .register(GgmMasterStep::<Pasta, CHUNK_SIZE> { poseidon_params })?
        .register(GgmNodeStep::<Pasta, CHUNK_SIZE, DEPTH> { poseidon_params })?
        .register(GgmBlindStep::<Pasta> { poseidon_params })?
        .register(GgmDelegateStep::<Pasta, CHUNK_SIZE, DEPTH> { poseidon_params })?
        .register(GgmNullifierStep::<Pasta, DEPTH> { poseidon_params })?
        .finalize(pasta)
}

/// Extract the `level`-th MSB-first base-`ARITY` digit of `epoch`
fn chunk_at<const ARITY: u8, const DEPTH: u8>(epoch: GgmIndex, level: u8) -> u8 {
    let place = (ARITY as GgmIndex).pow(u32::from(DEPTH - 1 - level));
    ((epoch / place) % ARITY as GgmIndex) as u8
}

fn seed(
    app: &App<'_>,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    nk: Fp,
    note: &Note,
) -> Result<Pcd<Pasta, ProductionRank, GgmMasterHeader>> {
    let (master, _) = app.seed(
        rng,
        GgmMasterSeed::<Pasta> { poseidon_params },
        (nk, note.pk, note.value, note.psi, note.rcm),
    )?;
    Ok(master)
}

fn descend_pre_blind<const ARITY: u8, const CHUNK_SIZE: u8, const DEPTH: u8>(
    app: &App<'_>,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    master: Pcd<Pasta, ProductionRank, GgmMasterHeader>,
    epoch: GgmIndex,
    depth_to: u8,
) -> Result<Pcd<Pasta, ProductionRank, GgmPrivateHeader>> {
    assert!(
        (1..=DEPTH).contains(&depth_to),
        "depth_to {depth_to} must be in [1, {DEPTH}]",
    );

    let trivial_pcd = app.seeded_trivial_pcd(rng);
    let (mut node_pcd, _) = app.fuse(
        rng,
        GgmMasterStep::<Pasta, CHUNK_SIZE> { poseidon_params },
        chunk_at::<ARITY, DEPTH>(epoch, 0),
        master,
        trivial_pcd,
    )?;

    for level in 1..depth_to {
        let trivial_pcd = app.seeded_trivial_pcd(rng);
        let (next, _) = app.fuse(
            rng,
            GgmNodeStep::<Pasta, CHUNK_SIZE, DEPTH> { poseidon_params },
            chunk_at::<ARITY, DEPTH>(epoch, level),
            node_pcd,
            trivial_pcd,
        )?;
        node_pcd = next;
    }
    Ok(node_pcd)
}

fn blind(
    app: &App<'_>,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    node_pcd: Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
    trap: Fp,
) -> Result<Pcd<Pasta, ProductionRank, GgmDelegateHeader>> {
    let trivial_pcd = app.seeded_trivial_pcd(rng);
    let (out, _) = app.fuse(
        rng,
        GgmBlindStep::<Pasta> { poseidon_params },
        trap,
        node_pcd,
        trivial_pcd,
    )?;
    Ok(out)
}

fn descend_post_blind<const ARITY: u8, const CHUNK_SIZE: u8, const DEPTH: u8>(
    app: &App<'_>,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    mut delegate_pcd: Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
    epoch: GgmIndex,
    depth_from: u8,
) -> Result<Pcd<Pasta, ProductionRank, GgmDelegateHeader>> {
    for level in depth_from..DEPTH {
        let trivial_pcd = app.seeded_trivial_pcd(rng);
        let (next, _) = app.fuse(
            rng,
            GgmDelegateStep::<Pasta, CHUNK_SIZE, DEPTH> { poseidon_params },
            chunk_at::<ARITY, DEPTH>(epoch, level),
            delegate_pcd,
            trivial_pcd,
        )?;
        delegate_pcd = next;
    }
    Ok(delegate_pcd)
}

fn finish<const DEPTH: u8>(
    app: &App<'_>,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    delegate_pcd: Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
) -> Result<Pcd<Pasta, ProductionRank, GgmNullifierHeader>> {
    let trivial_pcd = app.seeded_trivial_pcd(rng);
    let (out, _) = app.fuse(
        rng,
        GgmNullifierStep::<Pasta, DEPTH> { poseidon_params },
        (),
        delegate_pcd,
        trivial_pcd,
    )?;
    Ok(out)
}

fn blind_at_leaf<const ARITY: u8, const CHUNK_SIZE: u8, const DEPTH: u8>(
    app: &App<'_>,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    master: Pcd<Pasta, ProductionRank, GgmMasterHeader>,
    epoch: GgmIndex,
    trap: Fp,
) -> Result<Pcd<Pasta, ProductionRank, GgmNullifierHeader>> {
    let node_pcd = descend_pre_blind::<ARITY, CHUNK_SIZE, DEPTH>(
        app,
        rng,
        poseidon_params,
        master,
        epoch,
        DEPTH,
    )?;
    let delegate = blind(app, rng, poseidon_params, node_pcd, trap)?;
    finish::<DEPTH>(app, rng, poseidon_params, delegate)
}

fn expected<const CHUNK_SIZE: u8, const DEPTH: u8>(
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    nk: Fp,
    note: &Note,
    trap: Fp,
    epoch: GgmIndex,
) -> Result<(Fp, Fp, Fp)> {
    native_ggm::<Pasta, CHUNK_SIZE, DEPTH>(
        poseidon_params,
        (nk, note.pk, note.value, note.psi, note.rcm),
        trap,
        u32::from(epoch),
    )
}

#[test]
fn epoch_distinctness() -> Result<()> {
    let pasta = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);
    let app = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>(pasta)?;

    let mut rng = StdRng::seed_from_u64(1234);
    let nk = Fp::random(&mut rng);
    let note = Note::sample(&mut rng);
    let trap = Fp::random(&mut rng);

    let master = seed(&app, &mut rng, poseidon, nk, &note)?;
    assert!(app.verify(&master, &mut rng)?);

    // Epochs with maximal bit-path divergence.
    let epoch_a: GgmIndex = 0;
    let epoch_b: GgmIndex = GGM_MAX;
    assert_ne!(epoch_a, epoch_b);

    let leaf_a = blind_at_leaf::<GGM_ARITY, GGM_CHUNK_SIZE, GGM_DEPTH>(
        &app,
        &mut rng,
        poseidon,
        master.clone(),
        epoch_a,
        trap,
    )?;
    let leaf_b = blind_at_leaf::<GGM_ARITY, GGM_CHUNK_SIZE, GGM_DEPTH>(
        &app, &mut rng, poseidon, master, epoch_b, trap,
    )?;

    assert!(app.verify(&leaf_a, &mut rng)?);
    assert!(app.verify(&leaf_b, &mut rng)?);

    let (nf_a, ep_a, did_a) = *leaf_a.data();
    let (nf_b, ep_b, did_b) = *leaf_b.data();

    assert_eq!(
        (nf_a, ep_a, did_a),
        expected::<GGM_CHUNK_SIZE, GGM_DEPTH>(poseidon, nk, &note, trap, epoch_a)?,
        "leaf A disagrees with native walk",
    );
    assert_eq!(
        (nf_b, ep_b, did_b),
        expected::<GGM_CHUNK_SIZE, GGM_DEPTH>(poseidon, nk, &note, trap, epoch_b)?,
        "leaf B disagrees with native walk",
    );

    assert_eq!(
        did_a, did_b,
        "same note + trap must yield same delegation_id"
    );
    assert_eq!(ep_a, Fp::from(u64::from(epoch_a)));
    assert_eq!(ep_b, Fp::from(u64::from(epoch_b)));
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
    let app = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>(pasta)?;

    let mut rng = StdRng::seed_from_u64(4321);
    // Same nk, two distinct notes, two distinct trapdoors.
    let nk = Fp::random(&mut rng);
    let note_a = Note::sample(&mut rng);
    let note_b = Note::sample(&mut rng);
    let trap_a = Fp::random(&mut rng);
    let trap_b = Fp::random(&mut rng);

    let master_a = seed(&app, &mut rng, poseidon, nk, &note_a)?;
    let master_b = seed(&app, &mut rng, poseidon, nk, &note_b)?;

    let epoch: GgmIndex = 0b0101_0101_0101;

    let leaf_a = blind_at_leaf::<GGM_ARITY, GGM_CHUNK_SIZE, GGM_DEPTH>(
        &app, &mut rng, poseidon, master_a, epoch, trap_a,
    )?;
    let leaf_b = blind_at_leaf::<GGM_ARITY, GGM_CHUNK_SIZE, GGM_DEPTH>(
        &app, &mut rng, poseidon, master_b, epoch, trap_b,
    )?;

    assert!(app.verify(&leaf_a, &mut rng)?);
    assert!(app.verify(&leaf_b, &mut rng)?);

    let (nf_a, ep_a, did_a) = *leaf_a.data();
    let (nf_b, ep_b, did_b) = *leaf_b.data();

    assert_eq!(
        (nf_a, ep_a, did_a),
        expected::<GGM_CHUNK_SIZE, GGM_DEPTH>(poseidon, nk, &note_a, trap_a, epoch)?,
    );
    assert_eq!(
        (nf_b, ep_b, did_b),
        expected::<GGM_CHUNK_SIZE, GGM_DEPTH>(poseidon, nk, &note_b, trap_b, epoch)?,
    );

    assert_eq!(ep_a, Fp::from(u64::from(epoch)));
    assert_eq!(ep_a, ep_b);
    assert_ne!(
        did_a, did_b,
        "distinct notes must yield distinct delegation_ids"
    );
    assert_ne!(
        nf_a, nf_b,
        "distinct notes at the same epoch must produce distinct nullifiers",
    );

    Ok(())
}

#[test]
fn blind_distinctness() -> Result<()> {
    let pasta = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);
    let app = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>(pasta)?;

    let mut rng = StdRng::seed_from_u64(9001);
    let nk = Fp::random(&mut rng);
    let note = Note::sample(&mut rng);
    let trap_a = Fp::random(&mut rng);
    let trap_b = Fp::random(&mut rng);
    assert_ne!(trap_a, trap_b);

    let epoch: GgmIndex = 0b1011_0010_1101;

    let master = seed(&app, &mut rng, poseidon, nk, &note)?;
    let node_pcd = descend_pre_blind::<GGM_ARITY, GGM_CHUNK_SIZE, GGM_DEPTH>(
        &app, &mut rng, poseidon, master, epoch, GGM_DEPTH,
    )?;

    // Two independent blind+finish with different trapdoors.
    let leaf_a = {
        let delegate = blind(&app, &mut rng, poseidon, node_pcd.clone(), trap_a)?;
        finish::<GGM_DEPTH>(&app, &mut rng, poseidon, delegate)?
    };
    let leaf_b = {
        let delegate = blind(&app, &mut rng, poseidon, node_pcd, trap_b)?;
        finish::<GGM_DEPTH>(&app, &mut rng, poseidon, delegate)?
    };

    assert!(app.verify(&leaf_a, &mut rng)?);
    assert!(app.verify(&leaf_b, &mut rng)?);

    let (nf_a, _, did_a) = *leaf_a.data();
    let (nf_b, _, did_b) = *leaf_b.data();

    assert_eq!(
        nf_a, nf_b,
        "same GGM leaf must produce the same nullifier regardless of trap",
    );
    assert_ne!(
        did_a, did_b,
        "distinct traps must yield distinct delegation_ids",
    );

    Ok(())
}

#[test]
fn blind_path_equivalence() -> Result<()> {
    let pasta = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);
    let app = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>(pasta)?;

    let mut rng = StdRng::seed_from_u64(7777);
    let nk = Fp::random(&mut rng);
    let note = Note::sample(&mut rng);
    let trap = Fp::random(&mut rng);
    let epoch: GgmIndex = 0b1100_1001_0110;

    let master = seed(&app, &mut rng, poseidon, nk, &note)?;

    // Path A: blind at leaf.
    let leaf_a = blind_at_leaf::<GGM_ARITY, GGM_CHUNK_SIZE, GGM_DEPTH>(
        &app,
        &mut rng,
        poseidon,
        master.clone(),
        epoch,
        trap,
    )?;

    // Path B: blind at mid-depth, continue via GgmDelegateStep.
    let b = GGM_DEPTH / 2;
    let node_pcd = descend_pre_blind::<GGM_ARITY, GGM_CHUNK_SIZE, GGM_DEPTH>(
        &app, &mut rng, poseidon, master, epoch, b,
    )?;
    let delegate = blind(&app, &mut rng, poseidon, node_pcd, trap)?;
    let delegate = descend_post_blind::<GGM_ARITY, GGM_CHUNK_SIZE, GGM_DEPTH>(
        &app, &mut rng, poseidon, delegate, epoch, b,
    )?;
    let leaf_b = finish::<GGM_DEPTH>(&app, &mut rng, poseidon, delegate)?;

    assert!(app.verify(&leaf_a, &mut rng)?);
    assert!(app.verify(&leaf_b, &mut rng)?);

    assert_eq!(
        *leaf_a.data(),
        *leaf_b.data(),
        "blind-at-leaf and blind-early paths must produce identical headers",
    );

    Ok(())
}
