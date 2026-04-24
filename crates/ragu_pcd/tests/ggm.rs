use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::Pcd;
use ragu_testing::pcd::ggm::{
    DelegationIdWitness, DelegationTrapdoorWitness, EpochIndexWitness, GGM_ARITY, GGM_DEPTH,
    GGM_MAX, GgmDelegateHeader, GgmIndex, GgmMasterHeader, GgmNullifierHeader, GgmPrivateHeader,
    NoteWitness, NullifierKeyWitness, NullifierWitness, fixtures, native_ggm,
};
use rand::{SeedableRng, rngs::StdRng};

type App = fixtures::App<Pasta>;

fn pasta_params() -> (
    &'static <Pasta as Cycle>::Params,
    &'static <Pasta as Cycle>::CircuitPoseidon,
) {
    let params = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(params);
    (params, poseidon)
}

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

    fn to_witness(&self) -> NoteWitness<Fp> {
        NoteWitness {
            pk: self.pk,
            value: self.value,
            psi: self.psi,
            rcm: self.rcm,
        }
    }
}

/// Extract the `level`-th MSB-first base-`ARITY` digit of `epoch`
fn chunk_at(epoch: GgmIndex, level: u8) -> u8 {
    let place = (GGM_ARITY as u16).pow(u32::from(GGM_DEPTH - 1 - level));
    ((epoch / place) % GGM_ARITY as u16) as u8
}

fn seed(
    app: &App,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    nk: Fp,
    note: &Note,
) -> Result<Pcd<Pasta, ProductionRank, GgmMasterHeader>> {
    Ok(fixtures::seed_master(
        app,
        poseidon_params,
        rng,
        (NullifierKeyWitness(nk), note.to_witness()),
    ))
}

fn descend_pre_blind(
    app: &App,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    master_pcd: Pcd<Pasta, ProductionRank, GgmMasterHeader>,
    epoch: GgmIndex,
    depth_to: u8,
) -> Result<Pcd<Pasta, ProductionRank, GgmPrivateHeader>> {
    assert!(
        (1..=GGM_DEPTH).contains(&depth_to),
        "depth_to {depth_to} must be in [1, {GGM_DEPTH}]",
    );

    let mut node_pcd =
        fixtures::master_step(app, poseidon_params, rng, master_pcd, chunk_at(epoch, 0));

    for level in 1..depth_to {
        node_pcd = fixtures::node_step(app, poseidon_params, rng, node_pcd, chunk_at(epoch, level));
    }
    Ok(node_pcd)
}

fn blind(
    app: &App,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    node_pcd: Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
    trap: Fp,
) -> Result<Pcd<Pasta, ProductionRank, GgmDelegateHeader>> {
    Ok(fixtures::blind_step(
        app,
        poseidon_params,
        rng,
        node_pcd,
        DelegationTrapdoorWitness(trap),
    ))
}

fn descend_post_blind(
    app: &App,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    mut delegate_pcd: Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
    epoch: GgmIndex,
    depth_from: u8,
) -> Result<Pcd<Pasta, ProductionRank, GgmDelegateHeader>> {
    for level in depth_from..GGM_DEPTH {
        delegate_pcd = fixtures::delegate_step(
            app,
            poseidon_params,
            rng,
            delegate_pcd,
            chunk_at(epoch, level),
        );
    }
    Ok(delegate_pcd)
}

fn finish(
    app: &App,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    delegate_pcd: Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
) -> Result<Pcd<Pasta, ProductionRank, GgmNullifierHeader>> {
    Ok(fixtures::nullifier_step(
        app,
        poseidon_params,
        rng,
        delegate_pcd,
    ))
}

fn blind_at_leaf(
    app: &App,
    rng: &mut StdRng,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    master_pcd: Pcd<Pasta, ProductionRank, GgmMasterHeader>,
    epoch: GgmIndex,
    trap: Fp,
) -> Result<Pcd<Pasta, ProductionRank, GgmNullifierHeader>> {
    let node_pcd = descend_pre_blind(app, rng, poseidon_params, master_pcd, epoch, GGM_DEPTH)?;
    let delegate = blind(app, rng, poseidon_params, node_pcd, trap)?;
    finish(app, rng, poseidon_params, delegate)
}

fn expected(
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    nk: Fp,
    note: &Note,
    trap: Fp,
    epoch: GgmIndex,
) -> Result<(
    NullifierWitness<Fp>,
    EpochIndexWitness<Fp>,
    DelegationIdWitness<Fp>,
)> {
    native_ggm::<Pasta>(
        poseidon_params,
        NullifierKeyWitness(nk),
        note.to_witness(),
        DelegationTrapdoorWitness(trap),
        u32::from(epoch),
    )
}

#[test]
fn ggm_epoch_distinctness() -> Result<()> {
    let (params, poseidon) = pasta_params();
    let (app, poseidon) = fixtures::build_app::<Pasta>(params, poseidon);

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

    let leaf_a = blind_at_leaf(&app, &mut rng, poseidon, master.clone(), epoch_a, trap)?;
    let leaf_b = blind_at_leaf(&app, &mut rng, poseidon, master, epoch_b, trap)?;

    assert!(app.verify(&leaf_a, &mut rng)?);
    assert!(app.verify(&leaf_b, &mut rng)?);

    let (nf_a, ep_a, did_a) = *leaf_a.data();
    let (nf_b, ep_b, did_b) = *leaf_b.data();

    assert_eq!(
        *leaf_a.data(),
        expected(poseidon, nk, &note, trap, epoch_a)?,
        "leaf A disagrees with native walk",
    );
    assert_eq!(
        *leaf_b.data(),
        expected(poseidon, nk, &note, trap, epoch_b)?,
        "leaf B disagrees with native walk",
    );

    assert_eq!(
        did_a.0, did_b.0,
        "same note + trap must yield same delegation_id"
    );
    assert_eq!(ep_a.0, Fp::from(u64::from(epoch_a)));
    assert_eq!(ep_b.0, Fp::from(u64::from(epoch_b)));
    assert_ne!(
        nf_a.0, nf_b.0,
        "distinct epochs on the same note must produce distinct nullifiers",
    );

    Ok(())
}

#[test]
fn ggm_note_distinctness() -> Result<()> {
    let (params, poseidon) = pasta_params();
    let (app, poseidon) = fixtures::build_app::<Pasta>(params, poseidon);

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

    let leaf_a = blind_at_leaf(&app, &mut rng, poseidon, master_a, epoch, trap_a)?;
    let leaf_b = blind_at_leaf(&app, &mut rng, poseidon, master_b, epoch, trap_b)?;

    assert!(app.verify(&leaf_a, &mut rng)?);
    assert!(app.verify(&leaf_b, &mut rng)?);

    let (nf_a, ep_a, did_a) = *leaf_a.data();
    let (nf_b, ep_b, did_b) = *leaf_b.data();

    assert_eq!(
        *leaf_a.data(),
        expected(poseidon, nk, &note_a, trap_a, epoch)?,
    );
    assert_eq!(
        *leaf_b.data(),
        expected(poseidon, nk, &note_b, trap_b, epoch)?,
    );

    assert_eq!(ep_a.0, Fp::from(u64::from(epoch)));
    assert_eq!(ep_a.0, ep_b.0);
    assert_ne!(
        did_a.0, did_b.0,
        "distinct notes must yield distinct delegation_ids"
    );
    assert_ne!(
        nf_a.0, nf_b.0,
        "distinct notes at the same epoch must produce distinct nullifiers",
    );

    Ok(())
}

#[test]
fn ggm_blind_distinctness() -> Result<()> {
    let (params, poseidon) = pasta_params();
    let (app, poseidon) = fixtures::build_app::<Pasta>(params, poseidon);

    let mut rng = StdRng::seed_from_u64(9001);
    let nk = Fp::random(&mut rng);
    let note = Note::sample(&mut rng);
    let trap_a = Fp::random(&mut rng);
    let trap_b = Fp::random(&mut rng);
    assert_ne!(trap_a, trap_b);

    let epoch: GgmIndex = 0b1011_0010_1101;

    let master = seed(&app, &mut rng, poseidon, nk, &note)?;
    let node_pcd = descend_pre_blind(&app, &mut rng, poseidon, master, epoch, GGM_DEPTH)?;

    // Two independent blind+finish with different trapdoors.
    let leaf_a = {
        let delegate = blind(&app, &mut rng, poseidon, node_pcd.clone(), trap_a)?;
        finish(&app, &mut rng, poseidon, delegate)?
    };
    let leaf_b = {
        let delegate = blind(&app, &mut rng, poseidon, node_pcd, trap_b)?;
        finish(&app, &mut rng, poseidon, delegate)?
    };

    assert!(app.verify(&leaf_a, &mut rng)?);
    assert!(app.verify(&leaf_b, &mut rng)?);

    let (nf_a, _, did_a) = *leaf_a.data();
    let (nf_b, _, did_b) = *leaf_b.data();

    assert_eq!(
        nf_a.0, nf_b.0,
        "same GGM leaf must produce the same nullifier regardless of trap",
    );
    assert_ne!(
        did_a.0, did_b.0,
        "distinct traps must yield distinct delegation_ids",
    );

    Ok(())
}

#[test]
fn ggm_blind_path_equivalence() -> Result<()> {
    let (params, poseidon) = pasta_params();
    let (app, poseidon) = fixtures::build_app::<Pasta>(params, poseidon);

    let mut rng = StdRng::seed_from_u64(7777);
    let nk = Fp::random(&mut rng);
    let note = Note::sample(&mut rng);
    let trap = Fp::random(&mut rng);
    let epoch: GgmIndex = 0b1100_1001_0110;

    let master = seed(&app, &mut rng, poseidon, nk, &note)?;

    // Path A: blind at leaf.
    let leaf_a = blind_at_leaf(&app, &mut rng, poseidon, master.clone(), epoch, trap)?;

    // Path B: blind at mid-depth, continue via GgmDelegateStep.
    let b = GGM_DEPTH / 2;
    let node_pcd = descend_pre_blind(&app, &mut rng, poseidon, master, epoch, b)?;
    let delegate = blind(&app, &mut rng, poseidon, node_pcd, trap)?;
    let delegate = descend_post_blind(&app, &mut rng, poseidon, delegate, epoch, b)?;
    let leaf_b = finish(&app, &mut rng, poseidon, delegate)?;

    assert!(app.verify(&leaf_a, &mut rng)?);
    assert!(app.verify(&leaf_b, &mut rng)?);

    assert_eq!(
        *leaf_a.data(),
        *leaf_b.data(),
        "blind-at-leaf and blind-early paths must produce identical headers",
    );

    Ok(())
}
