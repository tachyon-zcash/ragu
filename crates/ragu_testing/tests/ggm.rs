#![allow(clippy::type_complexity)]

#[path = "../fixtures/ggm.rs"]
mod fixtures;

use ff::Field;
use fixtures::{
    NK, app_setup, cells_for, chunk_at, commit_note, delegate_step, ensure_delegate,
    ensure_nullifier, note, nullifier_step, sample_note, trap,
};
use ragu_pasta::{Fp, Pasta};
use ragu_testing::apps::ggm::{
    DelegationTrapdoorWitness, GGM_DEPTH, GgmIndex, NoteWitness, NullifierKeyWitness, native_ggm,
};
use rand::{SeedableRng, rngs::StdRng};

/// `nf` is `(nk, psi, epoch)`-determined → distinct epochs differ;
/// `did` is `(nk, psi, value, rcm, trap)`-determined → matches.
#[test]
fn ggm_epoch_distinctness() {
    let (app, mut rng, poseidon) = app_setup();
    let note = note();
    let trap = trap();
    let cell = cells_for(commit_note::<Pasta>(poseidon, &note));

    let leaf_a = ensure_nullifier::<Pasta>(
        &cell, &app, poseidon, &mut rng, NK, note, trap, GGM_DEPTH, 0,
    );
    let leaf_b = ensure_nullifier::<Pasta>(
        &cell, &app, poseidon, &mut rng, NK, note, trap, GGM_DEPTH, 1,
    );
    assert!(app.verify(&leaf_b, &mut rng).unwrap());
    assert_eq!(
        *leaf_b.data(),
        native_ggm::<Pasta>(poseidon, NK, note, trap, 1).unwrap(),
    );

    let (nf_a, _, did_a) = *leaf_a.data();
    let (nf_b, _, did_b) = *leaf_b.data();
    assert_ne!(nf_a.0, nf_b.0);
    assert_eq!(did_a.0, did_b.0);
}

/// `trap` doesn't feed `nf` → matches; `did` depends on `trap` → differs.
#[test]
fn ggm_trap_distinctness() {
    let (app, mut rng, poseidon) = app_setup();
    let note = note();
    let trap_a = trap();
    let trap_b = DelegationTrapdoorWitness(Fp::random(&mut StdRng::seed_from_u64(102)));
    let cell = cells_for(commit_note::<Pasta>(poseidon, &note));

    let leaf_a = ensure_nullifier::<Pasta>(
        &cell, &app, poseidon, &mut rng, NK, note, trap_a, GGM_DEPTH, 0,
    );
    let leaf_b = ensure_nullifier::<Pasta>(
        &cell, &app, poseidon, &mut rng, NK, note, trap_b, GGM_DEPTH, 0,
    );
    assert!(app.verify(&leaf_b, &mut rng).unwrap());
    assert_eq!(
        *leaf_b.data(),
        native_ggm::<Pasta>(poseidon, NK, note, trap_b, 0).unwrap(),
    );

    let (nf_a, _, did_a) = *leaf_a.data();
    let (nf_b, _, did_b) = *leaf_b.data();
    assert_eq!(nf_a.0, nf_b.0);
    assert_ne!(did_a.0, did_b.0);
}

/// Distinct `(nk, note)` → both `nf` and `did` differ.
#[test]
fn ggm_identity_distinctness() {
    let (app, mut rng, poseidon) = app_setup();
    let note_a = note();
    let trap = trap();
    let nk_b = NullifierKeyWitness(Fp::random(&mut StdRng::seed_from_u64(103)));
    let note_b = sample_note::<Pasta>(&mut StdRng::seed_from_u64(101), poseidon, nk_b);
    let cell_a = cells_for(commit_note::<Pasta>(poseidon, &note_a));
    let cell_b = cells_for(commit_note::<Pasta>(poseidon, &note_b));

    let leaf_a = ensure_nullifier::<Pasta>(
        &cell_a, &app, poseidon, &mut rng, NK, note_a, trap, GGM_DEPTH, 0,
    );
    let leaf_b = ensure_nullifier::<Pasta>(
        &cell_b, &app, poseidon, &mut rng, nk_b, note_b, trap, GGM_DEPTH, 0,
    );
    assert!(app.verify(&leaf_b, &mut rng).unwrap());
    assert_eq!(
        *leaf_b.data(),
        native_ggm::<Pasta>(poseidon, nk_b, note_b, trap, 0).unwrap(),
    );

    let (nf_a, _, did_a) = *leaf_a.data();
    let (nf_b, _, did_b) = *leaf_b.data();
    assert_ne!(nf_a.0, nf_b.0);
    assert_ne!(did_a.0, did_b.0);
}

/// Same `nk`, fresh note entropy (psi + value + rcm) → both differ.
#[test]
fn ggm_note_entropy_distinctness() {
    let (app, mut rng, poseidon) = app_setup();
    let note_a = note();
    let trap = trap();
    let note_b = sample_note::<Pasta>(&mut StdRng::seed_from_u64(100), poseidon, NK);
    let cell_a = cells_for(commit_note::<Pasta>(poseidon, &note_a));
    let cell_b = cells_for(commit_note::<Pasta>(poseidon, &note_b));

    let leaf_a = ensure_nullifier::<Pasta>(
        &cell_a, &app, poseidon, &mut rng, NK, note_a, trap, GGM_DEPTH, 0,
    );
    let leaf_b = ensure_nullifier::<Pasta>(
        &cell_b, &app, poseidon, &mut rng, NK, note_b, trap, GGM_DEPTH, 0,
    );
    assert!(app.verify(&leaf_b, &mut rng).unwrap());
    assert_eq!(
        *leaf_b.data(),
        native_ggm::<Pasta>(poseidon, NK, note_b, trap, 0).unwrap(),
    );

    let (nf_a, _, did_a) = *leaf_a.data();
    let (nf_b, _, did_b) = *leaf_b.data();
    assert_ne!(nf_a.0, nf_b.0);
    assert_ne!(did_a.0, did_b.0);
}

/// `rcm` doesn't feed `nf` → matches; `cm` depends on `rcm` → `did` differs.
#[test]
fn ggm_rcm_distinctness() {
    let (app, mut rng, poseidon) = app_setup();
    let note_a = note();
    let trap = trap();
    let note_b = NoteWitness {
        rcm: Fp::random(&mut StdRng::seed_from_u64(104)),
        ..note_a
    };
    let cell_a = cells_for(commit_note::<Pasta>(poseidon, &note_a));
    let cell_b = cells_for(commit_note::<Pasta>(poseidon, &note_b));

    let leaf_a = ensure_nullifier::<Pasta>(
        &cell_a, &app, poseidon, &mut rng, NK, note_a, trap, GGM_DEPTH, 0,
    );
    let leaf_b = ensure_nullifier::<Pasta>(
        &cell_b, &app, poseidon, &mut rng, NK, note_b, trap, GGM_DEPTH, 0,
    );
    assert!(app.verify(&leaf_b, &mut rng).unwrap());
    assert_eq!(
        *leaf_b.data(),
        native_ggm::<Pasta>(poseidon, NK, note_b, trap, 0).unwrap(),
    );

    let (nf_a, _, did_a) = *leaf_a.data();
    let (nf_b, _, did_b) = *leaf_b.data();
    assert_eq!(nf_a.0, nf_b.0);
    assert_ne!(did_a.0, did_b.0);
}

/// Path A: cached leaf delegate → nullifier. Path B: cached delegate at
/// `split_depth` → walk forward via `delegate_step` → nullifier. Both use
/// the canonical trap, so the resulting headers must match.
#[test]
fn ggm_blind_path_equivalence() {
    let (app, mut rng, poseidon) = app_setup();
    let note = note();
    let trap = trap();
    let cell = cells_for(commit_note::<Pasta>(poseidon, &note));
    let epoch: GgmIndex = 0;

    let leaf_a = ensure_nullifier::<Pasta>(
        &cell, &app, poseidon, &mut rng, NK, note, trap, GGM_DEPTH, epoch,
    );
    assert!(app.verify(&leaf_a, &mut rng).unwrap());

    for split_depth in [1, GGM_DEPTH / 2, GGM_DEPTH - 1] {
        let mut delegate_b = ensure_delegate(
            &cell, &app, poseidon, &mut rng, NK, note, trap, split_depth, epoch,
        );
        for level in split_depth..GGM_DEPTH {
            delegate_b = delegate_step::<Pasta>(
                &app, poseidon, &mut rng, delegate_b, chunk_at(epoch, level),
            );
        }
        let leaf_b = nullifier_step::<Pasta>(&app, poseidon, &mut rng, delegate_b);

        assert!(app.verify(&leaf_b, &mut rng).unwrap());
        assert_eq!(
            *leaf_a.data(),
            *leaf_b.data(),
            "split_depth={split_depth}: blind-at-leaf and blind-early paths must produce identical headers",
        );
    }
}
