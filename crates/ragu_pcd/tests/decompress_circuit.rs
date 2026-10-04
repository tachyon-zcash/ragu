//! The decompressed verifier end to end on a real compressed proof: both
//! sides' circuits accept the honest proof, and a message or statement
//! tampered with after the witness is prepared fails one of them. The
//! tamperings leave the witness's $G'$ honest; a prover who recomputes
//! $G'$ to fit is the open gap the module records, and is not covered.

use ragu_core::pasta::{Fp, Fq, Pasta};
use ragu_primitives::Simulator;
use udon::field::Field;

use super::{Witness, circuit_field_side, scalar_field_side};
use crate::{
    CompressedProof,
    decompress::support::{HEADER_SIZE, Setup, TestR},
};

fn witness(setup: &Setup) -> Witness<Pasta> {
    let pcd = setup.proof.clone().carry(());
    Witness::prepare::<TestR, HEADER_SIZE, _, ()>(&setup.app, &pcd).expect("the proof verifies")
}

/// Runs both sides on `witness`; `Ok` with the two sides' gate counts if
/// both accept.
fn run(witness: &Witness<Pasta>) -> crate::Result<(usize, usize)> {
    let circuit = Simulator::simulate((), |dr, _| {
        circuit_field_side::<_, Pasta, TestR, HEADER_SIZE>(dr, crate::pasta::baked(), witness)
    })?;
    let scalar = Simulator::simulate((), |dr, _| {
        scalar_field_side::<_, Pasta, TestR>(dr, witness)
    })?;
    Ok((circuit.num_gates(), scalar.num_gates()))
}

#[test]
fn accepts_the_honest_proof() {
    let setup = Setup::new();
    let witness = witness(&setup);
    let (circuit, scalar) = run(&witness).expect("both sides accept");
    std::println!("circuit-field side: {circuit} gates; scalar-field side: {scalar} gates");
}

#[test]
fn rejects_tampering() {
    let setup = Setup::new();
    let honest = witness(&setup);
    let tamperings: [fn(&mut CompressedProof<Pasta>); 5] = [
        |proof| proof.native.reduction.openings[0] += Fp::ONE,
        |proof| proof.native.opening.c += Fp::ONE,
        |proof| proof.nested.reduction.fold.inner_epsilon += Fq::ONE,
        |proof| proof.nested.batch.evaluations[3] += Fq::ONE,
        |proof| proof.instance.c += Fp::ONE,
    ];
    for tamper in tamperings {
        let mut tampered = Witness {
            proof: honest.proof.clone(),
            header: honest.header.clone(),
            fuse: honest.fuse,
            native: honest.native.clone(),
            nested: honest.nested.clone(),
            ab_terms: honest.ab_terms.clone(),
        };
        tamper(&mut tampered.proof);
        assert!(run(&tampered).is_err(), "a tampered proof fails a side");
    }

    let mut tampered = Witness {
        proof: honest.proof.clone(),
        header: honest.header.clone(),
        fuse: honest.fuse,
        native: honest.native.clone(),
        nested: honest.nested.clone(),
        ab_terms: honest.ab_terms.clone(),
    };
    tampered.header[0] += Fp::ONE;
    assert!(run(&tampered).is_err(), "a tampered statement fails a side");
}
