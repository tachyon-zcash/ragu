//! Review V06: pin the challenge stage's polynomial support and fixed bases
//! independently of the generator helper shared by the prover and binders.
//!
//! Calibration: shift StageExt::generator_index_for_a by one gate, rebuilding
//! every production caller together. Both the unit-vector placement oracle
//! and the independently summed partials must fail.

use alloc::vec::Vec;

use ragu_arithmetic::{
    Cycle, FixedGenerators,
    group::{Curve, Group},
};
use ragu_backend::ReferenceBackend;
use ragu_circuits::{
    polynomials::ProductionRank,
    staging::{Stage as _, StageExt},
};
use ragu_pasta::{Ep, EqAffine, Fq, Pasta};

use super::*;
use crate::internal::native::{
    circuits::bind_beta,
    stages::eval::{BindingPartials, generator_index},
};

type R = ProductionRank;
type Challenges = Stage<EqAffine, R>;

// Independently enumerated ancestor allocations, including the SYSTEM gate.
// These are protocol layout expectations, not calls to skip_gates, values,
// num_gates, stage_wire_indices, or either production generator helper.
const FIRST_GATE: usize = 1
    + 64 // endoscalar: 128 bits
    + 141 // points: 113 inputs (including F) and 28 interstitials
    + 114 // preamble: 109 points and the children's ten nested scalars
    + 3 // s_prime: three points
    + 254 // inner_error: two points and 12 * (7^2 - 7) error terms
    + 73 // outer_error: one point, 12^2 - 12 errors and 12 collapsed values
    + 3 // ab: three points
    + 71 // query: two points, 45 registry entries, one mesh, 2 * (42 + 4) child queries
    + 2 // f: two points
    + 50; // eval: one point, 2 * (42 + 4) child evaluations and six current evaluations

const NAMES: [&str; 12] = [
    "w", "y", "z", "mu", "nu", "mu_prime", "nu_prime", "x", "alpha", "u", "sign", "beta",
];

fn degree(i: usize) -> usize {
    // a[g] occupies degree 2n - 1 - g; its companion d[g] occupies 4n - 1 - g.
    2 * R::n() - 1 - (FIRST_GATE + i)
}

fn witness(terms: [Fq; 12]) -> Witness<Fq> {
    Witness {
        lifts: FixedVec::new(terms[..10].to_vec()).unwrap(),
        base_case_sign: terms[10],
        beta: terms[11],
    }
}

#[test]
fn every_challenge_term_uses_its_independently_specified_generator() -> Result<()> {
    let generators = Pasta::nested_generators(Pasta::baked());
    assert_eq!(
        Challenges::skip_gates(),
        FIRST_GATE,
        "ancestor stage layout changed"
    );
    assert_eq!(Challenges::values(), 24);
    assert_eq!(
        [
            W, Y, Z, MU, NU, MU_PRIME, NU_PRIME, X, ALPHA, U, SIGN_INDEX, BETA_INDEX
        ],
        core::array::from_fn::<_, 12, _>(|i| i),
        "semantic term order",
    );

    // Unit vectors isolate placement even if coefficients in an honest
    // witness coincide. These are serialization probes, not claims that a
    // stage with zero sign is a valid protocol witness.
    for (i, name) in NAMES.iter().enumerate() {
        let mut terms = [Fq::ZERO; 12];
        terms[i] = Fq::ONE;
        let rx = Challenges::rx(Fq::ZERO, &witness(terms))?;
        let nonzero: Vec<_> = rx
            .iter_coeffs()
            .enumerate()
            .filter(|(_, c)| *c != Fq::ZERO)
            .collect();
        assert_eq!(
            nonzero,
            [(degree(i), Fq::ONE)],
            "{name}: exact coefficient support"
        );
        let commitment = rx.commit_to_affine(generators);
        assert_eq!(
            commitment,
            generators.g()[degree(i)],
            "{name}: polynomial commitment"
        );
        assert_eq!(
            generator_index::<Pasta, R>(i),
            degree(i),
            "{name}: shared binder helper"
        );
        if i == 11 {
            assert_eq!(
                bind_beta::generator_index::<Pasta, R>(),
                degree(i),
                "beta: parent completion helper"
            );
        }

        // Positive sensitivity controls for common placement mistakes.
        for (mistake, wrong) in [
            ("first twelve generators", i),
            ("one gate early", degree(i) + 1),
            ("one gate late", degree(i) - 1),
            ("d instead of a", degree(i) + 2 * R::n()),
            ("reversed terms", degree(11 - i)),
        ] {
            assert_ne!(
                commitment,
                generators.g()[wrong],
                "{name}: {mistake} must change the commitment"
            );
        }
    }
    Ok(())
}

#[test]
fn challenge_partials_and_beta_completion_match_independent_bases() -> Result<()> {
    let params = Pasta::baked();
    let generators = Pasta::nested_generators(params);
    for sign in [Fq::ONE, -Fq::ONE] {
        let mut terms = core::array::from_fn::<_, 12, _>(|i| Fq::from(17 + 13 * i as u64));
        terms[10] = sign;
        let mut challenges = witness(terms);
        let rx = Challenges::rx(Fq::ZERO, &challenges)?;
        let coefficients: Vec<_> = rx.iter_coeffs().collect();
        assert_eq!(
            coefficients[2 * R::n() - 1],
            Fq::ZERO,
            "SYSTEM blinding must be zero"
        );
        for i in 0..12 {
            assert_eq!(coefficients[degree(i)], terms[i], "{}: a wire", NAMES[i]);
            assert_eq!(
                coefficients[degree(i) + 2 * R::n()],
                Fq::ZERO,
                "{}: companion d wire",
                NAMES[i]
            );
        }

        let sum = |end: usize| {
            (0..end).fold(Ep::identity(), |acc, i| {
                acc + generators.g()[degree(i)] * terms[i]
            })
        };
        let partials = BindingPartials::compute::<Pasta, R, ReferenceBackend>(params, &challenges);
        assert_eq!(partials.partials.len(), 4);
        for (k, partial) in partials.partials.iter().enumerate() {
            assert_eq!(*partial, sum(2 * (k + 1)).to_affine(), "partial {k}");
        }
        assert_eq!(partials.binding, sum(11).to_affine(), "ten lifts and sign");
        let beta_term = generators.g()[degree(11)] * terms[11];
        assert_eq!(
            rx.commit_to_affine(generators),
            (sum(11) + beta_term).to_affine(),
            "full stage completion"
        );

        // The pre-beta partial must not depend on the later beta field.
        challenges.beta += Fq::ONE;
        let changed = BindingPartials::compute::<Pasta, R, ReferenceBackend>(params, &challenges);
        for (changed, original) in changed.partials.iter().zip(partials.partials.iter()) {
            assert_eq!(changed, original);
        }
        assert_eq!(changed.binding, partials.binding);
        let completed = Challenges::rx(Fq::ZERO, &challenges)?.commit_to_affine(generators);
        assert_eq!(
            completed,
            (sum(12) + generators.g()[degree(11)]).to_affine()
        );
        assert_ne!(completed, rx.commit_to_affine(generators));
    }
    Ok(())
}
