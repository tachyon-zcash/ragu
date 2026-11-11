//! Confine the production base-case sign and both collapse exceptions to bootstrap.
//! Ordinary unit headers must still enforce child claims in every combination.

use alloc::{vec, vec::Vec};

use proptest::prelude::*;
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    Circuit,
    polynomials::{Rank, sparse},
    staging::{MultiStage, StageReader, stage_wire_indices, wire_degree, wires_of},
};
use ragu_core::{
    Coeff, Cycle, FixedGenerators, Result,
    drivers::{Driver, DriverTypes, DriverValue, LinearExpression},
    gadgets::Bound,
    maybe::Empty,
    pasta::{EqAffine, Fp, Fq},
    routines::Routine,
};
use ragu_primitives::{GadgetExt, allocator::Standard, io::Write};
use ragu_testing::strategies;
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::{
    curve::{Affine as _, Projective},
    field::Field,
};

use super::recursive_propagation_tests::support::{
    self, C, HEADER_SIZE, Merge, R, Seed, UnitLeft, UnitRight, Value,
};
use crate::{
    ApplicationBuilder, Proof,
    header::{Dummy, Header},
    internal::{
        Side, native,
        nested::{self, stages::challenges},
    },
    step::{Encoded, Index, InternalStepIndex, Oracles, Step},
};

/// Preserve ordinary unit headers through successive fuses.
struct UnitStep;

impl Step<C> for UnitStep {
    const INDEX: Index = Index::new(0);

    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, N>,
            Encoded<'dr, D, Self::Right, N>,
            Encoded<'dr, D, Self::Output, N>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        Ok((
            (
                Encoded::new(dr, allocator, left)?,
                Encoded::new(dr, allocator, right)?,
                Encoded::from_gadget(()),
            ),
            D::unit(),
            D::unit(),
        ))
    }
}

/// Flip the sign and repair its stage commitment and exported partial. The
/// native binder must still derive the original sign from the input headers.
fn flipped_sign(
    app: &support::App,
    proof: &Proof<C, R>,
    sign_wire: usize,
    sign: Fq,
) -> Proof<C, R> {
    let mut changed = proof.clone();
    assert_eq!(
        StageReader::new(&changed.nested_challenges_rx).read(sign_wire),
        sign
    );
    support::set_wires(&mut changed.nested_challenges_rx, &[sign_wire], &[-sign]);
    changed.nested_challenges_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
        &changed.nested_challenges_rx,
        C::nested_generators(app.params),
    );
    let delta = -sign - sign;
    let generator = C::nested_generators(app.params).g()[wire_degree::<R>(sign_wire)];
    changed.nested_challenges_partial =
        (changed.nested_challenges_partial.to_projective() + generator * delta).to_affine();
    changed
}

fn check_signs(app: &support::App, inputs: &support::Inputs) -> Result<()> {
    let mut rng = inputs.prover_rng();
    let unit = app.bootstrap_pcd();
    let left = app.seed(&mut rng, Seed::new(), inputs.left)?.0;
    let right = app.seed(&mut rng, Seed::new(), inputs.right)?.0;
    assert_ne!(left.data(), right.data());
    let cases = [
        (
            "both_unit",
            false,
            app.fuse(
                &mut rng,
                Seed::new(),
                inputs.salt,
                unit.clone(),
                unit.clone(),
            )?
            .0,
        ),
        (
            "left_unit",
            false,
            app.fuse(
                &mut rng,
                UnitLeft::new(),
                inputs.salt + Fp::ONE,
                unit.clone(),
                right.clone(),
            )?
            .0,
        ),
        (
            "right_unit",
            false,
            app.fuse(
                &mut rng,
                UnitRight::new(),
                inputs.salt + Fp::from(2),
                left.clone(),
                unit,
            )?
            .0,
        ),
        (
            "neither_unit",
            false,
            app.fuse(
                &mut rng,
                Merge::new(),
                inputs.salt + Fp::from(3),
                left.clone(),
                right,
            )?
            .0,
        ),
    ];
    let sign_wire =
        stage_wire_indices::<_, R, challenges::Stage<EqAffine, R, crate::profile::Standard>>(
            |stage| wires_of(&stage.base_case.lift),
        )?[0];
    // Only Dummy x Dummy selects +1. In particular, one Dummy input or
    // ordinary unit headers must not select the exception.
    let suffixes = [
        (<Dummy as Header<Fp>>::SUFFIX.get(), true),
        (<() as Header<Fp>>::SUFFIX.get(), false),
        (<Value as Header<Fp>>::SUFFIX.get(), false),
    ];
    for &(left_suffix, left_dummy) in &suffixes {
        for &(right_suffix, right_dummy) in &suffixes {
            let mut left_header = vec![inputs.left; HEADER_SIZE];
            let mut right_header = vec![inputs.right; HEADER_SIZE];
            left_header[HEADER_SIZE - 1] = Fp::from(left_suffix);
            right_header[HEADER_SIZE - 1] = Fp::from(right_suffix);
            let witness = challenges::Witness::new(
                [Fq::ZERO; challenges::NUM],
                challenges::takes_base_case::<_, HEADER_SIZE>(&left_header, &right_header),
                Fq::ZERO,
            );
            assert_eq!(
                witness.base_case_sign,
                if left_dummy && right_dummy {
                    Fq::ONE
                } else {
                    -Fq::ONE
                },
                "left suffix={left_suffix}, right suffix={right_suffix}"
            );
        }
    }
    for (case, base_case, honest) in cases {
        assert!(
            app.verify_uncompressed(&honest, inputs.verifier_rng())?,
            "{case}: honest proof"
        );
        let sign = if base_case { Fq::ONE } else { -Fq::ONE };
        let forged =
            flipped_sign(app, honest.proof(), sign_wire, sign).carry::<Value>(*honest.data());
        assert!(
            !app.verify_uncompressed(&forged, inputs.verifier_rng())?,
            "{case}: forged sign"
        );
        for (label, child, expected) in [("honest", &honest, true), ("forged", &forged, false)] {
            for (position, descendant) in support::descendants(app, child, &left, &mut rng)? {
                assert_eq!(
                    app.verify_uncompressed(&descendant, inputs.verifier_rng())?,
                    expected,
                    "{case}/{label}: {position}"
                );
            }
        }
    }

    // Bootstrap is the one legitimate exception. A forged bootstrap sign must
    // still be rejected when an application step consumes its unit output.
    let bootstrap = app.bootstrap_pcd();
    let forged = flipped_sign(app, bootstrap.proof(), sign_wire, Fq::ONE).carry::<()>(());
    for (label, child, expected) in [("honest", &bootstrap, true), ("forged", &forged, false)] {
        assert_eq!(
            app.verify_uncompressed(child, inputs.verifier_rng())?,
            expected,
            "bootstrap/{label}"
        );
        for parent_side in [Side::Left, Side::Right] {
            let salt = Fp::random(|bytes| rng.fill_bytes(bytes));
            let parent = match parent_side {
                Side::Left => {
                    app.fuse(&mut rng, UnitLeft::new(), salt, child.clone(), left.clone())?
                        .0
                }
                Side::Right => {
                    app.fuse(
                        &mut rng,
                        UnitRight::new(),
                        salt,
                        left.clone(),
                        child.clone(),
                    )?
                    .0
                }
            };
            support::assert_copied_endpoints(parent.proof(), child.proof(), parent_side)?;
            assert_eq!(
                app.verify_uncompressed(&parent, inputs.verifier_rng())?,
                expected,
                "bootstrap/{label}: parent {parent_side:?}"
            );
            for grandparent_side in [Side::Left, Side::Right] {
                let (l, r) = match grandparent_side {
                    Side::Left => (parent.clone(), left.clone()),
                    Side::Right => (left.clone(), parent.clone()),
                };
                let salt = Fp::random(|bytes| rng.fill_bytes(bytes));
                let grandparent = app.fuse(&mut rng, Merge::new(), salt, l, r)?.0;
                support::assert_copied_endpoints(
                    grandparent.proof(),
                    parent.proof(),
                    grandparent_side,
                )?;
                assert_eq!(
                    app.verify_uncompressed(&grandparent, inputs.verifier_rng())?,
                    expected,
                    "bootstrap/{label}: parent {parent_side:?}, grandparent {grandparent_side:?}"
                );
            }
        }
    }
    Ok(())
}

fn native_c_position() -> usize {
    let mut position = 0;
    let mut found = None;
    native::unified::Coverage::default().for_each_slot(|name, _, wires| {
        if name == "c" {
            assert!(found.is_none());
            found = Some(position);
        }
        position += wires;
    });
    found.expect("the native unified instance has a c slot")
}

/// Linear combinations of polynomial coefficients, used only to check the
/// stored collapse traces and locate the guard's `difference = c - computed_c`.
#[derive(Clone)]
struct Expression<F: Field> {
    constant: F,
    terms: Vec<(usize, F)>,
    gain: F,
}

impl<F: Field> Expression<F> {
    fn zero() -> Self {
        Self {
            constant: F::ZERO,
            terms: Vec::new(),
            gain: F::ONE,
        }
    }

    fn wire(degree: usize) -> Self {
        Self {
            terms: vec![(degree, F::ONE)],
            ..Self::zero()
        }
    }

    fn coefficient(&self, degree: usize) -> F {
        self.terms
            .iter()
            .filter(|(i, _)| *i == degree)
            .map(|(_, c)| c)
            .sum()
    }

    fn evaluate(&self, coefficients: &[F]) -> F {
        self.constant
            + self
                .terms
                .iter()
                .map(|&(i, c)| coefficients[i] * c)
                .sum::<F>()
    }
}

impl<F: Field> LinearExpression<Self, F> for Expression<F> {
    fn add_term(mut self, wire: &Self, coefficient: Coeff<F>) -> Self {
        let scale = self.gain * coefficient.value();
        self.constant += wire.constant * scale;
        self.terms
            .extend(wire.terms.iter().map(|&(i, c)| (i, c * scale)));
        self
    }

    fn gain(mut self, coefficient: Coeff<F>) -> Self {
        self.gain *= coefficient.value();
        self
    }
}

/// Evaluate constraints emitted by the production collapse circuits against
/// their stored trace coefficients. The tests supply any coefficient edits.
/// These circuits use a single gate segment; reject routine calls so a future
/// layout change cannot silently misindex the trace.
struct TraceConstraints<F: Field> {
    gates: usize,
    linear: Vec<(usize, Expression<F>)>,
}

impl<F: Field> TraceConstraints<F> {
    fn hold(&self, coefficients: &[F]) -> bool {
        let n = R::n();
        coefficients[4 * n - 1] == F::ONE
            && (1..self.gates).all(|i| {
                let [a, b, c, d] =
                    [2 * n - 1 - i, 2 * n + i, i, 4 * n - 1 - i].map(|degree| coefficients[degree]);
                a * b == c && c * d == F::ZERO
            })
            && self
                .linear
                .iter()
                .all(|(_, equation)| equation.evaluate(coefficients) == F::ZERO)
    }
}

impl<F: Field> DriverTypes for TraceConstraints<F> {
    type ImplField = F;
    type ImplWire = Expression<F>;
    type MaybeKind = Empty;
    type LCadd = Expression<F>;
    type LCenforce = Expression<F>;
    type Extra = usize;

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::ImplWire, Self::ImplWire, Self::ImplWire, usize)> {
        let i = self.gates;
        self.gates += 1;
        assert!(i < R::n());
        Ok((
            Expression::wire(2 * R::n() - 1 - i),
            Expression::wire(2 * R::n() + i),
            Expression::wire(i),
            4 * R::n() - 1 - i,
        ))
    }

    fn assign_extra(
        &mut self,
        degree: usize,
        _: impl Fn() -> Result<Coeff<F>>,
    ) -> Result<Self::ImplWire> {
        Ok(Expression::wire(degree))
    }
}

impl<'dr, F: Field> Driver<'dr> for TraceConstraints<F> {
    type F = F;
    type Wire = Expression<F>;
    const ONE: Self::Wire = Expression {
        constant: F::ONE,
        terms: Vec::new(),
        gain: F::ONE,
    };

    fn add(&mut self, expression: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        expression(Expression::zero())
    }

    fn enforce_zero(
        &mut self,
        expression: impl Fn(Self::LCenforce) -> Self::LCenforce,
    ) -> Result<()> {
        self.linear
            .push((self.gates - 1, expression(Expression::zero())));
        Ok(())
    }

    fn routine<Ro: Routine<F> + 'dr>(
        &mut self,
        _: Ro,
        _: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        panic!("collapse trace check requires a single gate segment")
    }
}

fn accepts_wrong_c<F: Field, Cir: Circuit<F>>(
    circuit: Cir,
    trace: &sparse::Polynomial<F, R>,
    c_position: usize,
    expected_c: F,
    delta: F,
) -> Result<bool>
where
    Cir::Output: Write<F>,
{
    let mut constraints = TraceConstraints {
        gates: 1,
        linear: Vec::new(),
    };
    let (output, _) = circuit.witness(&mut constraints, Empty)?.into_parts();
    let mut instance = Vec::new();
    output.write(&mut constraints, &mut instance)?;
    let c = instance[c_position].wire();
    assert_eq!(c.constant, F::ZERO);
    assert_eq!(c.terms.len(), 1, "c must be a single allocated wire");
    let (c_degree, coefficient) = c.terms[0];
    assert_eq!(coefficient, F::ONE);

    let mut coefficients: Vec<_> = trace.iter_coeffs().collect();
    assert_eq!(coefficients[c_degree], expected_c);
    assert!(
        constraints.hold(&coefficients),
        "honest trace must satisfy the circuit"
    );

    // Locate the one equation that binds c to the guard's B wire. Requiring
    // these coefficients makes a removed guard or changed layout fail loudly.
    let equations: Vec<_> = constraints
        .linear
        .iter()
        .filter(|(_, equation)| equation.coefficient(c_degree) != F::ZERO)
        .collect();
    assert_eq!(equations.len(), 1, "one collapse guard must consume c");
    let (gate, equation) = equations[0];
    let difference = 2 * R::n() + gate;
    assert_eq!(equation.coefficient(c_degree), -F::ONE);
    assert_eq!(equation.coefficient(difference), F::ONE);

    assert_ne!(delta, F::ZERO);
    coefficients[c_degree] += delta;
    assert!(
        !constraints.hold(&coefficients),
        "an unrepaired guard input must fail"
    );
    // Repair only difference = c - computed_c. Every other coefficient stays
    // honest; the remaining condition * difference = 0 must enforce the guard.
    coefficients[difference] += delta;
    Ok(constraints.hold(&coefficients))
}

fn nested_collapse_trace(proof: &Proof<C, R>) -> sparse::Polynomial<Fq, R> {
    let mut nested_trace = proof.nested_collapse_rx.clone();
    for stage in [
        nested::RxIndex::EndoscalarStage,
        nested::RxIndex::BridgeHash,
        nested::RxIndex::PointsStage,
        nested::RxIndex::BridgePreamble,
        nested::RxIndex::BridgeSPrime,
        nested::RxIndex::BridgeInnerError,
        nested::RxIndex::BridgeOuterError,
        nested::RxIndex::BridgeAB,
        nested::RxIndex::BridgeQuery,
        nested::RxIndex::BridgeF,
        nested::RxIndex::BridgeEval,
        nested::RxIndex::ChallengeStage,
    ] {
        nested_trace.add_assign(&proof[stage]);
    }
    nested_trace
}

fn check_proof_guards(
    proof: &Proof<C, R>,
    case: &str,
    exempt: bool,
    native_delta: Fp,
    nested_delta: Fq,
) -> Result<()> {
    let mut native_trace = proof.native_collapse_rx.clone();
    native_trace.add_assign(&proof.native_preamble_rx);
    native_trace.add_assign(&proof.native_outer_error_rx);
    native_trace.add_assign(&proof.native_inner_error_rx);
    assert_eq!(
        accepts_wrong_c(
            native::circuits::collapse::Circuit::<
                C,
                R,
                HEADER_SIZE,
                native::RevdotParameters<crate::profile::Standard>,
            >::new(),
            &native_trace,
            native_c_position(),
            proof.native_c(),
            native_delta,
        )?,
        exempt,
        "{case}: native c guard"
    );

    assert_eq!(
        accepts_wrong_c(
            MultiStage::new(nested::circuits::collapse::Circuit::<
                EqAffine,
                R,
                crate::profile::Standard,
            >::new()),
            &nested_collapse_trace(proof),
            0, // c_n is the first slot in the nested unified instance.
            proof.nested_c(),
            nested_delta,
        )?,
        exempt,
        "{case}: nested c guard"
    );
    Ok(())
}

#[test]
fn nested_collapse_uses_challenge_stage_y_even_in_bootstrap() -> Result<()> {
    support::with_app(|app| {
        let bootstrap = app.bootstrap_pcd();
        let mut rng = StdRng::seed_from_u64(873008);
        let (ordinary, _) = app.fuse(
            &mut rng,
            Seed::new(),
            Fp::from(7),
            bootstrap.clone(),
            bootstrap.clone(),
        )?;
        assert!(app.verify_uncompressed(&bootstrap, StdRng::seed_from_u64(873009))?);
        assert!(app.verify_uncompressed(&ordinary, StdRng::seed_from_u64(873010))?);

        let stage_wires =
            stage_wire_indices::<_, R, challenges::Stage<EqAffine, R, crate::profile::Standard>>(
                |stage| {
                    Ok(vec![
                        *stage.pairs[challenges::Y].lift.wire(),
                        *stage.base_case.lift.wire(),
                    ])
                },
            )?;
        let y_degree = wire_degree::<R>(stage_wires[0]);
        let sign_degree = wire_degree::<R>(stage_wires[1]);

        for (case, proof, sign) in [
            ("bootstrap", bootstrap.proof(), Fq::ONE),
            ("non-base", ordinary.proof(), -Fq::ONE),
        ] {
            let mut constraints = TraceConstraints {
                gates: 1,
                linear: Vec::new(),
            };
            let circuit = MultiStage::new(nested::circuits::collapse::Circuit::<
                EqAffine,
                R,
                crate::profile::Standard,
            >::new());
            let (output, _) = circuit.witness(&mut constraints, Empty)?.into_parts();
            let instance_y = output.y.wire();
            assert_eq!(instance_y.constant, Fq::ZERO);
            assert_eq!(instance_y.terms.len(), 1);
            let (instance_y_degree, coefficient) = instance_y.terms[0];
            assert_eq!(coefficient, Fq::ONE);
            assert_ne!(instance_y_degree, y_degree);

            let trace = nested_collapse_trace(proof);
            let coefficients: Vec<_> = trace.iter_coeffs().collect();
            assert!(constraints.hold(&coefficients), "{case}: honest trace");
            assert_eq!(coefficients[sign_degree], sign);
            assert_eq!(coefficients[y_degree], proof.nested_instance()?.y);
            assert_eq!(coefficients[instance_y_degree], coefficients[y_degree]);

            // Change only the supported challenge-stage coefficient. The
            // layer-one equalities must reject even when the final c_n
            // comparison is waived.
            let mut changed = coefficients.clone();
            changed[y_degree] += Fq::ONE;
            assert!(!constraints.hold(&changed), "{case}: substituted stage y");

            // The combined circuit must also reject a divergent public copy.
            let mut changed = coefficients;
            changed[instance_y_degree] += Fq::ONE;
            assert!(
                !constraints.hold(&changed),
                "{case}: substituted instance y"
            );
        }
        Ok(())
    })
}

fn check_guards(
    app: &support::App,
    inputs: &support::Inputs,
    native_delta: Fp,
    nested_delta: Fq,
) -> Result<()> {
    let mut rng = inputs.prover_rng();
    let unit = app.bootstrap_pcd();
    let left = app.seed(&mut rng, Seed::new(), inputs.left)?.0;
    let right = app.seed(&mut rng, Seed::new(), inputs.right)?.0;
    let cases = [
        (
            "both_unit",
            false,
            app.fuse(
                &mut rng,
                Seed::new(),
                inputs.salt,
                unit.clone(),
                unit.clone(),
            )?
            .0,
        ),
        (
            "left_unit",
            false,
            app.fuse(
                &mut rng,
                UnitLeft::new(),
                inputs.salt + Fp::ONE,
                unit.clone(),
                right.clone(),
            )?
            .0,
        ),
        (
            "right_unit",
            false,
            app.fuse(
                &mut rng,
                UnitRight::new(),
                inputs.salt + Fp::from(2),
                left.clone(),
                unit,
            )?
            .0,
        ),
        (
            "neither_unit",
            false,
            app.fuse(
                &mut rng,
                Merge::new(),
                inputs.salt + Fp::from(3),
                left,
                right,
            )?
            .0,
        ),
    ];
    let bootstrap = app.bootstrap_pcd();
    assert!(app.verify_uncompressed(&bootstrap, inputs.verifier_rng())?);
    check_proof_guards(
        bootstrap.proof(),
        "bootstrap",
        true,
        native_delta,
        nested_delta,
    )?;
    for (case, exempt, pcd) in cases {
        assert!(
            app.verify_uncompressed(&pcd, inputs.verifier_rng())?,
            "{case}: honest proof"
        );
        check_proof_guards(pcd.proof(), case, exempt, native_delta, nested_delta)?;
    }
    Ok(())
}

#[test]
fn noncanonical_unit_children_reject_through_two_generations() {
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(UnitStep)
        .expect("register unit step")
        .finalize(crate::pasta::baked())
        .expect("build unit application");
    let mut rng = StdRng::seed_from_u64(873003);
    let honest = app.bootstrap_pcd();
    let (control, ()) = app
        .fuse(&mut rng, UnitStep, (), honest.clone(), honest.clone())
        .expect("honest unit parent");
    assert!(
        app.verify_uncompressed(&control, StdRng::seed_from_u64(873004))
            .unwrap()
    );

    for (origin, original) in [
        ("raw dummy retyped as unit", app.dummy_proof()),
        ("valid bootstrap unit", honest.into_parts().0),
    ] {
        for (nested, mutation) in [(true, "nested p"), (false, "hashes_1 trace")] {
            let mut proof = original.clone();
            // Repair the changed polynomial's commitment so rejection must
            // enforce the child's claim beyond checking its cached commitment.
            if nested {
                proof
                    .nested_p_poly
                    .add_assign(&sparse::Polynomial::from_coeffs(vec![Fq::ONE]));
                proof.nested_p_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                    &proof.nested_p_poly,
                    C::nested_generators(app.params),
                );
            } else {
                proof
                    .native_hashes_1_rx
                    .add_assign(&sparse::Polynomial::from_coeffs(vec![Fp::ONE]));
                proof.native_hashes_1_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                    &proof.native_hashes_1_rx,
                    C::host_generators(app.params),
                );
            }
            let child = proof.carry::<()>(());
            assert!(
                !app.verify_uncompressed(&child, StdRng::seed_from_u64(873005))
                    .unwrap(),
                "{origin}/{mutation}: invalid child must reject after cache repair",
            );
            let (parent, ()) = app
                .fuse(&mut rng, UnitStep, (), child.clone(), child)
                .expect("assemble parent");
            assert!(
                !app.verify_uncompressed(&parent, StdRng::seed_from_u64(873006))
                    .unwrap(),
                "{origin}/{mutation}: parent must reject",
            );
            let (grandparent, ()) = app
                .fuse(&mut rng, UnitStep, (), parent.clone(), parent)
                .expect("assemble grandparent");
            assert!(
                !app.verify_uncompressed(&grandparent, StdRng::seed_from_u64(873007))
                    .unwrap(),
                "{origin}/{mutation}: grandparent must reject",
            );
        }
    }
}

proptest! {
    #![proptest_config(support::config())]

    #[test]
    #[ignore = "recursion regression suite: run by the scheduled heavy-tests workflow"]
    fn mixed_headers_bind_the_base_case_sign(inputs in support::inputs()) {
        support::with_app(|app| check_signs(app, &inputs)).unwrap();
    }

    #[test]
    #[ignore = "recursion regression suite: run by the scheduled heavy-tests workflow"]
    fn both_collapse_guards_confine_the_base_case_to_bootstrap(
        inputs in support::inputs(),
        native_delta in strategies::nonzero_prime_field_element::<Fp>(),
        nested_delta in strategies::nonzero_prime_field_element::<Fq>(),
    ) {
        support::with_app(|app| check_guards(app, &inputs, native_delta, nested_delta)).unwrap();
    }
}

/// A prover who witnesses `Dummy` input headers its application circuit did
/// not produce takes the base case, which leaves the step's folded claim, its
/// own application claim among them, unconstrained. The base-case pin in
/// `collapse` must then reject the proof unless it is what a bootstrap proof
/// is: the bootstrap step's circuit id with the unit output header.
///
/// The parent is the case that matters. At the root, the decider reads the
/// base-case sign of the challenge stage off the circuit id, which a forged
/// proof with its own id contradicts; a parent takes the child's stage from
/// the child's own binders, so without the pin it accepts the forgery.
#[test]
fn forged_base_case_must_be_a_bootstrap_proof() {
    let bootstrap = InternalStepIndex::Bootstrap
        .circuit_index::<<C as crate::profile::ProfiledCycle>::Profile>()
        .expect("the bootstrap step is registered in every profile");

    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(943);
        let unit = app.bootstrap_pcd();
        let (honest, ()) = app
            .fuse(
                &mut rng,
                Seed::new(),
                Fp::from(7),
                unit.clone(),
                unit.clone(),
            )
            .expect("honest seed");
        assert!(
            app.verify_uncompressed(&honest, StdRng::seed_from_u64(1))
                .unwrap(),
            "the honest control verifies"
        );

        // A seed step's output header is a value, not the unit header, so
        // neither its own circuit id nor the bootstrap step's lets it take
        // the base case.
        for (case, circuit_id) in [
            ("own circuit id", None),
            ("bootstrap circuit id", Some(bootstrap)),
        ] {
            let (forged, ()) = app
                .fuse_forging_dummy_inputs(
                    &mut rng,
                    Seed::new(),
                    Fp::from(7),
                    unit.clone(),
                    unit.clone(),
                    circuit_id,
                )
                .expect("the forging prover assembles a proof");
            assert!(
                !app.verify_uncompressed(&forged, StdRng::seed_from_u64(2))
                    .unwrap(),
                "{case}: a forged base case must not verify"
            );
            assert!(
                !verifies_compressed(app, &forged, &mut rng),
                "{case}: a forged base case must not verify compressed"
            );
            let (parent, ()) = app
                .fuse(&mut rng, Merge::new(), Fp::from(8), forged, honest.clone())
                .expect("fuse assembles a parent regardless of satisfiability");
            assert!(
                !app.verify_uncompressed(&parent, StdRng::seed_from_u64(3))
                    .unwrap(),
                "{case}: the parent of a forged base case must not verify"
            );
        }
    });

    // What the pin admits is a bootstrap proof, which any prover can mint
    // and which attests nothing: a unit step forging `Dummy` inputs and the
    // bootstrap circuit id verifies as the unit `Pcd` a bootstrap proof is.
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(UnitStep)
        .expect("register unit step")
        .finalize(crate::pasta::baked())
        .expect("build unit application");
    let mut rng = StdRng::seed_from_u64(944);
    let unit = app.bootstrap_pcd();
    let (minted, ()) = app
        .fuse_forging_dummy_inputs(&mut rng, UnitStep, (), unit.clone(), unit, Some(bootstrap))
        .expect("the forging prover assembles a proof");
    assert!(
        app.verify_uncompressed(&minted, StdRng::seed_from_u64(4))
            .unwrap(),
        "a forged base case that is a bootstrap proof verifies, as any bootstrap proof does"
    );
    assert!(verifies_compressed(&app, &minted, &mut rng));
}

/// Whether `pcd` compresses and its compressed proof verifies.
fn verifies_compressed<H: Header<Fp>>(
    app: &crate::Application<'_, C, R, HEADER_SIZE>,
    pcd: &crate::Pcd<C, R, H>,
    rng: &mut StdRng,
) -> bool {
    app.compress(pcd, rng)
        .and_then(|compressed| app.verify_compressed(&compressed))
        .unwrap_or(false)
}

/// A unit-to-unit step whose prover commits non-padding output polynomials
/// and whose circuit does not open them.
struct ChosenSlots;

impl Step<C> for ChosenSlots {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn polynomials<'source>(
        &self,
        _: &(),
        _: crate::step::HeaderInput<'_, Fp, ()>,
        _: crate::step::HeaderInput<'_, Fp, ()>,
    ) -> Result<[Vec<Fp>; crate::header::NUM_ONLINE_POLYNOMIALS]> {
        Ok([vec![Fp::from(5), Fp::ONE], vec![Fp::from(3), Fp::ONE]])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, N>,
            Encoded<'dr, D, Self::Right, N>,
            Encoded<'dr, D, Self::Output, N>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        Ok((
            (
                Encoded::new(dr, allocator, left)?,
                Encoded::new(dr, allocator, right)?,
                Encoded::from_gadget(()),
            ),
            D::unit(),
            D::unit(),
        ))
    }
}

/// A consumer of a unit left input that holds the input's slot 0, at
/// $\zeta$, to `X + offset`, or to the padding one for `None`. It holds its
/// own output slots to padding.
struct ReadLeftSlot(Option<u64>);

impl Step<C> for ReadLeftSlot {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, N>,
            Encoded<'dr, D, Self::Right, N>,
            Encoded<'dr, D, Self::Output, N>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        use ragu_primitives::Element;
        let zeta = oracles.zeta().clone();
        let value = oracles.query(dr, crate::step::Slot::left(0), &zeta)?;
        let expected = match self.0 {
            Some(offset) => {
                let offset = Element::constant(dr, Fp::from(offset));
                zeta.add(dr, &offset)
            }
            None => Element::one(),
        };
        value.enforce_equal(dr, &expected)?;
        for i in 0..crate::header::NUM_ONLINE_POLYNOMIALS {
            let value = oracles.query(dr, crate::step::Slot::output(i), &zeta)?;
            value.enforce_equal(dr, &Element::one())?;
        }
        let allocator = &mut Standard::new();
        Ok((
            (
                Encoded::new(dr, allocator, left)?,
                Encoded::new(dr, allocator, right)?,
                Encoded::from_gadget(()),
            ),
            D::unit(),
            D::unit(),
        ))
    }
}

/// The base-case pin holds a minted bootstrap proof's output slots to
/// padding. The bootstrap circuit's own slot check is in its application
/// claim, which the base case leaves free, so without the pin a prover
/// mints a unit proof that carries polynomials of its choosing: both
/// verifiers accept it, and so does a parent that reads the slots. A proof
/// supplied through `with_bootstrap` is the same case.
#[test]
fn forged_base_case_carries_padding_slots() {
    let bootstrap = InternalStepIndex::Bootstrap
        .circuit_index::<<C as crate::profile::ProfiledCycle>::Profile>()
        .expect("the bootstrap step is registered in every profile");
    let build = |expected| {
        ApplicationBuilder::<C, R, HEADER_SIZE>::new()
            .register(ChosenSlots)
            .expect("register the minting step")
            .register(ReadLeftSlot(expected))
            .expect("register the reading step")
    };

    // The reader that expects the minted polynomial is the attack; the
    // reader that expects padding is the honest control.
    for expected in [Some(5), None] {
        let app = build(expected)
            .finalize(crate::pasta::baked())
            .expect("build application");
        let mut rng = StdRng::seed_from_u64(946);
        let unit = app.bootstrap_pcd();

        let (minted, ()) = app
            .fuse_forging_dummy_inputs(
                &mut rng,
                ChosenSlots,
                (),
                unit.clone(),
                unit.clone(),
                Some(bootstrap),
            )
            .expect("the forging prover assembles a proof");
        assert_eq!(minted.proof().circuit_id(), bootstrap);
        assert!(
            !verifies(&app, &minted, &mut rng),
            "a minted bootstrap proof with chosen slots must not verify"
        );

        for (child, honest) in [(unit.clone(), true), (minted.clone(), false)] {
            let accepted = app
                .fuse(&mut rng, ReadLeftSlot(expected), (), child, unit.clone())
                .is_ok_and(|(parent, ())| verifies(&app, &parent, &mut rng));
            assert_eq!(
                accepted,
                honest && expected.is_none(),
                "expected {expected:?}, honest child {honest}"
            );
        }

        // The same proof, installed as the bootstrap proof: every seed then
        // reads it as its unit inputs.
        let installed = build(expected)
            .with_bootstrap(minted.proof().clone())
            .expect("a proof of the bootstrap step with this shape is installed")
            .finalize(crate::pasta::baked())
            .expect("build application");
        let accepted = installed
            .seed(&mut rng, ReadLeftSlot(expected), ())
            .is_ok_and(|(seeded, ())| verifies(&installed, &seeded, &mut rng));
        assert!(
            !accepted,
            "expected {expected:?}: a seed over an installed minted proof must not verify"
        );
    }
}

/// Whether both verifiers accept `pcd`; they must agree.
fn verifies<H: Header<Fp>>(
    app: &crate::Application<'_, C, R, HEADER_SIZE>,
    pcd: &crate::Pcd<C, R, H>,
    rng: &mut StdRng,
) -> bool {
    let uncompressed = app
        .verify_uncompressed(pcd, StdRng::seed_from_u64(5))
        .unwrap();
    assert_eq!(
        uncompressed,
        verifies_compressed(app, pcd, rng),
        "the verifiers agree"
    );
    uncompressed
}

/// The native preamble is committed after $w$, so a prover can choose a
/// child's values in it with $w$ in hand. The child's committed traces fix
/// those values, and the step folds the child's claims at $y$ over the
/// preamble's wires: a preamble that witnesses another input header than
/// the child exported is rejected, at the step and through its parent.
#[test]
fn input_header_edited_after_w_is_rejected() {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(9461);
        let unit = app.bootstrap_pcd();
        let seed = |rng: &mut StdRng, value: u64| {
            app.fuse(
                rng,
                Seed::new(),
                Fp::from(value),
                unit.clone(),
                unit.clone(),
            )
            .expect("honest seed")
            .0
        };
        let (left, right) = (seed(&mut rng, 7), seed(&mut rng, 8));
        let (honest, ()) = app
            .fuse(
                &mut rng,
                Merge::new(),
                Fp::from(9),
                left.clone(),
                right.clone(),
            )
            .expect("honest merge");
        assert!(
            verifies(app, &honest, &mut rng),
            "the honest control verifies"
        );

        let (edited, ()) = app
            .fuse_editing_left_header(&mut rng, Merge::new(), Fp::from(9), left, right, Fp::ONE)
            .expect("the editing prover assembles a proof");
        assert!(
            !verifies(app, &edited, &mut rng),
            "a preamble with another input header must not verify"
        );
        let (parent, ()) = app
            .fuse(&mut rng, Merge::new(), Fp::from(10), edited, honest)
            .expect("fuse assembles a parent regardless of satisfiability");
        assert!(
            !verifies(app, &parent, &mut rng),
            "the parent of such a proof must not verify"
        );
    });
}

/// A step folds its own application claim, so the decider has none to
/// check: an application trace that does not satisfy the step's circuit is
/// rejected through the root's own accumulator.
#[test]
fn unsatisfied_root_application_trace_is_rejected() {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(9462);
        let unit = app.bootstrap_pcd();
        let (root, ()) = app
            .fuse_editing_application(
                &mut rng,
                Seed::new(),
                Fp::from(7),
                unit.clone(),
                unit,
                |application| {
                    application.rx.scale(Fp::from(2));
                    application.commitment = ReferenceBackend::sparse_commit_to_affine(
                        &application.rx,
                        C::host_generators(app.params),
                    );
                },
            )
            .expect("the editing prover assembles a proof");
        assert!(
            !verifies(app, &root, &mut rng),
            "a root whose application trace is unsatisfied must not verify"
        );
    });
}

/// A proof carries no header: the decider encodes the output header from
/// the data the `Pcd` carries and holds it to the one the proof's
/// `hashes_1` exported.
#[test]
fn data_other_than_the_exported_header_is_rejected() {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(9463);
        let unit = app.bootstrap_pcd();
        let (honest, ()) = app
            .fuse(&mut rng, Seed::new(), Fp::from(7), unit.clone(), unit)
            .expect("honest seed");
        assert!(
            verifies(app, &honest, &mut rng),
            "the honest control verifies"
        );
        let (proof, data) = honest.into_parts();
        let relabelled = proof.carry::<Value>(data + Fp::ONE);
        assert!(
            !verifies(app, &relabelled, &mut rng),
            "a proof carried with other data must not verify"
        );
    });
}

/// A proof of the bootstrap step with a non-unit output header passes
/// `with_bootstrap`'s shape check, but the base-case pin rejects it, so no
/// seed built on it verifies.
#[test]
fn installed_non_unit_bootstrap_proof_is_rejected() {
    let bootstrap = InternalStepIndex::Bootstrap
        .circuit_index::<<C as crate::profile::ProfiledCycle>::Profile>()
        .expect("the bootstrap step is registered in every profile");
    let build = || {
        ApplicationBuilder::<C, R, HEADER_SIZE>::new()
            .register(Seed::new())
            .expect("register seed")
    };
    let app = build()
        .finalize(crate::pasta::baked())
        .expect("build application");
    let mut rng = StdRng::seed_from_u64(9464);
    let unit = app.bootstrap_pcd();
    let (forged, ()) = app
        .fuse_forging_dummy_inputs(
            &mut rng,
            Seed::new(),
            Fp::from(7),
            unit.clone(),
            unit,
            Some(bootstrap),
        )
        .expect("the forging prover assembles a proof");

    let installed = build()
        .with_bootstrap(forged.proof().clone())
        .expect("a proof of the bootstrap step with this shape is installed")
        .finalize(crate::pasta::baked())
        .expect("build application");
    let (seeded, ()) = installed
        .seed(&mut rng, Seed::new(), Fp::from(8))
        .expect("seed assembles a proof regardless of satisfiability");
    assert!(
        !verifies(&installed, &seeded, &mut rng),
        "a seed over an installed non-unit bootstrap proof must not verify"
    );
}

/// The rerandomization circuit holds its witnessed input suffix away from
/// `Dummy`, but that is its application claim, which the base case leaves
/// free. A rerandomizing prover that witnesses `Dummy` inputs is rejected
/// by the base-case pin instead.
#[test]
fn rerandomize_forging_dummy_inputs_is_rejected() {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(9465);
        let unit = app.bootstrap_pcd();
        let (honest, ()) = app
            .fuse(&mut rng, Seed::new(), Fp::from(7), unit.clone(), unit)
            .expect("honest seed");
        let seeded_trivial = app
            .seeded_trivial_pcd(&mut rng)
            .expect("the cached seeded unit proof");
        let (forged, ()) = app
            .fuse_forging_dummy_inputs(
                &mut rng,
                crate::step::internal::rerandomize::Rerandomize::new(),
                (),
                honest.clone(),
                seeded_trivial,
                None,
            )
            .expect("the forging prover assembles a proof");
        assert!(
            !verifies(app, &forged, &mut rng),
            "a rerandomization that takes the base case must not verify"
        );
        let (parent, ()) = app
            .fuse(&mut rng, Merge::new(), Fp::from(8), forged, honest)
            .expect("fuse assembles a parent regardless of satisfiability");
        assert!(
            !verifies(app, &parent, &mut rng),
            "the parent of such a rerandomization must not verify"
        );
    });
}
