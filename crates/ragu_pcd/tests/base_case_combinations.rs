//! Confine the production base-case sign and both collapse exceptions to bootstrap.
//! Ordinary unit headers must still enforce child claims in every combination.

use alloc::{vec, vec::Vec};

use proptest::prelude::*;
use ragu_arithmetic::{
    Coeff, Cycle, FixedGenerators,
    ff::Field,
    group::{Curve, CurveAffine},
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    Circuit,
    polynomials::{Rank, sparse},
    staging::MultiStage,
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes, DriverValue, LinearExpression},
    gadgets::Bound,
    maybe::Empty,
    routines::Routine,
};
use ragu_pasta::{EqAffine, Fp, Fq};
use ragu_primitives::{GadgetExt, allocator::Standard, io::Write};
use ragu_testing::strategies;
use rand::{SeedableRng, rngs::StdRng};

use super::recursive_propagation_tests::support::{
    self, C, HEADER_SIZE, Merge, R, Seed, UnitLeft, UnitRight, Value,
};
use crate::{
    ApplicationBuilder, Proof,
    header::{Dummy, Header},
    internal::{
        Side, native,
        nested::{self, stages::challenges},
        stage_wires::{StageReader, stage_wire_indices, wire_degree, wires_of},
    },
    step::{Encoded, Index, Step},
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
        (changed.nested_challenges_partial.to_curve() + generator * delta).to_affine();
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
    let sign_wire = stage_wire_indices::<_, R, challenges::Stage<EqAffine, R>>(|stage| {
        wires_of(&stage.base_case.lift)
    })?[0];
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
            let witness = challenges::Witness::new::<_, HEADER_SIZE>(
                [Fq::ZERO; challenges::NUM],
                &left_header,
                &right_header,
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
            app.verify(&honest, inputs.verifier_rng())?,
            "{case}: honest proof"
        );
        let sign = if base_case { Fq::ONE } else { -Fq::ONE };
        let forged =
            flipped_sign(app, honest.proof(), sign_wire, sign).carry::<Value>(*honest.data());
        assert!(
            !app.verify(&forged, inputs.verifier_rng())?,
            "{case}: forged sign"
        );
        for (label, child, expected) in [("honest", &honest, true), ("forged", &forged, false)] {
            for (position, descendant) in support::descendants(app, child, &left, &mut rng)? {
                assert_eq!(
                    app.verify(&descendant, inputs.verifier_rng())?,
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
            app.verify(child, inputs.verifier_rng())?,
            expected,
            "bootstrap/{label}"
        );
        for parent_side in [Side::Left, Side::Right] {
            let salt = Fp::random(&mut rng);
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
                app.verify(&parent, inputs.verifier_rng())?,
                expected,
                "bootstrap/{label}: parent {parent_side:?}"
            );
            for grandparent_side in [Side::Left, Side::Right] {
                let (l, r) = match grandparent_side {
                    Side::Left => (parent.clone(), left.clone()),
                    Side::Right => (left.clone(), parent.clone()),
                };
                let salt = Fp::random(&mut rng);
                let grandparent = app.fuse(&mut rng, Merge::new(), salt, l, r)?.0;
                support::assert_copied_endpoints(
                    grandparent.proof(),
                    parent.proof(),
                    grandparent_side,
                )?;
                assert_eq!(
                    app.verify(&grandparent, inputs.verifier_rng())?,
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

fn check_proof_guards(
    proof: &Proof<C, R>,
    case: &str,
    exempt: bool,
    native_delta: Fp,
    nested_delta: Fq,
) -> Result<()> {
    let mut native_trace = proof.native_outer_collapse_rx.clone();
    native_trace.add_assign(&proof.native_preamble_rx);
    native_trace.add_assign(&proof.native_outer_error_rx);
    assert_eq!(
        accepts_wrong_c(
            native::circuits::outer_collapse::Circuit::<
                C,
                R,
                HEADER_SIZE,
                native::RevdotParameters,
            >::new(),
            &native_trace,
            native_c_position(),
            proof.native_c(),
            native_delta,
        )?,
        exempt,
        "{case}: native c guard"
    );

    let mut nested_trace = proof.nested_collapse_rx.clone();
    for stage in [
        nested::RxIndex::EndoscalarStage,
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
    assert_eq!(
        accepts_wrong_c(
            MultiStage::new(nested::circuits::collapse::Circuit::<EqAffine, R>::new()),
            &nested_trace,
            0, // c_n is the first slot in the nested unified instance.
            proof.nested_c(),
            nested_delta,
        )?,
        exempt,
        "{case}: nested c guard"
    );
    Ok(())
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
    assert!(app.verify(&bootstrap, inputs.verifier_rng())?);
    check_proof_guards(
        bootstrap.proof(),
        "bootstrap",
        true,
        native_delta,
        nested_delta,
    )?;
    for (case, exempt, pcd) in cases {
        assert!(
            app.verify(&pcd, inputs.verifier_rng())?,
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
        .finalize(C::baked())
        .expect("build unit application");
    let mut rng = StdRng::seed_from_u64(873003);
    let honest = app.bootstrap_pcd();
    let (control, ()) = app
        .fuse(&mut rng, UnitStep, (), honest.clone(), honest.clone())
        .expect("honest unit parent");
    assert!(app.verify(&control, StdRng::seed_from_u64(873004)).unwrap());

    for (origin, original) in [
        ("raw dummy retyped as unit", app.dummy_proof()),
        ("valid bootstrap unit", honest.into_parts().0),
    ] {
        for (nested, mutation) in [(true, "nested p"), (false, "application trace")] {
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
                    .native_application_rx
                    .add_assign(&sparse::Polynomial::from_coeffs(vec![Fp::ONE]));
                proof.native_application_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                    &proof.native_application_rx,
                    C::host_generators(app.params),
                );
            }
            let child = proof.carry::<()>(());
            assert!(
                !app.verify(&child, StdRng::seed_from_u64(873005)).unwrap(),
                "{origin}/{mutation}: invalid child must reject after cache repair",
            );
            let (parent, ()) = app
                .fuse(&mut rng, UnitStep, (), child.clone(), child)
                .expect("assemble parent");
            assert!(
                !app.verify(&parent, StdRng::seed_from_u64(873006)).unwrap(),
                "{origin}/{mutation}: parent must reject",
            );
            let (grandparent, ()) = app
                .fuse(&mut rng, UnitStep, (), parent.clone(), parent)
                .expect("assemble grandparent");
            assert!(
                !app.verify(&grandparent, StdRng::seed_from_u64(873007))
                    .unwrap(),
                "{origin}/{mutation}: grandparent must reject",
            );
        }
    }
}

proptest! {
    #![proptest_config(support::config())]

    #[test]
    fn mixed_headers_bind_the_base_case_sign(inputs in support::inputs()) {
        support::with_app(|app| check_signs(app, &inputs)).unwrap();
    }

    #[test]
    fn both_collapse_guards_confine_the_base_case_to_bootstrap(
        inputs in support::inputs(),
        native_delta in strategies::nonzero_prime_field_element::<Fp>(),
        nested_delta in strategies::nonzero_prime_field_element::<Fq>(),
    ) {
        support::with_app(|app| check_guards(app, &inputs, native_delta, nested_delta)).unwrap();
    }
}
