//! Empirical check of the "Known routine prediction is returned without
//! checking the executed output" finding.
//!
//! The finding claims a `Prediction::Known` routine whose `predict` disagrees
//! with `execute` lets a prover make the parent continue with an attacker-chosen
//! predicted value while the deferred routine segment proves a different
//! computation, and that the resulting trace still verifies (soundness break).
//!
//! These tests build exactly that situation and run the Sonic-style satisfaction
//! relation `<<r, r·z + s(X,y) + t(z)>> == k(y)` (mirroring `test_simple_circuit`)
//! to see whether the inconsistent trace is accepted or rejected.

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::Fp,
    routines::{Prediction, Routine},
};
use ragu_primitives::{Element, allocator::Standard};
use udon::field::Field;

use crate::{
    Circuit, CircuitExt, WithAux, into_wiring_object,
    polynomials::{Rank, TestRank},
};

/// Squares its input. `predict` is configurable so we can make it agree with or
/// lie about the executed output.
///
/// * `LIE == 0`: honest — predicts the true square (`input^2`).
/// * `LIE != 0`: malicious — predicts `input^2 + LIE`, while `execute` still
///   constrains the true square. This is the exact "buggy / witness-dependent
///   predictor" scenario the finding posits.
#[derive(Clone)]
struct ConfigurableSquare<const LIE: u64>;

impl<const LIE: u64> Routine<Fp> for ConfigurableSquare<LIE> {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        // The deferred / always-executed body: genuinely constrains output = input^2.
        input.square(dr)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        // Returns `Known`, so witness drivers (the trace evaluator) hand this
        // value to the parent and defer `execute`.
        let output = Element::alloc(
            dr,
            &mut (),
            D::try_just(|| {
                let v = *input.value().take();
                Ok(v.square() + Fp::from(LIE))
            })?,
        )?;
        Ok(Prediction::Known(output, D::unit()))
    }
}

/// Circuit: `output = routine(input)^2`.
///
/// The parent *consumes* the routine output in a multiplication (the square),
/// which is precisely the finding's "parent emits or serializes gates using the
/// predicted value" step. `Element::square` records the consumed value into the
/// trace `r` at a gate whose input wire the constraint system `s` copy-binds to
/// the routine's executed output wire.
struct ParentUsesRoutineOutput<Ro>(Ro);

impl<Ro> Circuit<Fp> for ParentUsesRoutineOutput<Ro>
where
    Ro: Routine<Fp, Input = Kind![Fp; Element<'_, _>], Output = Kind![Fp; Element<'_, _>]>
        + Clone
        + Send
        + Sync
        + 'static,
{
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witness> = Fp;
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        Element::alloc(dr, allocator, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>> {
        let allocator = &mut Standard::new();
        let input = Element::alloc(dr, allocator, witness)?;
        let routine_output = dr.routine(self.0.clone(), input)?;
        // Parent uses the routine output in a fresh multiplication gate.
        let squared = routine_output.square(dr)?;
        Ok(WithAux::new(squared, D::unit()))
    }
}

/// Runs the full prover/verifier satisfaction relation at fixed verifier
/// challenges and returns whether the resulting trace is accepted.
fn trace_is_accepted_at<Ro>(routine: Ro, witness: Fp, instance: Fp, y: Fp, z: Fp) -> bool
where
    Ro: Routine<Fp, Input = Kind![Fp; Element<'_, _>], Output = Kind![Fp; Element<'_, _>]>
        + Clone
        + Send
        + Sync
        + 'static,
{
    type MyRank = TestRank;

    let circuit = ParentUsesRoutineOutput(routine);

    // Prover side: build the trace r(X) (this is the code under scrutiny —
    // trace::Evaluator::routine returns the *predicted* output to the parent).
    let trace = circuit.trace(witness).unwrap().into_output();

    // Verifier side: the public instance polynomial k(y).
    let expected = circuit.ky(instance, y).unwrap();

    // The fixed, witness-independent constraint structure s(X, Y), built by the
    // always-executing wiring drivers.
    let obj = into_wiring_object::<_, _, MyRank>(circuit).unwrap();
    let plan = obj.floor_plan();
    let assignment = trace.assemble(plan, Fp::ZERO).unwrap();

    // Sonic identity: <<r, r·z + s(X,y) + t(z)>> == k(y).
    let a = assignment.clone();
    let mut b = assignment.clone();
    b.dilate(z);
    b.add_assign(&obj.sy(y));
    b.add_assign(&MyRank::tz(z));

    expected == a.revdot(&b)
}

/// Fixed nonzero challenge pairs make these regression tests reproducible and
/// check the satisfaction identity at more than one point.
fn challenge_pairs() -> [(Fp, Fp); 3] {
    [
        (Fp::from(2u64), Fp::from(3u64)),
        (Fp::from(5u64), Fp::from(7u64)),
        (Fp::from(11u64), Fp::from(13u64)),
    ]
}

/// Control: an honest Known routine (predict == execute) produces a trace that
/// the verifier accepts. Confirms the harness and the Known/deferred path work.
#[test]
fn honest_known_routine_is_accepted() {
    let w = Fp::from(3u64);
    // output = (w^2)^2 = w^4
    let instance = w.square().square();
    for (y, z) in challenge_pairs() {
        assert!(
            trace_is_accepted_at(ConfigurableSquare::<0>, w, instance, y, z),
            "honest Known routine must verify at y={y:?}, z={z:?}"
        );
    }
}

/// The actual finding under test: a Known routine whose `predict` lies about the
/// output (predict = input^2 + 7, execute = input^2). The parent consumes the
/// predicted value. If the finding were a real soundness break, *some* instance
/// would make this verify. We test the two instances an attacker would pick:
///
///   * the value matching the honest/executed computation, and
///   * the value matching the lie they fed the parent.
///
/// Rejecting both provides deterministic regression coverage for the claimed
/// mismatch; it is not an exhaustive soundness proof over every instance.
#[test]
fn lying_known_routine_is_rejected_for_executed_instance() {
    let w = Fp::from(3u64);
    // Instance consistent with the EXECUTED routine: output = (w^2)^2 = w^4.
    let executed_instance = w.square().square();
    for (y, z) in challenge_pairs() {
        assert!(
            !trace_is_accepted_at(ConfigurableSquare::<7>, w, executed_instance, y, z),
            "lying Known routine must NOT verify against the executed-output instance at \
             y={y:?}, z={z:?}"
        );
    }
}

#[test]
fn lying_known_routine_is_rejected_for_predicted_instance() {
    let w = Fp::from(3u64);
    // Instance consistent with the PREDICTED (lied) routine output:
    // the parent squared input^2 + 7, so output = (w^2 + 7)^2.
    let predicted = w.square() + Fp::from(7u64);
    let predicted_instance = predicted.square();
    for (y, z) in challenge_pairs() {
        assert!(
            !trace_is_accepted_at(ConfigurableSquare::<7>, w, predicted_instance, y, z),
            "lying Known routine must NOT verify against the predicted-output instance at \
             y={y:?}, z={z:?}"
        );
    }
}
