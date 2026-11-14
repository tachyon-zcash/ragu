//! Adversarial openings of the step's private Fq polynomial.
//!
//! Mutations happen before the Query/Eval stages are committed, so the
//! transcript, circuit witnesses and parent proofs follow the changed data.
//! The wrong-point case also changes the quotient's opening point and uses
//! the polynomial's correct value there: only `compute_v`'s fold at
//! $\zeta_q$, which no stage can move, should reject it. The other cases
//! keep the polynomial and quotient construction honest while claiming a
//! false Query or Eval value.

use core::cell::Cell;

use ragu_circuits::polynomials::R;
use ragu_core::{Result, pasta::Pasta};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use crate::{
    Application, ApplicationBuilder, Pcd,
    profile::{
        Profiled,
        testing::{Proving, UnitStep},
    },
};

type C = Profiled<Pasta, Proving>;
type Rk = R<14>;
type App = Application<'static, C, Rk, 4>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutation {
    None,
    Point,
    QueryValue,
    EvalValue,
}

std::thread_local! {
    // All hook sites run on the thread invoking fuse, outside its
    // parallel jobs. Other tests and worker threads always see None.
    static MUTATION: Cell<Mutation> = const { Cell::new(Mutation::None) };
}

/// Installs a mutation for one fuse and restores honest behavior on unwind.
fn with_mutation<T>(mutation: Mutation, f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            MUTATION.set(Mutation::None);
        }
    }
    assert_eq!(MUTATION.get(), Mutation::None);
    let _reset = Reset;
    MUTATION.set(mutation);
    f()
}

/// Changes the point the prover opens at: the Query value and the quotient
/// both use it.
pub(crate) fn query_point<F: Field>(point: F) -> F {
    if MUTATION.get() == Mutation::Point {
        point + F::ONE
    } else {
        point
    }
}

/// Changes the claimed value without changing the committed polynomial.
pub(crate) fn query_value<F: Field>(value: F) -> F {
    if MUTATION.get() == Mutation::QueryValue {
        value + F::ONE
    } else {
        value
    }
}

/// Changes the evaluation at u without changing the committed polynomial.
pub(crate) fn eval_value<F: Field>(value: F) -> F {
    if MUTATION.get() == Mutation::EvalValue {
        value + F::ONE
    } else {
        value
    }
}

fn application() -> Result<App> {
    ApplicationBuilder::new()
        .register(UnitStep)?
        .finalize(crate::pasta::baked_aggregator())
}

/// Checks both terminal verification paths against the same proof.
fn assert_verification(
    app: &App,
    proof: &Pcd<C, Rk, ()>,
    rng: &mut StdRng,
    expected: bool,
) -> Result<()> {
    assert_eq!(
        app.verify_uncompressed(proof, &mut *rng)?,
        expected,
        "uncompressed verification"
    );
    let compressed = app.compress(proof, rng)?;
    assert_eq!(
        app.verify_compressed(&compressed)?,
        expected,
        "compressed verification"
    );
    Ok(())
}

fn rejects(mutation: Mutation) -> Result<()> {
    let app = application()?;
    let mut rng = StdRng::seed_from_u64(0xf005);
    let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
    assert_verification(&app, &child, &mut rng, true)?;

    let (bad, ()) = with_mutation(mutation, || {
        app.fuse(&mut rng, UnitStep, (), child.clone(), child.clone())
    })?;
    assert_verification(&app, &bad, &mut rng, false)?;

    // The mutation has been reset: the parent's prover follows the normal
    // path, but must propagate the child's false claim.
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), bad, child)?;
    assert_verification(&app, &parent, &mut rng, false)
}

#[test]
fn a_consistent_opening_at_the_wrong_point_rejects() -> Result<()> {
    rejects(Mutation::Point)
}

#[test]
fn a_false_query_value_rejects() -> Result<()> {
    rejects(Mutation::QueryValue)
}

#[test]
fn a_false_eval_value_rejects() -> Result<()> {
    rejects(Mutation::EvalValue)
}

#[cfg(feature = "unstable-fuzzing")]
mod capture {
    use ragu_circuits::Circuit;
    use ragu_testing::patcher::{capture_with_stage_values, constraints_hold, playback};

    use super::*;
    use crate::{
        fuzzing::patcher::{CircuitSpec, InternalCircuitVisitor, capture_internal_circuits},
        profile::ProfiledCycle,
    };

    struct Visitor(usize);

    impl<Cy: ProfiledCycle> InternalCircuitVisitor<Cy> for Visitor {
        fn visit<'w, Cir: Circuit<Cy::CircuitField>>(
            &mut self,
            _: &CircuitSpec,
            _: &Cir,
            _: &[Cy::CircuitField],
            _: impl Fn() -> Result<Cir::Witness<'w>>,
        ) -> Result<()> {
            Ok(())
        }

        fn visit_nested<'w, Cir: Circuit<Cy::ScalarField>>(
            &mut self,
            spec: &CircuitSpec,
            circuit: &Cir,
            stage_values: &[Cy::ScalarField],
            make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
        ) -> Result<()> {
            if spec.name == "nested_compute_v" {
                let capture = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
                assert!(constraints_hold(
                    &capture.recorder.events,
                    &capture.recorder.values
                ));
                assert!(playback(circuit, make_witness()?, capture.recorder.values)?);
                self.0 += 1;
            }
            Ok(())
        }
    }

    #[test]
    fn the_fq_enabled_compute_v_can_be_captured_and_replayed() -> Result<()> {
        let app = application()?;
        let mut rng = StdRng::seed_from_u64(0xf006);
        let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
        let mut visitor = Visitor(0);
        capture_internal_circuits(
            &app,
            &mut rng,
            UnitStep,
            (),
            child.clone(),
            child,
            &mut visitor,
        )?;
        assert_eq!(visitor.0, 1);
        Ok(())
    }
}
