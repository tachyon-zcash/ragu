use ff::Field;
use ragu_core::maybe::Always;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    routines::{Prediction, Routine},
};
use ragu_pasta::Fp;
use ragu_primitives::{Element, Simulator};

use crate::{
    Circuit,
    metrics::{self, RoutineFingerprint, RoutineIdentity},
};

/// Canonical single-square routine.
#[derive(Clone)]
struct SquareOnce;

impl Routine<Fp> for SquareOnce {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        input.square(dr)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// N sequential squares — parameterized constraint count.
#[derive(Clone)]
struct SquareN<const N: usize>;

impl<const N: usize> Routine<Fp> for SquareN<N> {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let mut acc = input;
        for _ in 0..N {
            acc = acc.square(dr)?;
        }
        Ok(acc)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Identical body to `SquareOnce` but a distinct Rust type.
#[derive(Clone)]
struct SquareOnceAlias;

impl Routine<Fp> for SquareOnceAlias {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        input.square(dr)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Zero input wires — produces an Element from nothing.
#[derive(Clone)]
struct Produce;

impl Routine<Fp> for Produce {
    type Input = Kind![Fp; ()];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, D::just(|| Fp::ZERO))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Two input wires — adds two elements.
#[derive(Clone)]
struct AddTwo;

impl Routine<Fp> for AddTwo {
    type Input = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (a, b) = input;
        Ok(a.add(dr, &b))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Duplicates input — output type differs from SquareOnce.
#[derive(Clone)]
struct Duplicate;

impl Routine<Fp> for Duplicate {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok((input.clone(), input))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Zero wires, zero constraints.
#[derive(Clone)]
struct EmptyRoutine;

impl Routine<Fp> for EmptyRoutine {
    type Input = Kind![Fp; ()];
    type Output = Kind![Fp; ()];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Pure delegation — calls SquareOnce as a nested routine.
#[derive(Clone)]
struct PureNesting;

impl Routine<Fp> for PureNesting {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        dr.routine(SquareOnce, input)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Nested call plus an extra constraint — fingerprint must differ from SquareOnce.
#[derive(Clone)]
struct NestingWithExtra;

impl Routine<Fp> for NestingWithExtra {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let result = dr.routine(SquareOnce, input)?;
        result.enforce_zero(dr)?;
        Ok(result)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Linear constraints only — no multiplications.
#[derive(Clone)]
struct LinearOnly;

impl Routine<Fp> for LinearOnly {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        input.enforce_zero(dr)?;
        input.enforce_zero(dr)?;
        Ok(input)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Mixed alloc + mul + enforce_zero.
#[derive(Clone)]
struct MixedConstraints;

impl Routine<Fp> for MixedConstraints {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let aux = Element::alloc(dr, D::just(|| Fp::ONE))?;
        let sq = input.square(dr)?;
        sq.enforce_zero(dr)?;
        Ok(aux)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Three-level nesting: wraps PureNesting which wraps SquareOnce.
#[derive(Clone)]
struct TripleNesting;

impl Routine<Fp> for TripleNesting {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        dr.routine(PureNesting, input)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Calls SquareOnce then squares the result locally.
#[derive(Clone)]
struct NestThenSquare;

impl Routine<Fp> for NestThenSquare {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let nested = dr.routine(SquareOnce, input)?;
        nested.square(dr)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Calls SquareOnce then adds the result to itself locally.
#[derive(Clone)]
struct NestThenAdd;

impl Routine<Fp> for NestThenAdd {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let nested = dr.routine(SquareOnce, input)?;
        Ok(nested.add(dr, &nested))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

fn fingerprint_elem(
    routine: &impl Routine<Fp, Input = Kind![Fp; Element<'_, _>]>,
) -> RoutineFingerprint {
    let mut sim = Simulator::<Fp>::new();
    let input = Element::alloc(&mut sim, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    match metrics::fingerprint_routine::<Fp, Simulator<Fp>, _>(routine, &input).unwrap() {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

fn fingerprint_unit(routine: &impl Routine<Fp, Input = Kind![Fp; ()]>) -> RoutineFingerprint {
    match metrics::fingerprint_routine::<Fp, Simulator<Fp>, _>(routine, &()).unwrap() {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

fn fingerprint_pair(
    routine: &impl Routine<Fp, Input = Kind![Fp; (Element<'_, _>, Element<'_, _>)]>,
) -> RoutineFingerprint {
    let sim = &mut Simulator::<Fp>::new();
    let a = Element::alloc(sim, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    let b = Element::alloc(sim, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    match metrics::fingerprint_routine::<Fp, Simulator<Fp>, _>(routine, &(a, b)).unwrap() {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

/// Wraps an `Element → Element` routine as a minimal Circuit for metrics tests.
#[derive(Clone)]
struct SingleRoutineCircuit<Ro: Clone>(Ro);

impl<Ro> Circuit<Fp> for SingleRoutineCircuit<Ro>
where
    Ro: Routine<Fp, Input = Kind![Fp; Element<'_, _>], Output = Kind![Fp; Element<'_, _>]>
        + Clone
        + Send
        + Sync,
    for<'dr> Ro::Aux<'dr>: Send + Clone,
{
    type Instance<'source> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'source> = Fp;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Element::alloc(dr, instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        Bound<'dr, D, Self::Output>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let input = Element::alloc(dr, witness)?;
        let output = dr.routine(self.0.clone(), input)?;
        Ok((output, D::just(|| ())))
    }
}

/// Same routine fingerprinted twice produces identical results.
#[test]
fn test_determinism() {
    assert_eq!(fingerprint_elem(&SquareOnce), fingerprint_elem(&SquareOnce));
    assert_eq!(
        fingerprint_unit(&EmptyRoutine),
        fingerprint_unit(&EmptyRoutine)
    );
}

/// Distinct Rust types with identical constraint structure share a fingerprint.
#[test]
fn test_structural_equivalence() {
    let sq = fingerprint_elem(&SquareOnce);
    let alias = fingerprint_elem(&SquareOnceAlias);
    let n1 = fingerprint_elem(&SquareN::<1>);

    assert_eq!(sq, alias);
    assert_eq!(sq, n1);
    assert_eq!(alias, n1);
}

/// Different constraint counts produce different fingerprints.
#[test]
fn test_structural_sensitivity() {
    let n1 = fingerprint_elem(&SquareN::<1>);
    let n2 = fingerprint_elem(&SquareN::<2>);
    let n3 = fingerprint_elem(&SquareN::<3>);

    assert_ne!(n1, n2);
    assert_ne!(n2, n3);
    assert_ne!(n1, n3);
}

/// Routines with different Input/Output TypeIds are always distinct.
#[test]
fn test_type_discrimination() {
    let all = [
        fingerprint_elem(&SquareOnce),
        fingerprint_unit(&Produce),
        fingerprint_elem(&Duplicate),
        fingerprint_unit(&EmptyRoutine),
    ];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j], "routines {i} and {j} must be distinct");
        }
    }
}

/// Different input wire counts produce different fingerprints.
#[test]
fn test_input_wire_count() {
    assert_ne!(fingerprint_elem(&SquareOnce), fingerprint_pair(&AddTwo));
}

/// Nested routine calls produce fingerprints based on local constraints only.
#[test]
fn test_nesting() {
    let square = fingerprint_elem(&SquareOnce);
    let pure = fingerprint_elem(&PureNesting);
    let extra = fingerprint_elem(&NestingWithExtra);

    assert_ne!(square, pure);
    assert_ne!(square, extra);
    assert_ne!(pure, extra);
}

/// Zero-constraint routines are distinguished by TypeId pairs alone.
#[test]
fn test_degenerate_cases() {
    assert_ne!(fingerprint_unit(&EmptyRoutine), fingerprint_unit(&Produce));
    assert_ne!(fingerprint_elem(&Duplicate), fingerprint_elem(&SquareOnce));
}

/// Segment 0 is Root; segments 1+ are Routine.
#[test]
fn test_root_identity() {
    let metrics = metrics::eval(&SingleRoutineCircuit(SquareOnce)).unwrap();

    assert_eq!(metrics.segments.len(), 2);
    assert!(matches!(
        metrics.segments[0].identity,
        RoutineIdentity::Root
    ));
    assert!(matches!(
        metrics.segments[1].identity,
        RoutineIdentity::Routine(_)
    ));
}

/// Guard against accidental changes to the fingerprint computation.
#[test]
fn test_known_value_regression() {
    assert_eq!(fingerprint_elem(&SquareOnce).scalar(), 12737696307900500113);
}

/// Fingerprint from metrics::eval matches standalone fingerprint_routine.
#[test]
fn test_metrics_integration() {
    let metrics = metrics::eval(&SingleRoutineCircuit(SquareOnce)).unwrap();
    let direct = fingerprint_elem(&SquareOnce);

    match metrics.segments[1].identity {
        RoutineIdentity::Routine(fp) => assert_eq!(fp, direct),
        RoutineIdentity::Root => panic!("record 1 should be Routine"),
    }
    assert!(metrics.segments[1].num_multiplication_constraints > 0);
}

/// Routines with only linear constraints (no multiplications) get nonzero fingerprints.
#[test]
fn test_linear_only() {
    let linear = fingerprint_elem(&LinearOnly);
    assert_ne!(linear, fingerprint_elem(&SquareOnce));
    assert_ne!(linear.scalar(), 0);
    assert_ne!(linear, fingerprint_unit(&EmptyRoutine));
}

/// Mixed alloc + mul + enforce_zero produces a fingerprint distinct from pure mul or pure linear.
#[test]
fn test_mixed_constraints() {
    let mixed = fingerprint_elem(&MixedConstraints);
    assert_ne!(mixed, fingerprint_elem(&SquareOnce));
    assert_ne!(mixed, fingerprint_elem(&LinearOnly));
}

/// Pure delegation wrappers are nesting-depth-invariant; metrics produces correct segment count.
#[test]
fn test_triple_nesting() {
    let triple = fingerprint_elem(&TripleNesting);
    assert_eq!(triple, fingerprint_elem(&PureNesting));
    assert_ne!(triple, fingerprint_elem(&SquareOnce));

    let metrics = metrics::eval(&SingleRoutineCircuit(TripleNesting)).unwrap();
    assert_eq!(metrics.segments.len(), 4);
}

/// Parents that call the same child but differ in post-processing get different fingerprints.
#[test]
fn test_output_remapping_preserves_parent() {
    assert_ne!(
        fingerprint_elem(&NestThenSquare),
        fingerprint_elem(&NestThenAdd)
    );
}
