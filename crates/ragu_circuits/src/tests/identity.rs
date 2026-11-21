use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Bound, Kind},
    maybe::{Always, Maybe},
    pasta::Fp,
    routines::{Prediction, Routine},
};
use ragu_primitives::{Element, Simulator, allocator::Standard};
use rand::Rng;
use udon::field::Field;

use crate::{
    Circuit, WithAux,
    metrics::{self, DeepFingerprint, RoutineIdentity},
    polynomials::TestRank,
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
        let allocator = &mut Standard::new();
        Element::alloc(dr, allocator, D::just(|| Fp::ZERO))
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

/// Passthrough — returns input unchanged. No constraints.
///
/// With [`DropFirst`], forms a pair whose [`BaseFingerprint`] fields
/// `(scalar, num_gates, num_constraints)` are identical: neither routine
/// calls `enforce_zero` (the zero-seeded Horner accumulator stays at 0),
/// and neither emits any gate. Only the `TypeId` of `Input`
/// distinguishes them via the deep hash.
#[derive(Clone)]
struct Passthrough;

impl Routine<Fp> for Passthrough {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
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

/// Takes two inputs, returns the first. No constraints.
///
/// Paired with [`Passthrough`]: both have zero body constraints and
/// identical zero-valued Horner scalars, but different `Input` types.
#[derive(Clone)]
struct DropFirst;

impl Routine<Fp> for DropFirst {
    type Input = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (a, _b) = input;
        Ok(a)
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

/// Calls [`SquareOnce`] twice on the same input. Used to check that two
/// structurally identical sub-routine invocations within one parent
/// receive identical fingerprints — the floor planner relies on this for
/// memoization.
#[derive(Clone)]
struct DoubleSquare;

impl Routine<Fp> for DoubleSquare {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let _ = dr.routine(SquareOnce, input.clone())?;
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

/// Constraints only — no gates.
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
        let allocator = &mut Standard::new();
        let aux = Element::alloc(dr, allocator, D::just(|| Fp::ONE))?;
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

/// Delegates to SquareOnce then enforces output == 0.
#[derive(Clone)]
struct DelegateThenEnforce;

impl Routine<Fp> for DelegateThenEnforce {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let output = dr.routine(SquareOnce, input)?;
        output.enforce_zero(dr)?;
        Ok(output)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Allocates two fresh wires, enforces the second == 0. No delegation.
#[derive(Clone)]
struct AllocThenEnforce;

impl Routine<Fp> for AllocThenEnforce {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let _consume_paired_b = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        let fresh = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        fresh.enforce_zero(dr)?;
        Ok(fresh)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Allocates a fresh wire and returns it. No constraints.
///
/// As with [`AllocThenEnforce`], the first alloc consumes the paired
/// d-wire so that the returned wire comes from a fresh gate.
#[derive(Clone)]
struct AllocOnly;

impl Routine<Fp> for AllocOnly {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let _consume_paired_b = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        Element::alloc(dr, allocator, D::just(|| Fp::ZERO))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Delegates to SquareOnce, adds output + input, enforces sum == 0.
#[derive(Clone)]
struct DelegateThenAddEnforce;

impl Routine<Fp> for DelegateThenAddEnforce {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let output = dr.routine(SquareOnce, input.clone())?;
        let sum = output.add(dr, &input);
        sum.enforce_zero(dr)?;
        Ok(output)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Allocates two fresh wires, adds the second + input, enforces sum == 0.
#[derive(Clone)]
struct AllocThenAddEnforce;

impl Routine<Fp> for AllocThenAddEnforce {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let _consume_paired_b = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        let fresh = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        let sum = fresh.add(dr, &input);
        sum.enforce_zero(dr)?;
        Ok(fresh)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Like [`SquareOnce`] but preceded by two trivial `enforce_zero` calls
/// (empty linear combination). The two leading empty constraints
/// contribute zero to the zero-seeded Horner accumulator, so the final
/// eval scalar is identical to [`SquareOnce`]; the pair is discriminated
/// solely by `num_constraints` (2 vs 4) in [`BaseFingerprint`].
#[derive(Clone)]
struct SquareOnceWithLeadingTrivial;

impl Routine<Fp> for SquareOnceWithLeadingTrivial {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        dr.enforce_zero(|lc| lc)?;
        dr.enforce_zero(|lc| lc)?;
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

/// Delegates to SquareOnce, pads with an extra alloc (to match constraint
/// counts with non-delegating routines), enforces the CHILD OUTPUT wire == 0.
#[derive(Clone)]
struct DelegateEnforceChild;

impl Routine<Fp> for DelegateEnforceChild {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let output = dr.routine(SquareOnce, input)?;
        let allocator = &mut Standard::new();
        let _consume_b = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        let _pad = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        output.enforce_zero(dr)?;
        Ok(output)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Delegates to SquareOnce, pads with an extra alloc (to match constraint
/// counts with non-delegating routines), enforces the LOCAL ALLOC wire == 0.
#[derive(Clone)]
struct DelegateEnforceLocal;

impl Routine<Fp> for DelegateEnforceLocal {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let output = dr.routine(SquareOnce, input)?;
        let allocator = &mut Standard::new();
        let _consume_b = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        let fresh = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        fresh.enforce_zero(dr)?;
        Ok(output)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Delegates to SquareOnce, pads with one alloc (to occupy a mul gate),
/// enforces the CHILD OUTPUT wire == 0.
///
/// Paired with [`DelegateAllocEnforceFirst`]: both have one local mul
/// gate and one constraint after delegation, but one enforces the
/// child output while the other enforces the local allocation.
#[derive(Clone)]
struct DelegatePadEnforceOutput;

impl Routine<Fp> for DelegatePadEnforceOutput {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let output = dr.routine(SquareOnce, input)?;
        let allocator = &mut Standard::new();
        let _pad = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        output.enforce_zero(dr)?;
        Ok(output)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Delegates to SquareOnce, allocates one wire, enforces the LOCAL ALLOC
/// wire == 0.
///
/// Paired with [`DelegatePadEnforceOutput`]: both have one local mul
/// gate and one constraint, but this routine enforces a fresh
/// input-independent allocation instead of the child's input-dependent
/// output.
#[derive(Clone)]
struct DelegateAllocEnforceFirst;

impl Routine<Fp> for DelegateAllocEnforceFirst {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let output = dr.routine(SquareOnce, input)?;
        let allocator = &mut Standard::new();
        let local = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        local.enforce_zero(dr)?;
        Ok(output)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Three input wires, returns first. Paired with [`PassthroughQuad`]:
/// neither routine calls `enforce_zero`, so both leave the Horner
/// accumulator at zero and produce identical [`BaseFingerprint`]s.
/// Only the input `TypeId` distinguishes them via the deep hash.
#[derive(Clone)]
struct PassthroughTriple;

impl Routine<Fp> for PassthroughTriple {
    type Input = Kind![Fp; (Element<'_, _>, (Element<'_, _>, Element<'_, _>))];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (a, _) = input;
        Ok(a)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Four input wires, returns first. Paired with [`PassthroughTriple`].
#[derive(Clone)]
struct PassthroughQuad;

impl Routine<Fp> for PassthroughQuad {
    type Input = Kind![Fp; ((Element<'_, _>, Element<'_, _>), (Element<'_, _>, Element<'_, _>))];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let ((a, _), _) = input;
        Ok(a)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Trivial enforce_zero (empty LC), returns input unchanged.
#[derive(Clone)]
struct TrivialEnforce;

impl Routine<Fp> for TrivialEnforce {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        dr.enforce_zero(|lc| lc)?;
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

/// Trivial enforce_zero (empty LC) with pair input, drops second.
#[derive(Clone)]
struct TrivialEnforcePair;

impl Routine<Fp> for TrivialEnforcePair {
    type Input = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        dr.enforce_zero(|lc| lc)?;
        let (a, _) = input;
        Ok(a)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Enforces input == 0, returns input.
#[derive(Clone)]
struct EnforceInput;

impl Routine<Fp> for EnforceInput {
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

/// Enforces first input == 0, drops second, returns first.
#[derive(Clone)]
struct EnforceInputPair;

impl Routine<Fp> for EnforceInputPair {
    type Input = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (a, _) = input;
        a.enforce_zero(dr)?;
        Ok(a)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Squares input and returns a duplicate pair of the result.
#[derive(Clone)]
struct SquareDuplicate;

impl Routine<Fp> for SquareDuplicate {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let sq = input.square(dr)?;
        Ok((sq.clone(), sq))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Pair passthrough — returns (Element, Element) input unchanged.
#[derive(Clone)]
struct PairPassthrough;

impl Routine<Fp> for PairPassthrough {
    type Input = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
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

/// Allocates an internal wire and enforces it zero. Single-element input.
#[derive(Clone)]
struct InternalEnforce;

impl Routine<Fp> for InternalEnforce {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let aux = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        aux.enforce_zero(dr)?;
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

/// Allocates an internal wire and enforces it zero. Pair input, drops second.
#[derive(Clone)]
struct InternalEnforcePair;

impl Routine<Fp> for InternalEnforcePair {
    type Input = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let aux = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        aux.enforce_zero(dr)?;
        let (a, _) = input;
        Ok(a)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Delegates to SquareOnce with first input wire. Pair input.
#[derive(Clone)]
struct PureNestingPair;

impl Routine<Fp> for PureNestingPair {
    type Input = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (a, _) = input;
        dr.routine(SquareOnce, a)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Three enforce_zero calls on the input wire.
#[derive(Clone)]
struct TripleEnforceInput;

impl Routine<Fp> for TripleEnforceInput {
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

/// Three enforce_zero calls on the first input wire. Pair input, drops second.
#[derive(Clone)]
struct TripleEnforceInputPair;

impl Routine<Fp> for TripleEnforceInputPair {
    type Input = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (a, _) = input;
        a.enforce_zero(dr)?;
        a.enforce_zero(dr)?;
        a.enforce_zero(dr)?;
        Ok(a)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Enforces ONE wire == 0 (references the distinguished ONE wire).
#[derive(Clone)]
struct OneWireEnforce;

impl Routine<Fp> for OneWireEnforce {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        dr.enforce_zero(|lc| lc.add(&D::ONE))?;
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

/// Enforces ONE wire == 0 with pair input, drops second.
#[derive(Clone)]
struct OneWireEnforcePair;

impl Routine<Fp> for OneWireEnforcePair {
    type Input = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        dr.enforce_zero(|lc| lc.add(&D::ONE))?;
        let (a, _) = input;
        Ok(a)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

fn fingerprint_triple(
    routine: &impl Routine<Fp, Input = Kind![Fp; (Element<'_, _>, (Element<'_, _>, Element<'_, _>))]>,
) -> DeepFingerprint {
    let sim = &mut Simulator::<Fp>::new();
    let allocator = &mut Standard::new();
    let a = Element::alloc(sim, allocator, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    let b = Element::alloc(sim, allocator, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    let c = Element::alloc(sim, allocator, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    match metrics::tests::fingerprint_routine::<Fp, Simulator<Fp>, _>(routine, &(a, (b, c)))
        .unwrap()
    {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

fn fingerprint_quad(
    routine: &impl Routine<
        Fp,
        Input = Kind![Fp; ((Element<'_, _>, Element<'_, _>), (Element<'_, _>, Element<'_, _>))],
    >,
) -> DeepFingerprint {
    let sim = &mut Simulator::<Fp>::new();
    let allocator = &mut Standard::new();
    let a = Element::alloc(sim, allocator, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    let b = Element::alloc(sim, allocator, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    let c = Element::alloc(sim, allocator, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    let d = Element::alloc(sim, allocator, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    match metrics::tests::fingerprint_routine::<Fp, Simulator<Fp>, _>(routine, &((a, b), (c, d)))
        .unwrap()
    {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

fn fingerprint_elem<F: Field>(
    routine: &impl Routine<F, Input = Kind![F; Element<'_, _>]>,
) -> DeepFingerprint {
    let mut sim = Simulator::<F>::new();
    let allocator = &mut Standard::new();
    let input = Element::alloc(&mut sim, allocator, Always::<F>::just(|| F::ONE)).unwrap();
    match metrics::tests::fingerprint_routine::<F, Simulator<F>, _>(routine, &input).unwrap() {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

fn fingerprint_unit(routine: &impl Routine<Fp, Input = Kind![Fp; ()]>) -> DeepFingerprint {
    match metrics::tests::fingerprint_routine::<Fp, Simulator<Fp>, _>(routine, &()).unwrap() {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

fn fingerprint_pair<F: Field>(
    routine: &impl Routine<F, Input = Kind![F; (Element<'_, _>, Element<'_, _>)]>,
) -> DeepFingerprint {
    let sim = &mut Simulator::<F>::new();
    let allocator = &mut Standard::new();
    let a = Element::alloc(sim, allocator, Always::<F>::just(|| F::ONE)).unwrap();
    let b = Element::alloc(sim, allocator, Always::<F>::just(|| F::ONE)).unwrap();
    match metrics::tests::fingerprint_routine::<F, Simulator<F>, _>(routine, &(a, b)).unwrap() {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

/// Extracts a routine's fingerprint via `metrics::eval`, which runs
/// through `Counter::routine` (the production path for input remapping).
fn fingerprint_via_eval<F: Field, Ro>(routine: &Ro) -> DeepFingerprint
where
    Ro: Routine<F, Input = Kind![F; Element<'_, _>], Output = Kind![F; Element<'_, _>]>
        + Clone
        + Send
        + Sync,
    for<'dr> Ro::Aux<'dr>: Send + Clone,
{
    let m = metrics::eval(&SingleRoutineCircuit(routine.clone())).unwrap();
    assert!(
        m.segments.len() >= 2,
        "fingerprint_via_eval expects at least 2 segments (root + routine); \
         got {}",
        m.segments.len(),
    );
    match *m.segments[1].identity() {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

/// Wraps an `Element → Element` routine as a minimal Circuit for metrics tests.
#[derive(Clone)]
struct SingleRoutineCircuit<Ro: Clone>(Ro);

impl<F: Field, Ro> Circuit<F> for SingleRoutineCircuit<Ro>
where
    Ro: Routine<F, Input = Kind![F; Element<'_, _>], Output = Kind![F; Element<'_, _>]>
        + Clone
        + Send
        + Sync,
    for<'dr> Ro::Aux<'dr>: Send + Clone,
{
    type Instance<'source> = F;
    type Output = Kind![F; Element<'_, _>];
    type Witness<'source> = F;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        Element::alloc(dr, allocator, instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let input = Element::alloc(dr, allocator, witness)?;
        let output = dr.routine(self.0.clone(), input)?;
        Ok(WithAux::new(output, D::just(|| ())))
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

/// Repeated invocations of the same routine within one circuit must
/// produce identical fingerprints, so the floor planner can memoize
/// structurally equivalent sub-routines. Pins the per-scope reset of
/// the `Counter`'s remap counter — without it, the second
/// `SquareOnce` call's input wires would receive different remap
/// tokens than the first, producing a divergent Horner accumulator.
#[test]
fn test_repeated_invocation_fingerprint_stability() {
    let metrics = metrics::eval(&SingleRoutineCircuit(DoubleSquare)).unwrap();
    // segments[0] = root, [1] = DoubleSquare, [2] = first SquareOnce,
    // [3] = second SquareOnce.
    assert_eq!(metrics.segments.len(), 4);
    let fp2 = match metrics.segments[2].identity() {
        RoutineIdentity::Routine(fp) => *fp,
        RoutineIdentity::Root => panic!("segment 2 should be Routine"),
    };
    let fp3 = match metrics.segments[3].identity() {
        RoutineIdentity::Routine(fp) => *fp,
        RoutineIdentity::Root => panic!("segment 3 should be Routine"),
    };
    assert_eq!(
        fp2, fp3,
        "two calls to SquareOnce within one parent must share a fingerprint",
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

/// Degenerate routines: EmptyRoutine (() → ()) allocates nothing while
/// Produce (() → Element) allocates one wire (1 mul gate), so their
/// routine fingerprints differ by constraint count. Duplicate vs
/// SquareOnce differ in constraints too.
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
        metrics.segments[0].identity(),
        RoutineIdentity::Root
    ));
    assert!(matches!(
        metrics.segments[1].identity(),
        RoutineIdentity::Routine(_)
    ));
}

/// The fingerprint is deterministic and nonzero for a non-trivial routine.
#[test]
fn test_known_value_regression() {
    let a = fingerprint_elem(&SquareOnce);
    let b = fingerprint_elem(&SquareOnce);
    assert_eq!(a.eval(), b.eval());
    assert_ne!(a.eval(), 0);
}

/// Fingerprint from metrics::eval matches standalone fingerprint_routine.
#[test]
fn test_metrics_integration() {
    let metrics = metrics::eval(&SingleRoutineCircuit(SquareOnce)).unwrap();
    let direct = fingerprint_elem(&SquareOnce);

    match *metrics.segments[1].identity() {
        RoutineIdentity::Routine(fp) => assert_eq!(fp, direct),
        RoutineIdentity::Root => panic!("record 1 should be Routine"),
    }
    assert!(metrics.segments[1].num_gates() > 0);
}

/// Routines with only constraints (no gates) get nonzero fingerprints.
#[test]
fn test_linear_only() {
    let linear = fingerprint_elem(&LinearOnly);
    assert_ne!(linear, fingerprint_elem(&SquareOnce));
    assert_ne!(linear.eval(), 0);
    assert_ne!(linear, fingerprint_unit(&EmptyRoutine));
}

/// Mixed alloc + mul + enforce_zero produces a fingerprint distinct from pure mul or pure linear.
#[test]
fn test_mixed_constraints() {
    let mixed = fingerprint_elem(&MixedConstraints);
    assert_ne!(mixed, fingerprint_elem(&SquareOnce));
    assert_ne!(mixed, fingerprint_elem(&LinearOnly));
}

/// Pure delegation wrappers share the same base fingerprint (same constraint
/// shape) but differ in their deep fingerprint (different recursive subtree).
#[test]
fn test_triple_nesting() {
    let triple = fingerprint_elem(&TripleNesting);
    let single = fingerprint_elem(&PureNesting);
    assert_eq!(triple.base(), single.base());
    assert_ne!(triple.deep(), single.deep());
    assert_ne!(triple.base(), fingerprint_elem(&SquareOnce).base());

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

/// Delegation + enforce vs local alloc + enforce.  Differs in mul count
/// (0 vs 1) and scalar (output remap wire vs local alloc wire have
/// distinct geometric values).
#[test]
fn test_aliasing_delegate_vs_alloc_enforce() {
    assert_ne!(
        fingerprint_elem(&DelegateThenEnforce),
        fingerprint_elem(&AllocThenEnforce),
    );
}

/// Pure delegation wrapper vs local alloc with no constraints.  With no
/// `enforce_zero` calls the scalars are both zero (the Horner seed), but
/// the gate counts differ (0 vs 1), so the base fingerprints differ.
#[test]
fn test_aliasing_delegate_vs_alloc_no_constraints() {
    assert_ne!(fingerprint_elem(&PureNesting), fingerprint_elem(&AllocOnly),);
}

/// Aliasing through linear combinations: delegation output + input vs
/// local alloc + input, fed into `add` then `enforce_zero`.  The
/// output remap wire and local alloc wire have distinct geometric
/// values, so the `add` sums and thus the Horner contributions differ.
#[test]
fn test_aliasing_propagates_through_linear_combinations() {
    assert_ne!(
        fingerprint_elem(&DelegateThenAddEnforce),
        fingerprint_elem(&AllocThenAddEnforce),
    );
}

/// [`SquareOnce`] (2 constraints) vs [`SquareOnceWithLeadingTrivial`]
/// (2 leading empty `enforce_zero` + 2 from square = 4 total). Leading
/// empty constraints are invisible to the zero-seeded Horner accumulator
/// (both routines produce the same eval scalar), but `num_constraints`
/// — part of [`BaseFingerprint`] — differs (2 vs 4), so the fingerprints
/// differ.
#[test]
fn test_aliasing_leading_trivial_constraints() {
    assert_ne!(
        fingerprint_elem(&SquareOnce),
        fingerprint_elem(&SquareOnceWithLeadingTrivial),
    );
}

/// The aliased routine pairs have genuinely different constraint structure,
/// confirmed by differing metrics (segment counts, child routines).
#[test]
fn test_aliasing_metrics_confirm_different_structure() {
    let m1 = metrics::eval(&SingleRoutineCircuit(DelegateThenEnforce)).unwrap();
    let m2 = metrics::eval(&SingleRoutineCircuit(AllocThenEnforce)).unwrap();
    assert_ne!(m1.segments.len(), m2.segments.len());

    let m3 = metrics::eval(&SingleRoutineCircuit(PureNesting)).unwrap();
    let m4 = metrics::eval(&SingleRoutineCircuit(AllocOnly)).unwrap();
    assert_ne!(m3.segments.len(), m4.segments.len());
}

/// Enforces the child output wire vs a local alloc wire.  The output
/// remap and the subsequent alloc land at different geometric positions,
/// producing distinct Horner contributions.
#[test]
fn test_wire_collision_child_output_vs_local_alloc() {
    assert_ne!(
        fingerprint_elem(&DelegateEnforceChild),
        fingerprint_elem(&DelegateEnforceLocal),
    );
}

/// Delegation + enforce child output vs no delegation + enforce local
/// alloc.  Different segment structure (delegation creates a child
/// segment) and different scalars.
#[test]
fn test_delegation_indistinguishable_from_alloc_with_matched_counts() {
    assert_ne!(
        fingerprint_elem(&DelegateEnforceChild),
        fingerprint_elem(&AllocThenEnforce),
    );
}

/// DelegateEnforceChild and DelegateEnforceLocal have identical segment
/// structure and per-segment constraint counts, but differ in which wire
/// is enforced (child output vs local alloc), producing distinct scalars.
#[test]
fn test_wire_collision_metrics_identical() {
    let m1 = metrics::eval(&SingleRoutineCircuit(DelegateEnforceChild)).unwrap();
    let m2 = metrics::eval(&SingleRoutineCircuit(DelegateEnforceLocal)).unwrap();
    assert_eq!(m1.segments.len(), m2.segments.len());
    assert_eq!(m1.segments.len(), 3);
    for (s1, s2) in m1.segments.iter().zip(m2.segments.iter()) {
        assert_eq!(s1.num_gates(), s2.num_gates());
        assert_eq!(s1.num_constraints(), s2.num_constraints());
    }
}

/// `fingerprint_routine` (standalone) and `fingerprint_via_eval`
/// (production path through `Counter::routine`) must agree for every
/// `Element → Element` test routine.
#[test]
fn test_cross_path_consistency() {
    macro_rules! check {
        ($($routine:expr),+ $(,)?) => {
            $(assert_eq!(
                fingerprint_elem(&$routine),
                fingerprint_via_eval(&$routine),
                concat!("cross-path mismatch for ", stringify!($routine)),
            );)+
        };
    }
    check![
        SquareOnce,
        SquareOnceAlias,
        PureNesting,
        NestingWithExtra,
        LinearOnly,
        MixedConstraints,
        TripleNesting,
        NestThenSquare,
        NestThenAdd,
        DelegateThenEnforce,
        AllocThenEnforce,
        AllocOnly,
        DelegateThenAddEnforce,
        AllocThenAddEnforce,
        SquareOnceWithLeadingTrivial,
        DelegateEnforceChild,
        DelegateEnforceLocal,
        DelegatePadEnforceOutput,
        DelegateAllocEnforceFirst,
    ];
}

/// Via `eval`, [`PureNesting`] and [`AllocOnly`] have identical (zero)
/// scalars — neither calls `enforce_zero`, so the Horner accumulator
/// stays at its zero seed — but differ in gate count (0 vs 1), and are
/// therefore distinguished by `num_gates` in [`BaseFingerprint`].
#[test]
fn test_missing_counts_via_eval() {
    assert_ne!(
        fingerprint_via_eval(&PureNesting),
        fingerprint_via_eval(&AllocOnly),
    );
}

/// Via `eval`, [`SquareOnce`] and [`SquareOnceWithLeadingTrivial`] produce
/// identical Horner scalars (leading zero LCs vanish under the zero-seeded
/// accumulator) but differ in `num_constraints` (2 vs 4), so they are
/// distinguished by [`BaseFingerprint::num_constraints`].
#[test]
fn test_vanishing_leading_trivial_via_eval() {
    assert_ne!(
        fingerprint_via_eval(&SquareOnce),
        fingerprint_via_eval(&SquareOnceWithLeadingTrivial),
    );
}

/// DelegatePadEnforceOutput enforces the remapped child output wire;
/// DelegateAllocEnforceFirst enforces a subsequent local alloc.  The
/// output wire carries a value from the parent's `x_remap` sequence,
/// while the local alloc carries a value from the `x0` (a-wire)
/// sequence — these are independent BLAKE2b bases, so the Horner
/// scalars differ.
#[test]
fn test_wire_collision_via_eval() {
    assert_ne!(
        fingerprint_via_eval(&DelegatePadEnforceOutput),
        fingerprint_via_eval(&DelegateAllocEnforceFirst),
    );
}

/// DelegatePadEnforceOutput and DelegateAllocEnforceFirst have identical
/// segment structure and per-segment constraint counts — they are
/// distinguished solely by the Horner scalar.
#[test]
fn test_wire_collision_via_eval_metrics_identical() {
    let m1 = metrics::eval(&SingleRoutineCircuit(DelegatePadEnforceOutput)).unwrap();
    let m2 = metrics::eval(&SingleRoutineCircuit(DelegateAllocEnforceFirst)).unwrap();
    assert_eq!(m1.segments.len(), m2.segments.len());
    assert_eq!(m1.segments.len(), 3);
    for (s1, s2) in m1.segments.iter().zip(m2.segments.iter()) {
        assert_eq!(s1.num_gates(), s2.num_gates());
        assert_eq!(s1.num_constraints(), s2.num_constraints());
    }
}

/// `Passthrough` (Input = Element) and `DropFirst` (Input = (Element,
/// Element)) have zero body constraints, identical Horner scalars, and
/// both forward the first input wire (so output wires are positionally
/// identical). Under relaxed fungibility the input Rust type alone must
/// not distinguish them — the deep hashes collide as well.
#[test]
fn test_input_type_does_not_distinguish_fingerprint() {
    let a = fingerprint_elem(&Passthrough);
    let b = fingerprint_pair(&DropFirst);

    assert_eq!(a.base(), b.base());
    assert_eq!(a.deep(), b.deep());
    assert_eq!(a, b);
}

/// `Passthrough` (Output = Element, 1 wire) vs `Duplicate`
/// (Output = (Element, Element), 2 wires) share the same input type and
/// algebraic contribution, but their output wire vectors differ in
/// length and content. The deep hash absorbs `output_wires` and
/// `output_wires.len()`, so the fingerprints remain distinct even with
/// type identity removed.
#[test]
fn test_output_arity_distinguishes_fingerprint() {
    let a = fingerprint_elem(&Passthrough);
    let b = fingerprint_elem(&Duplicate);

    assert_eq!(a.base(), b.base());
    assert_ne!(a.deep(), b.deep());
    assert_ne!(a, b);
}

/// 3 vs 4 input wires, both routines forward the first input. The first
/// input is at the same position (`x_remap`) in either case, so output
/// wires match. Under relaxed fungibility the input arity alone must
/// not distinguish.
#[test]
fn test_input_arity_does_not_distinguish_when_outputs_align() {
    let a = fingerprint_triple(&PassthroughTriple);
    let b = fingerprint_quad(&PassthroughQuad);

    assert_eq!(a.base(), b.base());
    assert_eq!(a.deep(), b.deep());
    assert_eq!(a, b);
}

/// Trivial enforce_zero (empty LC) with 1 vs 2 input wires, output is
/// the first input wire in both cases. Input type must not distinguish.
#[test]
fn test_trivial_enforce_zero_input_type_irrelevant() {
    let a = fingerprint_elem(&TrivialEnforce);
    let b = fingerprint_pair(&TrivialEnforcePair);

    assert_eq!(a.base(), b.base());
    assert_eq!(a.deep(), b.deep());
    assert_eq!(a, b);
}

/// Input-dependent enforce_zero with 1 vs 2 input wires; both forward
/// the first input. Input type must not distinguish.
#[test]
fn test_first_input_enforce_input_type_irrelevant() {
    let a = fingerprint_elem(&EnforceInput);
    let b = fingerprint_pair(&EnforceInputPair);

    assert_eq!(a.base(), b.base());
    assert_eq!(a.deep(), b.deep());
    assert_eq!(a, b);
}

/// `SquareOnce` (Output = Element, 1 wire) vs `SquareDuplicate`
/// (Output = (Element, Element), 2 wires) share input type and body
/// constraints, but differ in output arity. The deep hash distinguishes
/// them via `output_wires.len()`.
#[test]
fn test_output_arity_with_square_distinguishes() {
    let a = fingerprint_elem(&SquareOnce);
    let b = fingerprint_elem(&SquareDuplicate);

    assert_eq!(a.base(), b.base());
    assert_ne!(a.deep(), b.deep());
    assert_ne!(a, b);
}

/// `Passthrough` (Element → Element) vs `PairPassthrough`
/// ((Element, Element) → (Element, Element)): both input *and* output
/// arity differ. The deep hash distinguishes them via
/// `output_wires.len()` regardless of type identity.
#[test]
fn test_input_and_output_arity_both_differ() {
    let a = fingerprint_elem(&Passthrough);
    let b = fingerprint_pair(&PairPassthrough);

    assert_eq!(a.base(), b.base());
    assert_ne!(a.deep(), b.deep());
    assert_ne!(a, b);
}

/// Internal-only constraint (alloc + enforce_zero) with 1 vs 2 input
/// wires; output is unaffected by the extra unused input. Input type
/// must not distinguish.
#[test]
fn test_internal_only_constraints_input_type_irrelevant() {
    let a = fingerprint_elem(&InternalEnforce);
    let b = fingerprint_pair(&InternalEnforcePair);

    assert_eq!(a.base(), b.base());
    assert_eq!(a.deep(), b.deep());
    assert_eq!(a, b);
}

/// Production path cross-check: `Passthrough` via `metrics::eval` vs
/// `DropFirst` via the test-only `fingerprint_pair`. Both paths must
/// produce identical fingerprints under relaxed fungibility.
#[test]
fn test_production_path_input_type_irrelevant() {
    let a = fingerprint_via_eval(&Passthrough);
    let b = fingerprint_pair(&DropFirst);

    assert_eq!(
        fingerprint_via_eval(&Passthrough),
        fingerprint_elem(&Passthrough),
    );
    assert_eq!(a.base(), b.base());
    assert_eq!(a.deep(), b.deep());
    assert_eq!(a, b);
}

/// Nested delegation with 1 vs 2 input wires. The extra input shifts
/// where the child's output lands in the parent's `x_remap` sequence,
/// so `output_wires` content differs and the deep hash distinguishes —
/// independent of type identity.
#[test]
fn test_input_arity_affects_nested_output_position() {
    let a = fingerprint_elem(&PureNesting);
    let b = fingerprint_pair(&PureNestingPair);

    assert_eq!(a.base(), b.base());
    assert_ne!(a.deep(), b.deep());
    assert_ne!(a, b);
}

/// Three Horner steps (3× enforce_zero) with 1 vs 2 input wires; both
/// forward the first input. Input type must not distinguish.
#[test]
fn test_multiple_horner_steps_input_type_irrelevant() {
    let a = fingerprint_elem(&TripleEnforceInput);
    let b = fingerprint_pair(&TripleEnforceInputPair);

    assert_eq!(a.base(), b.base());
    assert_eq!(a.deep(), b.deep());
    assert_eq!(a, b);
}

/// ONE wire reference in enforce_zero with 1 vs 2 input wires; both
/// forward the first input. Input type must not distinguish.
#[test]
fn test_one_wire_constraint_input_type_irrelevant() {
    let a = fingerprint_elem(&OneWireEnforce);
    let b = fingerprint_pair(&OneWireEnforcePair);

    assert_eq!(a.base(), b.base());
    assert_eq!(a.deep(), b.deep());
    assert_eq!(a, b);
}

/// Allocates `w1` then `w2`, both zero, and enforces `w1 + w2 = 0`.
/// Returns `(w1, w2)`. Paired with [`SwapOrderReordered`], which swaps
/// the allocation order.
#[derive(Clone)]
struct SwapOrderIdentity;

impl Routine<Fp> for SwapOrderIdentity {
    type Input = Kind![Fp; ()];
    type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let w1 = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        let w2 = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        w1.add(dr, &w2).enforce_zero(dr)?;
        Ok((w1, w2))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Same shape as [`SwapOrderIdentity`] but allocates `w2` before `w1`.
/// Still enforces `w1 + w2 = 0` and returns `(w1, w2)`, so the output
/// gadget is identical; only the underlying wire values are swapped.
#[derive(Clone)]
struct SwapOrderReordered;

impl Routine<Fp> for SwapOrderReordered {
    type Input = Kind![Fp; ()];
    type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        // Allocations in opposite order: first alloc is labelled `w2`.
        let w2 = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        let w1 = Element::alloc(dr, allocator, D::just(|| Fp::ZERO))?;
        w1.add(dr, &w2).enforce_zero(dr)?;
        Ok((w1, w2))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Two routines with identical local shape and the same symmetric LC
/// `w1 + w2 = 0`, but opposite allocation order. Their base fingerprints
/// match (same `num_gates`, `num_constraints`, and Horner scalar). Their
/// deep fingerprints differ because the output-wire sequence — captured
/// in the deep hash before any parent-context remap — encodes the
/// swapped underlying wire values.
#[test]
fn test_swap_allocation_order_base_matches_deep_differs() {
    let a = fingerprint_unit(&SwapOrderIdentity);
    let b = fingerprint_unit(&SwapOrderReordered);

    assert_eq!(
        a.base(),
        b.base(),
        "symmetric LC + identical shape ⇒ identical base fingerprint",
    );
    assert_ne!(
        a, b,
        "swapped output-wire order ⇒ different deep fingerprint",
    );
}

/// Circuit wrapper for `(Element, Element) → Element` routines.
///
/// Allocates two input wires via paired allocation (consuming one
/// multiplication gate, matching [`SingleRoutineCircuit`]'s root
/// structure), then calls the routine.
struct PairRoutineCircuit<Ro: Clone>(Ro);

impl<F: Field, Ro> Circuit<F> for PairRoutineCircuit<Ro>
where
    Ro: Routine<
            F,
            Input = Kind![F; (Element<'_, _>, Element<'_, _>)],
            Output = Kind![F; Element<'_, _>],
        > + Clone
        + Send
        + Sync,
    for<'dr> Ro::Aux<'dr>: Send + Clone,
{
    type Instance<'source> = F;
    type Output = Kind![F; Element<'_, _>];
    type Witness<'source> = F;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        Element::alloc(dr, allocator, instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let a = Element::alloc(dr, allocator, witness.clone())?;
        let b = Element::alloc(dr, allocator, witness)?;
        let output = dr.routine(self.0.clone(), (a, b))?;
        Ok(WithAux::new(output, D::just(|| ())))
    }
}

/// Verifies that routines with matching [`BaseFingerprint`] (same
/// polynomial contribution) produce identical circuit polynomials, even
/// when their TypeIds differ.
///
/// This is the test that catches over-capture: if TypeIds affected the
/// polynomial, these assertions would fail. Each pair wraps a
/// single-input routine in [`SingleRoutineCircuit`] and a pair-input
/// routine in [`PairRoutineCircuit`]. Both wrappers allocate via paired
/// allocation (one mul gate), so the root segments are structurally
/// identical. The routines have matching `(eval, num_mul, num_lc)` but
/// different `Input` TypeIds.
///
/// [`BaseFingerprint`]: crate::BaseFingerprint
#[test]
fn test_typeid_does_not_affect_polynomial() {
    let x = Fp::random(|bytes| rand::rng().fill_bytes(bytes));
    let y = Fp::random(|bytes| rand::rng().fill_bytes(bytes));

    /// Compares s(x,y) for a single-input circuit vs a pair-input circuit
    /// whose routines share the same `BaseFingerprint`.
    fn assert_same_polynomial<F: Field, RoElem, RoPair>(
        elem_routine: RoElem,
        pair_routine: RoPair,
        x: F,
        y: F,
        label: &str,
    ) where
        RoElem: Routine<F, Input = Kind![F; Element<'_, _>], Output = Kind![F; Element<'_, _>]>
            + Clone
            + Send
            + Sync,
        for<'dr> RoElem::Aux<'dr>: Send + Clone,
        RoPair: Routine<
                F,
                Input = Kind![F; (Element<'_, _>, Element<'_, _>)],
                Output = Kind![F; Element<'_, _>],
            > + Clone
            + Send
            + Sync,
        for<'dr> RoPair::Aux<'dr>: Send + Clone,
    {
        // Confirm the routine fingerprints (polynomial identity) match.
        let fp_elem = fingerprint_elem(&elem_routine);
        let fp_pair = fingerprint_pair(&pair_routine);
        assert_eq!(
            fp_elem.base(),
            fp_pair.base(),
            "{label}: BaseFingerprint mismatch — test premise violated"
        );

        let obj_elem =
            crate::into_wiring_object::<F, _, TestRank>(SingleRoutineCircuit(elem_routine))
                .unwrap();
        let obj_pair =
            crate::into_wiring_object::<F, _, TestRank>(PairRoutineCircuit(pair_routine)).unwrap();

        let sxy_elem = obj_elem.sxy(x, y);
        let sxy_pair = obj_pair.sxy(x, y);

        assert_eq!(
            sxy_elem, sxy_pair,
            "{label}: same BaseFingerprint but different s(x,y) — \
             TypeIds affect the polynomial (this would be a soundness issue)"
        );
    }

    assert_same_polynomial(Passthrough, DropFirst, x, y, "Passthrough vs DropFirst");
    assert_same_polynomial(
        TrivialEnforce,
        TrivialEnforcePair,
        x,
        y,
        "TrivialEnforce vs TrivialEnforcePair",
    );
    assert_same_polynomial(
        EnforceInput,
        EnforceInputPair,
        x,
        y,
        "EnforceInput vs EnforceInputPair",
    );
    assert_same_polynomial(
        InternalEnforce,
        InternalEnforcePair,
        x,
        y,
        "InternalEnforce vs InternalEnforcePair",
    );
    assert_same_polynomial(
        OneWireEnforce,
        OneWireEnforcePair,
        x,
        y,
        "OneWireEnforce vs OneWireEnforcePair",
    );
    assert_same_polynomial(
        TripleEnforceInput,
        TripleEnforceInputPair,
        x,
        y,
        "TripleEnforceInput vs TripleEnforceInputPair",
    );
}
