use ff::Field;
use ragu_core::maybe::Always;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    routines::{Prediction, Routine},
};
use ragu_pasta::Fp;
use ragu_primitives::{Element, Simulator};

use crate::{
    Circuit, WithAux,
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

/// Passthrough — returns input unchanged. No constraints.
///
/// With [`DropFirst`], forms a pair whose `(scalar, mul_count,
/// linear_count)` triples are identical: paired allocation packs 1 and
/// 2 input wires into the same gate count during the uncounted input
/// remap, so the geometric sequences reach the same state. Only the
/// `TypeId` of `Input` distinguishes them.
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
/// identical Horner scalars (the untouched seed `h`), but different
/// `Input` types.
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
        let _consume_paired_b = Element::alloc(dr, D::just(|| Fp::ZERO))?;
        let fresh = Element::alloc(dr, D::just(|| Fp::ZERO))?;
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
        let _consume_paired_b = Element::alloc(dr, D::just(|| Fp::ZERO))?;
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
        let _consume_paired_b = Element::alloc(dr, D::just(|| Fp::ZERO))?;
        let fresh = Element::alloc(dr, D::just(|| Fp::ZERO))?;
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

/// Like SquareOnce but preceded by two trivial enforce_zero calls (empty linear
/// combination). The $s(X, Y)$ polynomial differs because the real constraints
/// land at $Y^2$ and $Y^3$ instead of $Y^0$ and $Y^1$. The nonzero Horner seed
/// `h` ensures the leading empty constraints shift the accumulator (via
/// `h * y^k`), so the scalars also differ.
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
        let _consume_b = Element::alloc(dr, D::just(|| Fp::ZERO))?;
        let _pad = Element::alloc(dr, D::just(|| Fp::ZERO))?;
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
        let _consume_b = Element::alloc(dr, D::just(|| Fp::ZERO))?;
        let fresh = Element::alloc(dr, D::just(|| Fp::ZERO))?;
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
        let _pad = Element::alloc(dr, D::just(|| Fp::ZERO))?;
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
/// gate and one linear constraint, but this routine enforces a fresh
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
        let local = Element::alloc(dr, D::just(|| Fp::ZERO))?;
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
/// 3 and 4 wires produce identical post-remap state due to paired allocation.
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
        let aux = Element::alloc(dr, D::just(|| Fp::ZERO))?;
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
        let aux = Element::alloc(dr, D::just(|| Fp::ZERO))?;
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
) -> RoutineFingerprint {
    let sim = &mut Simulator::<Fp>::new();
    let a = Element::alloc(sim, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    let b = Element::alloc(sim, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    let c = Element::alloc(sim, Always::<Fp>::just(|| Fp::ONE)).unwrap();
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
) -> RoutineFingerprint {
    let sim = &mut Simulator::<Fp>::new();
    let a = Element::alloc(sim, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    let b = Element::alloc(sim, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    let c = Element::alloc(sim, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    let d = Element::alloc(sim, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    match metrics::tests::fingerprint_routine::<Fp, Simulator<Fp>, _>(routine, &((a, b), (c, d)))
        .unwrap()
    {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

fn fingerprint_elem(
    routine: &impl Routine<Fp, Input = Kind![Fp; Element<'_, _>]>,
) -> RoutineFingerprint {
    let mut sim = Simulator::<Fp>::new();
    let input = Element::alloc(&mut sim, Always::<Fp>::just(|| Fp::ONE)).unwrap();
    match metrics::tests::fingerprint_routine::<Fp, Simulator<Fp>, _>(routine, &input).unwrap() {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

fn fingerprint_unit(routine: &impl Routine<Fp, Input = Kind![Fp; ()]>) -> RoutineFingerprint {
    match metrics::tests::fingerprint_routine::<Fp, Simulator<Fp>, _>(routine, &()).unwrap() {
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
    match metrics::tests::fingerprint_routine::<Fp, Simulator<Fp>, _>(routine, &(a, b)).unwrap() {
        RoutineIdentity::Routine(fp) => fp,
        RoutineIdentity::Root => panic!("expected Routine variant"),
    }
}

/// Extracts a routine's fingerprint via `metrics::eval`, which runs
/// through `Counter::routine` (the production path that correctly clears
/// `available_d` after input remapping).
fn fingerprint_via_eval<Ro>(routine: &Ro) -> RoutineFingerprint
where
    Ro: Routine<Fp, Input = Kind![Fp; Element<'_, _>], Output = Kind![Fp; Element<'_, _>]>
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
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let input = Element::alloc(dr, witness)?;
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
/// `enforce_zero` calls the scalars are both equal to the Horner seed
/// `h`, but the mul counts differ (0 vs 1).
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

/// SquareOnce (2 constraints) vs SquareOnceWithLeadingTrivial
/// (2 leading empty `enforce_zero` + 2 from square = 4 total).  The
/// nonzero Horner seed makes leading empty constraints visible: the
/// seed shifts through extra powers of $y$, producing distinct scalars.
/// Constraint counts also differ (2 vs 4).
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

/// Regression: via `eval`, PureNesting and AllocOnly have identical
/// scalars (both equal to the Horner seed `h`, since neither has
/// `enforce_zero` calls) but differ in mul count (0 vs 1).
#[test]
fn test_missing_counts_via_eval() {
    assert_ne!(
        fingerprint_via_eval(&PureNesting),
        fingerprint_via_eval(&AllocOnly),
    );
}

/// Regression: via `eval`, SquareOnce and SquareOnceWithLeadingTrivial
/// now produce distinct scalars thanks to the nonzero Horner seed.
/// They also differ in constraint count (2 vs 4).
#[test]
fn test_vanishing_leading_trivial_via_eval() {
    assert_ne!(
        fingerprint_via_eval(&SquareOnce),
        fingerprint_via_eval(&SquareOnceWithLeadingTrivial),
    );
}

/// DelegatePadEnforceOutput enforces the remapped child output wire;
/// DelegateAllocEnforceFirst enforces a subsequent local alloc.  The
/// output remap advances the parent's geometric sequences, giving
/// these wires distinct values and thus distinct Horner scalars.
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
/// Element)) have zero body constraints and identical Horner scalars —
/// paired allocation packs 1 and 2 input wires into the same gate
/// count during the uncounted input remap, leaving the geometric
/// sequences in the same state.  Without `input_kind` in the
/// fingerprint, these would collide.
#[test]
fn test_typeid_necessary_for_input_discrimination() {
    let a = fingerprint_elem(&Passthrough);
    let b = fingerprint_pair(&DropFirst);

    // Confirm the scalar component is identical (both equal to the
    // untouched Horner seed `h`).
    assert_eq!(a.eval(), b.eval());

    // The fingerprints must still differ — only TypeId saves us.
    assert_ne!(a, b);
}

/// `Passthrough` (Output = Element) and `Duplicate` (Output =
/// (Element, Element)) share the same Input type and have zero body
/// constraints, so their `(scalar, mul_count, linear_count)` triples
/// are identical.  Without `output_kind` in the fingerprint, these
/// would collide.
#[test]
fn test_typeid_necessary_for_output_discrimination() {
    let a = fingerprint_elem(&Passthrough);
    let b = fingerprint_elem(&Duplicate);

    assert_eq!(a.eval(), b.eval());
    assert_ne!(a, b);
}

/// 3 vs 4 input wires produce identical post-remap Counter state.
#[test]
fn test_typeid_triple_vs_quad_input_wires() {
    let a = fingerprint_triple(&PassthroughTriple);
    let b = fingerprint_quad(&PassthroughQuad);

    assert_eq!(a.eval(), b.eval());
    assert_ne!(a, b);
}

/// Trivial enforce_zero (empty LC) with 1 vs 2 input wires.
#[test]
fn test_typeid_trivial_enforce_zero() {
    let a = fingerprint_elem(&TrivialEnforce);
    let b = fingerprint_pair(&TrivialEnforcePair);

    assert_eq!(a.eval(), b.eval());
    assert_ne!(a, b);
}

/// Input-dependent enforce_zero with 1 vs 2 input wires.
#[test]
fn test_typeid_enforce_first_input() {
    let a = fingerprint_elem(&EnforceInput);
    let b = fingerprint_pair(&EnforceInputPair);

    assert_eq!(a.eval(), b.eval());
    assert_ne!(a, b);
}

/// SquareOnce (Output = Element) vs SquareDuplicate (Output = (Element, Element)):
/// identical body constraints, distinguished by output TypeId.
#[test]
fn test_typeid_output_with_square() {
    let a = fingerprint_elem(&SquareOnce);
    let b = fingerprint_elem(&SquareDuplicate);

    assert_eq!(a.eval(), b.eval());
    assert_ne!(a, b);
}

/// Passthrough (Element → Element) vs PairPassthrough ((Element, Element) →
/// (Element, Element)): both TypeIds differ simultaneously.
#[test]
fn test_typeid_both_differ() {
    let a = fingerprint_elem(&Passthrough);
    let b = fingerprint_pair(&PairPassthrough);

    assert_eq!(a.eval(), b.eval());
    assert_ne!(a, b);
}

/// Internal-only constraint (alloc + enforce_zero) with 1 vs 2 input wires.
#[test]
fn test_typeid_internal_only_constraints() {
    let a = fingerprint_elem(&InternalEnforce);
    let b = fingerprint_pair(&InternalEnforcePair);

    assert_eq!(a.eval(), b.eval());
    assert_ne!(a, b);
}

/// Production path cross-check: Passthrough via eval vs DropFirst via pair.
#[test]
fn test_typeid_production_path() {
    let a = fingerprint_via_eval(&Passthrough);
    let b = fingerprint_pair(&DropFirst);

    assert_eq!(
        fingerprint_via_eval(&Passthrough),
        fingerprint_elem(&Passthrough),
    );
    assert_eq!(a.eval(), b.eval());
    assert_ne!(a, b);
}

/// Nested delegation with 1 vs 2 input wires.
#[test]
fn test_typeid_nested_with_pairing() {
    let a = fingerprint_elem(&PureNesting);
    let b = fingerprint_pair(&PureNestingPair);

    assert_eq!(a.eval(), b.eval());
    assert_ne!(a, b);
}

/// Three Horner steps (3× enforce_zero) with 1 vs 2 input wires.
#[test]
fn test_typeid_multiple_horner_steps() {
    let a = fingerprint_elem(&TripleEnforceInput);
    let b = fingerprint_pair(&TripleEnforceInputPair);

    assert_eq!(a.eval(), b.eval());
    assert_ne!(a, b);
}

/// ONE wire reference in enforce_zero with 1 vs 2 input wires.
#[test]
fn test_typeid_one_wire_constraint() {
    let a = fingerprint_elem(&OneWireEnforce);
    let b = fingerprint_pair(&OneWireEnforcePair);

    assert_eq!(a.eval(), b.eval());
    assert_ne!(a, b);
}
