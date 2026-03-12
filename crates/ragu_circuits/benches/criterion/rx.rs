use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ff::Field;
use ragu_circuits::{Circuit, CircuitExt};
use ragu_core::Result;
use ragu_core::drivers::{Driver, DriverValue};
use ragu_core::gadgets::{Bound, Kind};
use ragu_core::maybe::Maybe;
use ragu_core::routines::{Prediction, Routine};
use ragu_pasta::Fp;
use ragu_primitives::Element;
use rand::SeedableRng;
use rand::rngs::StdRng;

/// A synthetic routine that does `depth` squarings in `execute()` but
/// predicts the output cheaply, exercising the `Known` parallel path.
#[derive(Clone)]
struct HeavyKnownRoutine {
    depth: usize,
}

impl Routine<Fp> for HeavyKnownRoutine {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let mut val = input;
        for _ in 0..self.depth {
            val = val.square(dr)?;
        }
        Ok(val)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        // Predict the output by computing the repeated squaring on the value.
        let output = Element::alloc(
            dr,
            D::try_just(|| {
                let mut v = *input.value().take();
                for _ in 0..self.depth {
                    v = v.square();
                }
                Ok(v)
            })?,
        )?;
        Ok(Prediction::Known(output, D::unit()))
    }
}

/// Circuit that calls `HeavyKnownRoutine` N times in sequence.
struct HeavyRoutineCircuit {
    calls: usize,
    depth: usize,
}

impl Circuit<Fp> for HeavyRoutineCircuit {
    type Instance = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness = Fp;
    type Aux = ();

    fn instance<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, instance)
    }

    fn witness<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness>,
    ) -> Result<(Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux>)> {
        let input = Element::alloc(dr, witness)?;
        let routine = HeavyKnownRoutine { depth: self.depth };

        let mut result = dr.routine(routine.clone(), input.clone())?;
        for _ in 1..self.calls {
            result = dr.routine(routine.clone(), input.clone())?;
        }

        Ok((result, D::unit()))
    }
}

fn rx_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("rx_heavy_known");
    let mut rng = StdRng::seed_from_u64(1234);
    let witness = Fp::random(&mut rng);

    let depth = 1000;
    for calls in [1, 4, 8] {
        let circuit = HeavyRoutineCircuit { calls, depth };

        group.bench_with_input(BenchmarkId::from_parameter(calls), &calls, |b, _| {
            b.iter(|| circuit.rx(witness).unwrap());
        });
    }

    group.finish();
}

criterion_group!(benches, rx_bench);
criterion_main!(benches);
