use ff::Field;
use ragu_circuits::polynomials::{ProductionRank, TestRank, structured, unstructured};
use ragu_circuits::registry::{Registry, RegistryBuilder};
use ragu_pasta::Fp;
use ragu_testing::circuits::{HeavyRoutineCircuit, MySimpleCircuit, SquareCircuit};
use rand::SeedableRng;
use rand::rngs::StdRng;

pub trait SetupRng<Out> {
    fn setup(self, rng: &mut StdRng) -> Out;
}

impl<A, FA: FnOnce(&mut StdRng) -> A> SetupRng<(A,)> for (FA,) {
    fn setup(self, rng: &mut StdRng) -> (A,) {
        (self.0(rng),)
    }
}

impl<A, B, FA: FnOnce(&mut StdRng) -> A, FB: FnOnce(&mut StdRng) -> B> SetupRng<(A, B)>
    for (FA, FB)
{
    fn setup(self, rng: &mut StdRng) -> (A, B) {
        (self.0(rng), self.1(rng))
    }
}

impl<
    A,
    B,
    C,
    FA: FnOnce(&mut StdRng) -> A,
    FB: FnOnce(&mut StdRng) -> B,
    FC: FnOnce(&mut StdRng) -> C,
> SetupRng<(A, B, C)> for (FA, FB, FC)
{
    fn setup(self, rng: &mut StdRng) -> (A, B, C) {
        (self.0(rng), self.1(rng), self.2(rng))
    }
}

pub fn setup_rng<Fns: SetupRng<T>, T>(fns: Fns) -> T {
    let mut rng = StdRng::seed_from_u64(1234);
    fns.setup(&mut rng)
}

pub fn setup_with_rng<T, Fns: SetupRng<S>, S>(other: T, fns: Fns) -> (T, S) {
    let mut rng = StdRng::seed_from_u64(1234);
    (other, fns.setup(&mut rng))
}

pub fn f<F: Field>(rng: &mut StdRng) -> F {
    F::random(rng)
}

pub fn rand_structured_poly(rng: &mut StdRng) -> structured::Polynomial<Fp, ProductionRank> {
    structured::Polynomial::random(rng)
}

pub fn rand_structured_poly_vec<const N: usize>(
    rng: &mut StdRng,
) -> Vec<structured::Polynomial<Fp, ProductionRank>> {
    (0..N)
        .map(|_| structured::Polynomial::random(rng))
        .collect()
}

pub fn rand_unstructured_poly(rng: &mut StdRng) -> unstructured::Polynomial<Fp, ProductionRank> {
    unstructured::Polynomial::random(rng)
}

pub fn builder_squares<'a>() -> RegistryBuilder<'a, Fp, ProductionRank> {
    RegistryBuilder::<'a, Fp, ProductionRank>::new()
        .register_circuit(SquareCircuit { times: 2 })
        .unwrap()
        .register_circuit(SquareCircuit { times: 10 })
        .unwrap()
        .register_circuit(SquareCircuit { times: 11 })
        .unwrap()
        .register_circuit(SquareCircuit { times: 19 })
        .unwrap()
        .register_circuit(SquareCircuit { times: 19 })
        .unwrap()
        .register_circuit(SquareCircuit { times: 19 })
        .unwrap()
        .register_circuit(SquareCircuit { times: 19 })
        .unwrap()
        .register_circuit(SquareCircuit { times: 19 })
        .unwrap()
}

pub fn builder_simple<'a>() -> RegistryBuilder<'a, Fp, TestRank> {
    RegistryBuilder::<'a, Fp, TestRank>::new()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
}

pub fn registry_simple<'a>() -> Registry<'a, Fp, TestRank> {
    builder_simple().finalize().unwrap()
}

/// Registry with circuits that use heavy routines (for memoization benchmarks).
///
/// Uses 100 iterations per routine call to make the memoization savings visible.
pub fn builder_heavy_routines<'a>() -> RegistryBuilder<'a, Fp, ProductionRank> {
    RegistryBuilder::<'a, Fp, ProductionRank>::new()
        .register_circuit(HeavyRoutineCircuit {
            num_calls: 5,
            iterations_per_call: 100,
        })
        .unwrap()
        .register_circuit(HeavyRoutineCircuit {
            num_calls: 5,
            iterations_per_call: 100,
        })
        .unwrap()
        .register_circuit(HeavyRoutineCircuit {
            num_calls: 5,
            iterations_per_call: 100,
        })
        .unwrap()
        .register_circuit(HeavyRoutineCircuit {
            num_calls: 5,
            iterations_per_call: 100,
        })
        .unwrap()
        .register_circuit(HeavyRoutineCircuit {
            num_calls: 5,
            iterations_per_call: 100,
        })
        .unwrap()
        .register_circuit(HeavyRoutineCircuit {
            num_calls: 5,
            iterations_per_call: 100,
        })
        .unwrap()
        .register_circuit(HeavyRoutineCircuit {
            num_calls: 5,
            iterations_per_call: 100,
        })
        .unwrap()
        .register_circuit(HeavyRoutineCircuit {
            num_calls: 5,
            iterations_per_call: 100,
        })
        .unwrap()
}

pub fn registry_heavy_routines<'a>() -> Registry<'a, Fp, ProductionRank> {
    builder_heavy_routines().finalize().unwrap()
}
