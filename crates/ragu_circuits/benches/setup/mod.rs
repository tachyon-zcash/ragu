use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::polynomials::{R, structured, unstructured};
use ragu_circuits::registry::{Key, Registry, RegistryBuilder};
use ragu_circuits::test_fixtures::{MySimpleCircuit, SquareCircuit};
use ragu_pasta::{Fp, Pasta};
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

pub fn key<F: Field>(rng: &mut StdRng) -> Key<F> {
    Key::new(F::random(rng))
}

pub fn rand_structured_poly(rng: &mut StdRng) -> structured::Polynomial<Fp, R<13>> {
    structured::Polynomial::random(rng)
}

pub fn rand_structured_poly_vec<const N: usize>(
    rng: &mut StdRng,
) -> Vec<structured::Polynomial<Fp, R<13>>> {
    (0..N)
        .map(|_| structured::Polynomial::random(rng))
        .collect()
}

pub fn rand_unstructured_poly(rng: &mut StdRng) -> unstructured::Polynomial<Fp, R<13>> {
    unstructured::Polynomial::random(rng)
}

pub fn setup_poseidon<'a>() -> &'a <Pasta as Cycle>::CircuitPoseidon {
    Pasta::circuit_poseidon(Pasta::baked())
}

pub fn builder_squares<'a>() -> RegistryBuilder<'a, Fp, R<25>, 0> {
    RegistryBuilder::<'a, Fp, R<25>, 0>::new()
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

pub fn builder_simple<'a>() -> RegistryBuilder<'a, Fp, R<5>, 0> {
    RegistryBuilder::<'a, Fp, R<5>, 0>::new()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
}

pub fn registry_simple<'a>() -> Registry<'a, Fp, R<5>> {
    builder_simple().finalize(setup_poseidon()).unwrap()
}
