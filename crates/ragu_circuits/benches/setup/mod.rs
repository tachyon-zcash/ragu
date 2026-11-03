use ragu_circuits::{
    polynomials::{TestRank, WalletRank, sparse},
    registry::{Registry, RegistryBuilder},
};
use ragu_core::pasta::Fp;
use ragu_testing::circuits::{MySimpleCircuit, SquareCircuit};
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::field::Field;

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
    F::random(|bytes| rng.fill_bytes(bytes))
}

pub fn rand_sparse_poly(rng: &mut StdRng) -> sparse::Polynomial<Fp, WalletRank> {
    sparse::Polynomial::random(rng)
}

pub fn rand_sparse_poly_vec<const N: usize>(
    rng: &mut StdRng,
) -> Vec<sparse::Polynomial<Fp, WalletRank>> {
    (0..N).map(|_| sparse::Polynomial::random(rng)).collect()
}

pub fn builder_squares<'a>() -> RegistryBuilder<'a, Fp, WalletRank> {
    RegistryBuilder::<'a, Fp, WalletRank>::new()
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
