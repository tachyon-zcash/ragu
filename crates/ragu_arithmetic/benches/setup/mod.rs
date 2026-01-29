use ff::Field;
use pasta_curves::group::prime::PrimeCurveAffine;
use pasta_curves::{EpAffine, Fp, Fq};
use ragu_arithmetic::Domain;
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

pub fn vec_f<const N: usize, F: Field>(rng: &mut StdRng) -> Vec<F> {
    (0..N).map(|_| F::random(&mut *rng)).collect()
}

pub fn vec_affine<const N: usize>(rng: &mut StdRng) -> Vec<EpAffine> {
    let g = EpAffine::generator();
    (0..N).map(|_| (g * Fq::random(&mut *rng)).into()).collect()
}

pub fn setup_domain_fft(k: u32) -> (Domain<Fp>, Vec<Fp>) {
    let mut rng = StdRng::seed_from_u64(1234);
    let domain = Domain::new(k);
    let data = (0..domain.n()).map(|_| Fp::random(&mut rng)).collect();
    (domain, data)
}

pub fn setup_domain_ell(k: u32) -> (Domain<Fp>, Fp, usize) {
    let mut rng = StdRng::seed_from_u64(1234);
    let domain = Domain::new(k);
    let n = domain.n();
    (domain, Fp::random(&mut rng), n)
}
