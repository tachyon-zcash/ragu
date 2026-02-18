use ff::Field;
use group::prime::PrimeCurveAffine;
use ragu_arithmetic::{Cycle, Uendo};
use ragu_core::drivers::Driver;
use ragu_core::drivers::emulator::{Emulator, Wireless};
use ragu_core::maybe::Always;
use ragu_pasta::{EpAffine, Fp, Fq, Pasta, PoseidonFp};
use ragu_primitives::poseidon::Sponge;
use ragu_primitives::{Boolean, Element, Endoscalar, Point};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

pub type BenchEmu = Emulator<Wireless<Always<()>, Fp>>;

// Composable emulator setup - allocator functions take (emu, rng) and return allocated value
pub trait SetupEmu<Out> {
    fn setup(self, emu: &mut BenchEmu, rng: &mut StdRng) -> Out;
}

impl<A, FA: FnOnce(&mut BenchEmu, &mut StdRng) -> A> SetupEmu<(A,)> for (FA,) {
    fn setup(self, emu: &mut BenchEmu, rng: &mut StdRng) -> (A,) {
        (self.0(emu, rng),)
    }
}

impl<A, B, FA: FnOnce(&mut BenchEmu, &mut StdRng) -> A, FB: FnOnce(&mut BenchEmu, &mut StdRng) -> B>
    SetupEmu<(A, B)> for (FA, FB)
{
    fn setup(self, emu: &mut BenchEmu, rng: &mut StdRng) -> (A, B) {
        (self.0(emu, rng), self.1(emu, rng))
    }
}

impl<
    A,
    B,
    C,
    FA: FnOnce(&mut BenchEmu, &mut StdRng) -> A,
    FB: FnOnce(&mut BenchEmu, &mut StdRng) -> B,
    FC: FnOnce(&mut BenchEmu, &mut StdRng) -> C,
> SetupEmu<(A, B, C)> for (FA, FB, FC)
{
    fn setup(self, emu: &mut BenchEmu, rng: &mut StdRng) -> (A, B, C) {
        (self.0(emu, rng), self.1(emu, rng), self.2(emu, rng))
    }
}

pub fn setup_emu<Fns: SetupEmu<T>, T>(fns: Fns) -> (BenchEmu, T) {
    let mut rng = StdRng::seed_from_u64(1234);
    let mut emu = BenchEmu::execute();
    let out = fns.setup(&mut emu, &mut rng);
    (emu, out)
}

// Allocator functions - each takes (emu, rng) and returns an allocated primitive
pub fn alloc_elem(emu: &mut BenchEmu, rng: &mut StdRng) -> Element<'static, BenchEmu> {
    let v = Fp::random(rng);
    Element::alloc(emu, BenchEmu::just(|| v)).unwrap()
}

pub fn alloc_point(emu: &mut BenchEmu, rng: &mut StdRng) -> Point<'static, BenchEmu, EpAffine> {
    let s = Fq::random(rng);
    Point::alloc(emu, BenchEmu::just(|| (EpAffine::generator() * s).into())).unwrap()
}

pub fn alloc_endo(emu: &mut BenchEmu, rng: &mut StdRng) -> Endoscalar<'static, BenchEmu> {
    let u: Uendo = rng.random();
    Endoscalar::alloc(emu, BenchEmu::just(|| u)).unwrap()
}

pub fn alloc_sponge(
    emu: &mut BenchEmu,
    _rng: &mut StdRng,
) -> Sponge<'static, BenchEmu, PoseidonFp> {
    Sponge::new(emu, Pasta::circuit_poseidon(Pasta::baked()))
}

// Parameterized allocators for collections
pub fn alloc_elems<const N: usize>(
    emu: &mut BenchEmu,
    rng: &mut StdRng,
) -> Vec<Element<'static, BenchEmu>> {
    (0..N)
        .map(|_| {
            let v = Fp::random(&mut *rng);
            Element::alloc(emu, BenchEmu::just(|| v)).unwrap()
        })
        .collect()
}

pub fn alloc_bools<const N: usize>(
    emu: &mut BenchEmu,
    rng: &mut StdRng,
) -> Vec<Boolean<'static, BenchEmu>> {
    (0..N)
        .map(|_| {
            let v: bool = rng.random();
            Boolean::alloc(emu, BenchEmu::just(|| v)).unwrap()
        })
        .collect()
}

pub fn alloc_coeffs<const N: usize>(_emu: &mut BenchEmu, rng: &mut StdRng) -> Vec<Fp> {
    (0..N).map(|_| Fp::random(&mut *rng)).collect()
}
