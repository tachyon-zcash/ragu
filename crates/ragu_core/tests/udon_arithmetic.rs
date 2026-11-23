//! Udon's field and curve arithmetic on a fixed pseudorandom workload,
//! digested and compared with a committed digest.
//!
//! Udon chooses its arithmetic when it is built: portable Rust, or assembly
//! under its `aarch64-asm` or `x86_64-asm` feature (see Udon's crate docs). A
//! `ragu_core` test build enables neither, so this test runs the portable
//! code unless the command selects an assembly backend, as CI does with
//! `--features udon/aarch64-asm` and `--features udon/x86_64-asm`. Every
//! build must reproduce the digest the portable code produced, so each
//! assembly backend computes exactly what the portable code computes on
//! these inputs.
//!
//! The inputs come from BLAKE2b in counter mode rather than from an RNG, so
//! they do not change when a dependency's generator does.

use blake2b_simd::{Params, State};
use ragu_core::{
    fft, ifft, msm, msm_many,
    pasta::{EpAffine, EqAffine, Fp, Fq},
};
use udon::{
    curve::{Affine, Projective},
    field::Field,
};

/// The digest of [`workload`] under the portable arithmetic.
const EXPECTED: &str = "92cce84521e0b2a808db50f3560c6bde6c73c4bf30b4cbbbdbb247fe5ff91bbf";

/// Pseudorandom bytes: BLAKE2b-512 of a counter.
struct Input(u64);

impl Input {
    fn fill(&mut self, out: &mut [u8; 64]) {
        let hash = Params::new()
            .hash_length(64)
            .personal(b"ragu-udon-input")
            .hash(&self.0.to_le_bytes());
        out.copy_from_slice(hash.as_bytes());
        self.0 += 1;
    }

    fn bytes(&mut self) -> [u8; 64] {
        let mut out = [0; 64];
        self.fill(&mut out);
        out
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.bytes()[..8].try_into().unwrap())
    }

    fn field<F: Field>(&mut self) -> F {
        F::random(|bytes| self.fill(bytes))
    }
}

fn absorb_field<F: Field>(digest: &mut State, value: F) {
    digest.update(value.to_bytes().as_ref());
}

fn absorb_option<F: Field>(digest: &mut State, value: Option<F>) {
    match value {
        Some(value) => {
            digest.update(&[1]);
            absorb_field(digest, value);
        }
        None => {
            digest.update(&[0]);
        }
    }
}

fn absorb_point<C: Affine>(digest: &mut State, point: C::Projective) {
    digest.update(point.to_affine().to_bytes().as_ref());
}

/// Every field operation Udon's assembly implements, on special and
/// pseudorandom values, then batch inversion, products and transforms.
fn field_workload<F: Field>(input: &mut Input, digest: &mut State) {
    let special = [
        F::ZERO,
        F::ONE,
        -F::ONE,
        F::from(2),
        -F::from(2),
        F::TWO_INVERSE,
        F::ROOT_OF_UNITY,
        F::ROOT_OF_UNITY_INVERSE,
        F::MULTIPLICATIVE_GENERATOR,
        F::DELTA,
        F::ZETA,
        F::from_u128(u128::MAX),
    ];
    let values: Vec<F> = special
        .into_iter()
        .chain((0..1024).map(|_| input.field()))
        .collect();

    for (i, &a) in values.iter().enumerate() {
        // Pair every value with a special one as well as pseudorandom ones.
        let b = values[(i * 7 + 3) % values.len()];
        let c = special[i % special.len()];
        let d = input.field::<F>();
        for value in [
            a * b,
            a * c,
            a.square(),
            a + b,
            a - b,
            a - c,
            -a,
            a.double(),
            a.mul_add(&b, &d),
            a.pow_u64(input.u64()),
            F::from_uniform_bytes(&input.bytes()),
            F::from_u128(u128::from(input.u64()) << 64 | u128::from(input.u64())),
        ] {
            absorb_field(digest, value);
        }
        absorb_option(digest, a.invert());
        absorb_option(digest, a.sqrt());
        absorb_option(digest, F::from_bytes(a.to_bytes()));
        // Arbitrary bytes, which may or may not encode a field element.
        let mut repr = a.to_bytes();
        let len = repr.as_ref().len();
        repr.as_mut().copy_from_slice(&input.bytes()[..len]);
        absorb_option(digest, F::from_bytes(repr));
        digest.update(&[u8::from(a.is_odd())]);
    }

    absorb_field(
        digest,
        F::sum_of_products_slice(&values[..256], &values[256..512]),
    );
    let mut inverses = values[..257].to_vec();
    let mut scratch = vec![F::ZERO; inverses.len()];
    F::batch_invert(&mut inverses, &mut scratch);
    for value in inverses {
        absorb_field(digest, value);
    }

    let domain = F::domain(10).unwrap();
    let mut evaluations = values[..1024].to_vec();
    fft(domain, &mut evaluations);
    let mut coefficients = evaluations.clone();
    ifft(domain, &mut coefficients);
    assert_eq!(coefficients, values[..1024]);
    for value in evaluations {
        absorb_field(digest, value);
    }
}

/// Point arithmetic, normalization and MSMs of several sizes through Ragu's
/// MSM entry points.
fn curve_workload<C: Affine>(input: &mut Input, digest: &mut State) {
    let generator = C::generator().to_projective();
    let points: Vec<C::Projective> = (0..256)
        .map(|_| generator * input.field::<C::Scalar>())
        .collect();
    let mut affine = vec![C::identity(); points.len()];
    C::batch_to_affine(&points, &mut affine);

    for (i, &p) in points.iter().enumerate() {
        let q = points[(i + 1) % points.len()];
        for point in [
            p.double(),
            p + q,
            p - q,
            p.add_mixed(&affine[(i + 2) % affine.len()]),
            p + C::Projective::identity(),
            p + (-p),
            generator * C::Scalar::ZERO,
            -p,
        ] {
            absorb_point::<C>(digest, point);
        }
    }
    for point in &affine {
        digest.update(point.to_bytes().as_ref());
    }

    let mut inputs = Vec::new();
    for n in [1, 2, 3, 31, 64, 255, 1024, 4096] {
        let scalars: Vec<C::Scalar> = (0..n).map(|_| input.field()).collect();
        let bases: Vec<C> = (0..n)
            .map(|i| affine[(i * 31 + n) % affine.len()])
            .collect();
        absorb_point::<C>(digest, msm(scalars.clone(), bases.clone()));
        inputs.push((scalars, bases));
    }
    for point in msm_many(inputs) {
        absorb_point::<C>(digest, point);
    }
}

fn workload() -> String {
    let mut input = Input(0);
    let mut digest = Params::new()
        .hash_length(32)
        .personal(b"ragu-udon-digest")
        .to_state();
    field_workload::<Fp>(&mut input, &mut digest);
    field_workload::<Fq>(&mut input, &mut digest);
    curve_workload::<EpAffine>(&mut input, &mut digest);
    curve_workload::<EqAffine>(&mut input, &mut digest);
    digest
        .finalize()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn arithmetic_matches_the_portable_digest() {
    assert_eq!(
        workload(),
        EXPECTED,
        "Udon's arithmetic in this build differs from the portable digest"
    );
}
