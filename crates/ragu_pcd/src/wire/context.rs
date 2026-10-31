//! Identifiers of an application's setup, derived from what it was built
//! with, so that a [`ProofContext`] needs no manifest of the caller's own.

use ragu_circuits::{polynomials::Rank, registry::Registry};
use ragu_core::{FixedGenerators, PoseidonPermutation};
use udon::{curve::Affine, field::Field};

use crate::{
    Application, RAGU_TAG, SelectableBackend,
    ipa::IPA_TAG,
    profile::{Profile, ProfiledCycle},
    wire::format::ProofContext,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Identifiers of this application's setup, derived from the parameters
    /// and registries it was built with and cached for its lifetime.
    ///
    /// `suite` is a BLAKE2b-256 digest, personalized `ragu-suite-v1`, of both
    /// curves (each by its generator point), every commitment and blinding
    /// generator of both curves, and both Poseidon permutations (width, rate,
    /// round counts, S-box exponent, round constants and MDS matrix).
    /// `application` is a BLAKE2b-256 digest, personalized
    /// `ragu-app-v1`, of the two protocol transcript tags, the
    /// profile's name, the rank, the header size, the number of application
    /// steps and, for each registry, its tag, its circuit count and the
    /// restriction of its registry polynomial to a fixed point, which pins
    /// every circuit's wiring. Variable-length inputs are length-prefixed.
    ///
    /// The identifiers cover the configuration Ragu can see. A change to any
    /// of it changes them; configuration outside it, such as the meaning of
    /// the data a header encodes, needs identifiers of your own through
    /// [`proof_format_with`](Self::proof_format_with).
    pub fn proof_context(&self) -> ProofContext {
        *self.proof_context.get_or_init(|| ProofContext {
            suite: self.suite_id(),
            application: self.application_id(),
        })
    }

    fn suite_id(&self) -> [u8; 32] {
        let host = C::host_generators(self.params);
        let nested = C::nested_generators(self.params);
        let mut digest = Digest::new(b"ragu-suite-v1");
        digest.point(&C::HostCurve::generator());
        digest.point(&C::NestedCurve::generator());
        digest.points(host.g());
        digest.point(host.h());
        digest.points(nested.g());
        digest.point(nested.h());
        digest.poseidon(C::circuit_poseidon(self.params));
        digest.poseidon(C::scalar_poseidon(self.params));
        digest.finish()
    }

    fn application_id(&self) -> [u8; 32] {
        let mut digest = Digest::new(b"ragu-app-v1");
        digest.bytes(RAGU_TAG);
        digest.bytes(IPA_TAG);
        digest.bytes(C::Profile::NAME.as_bytes());
        digest.u64(u64::from(R::RANK));
        digest.u64(HEADER_SIZE as u64);
        digest.u64(self.num_application_steps as u64);
        digest.registry(&self.native_registry);
        digest.registry(&self.nested_registry);
        digest.finish()
    }
}

/// A BLAKE2b-256 digest of a sequence of values. Each value's length is
/// either fixed by its position or written before it, so no two sequences
/// have the same digest input.
struct Digest(blake2b_simd::State);

impl Digest {
    fn new(personal: &[u8]) -> Self {
        Self(
            blake2b_simd::Params::new()
                .hash_length(32)
                .personal(personal)
                .to_state(),
        )
    }

    fn u64(&mut self, value: u64) {
        self.0.update(&value.to_le_bytes());
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.u64(bytes.len() as u64);
        self.0.update(bytes);
    }

    fn field<F: Field>(&mut self, value: &F) {
        self.0.update(Field::to_bytes(value).as_ref());
    }

    fn point<G: Affine>(&mut self, point: &G) {
        self.0.update(point.to_bytes().as_ref());
    }

    fn points<G: Affine>(&mut self, points: &[G]) {
        self.u64(points.len() as u64);
        for point in points {
            self.point(point);
        }
    }

    fn poseidon<F: Field, P: PoseidonPermutation<F>>(&mut self, permutation: &P) {
        for value in [P::T, P::RATE, P::FULL_ROUNDS, P::PARTIAL_ROUNDS] {
            self.u64(value as u64);
        }
        self.u64(u64::from(P::ALPHA));
        // The counts above fix the number of rows and their width.
        for row in permutation.round_constants() {
            for value in row.as_ref() {
                self.field(value);
            }
        }
        for row in permutation.mds_matrix() {
            for value in row.as_ref() {
                self.field(value);
            }
        }
    }

    /// The registry's tag, its circuit count and its registry polynomial
    /// restricted to a fixed point: a different wiring in any circuit changes
    /// the restriction, except with negligible probability.
    fn registry<F: Field, R: Rank>(&mut self, registry: &Registry<'_, F, R>) {
        self.field(&registry.tag());
        self.u64(registry.num_circuits() as u64);
        let restriction = registry.xy(
            fixed_point(b"registry point x"),
            fixed_point(b"registry point y"),
        );
        self.u64(R::num_coeffs() as u64);
        for coefficient in restriction.iter_coeffs() {
            self.field(&coefficient);
        }
    }

    fn finish(self) -> [u8; 32] {
        self.0
            .finalize()
            .as_bytes()
            .try_into()
            .expect("32-byte digest")
    }
}

/// A field element fixed by a label: the reduction of a 64-byte BLAKE2b
/// digest of the label.
fn fixed_point<F: Field>(label: &[u8]) -> F {
    let wide: [u8; 64] = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"ragu-app-v1")
        .hash(label)
        .as_bytes()
        .try_into()
        .expect("64-byte digest");
    F::from_uniform_bytes(&wide)
}
