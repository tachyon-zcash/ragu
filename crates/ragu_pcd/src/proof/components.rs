//! Proof component structs. Each component pairs a `Native*` struct
//! (host-curve data) with a shared [`Bridge`] struct (cross-curve data
//! that bridges to the inner verifier).

use core::marker::PhantomData;
use core::ops::Deref;

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::{
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;
use rand::CryptoRng;

use alloc::vec::Vec;

/// A grouped `(rx, blind, commitment)` triple for a native-field rx polynomial.
///
/// The `commitment` is the Pedersen commitment to `rx` under blinding scalar
/// `blind`.
#[derive(Clone)]
pub struct RxTriple<C: Cycle, R: Rank> {
    /// The rx polynomial.
    pub(crate) rx: sparse::Polynomial<C::CircuitField, R>,

    /// The Pedersen blinding scalar for `rx`.
    pub(crate) blind: C::CircuitField,

    /// The Pedersen commitment to `rx` under `blind`.
    pub(crate) commitment: C::HostCurve,
}

/// A field element tagged with a phantom type marker indicating its protocol
/// role as a specific Fiat-Shamir challenge.
///
/// The phantom tag `T` prevents accidentally passing one challenge where another
/// is expected, catching a class of subtle protocol bugs at compile time.
/// Use [`Deref`] (`*challenge`) to obtain the underlying field element for
/// arithmetic.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Challenge<F, T> {
    inner: F,
    _marker: PhantomData<T>,
}

impl<F, T> Challenge<F, T> {
    pub(crate) fn new(value: F) -> Self {
        Self {
            inner: value,
            _marker: PhantomData,
        }
    }

    /// Unwraps the challenge, returning the inner value and discarding the tag.
    pub(crate) fn into_inner(self) -> F {
        self.inner
    }
}

impl<F, T> Deref for Challenge<F, T> {
    type Target = F;

    fn deref(&self) -> &F {
        &self.inner
    }
}

// ZST markers for each challenge role in the protocol. These are phantom type
// parameters only — never instantiated as values.

/// Registry evaluation point $w$, squeezed after the preamble commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChallengeW;

/// First folding challenge $y$, squeezed after the $s'$ commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChallengeY;

/// Second folding challenge $z$, squeezed after the $s'$ commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChallengeZ;

/// First folding layer challenge $\mu$, squeezed after the error\_m commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChallengeMu;

/// First folding layer challenge $\nu$, squeezed after the error\_m commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChallengeNu;

/// Second folding layer challenge $\mu'$, squeezed after the error\_n commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChallengeMuPrime;

/// Second folding layer challenge $\nu'$, squeezed after the error\_n commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChallengeNuPrime;

/// Polynomial commitment challenge $x$, squeezed after the ab commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChallengeX;

/// Query polynomial challenge $\alpha$, squeezed after the query commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChallengeAlpha;

/// Final polynomial evaluation challenge $u$, squeezed after the eval commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChallengeU;

/// Pre-endoscalar beta challenge, squeezed after the eval commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChallengePreBeta;

#[derive(Clone)]
pub(crate) struct Application<C: Cycle, R: Rank> {
    pub(crate) circuit_id: CircuitIndex,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,
    pub(crate) rx_triple: RxTriple<C, R>,
}

#[derive(Clone)]
pub(crate) struct Bridge<C: Cycle, R: Rank> {
    pub(crate) rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) blind: C::ScalarField,
    pub(crate) commitment: C::NestedCurve,
}

impl<C: Cycle, R: Rank> Bridge<C, R> {
    pub(crate) fn commit(
        params: &C::Params,
        rng: &mut impl CryptoRng,
        rx: sparse::Polynomial<C::ScalarField, R>,
    ) -> Self {
        let blind = C::ScalarField::random(&mut *rng);
        let commitment = rx.commit_to_affine(C::nested_generators(params), blind);
        Bridge {
            rx,
            blind,
            commitment,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Preamble<C: Cycle, R: Rank> {
    pub(crate) native: RxTriple<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeSPrime<C: Cycle, R: Rank> {
    pub(crate) registry_wx0_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) registry_wx0_blind: C::CircuitField,
    pub(crate) registry_wx0_commitment: C::HostCurve,
    pub(crate) registry_wx1_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) registry_wx1_blind: C::CircuitField,
    pub(crate) registry_wx1_commitment: C::HostCurve,
}

#[derive(Clone)]
pub(crate) struct SPrime<C: Cycle, R: Rank> {
    pub(crate) native: NativeSPrime<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeInnerError<C: Cycle, R: Rank> {
    pub(crate) registry_wy_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) registry_wy_blind: C::CircuitField,
    pub(crate) registry_wy_commitment: C::HostCurve,
    pub(crate) rx_triple: RxTriple<C, R>,
}

#[derive(Clone)]
pub(crate) struct InnerError<C: Cycle, R: Rank> {
    pub(crate) native: NativeInnerError<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct OuterError<C: Cycle, R: Rank> {
    pub(crate) native: RxTriple<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeAB<C: Cycle, R: Rank> {
    pub(crate) a_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) a_blind: C::CircuitField,
    pub(crate) a_commitment: C::HostCurve,
    pub(crate) b_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) b_blind: C::CircuitField,
    pub(crate) b_commitment: C::HostCurve,
    pub(crate) c: C::CircuitField,
}

#[derive(Clone)]
pub(crate) struct AB<C: Cycle, R: Rank> {
    pub(crate) native: NativeAB<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeQuery<C: Cycle, R: Rank> {
    pub(crate) registry_xy_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) registry_xy_blind: C::CircuitField,
    pub(crate) registry_xy_commitment: C::HostCurve,
    pub(crate) rx_triple: RxTriple<C, R>,
}

#[derive(Clone)]
pub(crate) struct Query<C: Cycle, R: Rank> {
    pub(crate) native: NativeQuery<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeF<C: Cycle, R: Rank> {
    pub(crate) poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) blind: C::CircuitField,
    pub(crate) commitment: C::HostCurve,
}

#[derive(Clone)]
pub(crate) struct F<C: Cycle, R: Rank> {
    pub(crate) native: NativeF<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct Eval<C: Cycle, R: Rank> {
    pub(crate) native: RxTriple<C, R>,
    pub(crate) bridge: Bridge<C, R>,
}

#[derive(Clone)]
pub(crate) struct NativeP<C: Cycle, R: Rank> {
    pub(crate) poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) blind: C::CircuitField,
    pub(crate) commitment: C::HostCurve,
    pub(crate) v: C::CircuitField,
}

#[derive(Clone)]
pub(crate) struct NestedP<C: Cycle, R: Rank> {
    pub(crate) step_rxs: Vec<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) endoscalar_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) points_rx: sparse::Polynomial<C::ScalarField, R>,
}

#[derive(Clone)]
pub(crate) struct P<C: Cycle, R: Rank> {
    pub(crate) native: NativeP<C, R>,
    pub(crate) nested: NestedP<C, R>,
}

#[derive(Clone)]
pub(crate) struct Challenges<C: Cycle> {
    pub(crate) w: Challenge<C::CircuitField, ChallengeW>,
    pub(crate) y: Challenge<C::CircuitField, ChallengeY>,
    pub(crate) z: Challenge<C::CircuitField, ChallengeZ>,
    pub(crate) mu: Challenge<C::CircuitField, ChallengeMu>,
    pub(crate) nu: Challenge<C::CircuitField, ChallengeNu>,
    pub(crate) mu_prime: Challenge<C::CircuitField, ChallengeMuPrime>,
    pub(crate) nu_prime: Challenge<C::CircuitField, ChallengeNuPrime>,
    pub(crate) x: Challenge<C::CircuitField, ChallengeX>,
    pub(crate) alpha: Challenge<C::CircuitField, ChallengeAlpha>,
    pub(crate) u: Challenge<C::CircuitField, ChallengeU>,
    /// Pre-endoscalar beta challenge. Effective beta is derived via endoscalar extraction.
    pub(crate) pre_beta: Challenge<C::CircuitField, ChallengePreBeta>,
}

impl<C: Cycle> Challenges<C> {
    pub(crate) fn new<'dr, D>(
        w: &Challenge<Element<'dr, D>, ChallengeW>,
        y: &Challenge<Element<'dr, D>, ChallengeY>,
        z: &Challenge<Element<'dr, D>, ChallengeZ>,
        mu: &Challenge<Element<'dr, D>, ChallengeMu>,
        nu: &Challenge<Element<'dr, D>, ChallengeNu>,
        mu_prime: &Challenge<Element<'dr, D>, ChallengeMuPrime>,
        nu_prime: &Challenge<Element<'dr, D>, ChallengeNuPrime>,
        x: &Challenge<Element<'dr, D>, ChallengeX>,
        alpha: &Challenge<Element<'dr, D>, ChallengeAlpha>,
        u: &Challenge<Element<'dr, D>, ChallengeU>,
        pre_beta: &Challenge<Element<'dr, D>, ChallengePreBeta>,
    ) -> Self
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        Self {
            w: Challenge::new(*w.value().take()),
            y: Challenge::new(*y.value().take()),
            z: Challenge::new(*z.value().take()),
            mu: Challenge::new(*mu.value().take()),
            nu: Challenge::new(*nu.value().take()),
            mu_prime: Challenge::new(*mu_prime.value().take()),
            nu_prime: Challenge::new(*nu_prime.value().take()),
            x: Challenge::new(*x.value().take()),
            alpha: Challenge::new(*alpha.value().take()),
            u: Challenge::new(*u.value().take()),
            pre_beta: Challenge::new(*pre_beta.value().take()),
        }
    }

    pub(crate) fn trivial() -> Self {
        Self {
            w: Challenge::new(C::CircuitField::ZERO),
            y: Challenge::new(C::CircuitField::ZERO),
            z: Challenge::new(C::CircuitField::ZERO),
            mu: Challenge::new(C::CircuitField::ZERO),
            nu: Challenge::new(C::CircuitField::ZERO),
            mu_prime: Challenge::new(C::CircuitField::ZERO),
            nu_prime: Challenge::new(C::CircuitField::ZERO),
            x: Challenge::new(C::CircuitField::ZERO),
            alpha: Challenge::new(C::CircuitField::ZERO),
            u: Challenge::new(C::CircuitField::ZERO),
            pre_beta: Challenge::new(C::CircuitField::ZERO),
        }
    }
}

#[derive(Clone)]
pub(crate) struct InternalCircuits<C: Cycle, R: Rank> {
    pub(crate) hashes_1: RxTriple<C, R>,
    pub(crate) hashes_2: RxTriple<C, R>,
    pub(crate) inner_collapse: RxTriple<C, R>,
    pub(crate) outer_collapse: RxTriple<C, R>,
    pub(crate) compute_v: RxTriple<C, R>,
}

/// Verify that `Challenge<F, T>` is zero-cost, produces distinct types per
/// ZST marker, derefs transparently, and that typed function boundaries
/// reject mismatched tags at compile time.
#[cfg(test)]
mod tests {
    use super::*;
    use core::any::TypeId;
    use core::mem::size_of;
    use ff::Field;
    use ragu_pasta::{Fp, Pasta};

    #[test]
    fn challenge_is_zero_cost() {
        assert_eq!(size_of::<Challenge<Fp, ChallengeW>>(), size_of::<Fp>());
        assert_eq!(size_of::<Challenge<Fp, ChallengeX>>(), size_of::<Fp>());
        assert_eq!(size_of::<Challenge<u64, ChallengeY>>(), size_of::<u64>());
    }

    #[test]
    fn deref_round_trip() {
        let value = Fp::from(42u64);
        let challenge = Challenge::<Fp, ChallengeW>::new(value);
        assert_eq!(*challenge, value);
    }

    #[test]
    fn distinct_tags_produce_distinct_types() {
        assert_ne!(
            TypeId::of::<Challenge<Fp, ChallengeW>>(),
            TypeId::of::<Challenge<Fp, ChallengeX>>(),
        );
        assert_ne!(
            TypeId::of::<Challenge<Fp, ChallengeY>>(),
            TypeId::of::<Challenge<Fp, ChallengeZ>>(),
        );
        assert_ne!(
            TypeId::of::<Challenge<Fp, ChallengeMu>>(),
            TypeId::of::<Challenge<Fp, ChallengeNu>>(),
        );
        assert_eq!(
            TypeId::of::<Challenge<Fp, ChallengeW>>(),
            TypeId::of::<Challenge<Fp, ChallengeW>>(),
        );
    }

    #[test]
    fn typed_boundary_accepts_correct_challenge() {
        fn needs_x(c: &Challenge<Fp, ChallengeX>) -> Fp {
            **c * Fp::from(2u64)
        }

        let challenge_w = Challenge::<Fp, ChallengeW>::new(Fp::from(10u64));
        let challenge_x = Challenge::<Fp, ChallengeX>::new(Fp::from(5u64));

        let result = needs_x(&challenge_x);
        assert_eq!(result, Fp::from(10u64));

        // needs_x(&challenge_w) would not compile:
        //   expected Challenge<Fp, ChallengeX>, found Challenge<Fp, ChallengeW>
        let _ = challenge_w;
    }

    #[test]
    fn trivial_challenges_are_zero() {
        let trivial = Challenges::<Pasta>::trivial();
        assert_eq!(*trivial.w, Fp::ZERO);
        assert_eq!(*trivial.y, Fp::ZERO);
        assert_eq!(*trivial.z, Fp::ZERO);
        assert_eq!(*trivial.mu, Fp::ZERO);
        assert_eq!(*trivial.nu, Fp::ZERO);
        assert_eq!(*trivial.mu_prime, Fp::ZERO);
        assert_eq!(*trivial.nu_prime, Fp::ZERO);
        assert_eq!(*trivial.x, Fp::ZERO);
        assert_eq!(*trivial.alpha, Fp::ZERO);
        assert_eq!(*trivial.u, Fp::ZERO);
        assert_eq!(*trivial.pre_beta, Fp::ZERO);
    }
}
