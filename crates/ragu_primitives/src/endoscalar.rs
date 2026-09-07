//! Implements logic for endoscaling, as introduced in
//! [Halo](https://eprint.iacr.org/2019/1021).
//!
//! An endoscalar is the catchy name for a small binary string that is used to
//! perform elliptic curve scalar multiplication on curves that have an
//! efficient endomorphism attached. By producing endoscalars as challenges and
//! applying an appropriate algorithm, points on an elliptic curve can be
//! multiplied by equally "random" challenge scalars more efficiently within a
//! circuit than an arbitrary scalar.
//!
//! This module provides an implementation of the scaling operation for curves
//! which support the endomorphism, and an implementation of the algorithm for
//! recovering the effective scalar that an endoscalar maps to for a particular
//! prime field.

use alloc::boxed::Box;

use ragu_arithmetic::{
    Coeff, CurveAffine,
    ff::{Field, PrimeFieldBits, WithSmallOrderMulGroup},
};
use ragu_core::{
    Error, Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::Gadget,
    maybe::{Always, Maybe},
};

use crate::{
    Boolean, Element, NonzeroBank, Point,
    allocator::Allocator,
    boolean::decompose,
    promotion::Demoted,
    vec::{CollectFixed, ConstLen, FixedVec},
};

/// An error indicating that an element is out of range for an endoscalar
/// challenge.
///
/// [`EndoscalarChallenge::from_element`] boxes this type as the source of
/// [`Error::InvalidWitness`] when the element's canonical representative is
/// not below $2^{\mathtt{CAPACITY}}$. A caller that grinds candidate
/// challenges detects this condition with [`Error::invalid_witness_source`],
/// resamples, and retries; every other error reports a distinct failure.
///
/// # Examples
///
/// ```
/// use ragu_core::Error;
/// use ragu_primitives::EndoscalarRangeError;
///
/// let err = Error::InvalidWitness(Box::new(EndoscalarRangeError));
/// assert!(err.invalid_witness_source::<EndoscalarRangeError>().is_some());
/// ```
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
#[error("endoscalar challenge must satisfy value < 2^CAPACITY")]
pub struct EndoscalarRangeError;

/// A transcript challenge constrained for endoscalar extraction.
///
/// Carries the precondition required by [`Endoscalar::extract`]: the element's
/// canonical representative is below $2^{\mathtt{CAPACITY}}$, so it admits a
/// canonical $\mathtt{CAPACITY}$-bit decomposition with no separate in-circuit
/// canonicity check.
///
/// Construction decomposes the element and constrains the decomposition to it,
/// so every satisfying assignment places the element below
/// $2^{\mathtt{CAPACITY}}$.
///
/// Deliberately not a [`Gadget`]: this type certifies that an [`Element`] has a
/// particular quality, and a gadget must never carry a contract over its
/// witness. It is a plain wrapper holding that element alongside the
/// decomposition wires constraining it, so it cannot be remapped into another
/// circuit without re-emitting those constraints through [`from_element`].
///
/// # Field requirements
///
/// The field must have at least 128 bits of capacity; Ragu's supported Pasta
/// fields satisfy this.
///
/// [`from_element`]: EndoscalarChallenge::from_element
pub struct EndoscalarChallenge<'dr, D: Driver<'dr>> {
    elem: Element<'dr, D>,

    endoscalar: Endoscalar<'dr, D>,
}

impl<'dr, D: Driver<'dr>> EndoscalarChallenge<'dr, D> {
    /// Validates an in-range element as an endoscalar challenge.
    ///
    /// The single-attempt constructor, which emits the binding decomposition
    /// directly.
    ///
    /// It serves the in-circuit verifier path, where an honest prover has
    /// already ground the challenge into range and it is only re-derived
    /// (see the `compute_v` internal circuit). Native provers sampling a fresh
    /// challenge must use [`sample`] instead, which owns the rejection-sampling
    /// loop and so cannot be skipped.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the represented element equal the
    /// returned challenge's canonical $\mathtt{CAPACITY}$-bit decomposition,
    /// and so places it below $2^{\mathtt{CAPACITY}}$.
    ///
    /// # Completeness
    ///
    /// Honest proving succeeds only when `elem` is in range. The witness value
    /// is checked directly as well, so the emulators — which compute witness
    /// data without evaluating constraints — reject an out-of-range element
    /// rather than returning a truncated endoscalar.
    ///
    /// # Errors
    ///
    /// Witness generation fails with [`Error::InvalidWitness`] when `elem` is
    /// out of range ($\mathtt{elem} \geq 2^{\mathtt{CAPACITY}}$). The boxed
    /// source is an [`EndoscalarRangeError`] value, which callers that grind
    /// candidate challenges can detect with
    /// [`Error::invalid_witness_source`]. Any other error propagates
    /// unchanged.
    ///
    /// [`sample`]: EndoscalarChallenge::sample
    pub fn from_element<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        elem: Element<'dr, D>,
    ) -> Result<Self>
    where
        D::F: PrimeFieldBits,
    {
        // Emulator drivers never evaluate the decomposition constraints, so
        // also reject an out-of-range witness value directly; `try_just` runs
        // only during witness generation and emits nothing, leaving circuit
        // structure untouched.
        D::try_just(|| {
            if !endoscalar_in_range(*elem.value().take()) {
                return Err(Error::InvalidWitness(Box::new(EndoscalarRangeError)));
            }

            Ok(())
        })?;

        let endoscalar = Endoscalar::extract_element(dr, allocator, &elem)?;

        Ok(Self { elem, endoscalar })
    }

    /// Returns the underlying field element.
    ///
    /// Construction of this challenge constrains the element in range.
    pub fn element(&self) -> &Element<'dr, D> {
        &self.elem
    }
}

type NativeEmulator<F> = Emulator<Wireless<Always<()>, F>>;

impl<'dr, F: PrimeFieldBits> EndoscalarChallenge<'dr, NativeEmulator<F>> {
    /// Attempts to validate an element as an endoscalar challenge, reporting an
    /// out-of-range element as `Ok(None)` rather than an error.
    ///
    /// The rejection-sampling primitive behind [`sample`], and the prover-side
    /// counterpart to [`from_element`]: it delegates validation to
    /// [`from_element`] — the single place the range rule is checked — and
    /// translates its typed range failure ([`EndoscalarRangeError`]) into the
    /// *expected* out-of-range outcome (`Ok(None)`, a retry signal). Every
    /// other failure is a *genuine* error, to propagate, not retry.
    ///
    /// # Errors
    ///
    /// An out-of-range element is reported as `Ok(None)` rather than as an
    /// error; errors arise only while validating an in-range element.
    ///
    /// [`sample`]: EndoscalarChallenge::sample
    /// [`from_element`]: EndoscalarChallenge::from_element
    pub(crate) fn try_from_element(
        dr: &mut NativeEmulator<F>,
        elem: Element<'dr, NativeEmulator<F>>,
    ) -> Result<Option<Self>> {
        match Self::from_element(dr, &mut (), elem) {
            Ok(challenge) => Ok(Some(challenge)),
            Err(err)
                if err
                    .invalid_witness_source::<EndoscalarRangeError>()
                    .is_some() =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Produces a validated endoscalar challenge by rejection sampling.
    ///
    /// `produce` is invoked to (re)sample fresh randomness, returning a
    /// candidate challenge [`Element`] together with a `payload` of side state
    /// derived from it. The candidate is validated by `try_from_element`: on
    /// acceptance the challenge and its payload are returned; on an
    /// out-of-range candidate `produce` is called again with fresh randomness.
    ///
    /// Baking the loop into the constructor means a native prover cannot
    /// obtain a challenge from a rejected sample: [`from_element`] refuses an
    /// out-of-range element outright, so no [`EndoscalarChallenge`] can exist
    /// whose element is out of range, and this is the only constructor that
    /// retries rather than fails.
    ///
    /// `produce` is required to differ between calls rather than to agree with
    /// itself: it runs during native witness generation, never on a driver
    /// walk, so the determinism requirement on circuit code does not apply.
    ///
    /// # Completeness
    ///
    /// With uniformly random field elements each attempt succeeds with
    /// overwhelming probability (about $1 - 2^{-129}$ over the Pasta fields),
    /// so the loop terminates after a handful of iterations in expectation.
    ///
    /// # Errors
    ///
    /// An error from `produce`, or from validating an in-range candidate,
    /// propagates immediately; the loop retries only on the expected
    /// out-of-range condition and so cannot spin on a real error.
    ///
    /// [`from_element`]: EndoscalarChallenge::from_element
    pub fn sample<T>(
        dr: &mut NativeEmulator<F>,
        mut produce: impl FnMut(&mut NativeEmulator<F>) -> Result<(Element<'dr, NativeEmulator<F>>, T)>,
    ) -> Result<(Self, T)> {
        loop {
            let (elem, payload) = produce(dr)?;
            if let Some(challenge) = Self::try_from_element(dr, elem)? {
                return Ok((challenge, payload));
            }
        }
    }

    /// Extracts the native endoscalar from this validated challenge.
    ///
    /// Returns the low 128 bits of the challenge's canonical bit
    /// decomposition, the native, wireless counterpart to
    /// [`Endoscalar::extract`], intended for native provers that constructed the
    /// challenge via [`sample`]. Because an [`EndoscalarChallenge`] already
    /// contains the constrained extraction, this operation is infallible.
    ///
    /// [`sample`]: EndoscalarChallenge::sample
    pub fn extract_native(&self) -> u128 {
        *self.endoscalar.value.snag()
    }
}

/// Reports whether `value` lies in the range admitted by an endoscalar
/// challenge (canonical representative below $2^{\mathtt{CAPACITY}}$).
///
/// A pure, wireless mirror of the canonical bit decomposition enforced in
/// circuit by [`EndoscalarChallenge::from_element`]: it checks that no bit at
/// index $\geq \mathtt{CAPACITY}$ of the canonical little-endian bit
/// decomposition is set, so it is `true` exactly when that in-circuit
/// decomposition is satisfiable.
///
/// An implementation detail of `from_element`, which reports an out-of-range
/// value as a typed [`EndoscalarRangeError`] failure that rejection-sampling
/// callers detect with [`Error::invalid_witness_source`].
fn endoscalar_in_range<F: PrimeFieldBits>(value: F) -> bool {
    value.to_le_bits()[F::CAPACITY as usize..].not_any()
}

/// Represents a challenge used to scale elliptic curve points.
#[derive(Gadget)]
pub struct Endoscalar<'dr, D: Driver<'dr>> {
    /// The bits of this endoscalar in little-endian order.
    #[ragu(gadget)]
    bits: FixedVec<Demoted<'dr, D, Boolean<'dr, D>>, ConstLen<{ u128::BITS as usize }>>,

    /// Witness data for the represented endoscalar in compact representation.
    #[ragu(value)]
    value: DriverValue<D, u128>,
}

impl<'dr, D: Driver<'dr>> Endoscalar<'dr, D> {
    /// Allocates an endoscalar with the provided witness input value.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes each stored bit represent `0` or `1`.
    /// Nothing ties those bits to `value`, which is witness input: witness
    /// generation decomposes it in little-endian order, but callers needing the
    /// endoscalar bound to a specific field element must enforce that relation
    /// themselves (see [`extract`](Self::extract)).
    pub fn alloc(dr: &mut D, value: DriverValue<D, u128>) -> Result<Self> {
        let bits = (0..u128::BITS as usize)
            .map(|i| {
                let bit = Boolean::alloc(
                    dr,
                    &mut (),
                    value.as_ref().map(|v| (*v >> i) & 1u128 == 1u128),
                )?;
                Demoted::new(&bit)
            })
            .try_collect_fixed()?;

        Ok(Endoscalar { bits, value })
    }

    /// Returns an iterator over the bits in this endoscalar, little endian order.
    pub fn bits(&self) -> impl Iterator<Item = Boolean<'dr, D>> {
        let mut bits = self
            .value
            .as_ref()
            .map(|v| (0..(u128::BITS as usize)).map(move |i| (*v >> i) & 1u128 == 1u128));

        self.bits.iter().map(move |demoted_bit| {
            demoted_bit.promote(bits.as_mut().map(|bits| bits.next().unwrap()))
        })
    }

    /// Returns the endoscalar constrained during challenge construction.
    ///
    /// The endoscalar is the low 128 bits of the challenge's canonical bit
    /// decomposition. [`EndoscalarChallenge::from_element`] already emitted the
    /// binding decomposition and range constraint, so extraction emits no
    /// additional constraints.
    pub fn extract(challenge: EndoscalarChallenge<'dr, D>) -> Self {
        challenge.endoscalar
    }

    /// Constrains `elem` to its canonical decomposition and returns its low 128
    /// bits as an endoscalar.
    fn extract_element<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        elem: &Element<'dr, D>,
    ) -> Result<Self>
    where
        D::F: PrimeFieldBits,
    {
        let bits = decompose(dr, allocator, elem)?;

        let value = elem.value().map(|v| {
            let le_bits = v.to_le_bits();
            let mut acc = 0u128;
            for i in 0..(u128::BITS as usize) {
                if le_bits[i] {
                    acc |= 1u128 << i;
                }
            }
            acc
        });

        let bits = bits
            .iter()
            .take(u128::BITS as usize)
            .map(|bit| Demoted::new(bit))
            .try_collect_fixed()?;

        Ok(Endoscalar { bits, value })
    }

    /// Scale a point by the endoscalar.
    ///
    /// Endoscalars in this library are $2n = 128$ bits long, and this algorithm
    /// is proven to be injective for all prime fields of size greater than
    /// $4(2^n - 1)^2$, which is comfortably safe for the Pasta fields because
    /// they are larger than $1361129467683753853705924477137396432900$. See
    /// `qa/fv/Ragu/Lemmas/EndoscalarProof.lean`.
    ///
    /// # Exceptional Cases
    ///
    /// The incomplete point additions used by this method require distinct
    /// x-coordinates at every addition step. The method uses an unchecked
    /// [`NonzeroBank`] and relies on the no-collision argument above for the
    /// supported curve/endoscalar setting.
    ///
    /// # Soundness
    ///
    /// Under the no-collision assumption above, any satisfying assignment makes
    /// the returned point represent `p` scaled by this endoscalar.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error if witness input falls into an
    /// incomplete-addition exceptional case.
    pub fn group_scale<C: CurveAffine<Base = D::F>>(
        &self,
        dr: &mut D,
        p: &Point<'dr, D, C>,
    ) -> Result<Point<'dr, D, C>> {
        // Soundness: every `add_incomplete` and `double_and_add_incomplete`
        // call below requires `x_1 != x_0`. Appendix C of the Halo paper
        // (<https://eprint.iacr.org/2019/1021>) proves no such collision occurs
        // for endoscalars well beyond 128 bits on the Pasta curves Ragu uses,
        // so the bank is created in unchecked mode.
        //
        // TODO(ebfull): The no-collision argument above is a property of the
        // curve / endoscalar interaction that the `Cycle` API should attest to
        // at compile time, so callers can verify it holds for their choice of
        // curve rather than relying on this ad-hoc local justification.
        let mut bank = NonzeroBank::new_unchecked();

        let mut acc = p.endo(dr).add_incomplete(dr, p, &mut bank)?.double(dr)?;
        let mut bits = self.bits();

        // Each iteration consumes a pair of bits; u128::BITS is even.
        for _ in 0..(u128::BITS as usize / 2) {
            let negate_bit = bits.next().unwrap();
            let endo_bit = bits.next().unwrap();

            let q = p
                .conditional_negate(dr, &negate_bit)?
                .conditional_endo(dr, &endo_bit)?;
            acc = acc.double_and_add_incomplete(dr, &q, &mut bank)?;
        }

        Ok(acc)
    }

    /// Lifts this endoscalar to a field element (scales $1$ by the endoscalar).
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned element represent the
    /// effective scalar for this endoscalar.
    pub fn lift(&self, dr: &mut D) -> Result<Element<'dr, D>>
    where
        D::F: WithSmallOrderMulGroup<3>,
    {
        let mut constant_term = (D::F::ZETA + D::F::ONE).double();
        let coeffs = [
            -D::F::from(2),
            D::F::ZETA - D::F::ONE,
            (D::F::ONE - D::F::ZETA).double(),
        ];

        let mut acc = Element::zero(dr);
        let mut bits = self.bits();

        // Each iteration consumes a pair of bits; u128::BITS is even.
        for _ in 0..(u128::BITS as usize / 2) {
            let n = bits.next().unwrap();
            let e = bits.next().unwrap();
            let ne = n.and(dr, &e)?;

            acc = acc.double(dr);
            constant_term = constant_term.double();
            constant_term += D::F::ONE;

            let n = n.element().scale(dr, Coeff::Arbitrary(coeffs[0]));
            let e = e.element().scale(dr, Coeff::Arbitrary(coeffs[1]));
            let ne = ne.element().scale(dr, Coeff::Arbitrary(coeffs[2]));

            acc = acc.add(dr, &n);
            acc = acc.add(dr, &e);
            acc = acc.add(dr, &ne);
        }

        let tmp = Element::constant(dr, constant_term);
        acc = acc.add(dr, &tmp);

        Ok(acc)
    }
}

/// Lifts an endoscalar to a field element (computes the effective scalar).
///
/// This implements [Algorithm 2, \[BGH19\]](https://eprint.iacr.org/2019/1021)
/// and is the native counterpart to [`Endoscalar::lift`].
pub fn lift_endoscalar<F: WithSmallOrderMulGroup<3>>(endo: u128) -> F {
    let mut acc = (F::ZETA + F::ONE).double();
    for i in 0..(u128::BITS as usize / 2) {
        let bits = endo >> (i << 1);
        let mut tmp = F::ONE;
        if bits & 0b01u128 != 0u128 {
            tmp = -tmp;
        }
        if bits & 0b10u128 != 0u128 {
            tmp *= F::ZETA;
        }
        acc = acc.double() + tmp;
    }
    acc
}

/// Extracts an endoscalar from a validated field element.
///
/// Returns the low 128 bits of the element's canonical bit decomposition, the
/// native counterpart to [`Endoscalar::extract`].
///
/// A low-level helper: prefer [`EndoscalarChallenge::extract_native`], which
/// upholds the precondition below as a type invariant. This function is exposed
/// directly only for native setup paths with no [`EndoscalarChallenge`] in
/// scope (e.g. the dummy proof construction over a constant that is in range
/// by inspection).
///
/// # Completeness
///
/// Infallible when `value` has already passed rejection sampling
/// ($\mathtt{value} < 2^{\mathtt{CAPACITY}}$). An out-of-range value is
/// rejected by the [`EndoscalarChallenge`] construction it delegates to,
/// matching the in-circuit path that becomes unsatisfiable before
/// [`Endoscalar::extract`] is reachable.
///
/// # Field requirements
///
/// The field must have at least 128 bits of capacity; Ragu's supported Pasta
/// fields satisfy this.
///
/// # Errors
///
/// Fails with [`Error::InvalidWitness`] when `value` is out of range
/// ($\mathtt{value} \geq 2^{\mathtt{CAPACITY}}$); the boxed source is an
/// [`EndoscalarRangeError`], so callers modeling transcript rejection can
/// detect the condition with [`Error::invalid_witness_source`].
pub fn extract_endoscalar<F: PrimeFieldBits>(value: F) -> Result<u128> {
    Emulator::emulate_wireless(value, |dr, witness| {
        let elem = Element::alloc(dr, &mut (), witness)?;
        let challenge = EndoscalarChallenge::from_element(dr, &mut (), elem)?;
        let endo = Endoscalar::extract(challenge);
        Ok(*endo.value.snag())
    })
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::{
        CurveAffine, CurveExt,
        ff::{Field, PrimeField, PrimeFieldBits, WithSmallOrderMulGroup},
        group::{CurveAffine as _, Group},
        rand::RngExt,
    };
    use ragu_core::{Result, drivers::emulator::Wireless};
    use ragu_pasta::{EpAffine, Fp};

    use super::{
        Always, Element, Emulator, Endoscalar, EndoscalarChallenge, EndoscalarRangeError, Maybe,
        Point,
    };
    use crate::{Simulator, allocator::Standard};

    pub struct EndoscalarTest {
        pub value: u128,
    }

    impl EndoscalarTest {
        /// Implements [Algorithm 1, \[BGH19\]](https://eprint.iacr.org/2019/1021).
        pub fn scale<C: CurveAffine>(&self, p: &C) -> C {
            let p = p.to_curve();
            let mut acc = (p.endo() + p).double();
            for bits in (0..(u128::BITS as usize / 2)).map(|i| self.value >> (i << 1)) {
                let mut s = p;
                if bits & 0b01u128 != 0u128 {
                    s = -s;
                }
                if bits & 0b10u128 != 0u128 {
                    s = s.endo();
                }

                acc = (acc + s) + acc;
            }
            acc.into()
        }

        /// Implements [Algorithm 2, \[BGH19\]](https://eprint.iacr.org/2019/1021).
        pub fn lift<F: WithSmallOrderMulGroup<3>>(&self) -> F {
            super::lift_endoscalar(self.value)
        }
    }

    pub fn extract<F: PrimeFieldBits + WithSmallOrderMulGroup<3>>(value: F) -> EndoscalarTest {
        EndoscalarTest {
            value: super::extract_endoscalar(value)
                .expect("test challenge should satisfy value < 2^CAPACITY"),
        }
    }

    #[test]
    #[allow(clippy::useless_conversion)]
    fn test_endoscaling_consistency() {
        use ragu_arithmetic::group::CurveAffine as _;
        use ragu_pasta::{EpAffine, Fq};

        let p = EpAffine::generator();
        let e = EndoscalarTest {
            value: 206786806484900909362154774549736492353u128,
        };
        let scaled = e.scale(&p);
        let expected: EpAffine = (p * e.lift::<Fq>()).into();

        assert_eq!(scaled, expected);
    }

    #[test]
    fn test_extract() -> Result<()> {
        let p = EpAffine::generator();
        let r = loop {
            let r = Fp::random(&mut ragu_arithmetic::rand::rng());
            if super::endoscalar_in_range(r) {
                break r;
            }
        };
        let extracted = extract(r).value;

        Simulator::<Fp>::simulate((r, extracted, p), |dr, witness| {
            let (r, extracted, p) = witness.cast();
            let p = Point::alloc(dr, p)?;
            let allocator = &mut Standard::new();
            let r = Element::alloc(dr, allocator, r)?;
            let constraints_before_challenge = dr.num_constraints();
            let r = EndoscalarChallenge::from_element(dr, allocator, r)?;
            let constraints_after_challenge = dr.num_constraints();
            assert!(constraints_after_challenge > constraints_before_challenge);
            let my_extracted = Endoscalar::extract(r);
            assert_eq!(dr.num_constraints(), constraints_after_challenge);
            let allocated = Endoscalar::alloc(dr, extracted)?;

            assert_eq!(my_extracted.value.snag(), allocated.value.snag());

            let a = my_extracted.group_scale(dr, &p)?;
            let b = allocated.group_scale(dr, &p)?;
            assert_eq!(a.value().take(), b.value().take());

            Ok(())
        })?;

        Ok(())
    }

    /// Out-of-range rejection fails with the typed [`EndoscalarRangeError`]
    /// source, so grinding callers can detect the condition programmatically.
    #[test]
    fn test_endoscalar_challenge_rejects_out_of_range() {
        let err = super::extract_endoscalar(-Fp::ONE)
            .expect_err("out-of-range challenge must not extract");
        assert_eq!(
            err.invalid_witness_source::<EndoscalarRangeError>(),
            Some(&EndoscalarRangeError)
        );

        let result = Simulator::<Fp>::simulate(-Fp::ONE, |dr, witness| {
            let elem = Element::alloc(dr, &mut (), witness)?;
            EndoscalarChallenge::from_element(dr, &mut (), elem)?;
            Ok(())
        });

        let Err(err) = result else {
            panic!("out-of-range challenge must be rejected");
        };
        assert_eq!(
            err.invalid_witness_source::<EndoscalarRangeError>(),
            Some(&EndoscalarRangeError)
        );
    }

    /// `from_element` rejects an out-of-range witness value even on drivers
    /// that do not evaluate constraints (the wireless emulator), so the range
    /// contract cannot be bypassed by driver choice.
    #[test]
    fn test_from_element_rejects_out_of_range_wireless() {
        let result =
            Emulator::<Wireless<Always<()>, Fp>>::emulate_wireless(-Fp::ONE, |dr, value| {
                let elem = Element::alloc(dr, &mut (), value)?;
                EndoscalarChallenge::from_element(dr, &mut (), elem)?;
                Ok(())
            });

        let err = result.expect_err("out-of-range challenge must be rejected");
        assert_eq!(
            err.invalid_witness_source::<EndoscalarRangeError>(),
            Some(&EndoscalarRangeError)
        );
    }

    /// The pure-value range predicate must agree with the simulator-based
    /// decomposition check for every value, so that rejection sampling using
    /// `endoscalar_in_range` never disagrees with what the circuit enforces.
    ///
    /// Exercises `decompose` directly rather than `from_element`, whose native
    /// witness check would reject an out-of-range value before the emitted
    /// constraints are ever evaluated.
    #[test]
    fn test_in_range_matches_constraints() {
        let largest_in_range = {
            let mut acc = Fp::ZERO;
            for _ in 0..(Fp::CAPACITY as usize) {
                acc = acc.double() + Fp::ONE;
            }
            acc
        };

        let cases = [
            Fp::ZERO,
            Fp::ONE,
            Fp::from(0x0123_4567_89ab_cdefu64),
            largest_in_range,
            largest_in_range + Fp::ONE, // first out-of-range value
            -Fp::ONE,                   // p - 1, out of range
        ];

        let constraints_accept = |value| {
            Simulator::<Fp>::simulate(value, |dr, witness| {
                let elem = Element::alloc(dr, &mut (), witness)?;
                crate::boolean::decompose(dr, &mut (), &elem)?;
                Ok(())
            })
            .is_ok()
        };

        for value in cases {
            assert_eq!(
                super::endoscalar_in_range(value),
                constraints_accept(value),
                "in-range predicate disagreed with circuit constraints",
            );
        }

        // Random sampling: the predicate must match validation on fresh draws,
        // exercising the overwhelmingly-in-range path.
        for _ in 0..32 {
            let value = Fp::random(&mut ragu_arithmetic::rand::rng());
            assert_eq!(super::endoscalar_in_range(value), constraints_accept(value));
        }
    }

    /// `sample` grinds an out-of-range candidate away and returns the accepted
    /// candidate together with its payload; `extract_native` then matches the
    /// in-circuit extraction.
    #[test]
    fn test_sample_grinds_until_in_range() -> Result<()> {
        // Feed one out-of-range candidate followed by an in-range one. `sample`
        // must reject the first, accept the second, and thread the payload
        // through unchanged. The wireless emulator is the only driver `sample`
        // accepts (native witness generation, `Wire = ()`).
        let in_range = Fp::from(0x0123_4567_89ab_cdefu64);

        Emulator::<Wireless<Always<()>, Fp>>::emulate_wireless(in_range, |dr, in_range| {
            let in_range = in_range.take();
            let candidates = [(-Fp::ONE, 7u32), (in_range, 9u32)];
            let mut attempt = 0usize;

            let (challenge, payload) = EndoscalarChallenge::sample(dr, |dr| {
                let (value, tag) = candidates[attempt];
                attempt += 1;
                let elem = Element::alloc(dr, &mut (), Always::<Fp>::just(|| value))?;
                Ok((elem, tag))
            })?;

            assert_eq!(attempt, 2, "expected exactly one rejection");
            assert_eq!(payload, 9, "accepted candidate's payload must be returned");
            assert_eq!(
                challenge.extract_native(),
                super::extract_endoscalar(in_range)?,
            );

            Ok(())
        })?;

        Ok(())
    }

    /// A genuine error from `produce` propagates immediately instead of being
    /// retried: the rejection loop retries only on the expected out-of-range
    /// outcome, never on a real error.
    #[test]
    fn test_sample_propagates_produce_error() -> Result<()> {
        // The wireless emulator is the sole driver `sample` accepts; the
        // witness is unused here.
        Emulator::<Wireless<Always<()>, Fp>>::emulate_wireless((), |dr, _| {
            let mut calls = 0usize;
            let outcome = EndoscalarChallenge::sample(dr, |_dr| {
                calls += 1;
                Result::<(Element<'_, _>, ())>::Err(ragu_core::Error::InvalidWitness(
                    "produce failure".into(),
                ))
            });

            assert!(outcome.is_err(), "produce error must surface as Err");
            assert_eq!(calls, 1, "produce error must not be retried");

            Ok(())
        })?;

        Ok(())
    }

    /// `try_from_element` classifies an out-of-range element as `Ok(None)` (the
    /// retry signal) and an in-range element as `Ok(Some(_))`, pinning the
    /// acceptance boundary at `2^CAPACITY`.
    #[test]
    fn test_try_from_element_classifies_range() -> Result<()> {
        let largest_in_range = {
            let mut acc = Fp::ZERO;
            for _ in 0..(Fp::CAPACITY as usize) {
                acc = acc.double() + Fp::ONE;
            }
            acc
        };

        let check = |value: Fp, expect_in_range: bool| -> Result<()> {
            Emulator::<Wireless<Always<()>, Fp>>::emulate_wireless(value, |dr, value| {
                let elem = Element::alloc(dr, &mut (), value)?;
                let classified = EndoscalarChallenge::try_from_element(dr, elem)?;
                assert_eq!(classified.is_some(), expect_in_range);
                Ok(())
            })?;
            Ok(())
        };

        check(Fp::ZERO, true)?;
        check(largest_in_range, true)?; // 2^CAPACITY - 1, the largest in range
        check(largest_in_range + Fp::ONE, false)?; // 2^CAPACITY, first out of range
        check(-Fp::ONE, false)?; // p - 1, out of range

        Ok(())
    }

    #[test]
    fn test_endoscaling() -> Result<()> {
        let p = EpAffine::generator();
        let r: u128 = ragu_arithmetic::rand::rng().random();
        let expected = EndoscalarTest { value: r }.scale(&p);

        Simulator::simulate((p, r), |dr, witness| {
            let (p, r) = witness.cast();
            let p = Point::alloc(dr, p.clone())?;
            let r = Endoscalar::alloc(dr, r.clone())?;

            dr.reset();
            assert_eq!(r.group_scale(dr, &p)?.value().take(), expected);
            assert_eq!(dr.num_gates(), 7 * (1 + (u128::BITS as usize / 2)));

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_endoscalar_lift() -> Result<()> {
        let r: u128 = ragu_arithmetic::rand::rng().random();
        let expected: Fp = EndoscalarTest { value: r }.lift();

        Simulator::<Fp>::simulate(r, |dr, witness| {
            let r = Endoscalar::alloc(dr, witness)?;
            let s = r.lift(dr)?;

            assert_eq!(*s.value().take(), expected);

            Ok(())
        })?;

        Ok(())
    }
}
