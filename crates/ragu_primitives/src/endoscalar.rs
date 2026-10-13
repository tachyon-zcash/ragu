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
//!
//! The scaling walks the endoscalar in radix 3 rather than Halo's radix 2:
//! after two initial bits, every three bits select one of the eight digits
//! $\pm 1, \pm \lambda, \pm \lambda^2, \pm (1 - \lambda)$, where $\lambda$
//! is the scalar the endomorphism acts by, and the accumulator is tripled
//! before the digit's multiple of the base point is added. Those digits are
//! the nonzero residues of $\mathbb{Z}[\lambda]$ modulo $3$, so the encoding
//! stays injective, and a tripling costs fewer gates per bit than a doubling.
//! See [`Endoscalar::group_scale`] for the layout and the scalar it maps to.

use alloc::boxed::Box;

use ragu_core::{
    Coeff, Error, Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::Gadget,
    maybe::{Always, Maybe},
};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use crate::{
    Boolean, Element, Nonzero, NonzeroBank, Point,
    allocator::Allocator,
    boolean::decompose,
    promotion::Demoted,
    vec::{CollectFixed, ConstLen, FixedVec},
};

/// The width of an endoscalar in bits.
///
/// An endoscalar is the low `ENDOSCALAR_BITS` bits of a transcript challenge
/// (see [`EndoscalarChallenge`]), so the field must have at least this much
/// capacity, which the Pasta fields do.
pub const ENDOSCALAR_BITS: usize = 143;

/// The radix-3 digits an endoscalar carries after its two initial bits.
///
/// An endoscalar's [`ENDOSCALAR_BITS`] bits are consumed as two initial
/// bits, which sign and twist the doubled base point, and then this many
/// three-bit digits; see [`Endoscalar::group_scale`].
pub const ENDOSCALAR_DIGITS: usize = 47;

/// The product wires a [`HoistedEndoscalar`] carries beside its bits: two per
/// digit, $e_1 e_2$ and $e_1 e_2 s$.
pub const ENDOSCALAR_PRODUCTS: usize = 2 * ENDOSCALAR_DIGITS;

const _: () = assert!(2 + 3 * ENDOSCALAR_DIGITS == ENDOSCALAR_BITS);
const _: () = assert!(
    ENDOSCALAR_BITS >= u128::BITS as usize,
    "Uendo's conversion from u128 must be lossless"
);

/// The value of an endoscalar: an [`ENDOSCALAR_BITS`]-bit string, read as
/// an unsigned integer with its least significant bit first.
///
/// The compact witness of the [`Endoscalar`] gadget, what
/// [`extract_endoscalar`] produces and what [`lift_endoscalar`] consumes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Uendo([u64; Uendo::LIMBS]);

impl Uendo {
    /// The number of bits.
    pub const BITS: usize = ENDOSCALAR_BITS;

    const LIMBS: usize = ENDOSCALAR_BITS.div_ceil(64);

    /// The all-zero endoscalar.
    pub const ZERO: Self = Self([0; Self::LIMBS]);

    /// Bit `i`, least significant first.
    ///
    /// # Panics
    ///
    /// Panics if `i` is not below [`Self::BITS`].
    pub fn bit(&self, i: usize) -> bool {
        assert!(i < Self::BITS, "bit {i} exceeds the endoscalar width");
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    /// The bits, least significant first.
    pub fn bits(&self) -> impl Iterator<Item = bool> + '_ {
        (0..Self::BITS).map(move |i| self.bit(i))
    }

    /// Builds an endoscalar from its bits, least significant first.
    ///
    /// # Panics
    ///
    /// Panics unless exactly [`Self::BITS`] bits are given.
    pub fn from_le_bits(bits: impl IntoIterator<Item = bool>) -> Self {
        let mut limbs = [0u64; Self::LIMBS];
        let mut count = 0;
        for (i, bit) in bits.into_iter().enumerate() {
            assert!(i < Self::BITS, "more than {} bits", Self::BITS);
            if bit {
                limbs[i / 64] |= 1 << (i % 64);
            }
            count += 1;
        }
        assert_eq!(count, Self::BITS, "fewer than {} bits", Self::BITS);
        Self(limbs)
    }

    /// Returns this endoscalar with bit `i` flipped.
    ///
    /// # Panics
    ///
    /// Panics if `i` is not below [`Self::BITS`].
    pub fn flip_bit(mut self, i: usize) -> Self {
        assert!(i < Self::BITS, "bit {i} exceeds the endoscalar width");
        self.0[i / 64] ^= 1 << (i % 64);
        self
    }

    /// Draws an endoscalar from the limbs `fill` produces, discarding the
    /// bits beyond the width.
    pub fn random(mut fill: impl FnMut() -> u64) -> Self {
        let mut limbs = [0u64; Self::LIMBS];
        for limb in &mut limbs {
            *limb = fill();
        }
        let unused = Self::LIMBS * 64 - Self::BITS;
        if unused > 0 {
            limbs[Self::LIMBS - 1] &= u64::MAX >> unused;
        }
        Self(limbs)
    }
}

impl From<u128> for Uendo {
    /// Zero-extends `value`; the width is at least 128 bits.
    fn from(value: u128) -> Self {
        let mut limbs = [0u64; Self::LIMBS];
        limbs[0] = value as u64;
        limbs[1] = (value >> 64) as u64;
        Self(limbs)
    }
}

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
/// The field must have at least [`ENDOSCALAR_BITS`] bits of capacity; Ragu's
/// supported Pasta fields satisfy this.
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
    ) -> Result<Self> {
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

impl<'dr, F: Field> EndoscalarChallenge<'dr, NativeEmulator<F>> {
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
    /// Returns the low [`ENDOSCALAR_BITS`] bits of the challenge's canonical
    /// bit decomposition, the native, wireless counterpart to
    /// [`Endoscalar::extract`], intended for native provers that constructed the
    /// challenge via [`sample`]. Because an [`EndoscalarChallenge`] already
    /// contains the constrained extraction, this operation is infallible.
    ///
    /// [`sample`]: EndoscalarChallenge::sample
    pub fn extract_native(&self) -> Uendo {
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
fn endoscalar_in_range<F: Field>(value: F) -> bool {
    !Field::to_le_bits(&value).as_ref()[F::CAPACITY as usize..]
        .iter()
        .any(|bit| *bit)
}

/// Represents a challenge used to scale elliptic curve points.
#[derive(Gadget)]
pub struct Endoscalar<'dr, D: Driver<'dr>> {
    /// The bits of this endoscalar in little-endian order.
    #[ragu(gadget)]
    bits: FixedVec<Demoted<'dr, D, Boolean<'dr, D>>, ConstLen<ENDOSCALAR_BITS>>,

    /// Witness data for the represented endoscalar in compact representation.
    #[ragu(value)]
    value: DriverValue<D, Uendo>,
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
    pub fn alloc(dr: &mut D, value: DriverValue<D, Uendo>) -> Result<Self> {
        let bits = (0..ENDOSCALAR_BITS)
            .map(|i| {
                let bit = Boolean::alloc(dr, &mut (), value.as_ref().map(|v| v.bit(i)))?;
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
            .map(|v| (0..ENDOSCALAR_BITS).map(move |i| v.bit(i)));

        self.bits.iter().map(move |demoted_bit| {
            demoted_bit.promote(bits.as_mut().map(|bits| bits.next().unwrap()))
        })
    }

    /// Returns the endoscalar constrained during challenge construction.
    ///
    /// The endoscalar is the low [`ENDOSCALAR_BITS`] bits of the challenge's
    /// canonical bit decomposition. [`EndoscalarChallenge::from_element`] already emitted the
    /// binding decomposition and range constraint, so extraction emits no
    /// additional constraints.
    pub fn extract(challenge: EndoscalarChallenge<'dr, D>) -> Self {
        challenge.endoscalar
    }

    /// Constrains `elem` to its canonical decomposition and returns its low
    /// [`ENDOSCALAR_BITS`] bits as an endoscalar.
    fn extract_element<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        elem: &Element<'dr, D>,
    ) -> Result<Self> {
        let bits = decompose(dr, allocator, elem)?;

        let value = elem.value().map(|v| {
            let le_bits = Field::to_le_bits(v);
            Uendo::from_le_bits(le_bits.as_ref().iter().take(ENDOSCALAR_BITS).copied())
        });

        let bits = bits
            .iter()
            .take(ENDOSCALAR_BITS)
            .map(|bit| Demoted::new(bit))
            .try_collect_fixed()?;

        Ok(Endoscalar { bits, value })
    }

    /// Scale a point by the endoscalar.
    ///
    /// The bits are read least significant first as two initial bits
    /// $(s_0, e_0)$ and then [`ENDOSCALAR_DIGITS`] three-bit digits
    /// $(s_i, e_{1,i}, e_{2,i})$. Writing $\phi$ for the endomorphism
    /// $(x, y) \mapsto (\zeta x, y)$, which acts on the group as the scalar
    /// $\lambda$ with $\lambda^2 + \lambda + 1 = 0$, the walk starts from
    /// $A_0 = \[2\] (-1)^{s_0} \phi^{e_0}(P)$ and performs
    /// $A_{i+1} = \[3\] A_i + \[d_i\] P$ with the digit
    /// $d_i = (-1)^{s_i} \cdot \{1, \lambda, \lambda^2, 1 - \lambda\}[e_{1,i},
    /// e_{2,i}]$, so with $n = \mathtt{ENDOSCALAR\_DIGITS}$ the result is
    /// $\[k\] P$ for
    ///
    /// $$k = 2 \cdot 3^{n} (-1)^{s_0} \lambda^{e_0} + \sum_{i} 3^{n - 1 - i} d_i,$$
    ///
    /// the scalar [`lift`](Self::lift) computes.
    ///
    /// The eight digits are the eight nonzero residues of $\mathbb{Z}[\lambda]$
    /// modulo $3$, so a radix-3 expansion decodes uniquely from its residues
    /// and the map from bit strings to $k \in \mathbb{Z}[\lambda]$ is
    /// injective. Two distinct encodings differ by an element of norm below
    /// $33 \cdot 9^{n}$, about $2^{154}$ here, which no prime above that
    /// divides, so they stay distinct in the scalar field of the Pasta
    /// curves.
    ///
    /// The point is first moved to the isomorphic curve on which it has
    /// coordinates $(r, r)$, by $(x, y) \mapsto (c^2 x, c^3 y)$ for
    /// $c = x / y$. There every digit multiple of the base point has
    /// coordinates affine in $r$, which lets the eight-way selection cost
    /// three gates; the result is moved back at the end. The intermediate
    /// points lie on the isomorphic curve, whose equation differs from this
    /// curve's only in its constant term, and the addition formulas never
    /// read that term.
    ///
    /// This costs $3 + 4 + 10 n + 3$ gates, $480$ here.
    ///
    /// # Exceptional Cases
    ///
    /// The incomplete additions used by this method require distinct
    /// x-coordinates at every addition. The method uses an unchecked
    /// [`NonzeroBank`] and relies on the magnitudes of the coefficients
    /// involved: every accumulator is $\[a\] P$ for an $a \in \mathbb{Z}[\lambda]$
    /// with $|a| \geq 2$, every digit has $|d| \leq \sqrt{3}$, and
    /// $|3a + d| \geq 3|a| - \sqrt{3} > |a|$, so none of $d = \pm a$,
    /// $d = -2a$, $a + d = 0$ or $3a + d = 0$ holds in $\mathbb{Z}[\lambda]$.
    /// All of these have norm far below the group order, so none holds
    /// modulo it either.
    ///
    /// # Soundness
    ///
    /// Under the argument above, any satisfying assignment makes the returned
    /// point represent `p` scaled by this endoscalar.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error if witness input falls into an
    /// incomplete-addition exceptional case.
    pub fn group_scale<C: Affine<Base = D::F>>(
        &self,
        dr: &mut D,
        p: &Point<'dr, D, C>,
    ) -> Result<Point<'dr, D, C>> {
        let zeta = D::F::ZETA;
        let one = Element::one();
        let two = D::F::from(2);
        let third = D::F::from(3)
            .invert()
            .expect("3 is invertible in a field of large characteristic");
        let zm1 = zeta - D::F::ONE;
        let z2m1 = zeta.square() - D::F::ONE;
        let four_ninths_zm1 = zm1 * third.square().double().double();
        let zm1_third = zm1 * third;
        let four_zeta_third = zeta * third.double().double();
        let neg_two_zeta_third = -(zeta * third.double());

        let mut bits = self.bits();
        let s0 = bits.next().unwrap().element();
        let e0 = bits.next().unwrap().element();

        // D = (-1)^s {P, φP, φ²P, P - φP}[u, v], in three gates: with
        // h = (r + (4/9)(ζ-1) u) ((ζ-1) u + (ζ²-1) v) and j = (u + v - 1) h,
        // x_D = r + h + ((ζ-1)/3) j + (4ζ/3) u and
        // y_D = (1 - 2s) (r - (2ζ/3) j).
        let point = walk(dr, p, (s0, e0), |dr, r| {
            let s = bits.next().unwrap().element();
            let u = bits.next().unwrap().element();
            let v = bits.next().unwrap().element();

            let lhs = r.add_coeff(dr, &u, Coeff::Arbitrary(four_ninths_zm1));
            let rhs = u
                .scale(dr, Coeff::Arbitrary(zm1))
                .add_coeff(dr, &v, Coeff::Arbitrary(z2m1));
            let h = lhs.mul(dr, &rhs)?;
            let j = u.add(dr, &v).sub(dr, &one).mul(dr, &h)?;
            let xd = r
                .add(dr, &h)
                .add_coeff(dr, &j, Coeff::Arbitrary(zm1_third))
                .add_coeff(dr, &u, Coeff::Arbitrary(four_zeta_third));
            let sign = one.add_coeff(dr, &s, Coeff::NegativeArbitrary(two));
            let yd_unsigned = r.add_coeff(dr, &j, Coeff::Arbitrary(neg_two_zeta_third));
            let yd = sign.mul(dr, &yd_unsigned)?;
            Ok((xd, yd))
        })?;
        debug_assert!(bits.next().is_none());

        Ok(point)
    }

    /// Lifts this endoscalar to a field element (scales $1$ by the endoscalar).
    ///
    /// Computes the scalar $k$ of [`group_scale`](Self::group_scale) by
    /// Horner's rule in radix 3, with $\lambda$ the field's cube root of
    /// unity. Each digit costs two gates: the product of its two twist bits,
    /// and the product of its sign with the digit's unsigned value.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned element represent the
    /// effective scalar for this endoscalar.
    pub fn lift(&self, dr: &mut D) -> Result<Element<'dr, D>> {
        let mut bits = self.bits();
        let s0 = bits.next().unwrap();
        let e0 = bits.next().unwrap();
        let acc = lift_init(dr, &s0, &e0)?;

        let acc = lift_digits(dr, acc, |dr| {
            let s = bits.next().unwrap();
            let e1 = bits.next().unwrap();
            let e2 = bits.next().unwrap();
            let e1e2 = e1.and(dr, &e2)?;
            Ok((s, e1, e2, e1e2))
        })?;
        debug_assert!(bits.next().is_none());

        Ok(acc)
    }
}

/// An endoscalar whose per-digit bit products are carried as wires, so that
/// scaling selects each digit's point in two gates instead of three and
/// lifting costs one gate per digit instead of two.
///
/// The products are $e_1 e_2$ and $e_1 e_2 s$ for every digit
/// $(s, e_1, e_2)$. They are plain wires: nothing in this gadget ties them to
/// the bits, exactly as nothing ties the bits to the compact witness. A
/// circuit that loads this gadget from a stage without enforcing its
/// contracts must have [`enforce_products`](Self::enforce_products) and the
/// bits' booleanity emitted once by whichever circuit owns those contracts,
/// or [`group_scale`](Self::group_scale) and [`lift`](Self::lift) are
/// unsound.
///
/// This pays off when many circuits scale by the same endoscalar: the
/// products live in the stage the circuits share and are constrained once.
#[derive(Gadget)]
pub struct HoistedEndoscalar<'dr, D: Driver<'dr>> {
    /// The bits.
    #[ragu(gadget)]
    endoscalar: Endoscalar<'dr, D>,

    /// Per digit, in digit order: the demoted products $e_1 e_2$ and
    /// $e_1 e_2 s$.
    #[ragu(gadget)]
    products: FixedVec<Demoted<'dr, D, Boolean<'dr, D>>, ConstLen<ENDOSCALAR_PRODUCTS>>,
}

impl<'dr, D: Driver<'dr>> HoistedEndoscalar<'dr, D> {
    /// The two products of digit `i` of `value`.
    fn digit_products(value: &Uendo, i: usize) -> (bool, bool) {
        let base = 2 + 3 * i;
        let p = value.bit(base + 1) && value.bit(base + 2);
        (p, p && value.bit(base))
    }

    /// Allocates an endoscalar with the provided witness input value, its
    /// bits and its products.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes each bit and each product wire
    /// represent `0` or `1`. Nothing ties the products to the bits, nor the
    /// bits to `value`; see [`enforce_products`](Self::enforce_products).
    pub fn alloc(dr: &mut D, value: DriverValue<D, Uendo>) -> Result<Self> {
        let endoscalar = Endoscalar::alloc(dr, value.clone())?;
        let products = (0..ENDOSCALAR_PRODUCTS)
            .map(|k| {
                let bit = Boolean::alloc(
                    dr,
                    &mut (),
                    value.as_ref().map(|v| {
                        let (p, q) = Self::digit_products(v, k / 2);
                        if k % 2 == 0 { p } else { q }
                    }),
                )?;
                Demoted::new(&bit)
            })
            .try_collect_fixed()?;

        Ok(HoistedEndoscalar {
            endoscalar,
            products,
        })
    }

    /// Returns an iterator over the bits in this endoscalar, little endian
    /// order.
    pub fn bits(&self) -> impl Iterator<Item = Boolean<'dr, D>> {
        self.endoscalar.bits()
    }

    /// Returns an iterator over the digits' product pairs $(e_1 e_2,
    /// e_1 e_2 s)$, in digit order.
    pub fn products(&self) -> impl Iterator<Item = (Boolean<'dr, D>, Boolean<'dr, D>)> {
        let mut values = self
            .endoscalar
            .value
            .as_ref()
            .map(|v| (0..ENDOSCALAR_DIGITS).map(move |i| Self::digit_products(v, i)));

        self.products.chunks_exact(2).map(move |pair| {
            let value = values.as_mut().map(|values| values.next().unwrap());
            (
                pair[0].promote(value.as_ref().map(|(p, _)| *p)),
                pair[1].promote(value.as_ref().map(|(_, q)| *q)),
            )
        })
    }

    /// Enforces that every product wire is the product of the bits it
    /// stands for.
    ///
    /// This costs two gates per digit. Together with the bits' booleanity,
    /// it is the contract [`group_scale`](Self::group_scale) and
    /// [`lift`](Self::lift) rest on.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes each digit's product wires represent
    /// $e_1 e_2$ and $e_1 e_2 s$ of its bit wires.
    pub fn enforce_products(&self, dr: &mut D) -> Result<()> {
        let mut bits = self.bits().skip(2);
        for (p, q) in self.products() {
            let s = bits.next().unwrap();
            let e1 = bits.next().unwrap();
            let e2 = bits.next().unwrap();
            let fresh_p = e1.and(dr, &e2)?;
            dr.enforce_equal(fresh_p.wire(), p.wire())?;
            let fresh_q = p.and(dr, &s)?;
            dr.enforce_equal(fresh_q.wire(), q.wire())?;
        }
        debug_assert!(bits.next().is_none());
        Ok(())
    }

    /// Scale a point by the endoscalar, selecting each digit's point in two
    /// gates from the hoisted products.
    ///
    /// Computes the same $\[k\] P$ as [`Endoscalar::group_scale`], whose
    /// exceptional-case argument applies unchanged, for $3 + 4 + 9 n + 3$
    /// gates.
    ///
    /// # Soundness
    ///
    /// Given the bits' booleanity and [`enforce_products`](Self::enforce_products),
    /// and under the exceptional-case argument of
    /// [`Endoscalar::group_scale`], any satisfying assignment makes the
    /// returned point represent `p` scaled by this endoscalar.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error if witness input falls into an
    /// incomplete-addition exceptional case.
    pub fn group_scale<C: Affine<Base = D::F>>(
        &self,
        dr: &mut D,
        p: &Point<'dr, D, C>,
    ) -> Result<Point<'dr, D, C>> {
        let zeta = D::F::ZETA;
        let zeta2 = zeta.square();
        let one = Element::one();
        let two = D::F::from(2);
        let third = D::F::from(3)
            .invert()
            .expect("3 is invertible in a field of large characteristic");
        let zm1 = zeta - D::F::ONE;
        let z2m1 = zeta2 - D::F::ONE;
        let one_minus_zeta = D::F::ONE - zeta;
        // P - φP is (ζ² (r - 4/3), (1 + 2ζ)(r - 8/9)) on the normalized curve.
        let xq0 = -(zeta2 * third.double().double());
        let c1 = D::F::ONE + zeta.double();
        let yq0 = -(c1 * third.square().double().double().double());
        let c1m1 = c1 - D::F::ONE;

        let mut bits = self.bits();
        let s0 = bits.next().unwrap().element();
        let e0 = bits.next().unwrap().element();
        let mut products = self.products();

        // With the products p = e₁e₂ and q = p s as wires, both coordinates
        // of D are r times a linear form plus a linear form:
        // x_D = r (1 + (ζ-1) e₁ + (ζ²-1) e₂ + (1-ζ) p) + xq0 p,
        // y_D = r ((1 - 2s) + (c₁-1)(p - 2q)) + yq0 (p - 2q).
        let point = walk(dr, p, (s0, e0), |dr, r| {
            let s = bits.next().unwrap().element();
            let e1 = bits.next().unwrap().element();
            let e2 = bits.next().unwrap().element();
            let (p, q) = products.next().unwrap();
            let (p, q) = (p.element(), q.element());

            let lx = one
                .add_coeff(dr, &e1, Coeff::Arbitrary(zm1))
                .add_coeff(dr, &e2, Coeff::Arbitrary(z2m1))
                .add_coeff(dr, &p, Coeff::Arbitrary(one_minus_zeta));
            let xd = r.mul(dr, &lx)?.add_coeff(dr, &p, Coeff::Arbitrary(xq0));

            let p_minus_2q = p.add_coeff(dr, &q, Coeff::NegativeArbitrary(two));
            let ly = one
                .add_coeff(dr, &s, Coeff::NegativeArbitrary(two))
                .add_coeff(dr, &p_minus_2q, Coeff::Arbitrary(c1m1));
            let yd = r
                .mul(dr, &ly)?
                .add_coeff(dr, &p_minus_2q, Coeff::Arbitrary(yq0));
            Ok((xd, yd))
        })?;
        debug_assert!(bits.next().is_none());
        debug_assert!(products.next().is_none());

        Ok(point)
    }

    /// Lifts this endoscalar to a field element, reading each digit's
    /// $e_1 e_2$ from the hoisted products so that a digit costs one gate.
    ///
    /// # Soundness
    ///
    /// Given the bits' booleanity and [`enforce_products`](Self::enforce_products),
    /// any satisfying assignment makes the returned element represent the
    /// effective scalar for this endoscalar.
    pub fn lift(&self, dr: &mut D) -> Result<Element<'dr, D>> {
        let mut bits = self.bits();
        let s0 = bits.next().unwrap();
        let e0 = bits.next().unwrap();
        let acc = lift_init(dr, &s0, &e0)?;

        let mut products = self.products();
        let acc = lift_digits(dr, acc, |_| {
            let s = bits.next().unwrap();
            let e1 = bits.next().unwrap();
            let e2 = bits.next().unwrap();
            let (e1e2, _) = products.next().unwrap();
            Ok((s, e1, e2, e1e2))
        })?;
        debug_assert!(bits.next().is_none());
        debug_assert!(products.next().is_none());

        Ok(acc)
    }
}

/// The radix-3 walk shared by [`Endoscalar::group_scale`] and
/// [`HoistedEndoscalar::group_scale`]: normalizes `p` to $(r, r)$, forms the
/// initial point from the two initial bits, then for each digit adds the
/// point `select` returns to the tripled accumulator, and moves the result
/// back. `select` is called once per digit with $r$ and returns the digit
/// point's coordinates on the normalized curve.
///
/// Costs $3 + 4 + 7 n + 3$ gates plus what `select` emits.
fn walk<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
    dr: &mut D,
    p: &Point<'dr, D, C>,
    (s0, e0): (Element<'dr, D>, Element<'dr, D>),
    mut select: impl FnMut(&mut D, &Element<'dr, D>) -> Result<(Element<'dr, D>, Element<'dr, D>)>,
) -> Result<Point<'dr, D, C>> {
    // Soundness: every `fold` below guards a division whose denominator the
    // magnitude argument in `Endoscalar::group_scale` keeps nonzero, so the
    // bank is created in unchecked mode and the folds emit nothing.
    //
    // TODO(ebfull): The no-collision argument is a property of the curve /
    // endoscalar interaction that the `Cycle` API should attest to at compile
    // time, so callers can verify it holds for their choice of curve rather
    // than relying on this ad-hoc local justification.
    let mut bank = NonzeroBank::new_unchecked();

    let zeta = D::F::ZETA;
    let one = Element::one();
    let two = D::F::from(2);
    let zm1 = zeta - D::F::ONE;
    let three_halves = D::F::from(3) * D::F::TWO_INVERSE;

    // Normalize: c = x / y and r = c² x move p to (r, r) on y² = x³ + c⁶ b.
    let c = p.x.divide(dr, &p.y)?;
    let c2 = c.square(dr)?;
    let r = c2.mul(dr, &p.x)?.into_inner();

    // A₀ = [2] (-1)^{s₀} φ^{e₀} (r, r); the tangent at (r, r) has the linear
    // slope 3r / 2.
    let t = r.scale(dr, Coeff::Arbitrary(three_halves));
    let two_r = r.double(dr);
    let x2 = t.square(dr)?.sub(dr, &two_r);
    let r_minus_x2 = r.sub(dr, &x2);
    let y2 = t.mul(dr, &r_minus_x2)?.sub(dr, &r);
    let twist = one.add_coeff(dr, &e0, Coeff::Arbitrary(zm1));
    let sign = one.add_coeff(dr, &s0, Coeff::NegativeArbitrary(two));
    let mut x = x2.mul(dr, &twist)?;
    let mut y = y2.mul(dr, &sign)?;

    for _ in 0..ENDOSCALAR_DIGITS {
        let (xd, yd) = select(dr, &r)?;

        // [3] A + D = ((A + D) + A) + A in seven gates: the intermediate
        // y-coordinates cancel out of the slope equations
        // (t₁ + t₂)(x₁ - x) = -2y and (t₂ + t₃)(x₂ - x) = -2y.
        let neg_2y = y.scale(dr, Coeff::NegativeArbitrary(two));
        let diff = xd.sub(dr, &x);
        let den = bank.fold(dr, diff)?;
        let t1 = yd.sub(dr, &y).divide(dr, &den)?;
        let x1 = t1.square(dr)?.sub(dr, &x).sub(dr, &xd);
        let diff = x1.sub(dr, &x);
        let den = bank.fold(dr, diff)?;
        let t2 = neg_2y.divide(dr, &den)?.sub(dr, &t1);
        let x2 = t2.square(dr)?.sub(dr, &x1).sub(dr, &x);
        let diff = x2.sub(dr, &x);
        let den = bank.fold(dr, diff)?;
        let t3 = neg_2y.divide(dr, &den)?.sub(dr, &t2);
        let x3 = t3.square(dr)?.sub(dr, &x2).sub(dr, &x);
        let x_minus_x3 = x.sub(dr, &x3);
        let y3 = t3.mul(dr, &x_minus_x3)?.sub(dr, &y);
        x = x3;
        y = y3;
    }

    // Move the result back: x = X / c², y = Y / c³. The result is a nonzero
    // multiple of p, so its coordinates are nonzero.
    let c3 = c2.mul(dr, &c)?;
    let x = x.divide(dr, &c2)?;
    let y = y.divide(dr, &c3)?;

    Ok(Point::new_unchecked(
        Nonzero::new_unchecked(x),
        Nonzero::new_unchecked(y),
    ))
}

/// The lift's initial accumulator
/// $2 (1 - 2 s_0)(1 + (\lambda - 1) e_0)$, in one gate for $s_0 e_0$.
fn lift_init<'dr, D: Driver<'dr>>(
    dr: &mut D,
    s0: &Boolean<'dr, D>,
    e0: &Boolean<'dr, D>,
) -> Result<Element<'dr, D>> {
    let lm1 = D::F::ZETA - D::F::ONE;
    let two = D::F::from(2);

    // 2 (1 - 2 s₀) (1 + (λ - 1) e₀) = 2 + 2 (λ - 1) e₀ - 4 s₀ - 4 (λ - 1) s₀ e₀.
    let s0e0 = s0.and(dr, e0)?;
    Ok(Element::constant(dr, two)
        .add_coeff(dr, &e0.element(), Coeff::Arbitrary(lm1.double()))
        .add_coeff(dr, &s0.element(), Coeff::NegativeArbitrary(two.double()))
        .add_coeff(
            dr,
            &s0e0.element(),
            Coeff::NegativeArbitrary(lm1.double().double()),
        ))
}

/// Folds the digits into the lift's accumulator by Horner's rule in radix 3.
/// `digit` yields each digit's $(s, e_1, e_2, e_1 e_2)$ in turn; a digit
/// then costs one gate, for its sign times its unsigned value.
fn lift_digits<'dr, D: Driver<'dr>>(
    dr: &mut D,
    mut acc: Element<'dr, D>,
    mut digit: impl FnMut(
        &mut D,
    ) -> Result<(
        Boolean<'dr, D>,
        Boolean<'dr, D>,
        Boolean<'dr, D>,
        Boolean<'dr, D>,
    )>,
) -> Result<Element<'dr, D>> {
    let lambda = D::F::ZETA;
    let lm1 = lambda - D::F::ONE;
    let l2m1 = lambda.square() - D::F::ONE;
    let three_minus_lambda = D::F::from(3) - lambda;
    let two = D::F::from(2);
    let one = Element::one();

    for _ in 0..ENDOSCALAR_DIGITS {
        let (s, e1, e2, e1e2) = digit(dr)?;

        // v = {1, λ, λ², 1 - λ}[e₁, e₂]
        //   = 1 + (λ - 1) e₁ + (λ² - 1) e₂ + (3 - λ) e₁ e₂.
        let v = one
            .add_coeff(dr, &e1.element(), Coeff::Arbitrary(lm1))
            .add_coeff(dr, &e2.element(), Coeff::Arbitrary(l2m1))
            .add_coeff(dr, &e1e2.element(), Coeff::Arbitrary(three_minus_lambda));
        let sign = one.add_coeff(dr, &s.element(), Coeff::NegativeArbitrary(two));
        let d = sign.mul(dr, &v)?;

        // acc = 3 acc + d.
        acc = acc.scale(dr, Coeff::Arbitrary(D::F::from(3))).add(dr, &d);
    }

    Ok(acc)
}

/// Lifts an endoscalar to a field element (computes the effective scalar).
///
/// The native counterpart to [`Endoscalar::lift`]: the scalar $k$ of
/// [`Endoscalar::group_scale`], with $\lambda$ the field's cube root of unity.
pub fn lift_endoscalar<F: Field>(endo: Uendo) -> F {
    let bit = |i: usize| endo.bit(i);
    let lambda = F::ZETA;
    let lambda2 = lambda.square();

    let mut acc = if bit(1) { lambda } else { F::ONE };
    if bit(0) {
        acc = -acc;
    }
    acc = acc.double();

    for i in 0..ENDOSCALAR_DIGITS {
        let base = 2 + 3 * i;
        let mut d = match (bit(base + 1), bit(base + 2)) {
            (false, false) => F::ONE,
            (true, false) => lambda,
            (false, true) => lambda2,
            (true, true) => F::ONE - lambda,
        };
        if bit(base) {
            d = -d;
        }
        acc = acc + acc.double() + d;
    }
    acc
}

/// Extracts an endoscalar from a validated field element.
///
/// Returns the low [`ENDOSCALAR_BITS`] bits of the element's canonical bit
/// decomposition, the native counterpart to [`Endoscalar::extract`].
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
/// The field must have at least [`ENDOSCALAR_BITS`] bits of capacity; Ragu's
/// supported Pasta fields satisfy this.
///
/// # Errors
///
/// Fails with [`Error::InvalidWitness`] when `value` is out of range
/// ($\mathtt{value} \geq 2^{\mathtt{CAPACITY}}$); the boxed source is an
/// [`EndoscalarRangeError`], so callers modeling transcript rejection can
/// detect the condition with [`Error::invalid_witness_source`].
pub fn extract_endoscalar<F: Field>(value: F) -> Result<Uendo> {
    Emulator::emulate_wireless(value, |dr, witness| {
        let elem = Element::alloc(dr, &mut (), witness)?;
        let challenge = EndoscalarChallenge::from_element(dr, &mut (), elem)?;
        let endo = Endoscalar::extract(challenge);
        Ok(*endo.value.snag())
    })
}

#[cfg(test)]
mod tests {
    use ragu_core::{
        Result,
        drivers::emulator::Wireless,
        pasta::{EpAffine, Fp},
    };
    use rand::{Rng, RngExt};
    use udon::{
        curve::{Affine as _, EndomorphismAffine as Affine, EndomorphismProjective, Projective},
        field::Field,
    };

    use super::{
        Always, Boolean, Demoted, Element, Emulator, Endoscalar, EndoscalarChallenge,
        EndoscalarRangeError, HoistedEndoscalar, Maybe, Point, Uendo,
    };
    use crate::{Simulator, allocator::Standard, vec::CollectFixed};

    pub struct EndoscalarTest {
        pub value: Uendo,
    }

    /// A uniformly random endoscalar.
    pub fn random_endoscalar() -> Uendo {
        Uendo::random(|| rand::rng().random())
    }

    impl EndoscalarTest {
        /// The radix-3 walk of [`Endoscalar::group_scale`], in projective
        /// coordinates with the digit multiples formed by the endomorphism.
        pub fn scale<C: Affine>(&self, p: &C) -> C {
            let bit = |i: usize| self.value.bit(i);
            let p = p.to_projective();

            let mut acc = if bit(1) { p.endomorphism() } else { p };
            if bit(0) {
                acc = -acc;
            }
            acc = acc.double();

            for i in 0..super::ENDOSCALAR_DIGITS {
                let base = 2 + 3 * i;
                let mut d = match (bit(base + 1), bit(base + 2)) {
                    (false, false) => p,
                    (true, false) => p.endomorphism(),
                    (false, true) => p.endomorphism().endomorphism(),
                    (true, true) => p + (-p.endomorphism()),
                };
                if bit(base) {
                    d = -d;
                }
                acc = acc.double() + acc + d;
            }
            acc.into()
        }

        /// The scalar of the walk above, from [`super::lift_endoscalar`].
        pub fn lift<F: Field>(&self) -> F {
            super::lift_endoscalar(self.value)
        }
    }

    pub fn extract<F: Field>(value: F) -> EndoscalarTest {
        EndoscalarTest {
            value: super::extract_endoscalar(value)
                .expect("test challenge should satisfy value < 2^CAPACITY"),
        }
    }

    /// The reference walk scales by the lifted scalar on both curves of the
    /// cycle, so the endomorphism's $\zeta$ and the scalar field's $\lambda$
    /// pair up correctly.
    #[test]
    #[allow(clippy::useless_conversion)]
    fn test_endoscaling_consistency() {
        use ragu_core::pasta::{EpAffine, EqAffine, Fq};

        let mut values = alloc::vec![
            Uendo::ZERO,
            Uendo::from_le_bits((0..Uendo::BITS).map(|_| true)),
            Uendo::from(206786806484900909362154774549736492353u128),
        ];
        values.extend((0..16).map(|_| random_endoscalar()));

        for value in values {
            let e = EndoscalarTest { value };

            let p = EpAffine::generator();
            let expected: EpAffine = (p * e.lift::<Fq>()).into();
            assert_eq!(e.scale(&p), expected);

            let q = EqAffine::generator();
            let expected: EqAffine = (q * e.lift::<Fp>()).into();
            assert_eq!(e.scale(&q), expected);
        }
    }

    #[test]
    fn test_extract() -> Result<()> {
        let p = EpAffine::generator();
        let r = loop {
            let r = Fp::random(|bytes| rand::rng().fill_bytes(bytes));
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
            let value = Fp::random(|bytes| rand::rng().fill_bytes(bytes));
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
        let r = random_endoscalar();
        let expected = EndoscalarTest { value: r }.scale(&p);

        Simulator::simulate((p, r), |dr, witness| {
            let (p, r) = witness.cast();
            let p = Point::alloc(dr, p.clone())?;
            let r = Endoscalar::alloc(dr, r.clone())?;

            dr.reset();
            assert_eq!(r.group_scale(dr, &p)?.value().take(), expected);
            assert_eq!(dr.num_gates(), 3 + 4 + 10 * super::ENDOSCALAR_DIGITS + 3);

            Ok(())
        })?;

        Ok(())
    }

    /// The hoisted gadget scales and lifts exactly as the plain one, at its
    /// pinned gate counts, and its product contract costs two gates a digit.
    #[test]
    fn test_hoisted_endoscalar() -> Result<()> {
        let p = EpAffine::generator();
        let r = random_endoscalar();
        let expected = EndoscalarTest { value: r }.scale(&p);
        let expected_lift: Fp = EndoscalarTest { value: r }.lift();

        Simulator::simulate((p, r), |dr, witness| {
            let (p, r) = witness.cast();
            let p = Point::alloc(dr, p.clone())?;
            let r = HoistedEndoscalar::alloc(dr, r.clone())?;

            dr.reset();
            assert_eq!(r.group_scale(dr, &p)?.value().take(), expected);
            assert_eq!(dr.num_gates(), 3 + 4 + 9 * super::ENDOSCALAR_DIGITS + 3);

            dr.reset();
            assert_eq!(*r.lift(dr)?.value().take(), expected_lift);
            assert_eq!(dr.num_gates(), 1 + super::ENDOSCALAR_DIGITS);

            dr.reset();
            r.enforce_products(dr)?;
            assert_eq!(dr.num_gates(), 2 * super::ENDOSCALAR_DIGITS);

            Ok(())
        })?;

        Ok(())
    }

    /// A product wire that is not the product of its bits changes the
    /// scaled point and the lift, and fails `enforce_products`: the products
    /// are a contract, not a convenience.
    #[test]
    fn test_hoisted_endoscalar_products_are_binding() -> Result<()> {
        let p = EpAffine::generator();
        let r = random_endoscalar();
        let honest = EndoscalarTest { value: r }.scale(&p);
        let honest_lift: Fp = EndoscalarTest { value: r }.lift();

        // Corrupt the first digit's `e₁ e₂` wire whichever way flips it.
        let corrupt =
            |dr: &mut Simulator<Fp>, r: &Uendo| -> Result<HoistedEndoscalar<'_, Simulator<Fp>>> {
                let (p0, _) = HoistedEndoscalar::<Simulator<Fp>>::digit_products(r, 0);
                let endoscalar = Endoscalar::alloc(dr, Always::<Uendo>::just(|| *r))?;
                let products = (0..super::ENDOSCALAR_PRODUCTS)
                    .map(|k| {
                        let (p, q) = HoistedEndoscalar::<Simulator<Fp>>::digit_products(r, k / 2);
                        let value = if k == 0 {
                            !p0
                        } else if k % 2 == 0 {
                            p
                        } else {
                            q
                        };
                        let bit = Boolean::alloc(dr, &mut (), Always::<bool>::just(|| value))?;
                        Demoted::new(&bit)
                    })
                    .try_collect_fixed()?;
                Ok(HoistedEndoscalar {
                    endoscalar,
                    products,
                })
            };

        let outcome = Simulator::simulate((p, r), |dr, witness| {
            let (p, r) = witness.cast();
            let p = Point::alloc(dr, p.clone())?;
            let r = corrupt(dr, &r.take())?;
            assert_ne!(r.group_scale(dr, &p)?.value().take(), honest);
            assert_ne!(*r.lift(dr)?.value().take(), honest_lift);
            r.enforce_products(dr)
        });
        assert!(
            outcome.is_err(),
            "a corrupted product must fail the contract"
        );

        Ok(())
    }

    #[test]
    fn test_endoscalar_lift() -> Result<()> {
        let r = random_endoscalar();
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
