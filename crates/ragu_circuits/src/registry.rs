//! Management of polynomials that encode large sets of wiring polynomials for
//! efficient querying.
//!
//! ## Overview
//!
//! Individual circuits in Ragu are represented by a bivariate polynomial
//! $s_i(X, Y)$. Multiple circuits are used over any particular field throughout
//! Ragu's PCD construction, and so the [`Registry`] structure represents a larger
//! polynomial $m(W, X, Y)$ that interpolates such that $m(\omega^i, X, Y) =
//! s_i(X, Y)$ for some $\omega \in \mathbb{F}$ of sufficiently high $2^k$ order
//! to encode all circuits for both PCD and for application circuits. The book's
//! [registry chapter] gives the full construction, including Lagrange
//! interpolation at an arbitrary $W$ and the rolling domain extension.
//!
//! ## Every domain point is a wiring polynomial
//!
//! The domain is padded to a power of two, so it usually has more points than
//! there are explicitly registered wiring polynomials. Rather than treat the
//! surplus points as "out of bounds", the registry assigns a wiring polynomial
//! to *every* domain point: an explicit registration at $\omega^i$ contributes
//! its $s_i(X, Y)$, and every other domain point is implicitly the zero
//! polynomial (the interpolation is zero there). A [`CircuitIndex`] is therefore
//! never out of bounds within the domain — if its $\omega^j$ (the bit-reversed
//! exponent of its index $i$; see [`CircuitIndex::omega_j`]) is in the domain,
//! it selects a wiring polynomial.
//!
//! The zero polynomial is not a special case: a bonding polynomial is precisely
//! a wiring polynomial with $s(X, 0) = 0$, so the zero polynomial *is* one. The
//! domain thus holds circuit wiring polynomials ($s(X, 0) = 1$) and bonding
//! polynomials ($s(X, 0) = 0$) — the latter being both the explicitly registered
//! ones (see [`register_bonding`](RegistryBuilder::register_bonding)) and the
//! unassigned points. See [`BondingObject`] for how this $s(X, 0)$ distinction
//! keeps one kind from standing in for the other.
//!
//! This is why selecting by domain membership alone is safe. A verifier that
//! expects a circuit fixes $\mathbf{k}_0 = 1$, which no bonding polynomial can
//! satisfy, so permitting an arbitrary in-domain index already confines the
//! selection to the registered circuits by construction — registered bonding
//! polynomials and unassigned points are excluded by that same mechanism, not by
//! a bounds check.
//!
//! [`circuit_in_domain`](Registry::circuit_in_domain) reports domain membership
//! only; it does *not* report whether anything was explicitly registered at that
//! point, which is why it is not a registration check. An index whose $\omega^j$
//! falls *outside* the domain is the general case of [`at`](Registry::at): it
//! evaluates the registry interpolation at that arbitrary point, mixing all
//! domain points together, and is what `circuit_in_domain` returns `false` for.
//!
//! The [`RegistryBuilder`] structure is used to construct a new [`Registry`] by
//! inserting circuits and performing a [`finalize`](RegistryBuilder::finalize) step
//! to compile the added circuits into a registry polynomial representation that can
//! be efficiently evaluated at different restrictions.
//!
//! [registry chapter]: https://tachyon.z.cash/ragu/protocol/extensions/registry.html

use alloc::{boxed::Box, vec::Vec};

use blake2b_simd::Params;
use ragu_arithmetic::{
    Domain, bitreverse,
    ff::{Field, FromUniformBytes, PrimeField},
};
use ragu_core::{Error, Result};

use crate::{
    BondingObject, Circuit, WiringObject,
    floor_planner::ConstraintSegment,
    polynomials::{Rank, sparse},
};

/// Represents a simple numeric index of a circuit in the registry.
///
/// Any value naming a domain point selects a wiring polynomial: the $s_i(X, Y)$
/// explicitly registered at that index, or the zero polynomial if nothing was.
/// See the [module overview](crate::registry).
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(transparent)]
pub struct CircuitIndex(u32);

impl CircuitIndex {
    /// Creates a new circuit index.
    pub fn new(index: usize) -> Self {
        Self(index.try_into().unwrap())
    }

    /// Creates a circuit index from a `u32` value.
    pub const fn from_u32(index: u32) -> Self {
        Self(index)
    }

    /// Returns $\omega^j$ field element that corresponds to this $i$th circuit index.
    ///
    /// The $i$th circuit added to any [`Registry`] (for a given [`PrimeField`] `F`) is
    /// assigned the domain element of smallest multiplicative order not yet
    /// assigned to any circuit prior to $i$. This corresponds with $\Omega^{f(i)}$
    /// where $f(i)$ is the [`S`](PrimeField::S)-bit reversal of `i` and $\Omega$ is
    /// the primitive [root of unity](PrimeField::ROOT_OF_UNITY) of order $2^{S}$ in
    /// `F`.
    ///
    /// Notably, the result of this function does not depend on the actual size of
    /// the [`Registry`]'s interpolation polynomial domain.
    pub fn omega_j<F: PrimeField>(self) -> F {
        let bit_reversal_id = bitreverse(self.0, F::S);
        F::ROOT_OF_UNITY.pow([bit_reversal_id.into()])
    }
}

impl From<CircuitIndex> for usize {
    fn from(idx: CircuitIndex) -> usize {
        idx.0 as usize
    }
}

/// A builder that constructs a [`Registry`].
///
/// Circuits are organized into four categories:
/// - Internal circuits: system circuits for the PCD construction
/// - Bonding: bonding polynomials for well-formedness enforcement
/// - Internal steps: internal step circuits (e.g. rerandomize, trivial)
/// - Application steps: user-defined application step circuits
///
/// During finalization, circuits are concatenated in the order above,
/// ensuring internal circuits get lower indices while maintaining
/// proper PCD indexing.
pub struct RegistryBuilder<'params, F: PrimeField, R: Rank> {
    internal_circuits: Vec<Box<dyn WiringObject<F, R> + 'params>>,
    bonding: Vec<Box<dyn WiringObject<F, R> + 'params>>,
    internal_steps: Vec<Box<dyn WiringObject<F, R> + 'params>>,
    application_steps: Vec<Box<dyn WiringObject<F, R> + 'params>>,
}

impl<F: FromUniformBytes<64>, R: Rank> Default for RegistryBuilder<'_, F, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, F: FromUniformBytes<64>, R: Rank> RegistryBuilder<'params, F, R> {
    /// Creates a new empty [`Registry`] builder.
    pub fn new() -> Self {
        Self {
            internal_circuits: Vec::new(),
            bonding: Vec::new(),
            internal_steps: Vec::new(),
            application_steps: Vec::new(),
        }
    }

    /// Returns the number of internal circuits (circuits + bonding).
    pub fn num_internal_circuits(&self) -> usize {
        self.bonding.len() + self.internal_circuits.len()
    }

    /// Returns the total number of circuits across all categories.
    pub fn num_circuits(&self) -> usize {
        self.num_internal_circuits() + self.internal_steps.len() + self.application_steps.len()
    }

    /// Returns the log2 of the smallest power-of-2 domain size that fits all circuits.
    pub fn log2_circuits(&self) -> u32 {
        self.num_circuits().next_power_of_two().trailing_zeros()
    }

    /// Registers an application step circuit.
    ///
    /// # Errors
    ///
    /// Propagates any error from converting `circuit` into the registry's
    /// internal wiring representation.
    pub fn register_circuit<C>(mut self, circuit: C) -> Result<Self>
    where
        C: Circuit<F> + 'params,
    {
        self.application_steps
            .push(crate::into_wiring_object(circuit)?);
        Ok(self)
    }

    /// Registers an internal circuit.
    ///
    /// # Errors
    ///
    /// Propagates any error from converting `circuit` into the registry's
    /// internal wiring representation.
    pub fn register_internal_circuit<C>(mut self, circuit: C) -> Result<Self>
    where
        C: Circuit<F> + 'params,
    {
        self.internal_circuits
            .push(crate::into_wiring_object(circuit)?);
        Ok(self)
    }

    /// Registers an internal step circuit.
    ///
    /// # Errors
    ///
    /// Propagates any error from converting `circuit` into the registry's
    /// internal wiring representation.
    pub fn register_internal_step<C>(mut self, circuit: C) -> Result<Self>
    where
        C: Circuit<F> + 'params,
    {
        self.internal_steps
            .push(crate::into_wiring_object(circuit)?);
        Ok(self)
    }

    /// Registers a bonding polynomial.
    pub fn register_bonding(mut self, bonding: BondingObject<'params, F, R>) -> Self {
        self.bonding.push(bonding.into_inner());
        self
    }

    /// Builds the [`Registry`].
    ///
    /// Circuits are concatenated in the following order for proper indexing:
    /// 1. Internal circuits: System circuits for the PCD construction
    /// 2. Bonding: bonding polynomials
    /// 3. Internal steps: Internal step circuits (e.g. rerandomize, trivial)
    /// 4. Application steps: User-defined step circuits
    ///
    /// This concatenation order must match `InternalCircuitIndex::ALL` in
    /// `ragu_pcd`, which derives [`CircuitIndex`] from position in the array.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CircuitBoundExceeded`] if the total number of
    /// registered circuits exceeds the rank capacity.
    pub fn finalize(self) -> Result<Registry<'params, F, R>>
    where
        F: FromUniformBytes<64>,
    {
        let total_circuits = self.num_circuits();
        if total_circuits > R::num_coeffs() {
            return Err(Error::CircuitBoundExceeded {
                limit: R::num_coeffs(),
            });
        }

        let log2_circuits = self.log2_circuits();
        let domain = Domain::<F>::new(log2_circuits);

        let circuits: Vec<_> = self
            .internal_circuits
            .into_iter()
            .chain(self.bonding)
            .chain(self.internal_steps)
            .chain(self.application_steps)
            .collect();

        // Compute floor plans for each circuit.
        let floor_plans: Vec<Vec<ConstraintSegment>> = circuits
            .iter()
            .map(|circuit| crate::floor_planner::floor_plan(circuit.segment_records()))
            .collect();

        // Create provisional registry (key not yet computed)
        let mut registry = Registry {
            domain,
            circuits,
            floor_plans,
            key: Key::default(),
        };
        registry.key = Key::new(registry.compute_registry_digest());

        Ok(registry)
    }
}

/// Key that binds the registry polynomial $m(W, X, Y)$ to prevent Fiat-Shamir
/// soundness attacks.
///
/// In Fiat-Shamir transformed protocols, common inputs such as the proving
/// statement (i.e., circuit descriptions) must be included in the transcript
/// before any prover messages or verifier challenges. Otherwise, malicious
/// provers may adapatively choose another statement during, or even after,
/// generating a proof. In the literature, this is known as
/// [weak Fiat-Shamir attacks](https://eprint.iacr.org/2023/1400).
///
/// To prevent such attacks, one can salt the registry digest $H(m(W, X, Y))$ to
/// the transcript before any prover messages, forcing a fixed instance.
/// However, the registry polynomial $m$ contains the description of a recursive
/// verifier whose logic depends on a transcript salted with the very digest
/// itself, creating a circular dependency.
///
/// Many preprocessing recursive SNARKs avoid this self-reference problem
/// implicitly because the circuit descriptions are encoded in a verification
/// key that is generated ahead of time and carried through public inputs to the
/// recursive verifier. Ragu avoids preprocessing by design, and does not use
/// verification keys, which suggests an alternative solution.
///
/// # Binding a polynomial through its evaluation
///
/// Polynomials of bounded degree are overdetermined by their evaluation at a
/// sufficient number of distinct points. Starting from public constants, we
/// iteratively evaluate $e_i = m(w_i, x_i, y_i)$ where each evaluation point
/// $(w_{i+1}, x_{i+1}, y_{i+1})$ is seeded by hashing the prior evaluation $e_i$.
/// The final evaluation serves as the binding key.
///
/// The number of iterations must exceed the degrees of freedom an adversary
/// could exploit to adaptively modify circuits.
/// See [#78] for the security argument.
///
/// # Break self-reference without preprocessing
///
/// Now with a binding evaluation `e_d`, which is the registry [`Key`], we can
/// break the self-reference more elegantly without preprocessing or reliance on
/// public inputs.
///
/// Concretely, the registry key $k$ is injected as the monomial
/// $k \cdot (XY)^{4n-1}$ at the registry level, binding each circuit's wiring
/// polynomial to the registry polynomial and thus the entire registry polynomial
/// to the Fiat-Shamir transcript without self-reference. The key randomizes the
/// wiring polynomial directly.
///
/// The key is computed during [`RegistryBuilder::finalize`] and used during
/// polynomial evaluations of circuits in the registry.
///
/// [#78]: https://github.com/tachyon-zcash/ragu/issues/78
pub struct Key<F: Field>(F);

impl<F: Field> Default for Key<F> {
    fn default() -> Self {
        Self(F::ONE)
    }
}

impl<F: Field> Key<F> {
    /// Creates a new registry key from a field element.
    pub fn new(val: F) -> Self {
        Self(val)
    }

    /// Returns the registry key value.
    pub fn value(&self) -> F {
        self.0
    }
}

/// Represents a collection of circuits over a particular field, some of which
/// may make reference to the others or be executed in similar contexts. The
/// circuits are combined together using an interpolation polynomial so that
/// they can be queried efficiently.
pub struct Registry<'params, F: PrimeField, R: Rank> {
    domain: Domain<F>,
    circuits: Vec<Box<dyn WiringObject<F, R> + 'params>>,

    /// Per-circuit floor plans computed during finalization.
    floor_plans: Vec<Vec<ConstraintSegment>>,

    /// Registry key used to bind circuits to this registry.
    key: Key<F>,
}

/// Cached Lagrange state for a fixed W point.
///
/// Distinguishes the kind of point the registry interpolation is being
/// evaluated at; see the [module overview](crate::registry).
enum LagrangeCache<F> {
    /// `w` is an arbitrary point, not one of the domain points the registry
    /// assigns wiring polynomials to. Holds the Lagrange coefficients used to
    /// evaluate the interpolation there.
    Arbitrary(Vec<F>),
    /// `w` is a domain point with a wiring polynomial explicitly registered at
    /// index `i`.
    Assigned(usize),
    /// `w` is a domain point with nothing explicitly registered; its wiring
    /// polynomial is implicitly the zero polynomial.
    Zero,
}

/// A registry bound to a specific W point, with cached Lagrange coefficients.
///
/// Created via [`Registry::at`]. All evaluation methods (`wx`, `wy`, `wxy`)
/// reuse the cached Lagrange coefficients, avoiding recomputation when
/// evaluating at multiple X/Y points.
pub struct RegistryAt<'a, F: PrimeField, R: Rank> {
    registry: &'a Registry<'a, F, R>,
    cache: LagrangeCache<F>,
    mask_coeff_sum: F,
}

impl<F: PrimeField, R: Rank> Registry<'_, F, R> {
    /// Assembles a [`Trace`](crate::Trace) into a [`sparse::Polynomial`] using
    /// the floor plan for the specified circuit.
    ///
    /// Calls [`assemble_with_alpha`](Self::assemble_with_alpha) with a
    /// random value sampled from `rng`.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`Registry::assemble_with_alpha`].
    pub fn assemble(
        &self,
        trace: &crate::trace::Trace<F>,
        circuit: CircuitIndex,
        rng: &mut impl ragu_arithmetic::rand::CryptoRng,
    ) -> Result<sparse::Polynomial<F, R>> {
        self.assemble_with_alpha(trace, circuit, F::random(rng))
    }

    /// Like [`assemble`](Self::assemble), but accepts an explicit
    /// `alpha` instead of sampling one from an RNG.
    ///
    /// `alpha` is written to `a[0]` of the assembled polynomial to
    /// prevent point-at-infinity commitments. The trace itself is never
    /// all-zero (the ONE wire at `d[0] = 1` ensures this), but the
    /// predictable ONE slot can cancel in linear combinations of traces;
    /// a random `alpha` at `a[0]` keeps derived polynomials non-zero.
    ///
    /// `circuit` indexes the registered circuits directly (for the floor plan)
    /// and **panics** if it is not a registered index. Unlike the
    /// polynomial-evaluation methods, this is the registered-`Vec` view; there
    /// is no implicit zero-polynomial slot here.
    ///
    /// # Errors
    ///
    /// Propagates any error from assembling the trace against the stored
    /// floor plan.
    pub fn assemble_with_alpha(
        &self,
        trace: &crate::trace::Trace<F>,
        circuit: CircuitIndex,
        alpha: F,
    ) -> Result<sparse::Polynomial<F, R>> {
        trace.assemble(&self.floor_plans[usize::from(circuit)], alpha)
    }

    /// Returns the registry digest value.
    ///
    /// This is the binding key computed during
    /// [`RegistryBuilder::finalize`] that ties each circuit's wiring
    /// polynomial to this registry.
    pub fn digest(&self) -> F {
        self.key.value()
    }

    /// Returns the number of circuits in this registry.
    pub fn num_circuits(&self) -> usize {
        self.circuits.len()
    }

    /// Converts between a domain position and its circuit index: circuit `i`
    /// is assigned to domain position `bitreverse(i)` over `log2_n` bits, and
    /// the map is its own inverse.
    fn bitreversed_index(&self, i: usize) -> usize {
        bitreverse(i as u32, self.domain.log2_n()) as usize
    }

    /// Evaluates the registry key contribution $k \cdot (XY)^{4n-1}$
    /// at $(x, y)$, returning a scalar.
    fn key_sxy(&self, x: F, y: F) -> F {
        if x == F::ZERO || y == F::ZERO {
            return F::ZERO;
        }
        let xy_4n_minus_1 = (x * y).pow_vartime([(4 * R::n() - 1) as u64]);
        self.key.value() * xy_4n_minus_1
    }

    /// Evaluate the registry polynomial unrestricted at $W$.
    ///
    /// Composed of [`wxy_over_domain`](Self::wxy_over_domain) followed by
    /// [`interpolate_xy`](Self::interpolate_xy). When a caller needs both
    /// representations, it can call those two methods directly to share a
    /// single per-circuit pass.
    pub fn xy(&self, x: F, y: F) -> sparse::Polynomial<F, R> {
        let evals = self.wxy_over_domain(x, y);
        self.interpolate_xy(evals)
    }

    /// Evaluate the registry polynomial at every element of its $W$-domain,
    /// returning $m(\omega^j, x, y)$ at index $j$ for $j \in [0, n)$, where
    /// $\omega$ generates the domain.
    ///
    /// Entries are indexed by domain position: circuit $i$'s evaluation lives
    /// at $j = \text{bitreverse}(i, \log\_2 n)$, the same point
    /// [`CircuitIndex::omega_j`] computes against the field's full $2^S$
    /// domain. Every entry includes the $W$-independent key term (positions
    /// with no registered circuit hold it alone), and masking circuits also
    /// carry the shared global term.
    pub fn wxy_over_domain(&self, x: F, y: F) -> Vec<F> {
        // The key term k * (XY)^{4n-1} has no W factor, so it adds the same
        // scalar to every domain evaluation.
        let key_scalar = self.key_sxy(x, y);
        let global_xy = crate::staging::mask::global_mask::<F, R>(x, y);

        let mut evals = alloc::vec![key_scalar; self.domain.n()];
        // Masking polynomials return only -notch from sxy(); add the shared
        // global term to each mask slot inline.
        for (i, circuit) in self.circuits.iter().enumerate() {
            let j = self.bitreversed_index(i);
            let mut v = circuit.sxy(x, y, &self.floor_plans[i]);
            if circuit.is_mask() {
                v += global_xy;
            }
            evals[j] += v;
        }
        evals
    }

    /// Interpolate the Lagrange-basis evaluations from
    /// [`wxy_over_domain`](Self::wxy_over_domain) into the monomial-basis
    /// polynomial $m(W, x, y)$ via an inverse FFT.
    ///
    /// `evals` is consumed and transformed in place by the inverse FFT before
    /// being compressed into sparse block form.
    ///
    /// # Panics
    ///
    /// Panics if `evals.len()` does not equal the registry's domain size.
    pub fn interpolate_xy(&self, mut evals: Vec<F>) -> sparse::Polynomial<F, R> {
        assert_eq!(evals.len(), self.domain.n());
        self.domain.ifft(&mut evals);
        sparse::Polynomial::from_coeffs(evals)
    }

    /// Returns $\log_2$ of the registry's $W$-domain size (the smallest power
    /// of two that fits all registered circuits).
    pub fn log2_domain(&self) -> u32 {
        self.domain.log2_n()
    }

    /// Index the $i$th circuit to field element $\omega^j$ as $w$, and evaluate
    /// the registry polynomial unrestricted at $X$.
    ///
    /// Wraps [`Registry::at`] and [`RegistryAt::y`].
    /// See [`CircuitIndex::omega_j`] for more details.
    ///
    /// Every domain point carries a wiring polynomial; an index with nothing
    /// explicitly registered carries the zero polynomial. See
    /// [`circuit_in_domain`](Self::circuit_in_domain).
    pub fn circuit_y(&self, i: CircuitIndex, y: F) -> sparse::Polynomial<F, R> {
        let w: F = i.omega_j();
        self.at(w).y(y)
    }

    /// Evaluates $s_i(x, y)$ for circuit `i` at point $(x, y)$.
    ///
    /// See [`CircuitIndex::omega_j`] for details on the $\omega^j$ mapping.
    ///
    /// As with [`circuit_y`](Self::circuit_y), an index with nothing explicitly
    /// registered carries the zero polynomial. See
    /// [`circuit_in_domain`](Self::circuit_in_domain).
    pub fn circuit_xy(&self, i: CircuitIndex, x: F, y: F) -> F {
        self.wxy(i.omega_j(), x, y)
    }

    /// Returns true if this index's $\omega^j$ value lies in the registry's
    /// domain.
    ///
    /// This reports domain membership, and nothing more. Every domain point is a
    /// wiring polynomial — a registered circuit, a registered bonding
    /// polynomial, or (at points left over when
    /// [`num_circuits`](Self::num_circuits) is not a power of two) the zero
    /// polynomial, which is itself a bonding polynomial. All are selected the
    /// same way by [`circuit_y`](Self::circuit_y) /
    /// [`circuit_xy`](Self::circuit_xy), so a `true` result means "in domain",
    /// not "a circuit is registered here".
    ///
    /// A caller expecting a circuit does not need it to mean more than that: it
    /// fixes $\mathbf{k}_0 = 1$, and no bonding polynomial ($s(X, 0) = 0$) can
    /// satisfy such a claim; see [`BondingObject`]. An index whose $\omega^j$
    /// falls *outside* the domain (returns `false`) escapes that argument — it
    /// evaluates the registry interpolation at an arbitrary point, mixing all
    /// domain points together.
    ///
    /// See [`CircuitIndex::omega_j`] for details on the $\omega^j$ mapping.
    pub fn circuit_in_domain(&self, i: CircuitIndex) -> bool {
        let w: F = i.omega_j();
        self.domain.contains(w)
    }

    /// Evaluate the registry polynomial unrestricted at $X$.
    pub fn wy(&self, w: F, y: F) -> sparse::Polynomial<F, R> {
        self.at(w).y(y)
    }

    /// Evaluate the registry polynomial unrestricted at $Y$.
    pub fn wx(&self, w: F, x: F) -> sparse::Polynomial<F, R> {
        self.at(w).x(x)
    }

    /// Evaluate the registry polynomial at the provided point.
    pub fn wxy(&self, w: F, x: F, y: F) -> F {
        self.at(w).xy(x, y)
    }

    /// Computes the polynomial restricted at $W$ based on the provided
    /// closures, using cached Lagrange coefficients.
    fn w_cached<T>(
        &self,
        cache: &LagrangeCache<F>,
        init: impl FnOnce() -> T,
        add_poly: impl Fn(&dyn WiringObject<F, R>, &[ConstraintSegment], F, &mut T),
    ) -> T {
        let mut result = init();

        match cache {
            LagrangeCache::Arbitrary(coeffs) => {
                // The provided `w` was not in the domain, and `coeffs` are the
                // coefficients we need to use to separate each (partial) circuit
                // evaluation.
                for (j, coeff) in coeffs.iter().enumerate() {
                    let i = self.bitreversed_index(j);
                    if let Some(circuit) = self.circuits.get(i) {
                        add_poly(&**circuit, &self.floor_plans[i], *coeff, &mut result);
                    }
                }
            }
            LagrangeCache::Assigned(i) => {
                if let Some(circuit) = self.circuits.get(*i) {
                    add_poly(&**circuit, &self.floor_plans[*i], F::ONE, &mut result);
                }
            }
            LagrangeCache::Zero => {
                // This domain point carries the zero polynomial, so it
                // contributes nothing. The registry key term is still added by
                // the caller (`RegistryAt` methods), so the evaluation is not
                // identically zero.
            }
        }

        result
    }

    /// Sums Lagrange coefficients for masking polynomials at the given $W$ point.
    ///
    /// Only circuits where [`WiringObject::is_mask`] returns `true` contribute.
    fn mask_coeff_sum(&self, cache: &LagrangeCache<F>) -> F {
        match cache {
            LagrangeCache::Arbitrary(coeffs) => {
                let mut sum = F::ZERO;
                for (i, circuit) in self.circuits.iter().enumerate() {
                    if circuit.is_mask() {
                        let j = self.bitreversed_index(i);
                        sum += coeffs[j];
                    }
                }
                sum
            }
            LagrangeCache::Assigned(i) => {
                // W is exactly omega^bitreverse(i), so the Lagrange
                // coefficient for circuit i is ONE and all others are ZERO.
                if self.circuits[*i].is_mask() {
                    F::ONE
                } else {
                    F::ZERO
                }
            }
            LagrangeCache::Zero => F::ZERO,
        }
    }

    /// Bind the registry to a specific $W$ point, caching Lagrange coefficients.
    ///
    /// Returns a [`RegistryAt`] that can be used to evaluate the registry
    /// polynomial at multiple $X$/$Y$ points without recomputing the W-restriction.
    pub fn at(&self, w: F) -> RegistryAt<'_, F, R> {
        let cache = match self.domain.lagrange_evals(w, self.domain.n()) {
            Ok(coeffs) => {
                // w is not a domain point; the Lagrange coefficients evaluate
                // the registry interpolation there.
                LagrangeCache::Arbitrary(coeffs)
            }
            Err(j) => {
                // w is the domain point omega^j. The i-th circuit is assigned
                // to omega^bitreverse(i) rather than omega^i — the domain-local
                // half of `CircuitIndex::omega_j`'s size-independent mapping,
                // which in effect *implicitly* performs domain extensions as
                // smaller domains become exhausted. Inverting that assignment,
                // the wiring polynomial registered at omega^j (if any) sits at
                // the bit-reversed index.
                let i = self.bitreversed_index(j);
                if i < self.circuits.len() {
                    LagrangeCache::Assigned(i)
                } else {
                    // w is a padded domain point with nothing explicitly
                    // registered; its wiring polynomial is implicitly the
                    // zero polynomial.
                    LagrangeCache::Zero
                }
            }
        };
        let mask_coeff_sum = self.mask_coeff_sum(&cache);
        RegistryAt {
            registry: self,
            cache,
            mask_coeff_sum,
        }
    }
}

impl<F: PrimeField, R: Rank> RegistryAt<'_, F, R> {
    /// Evaluate the registry polynomial restricted at $W$ and $Y$, unrestricted at $X$.
    pub fn y(&self, y: F) -> sparse::Polynomial<F, R> {
        let mut poly = self.registry.w_cached(
            &self.cache,
            sparse::Polynomial::default,
            |circuit, floor_plan, coeff, poly| {
                let mut tmp = circuit.sy(y, floor_plan);
                tmp.scale(coeff);
                poly.add_assign(&tmp);
            },
        );

        // Masking polynomials return only -notch; add the shared global once,
        // weighted by the sum of Lagrange coefficients for all mask circuits at W.
        let mut global = crate::staging::mask::global_project::<F, R>(y);
        global.scale(self.mask_coeff_sum);
        poly.add_assign(&global);

        // Add the registry key contribution k * (XY)^{4n-1}.  Restricted
        // at Y, this is k * y^{4n-1} at X^{4n-1} (c-wire of the SYSTEM gate in
        // the wiring layout).
        if y != F::ZERO {
            let y_4n_minus_1 = y.pow_vartime([(4 * R::n() - 1) as u64]);
            let mut key_view = sparse::View::<_, R, _>::wiring();
            key_view.c.push(self.registry.key.value() * y_4n_minus_1);
            poly.add_assign(&key_view.build());
        }

        poly
    }

    /// Evaluate the registry polynomial restricted at $W$ and $X$, unrestricted at $Y$.
    pub fn x(&self, x: F) -> sparse::Polynomial<F, R> {
        let mut poly = self.registry.w_cached(
            &self.cache,
            sparse::Polynomial::default,
            |circuit, floor_plan, coeff, poly| {
                let mut tmp = circuit.sx(x, floor_plan);
                tmp.scale(coeff);
                poly.add_assign(&tmp);
            },
        );

        // Masking polynomials return only -notch; add the shared global once,
        // weighted by the sum of Lagrange coefficients for all mask circuits at W.
        let mut global = crate::staging::mask::global_project::<F, R>(x);
        global.scale(self.mask_coeff_sum);
        poly.add_assign(&global);

        // Add the registry key contribution k * (XY)^{4n-1}.  Restricted
        // at X, this is k * x^{4n-1} at Y^{4n-1}.
        if x != F::ZERO {
            let x_4n_minus_1 = x.pow_vartime([(4 * R::n() - 1) as u64]);
            let key_coeff = self.registry.key.value() * x_4n_minus_1;
            let mut key_coeffs = alloc::vec![F::ZERO; R::num_coeffs()];
            // Y^{4n-1} is the last coefficient (index num_coeffs() - 1 = 4n - 1),
            // the slot reserved by circuit-level bounds checks.
            key_coeffs[R::num_coeffs() - 1] = key_coeff;
            poly.add_assign(&sparse::Polynomial::from_coeffs(key_coeffs));
        }

        poly
    }

    /// Evaluate the registry polynomial at the point ($W$, $X$, $Y$).
    pub fn xy(&self, x: F, y: F) -> F {
        let mut result: F = self.registry.w_cached(
            &self.cache,
            || F::ZERO,
            |circuit, floor_plan, coeff, result| {
                *result += circuit.sxy(x, y, floor_plan) * coeff;
            },
        );

        // Masking polynomials return only -notch; apply the shared global
        // scalar once.
        result += self.mask_coeff_sum * crate::staging::mask::global_mask::<F, R>(x, y);

        // Add the registry key contribution.
        result + self.registry.key_sxy(x, y)
    }
}

impl<F: FromUniformBytes<64>, R: Rank> Registry<'_, F, R> {
    /// Compute a digest of this registry using BLAKE2b.
    fn compute_registry_digest(&self) -> F {
        let mut hasher = Params::new().personal(b"ragu_registry___").to_state();

        let field_from_hash = |digest_state: &blake2b_simd::Hash, index: u8| {
            F::from_uniform_bytes(
                Params::new()
                    .personal(b"ragu_registry___")
                    .to_state()
                    .update(digest_state.as_bytes())
                    .update(&[index])
                    .finalize()
                    .as_array(),
            )
        };

        // Placeholder "nothing-up-my-sleeve challenges" (small primes).
        let mut w = F::from(2u64);
        let mut x = F::from(3u64);
        let mut y = F::from(5u64);

        // FIXME(security): 6 iterations is insufficient to fully bind the registry
        // polynomial. This should be increased to a value that overdetermines the
        // polynomial (exceeds the degrees of freedom an adversary could exploit).
        // Currently limited by registry evaluation performance; See #78 and #316.
        for _ in 0..6 {
            let eval = self.wxy(w, x, y);
            hasher.update(eval.to_repr().as_ref());

            let digest_state = hasher.finalize();
            w = field_from_hash(&digest_state, 0);
            x = field_from_hash(&digest_state, 1);
            y = field_from_hash(&digest_state, 2);

            hasher = Params::new().personal(b"ragu_registry___").to_state();
            hasher.update(digest_state.as_bytes());
        }

        field_from_hash(&hasher.finalize(), 0)
    }
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::{
        Domain, bitreverse,
        ff::{Field, PrimeField},
    };
    use ragu_core::Result;
    use ragu_pasta::Fp;

    use super::{CircuitIndex, RegistryBuilder};
    use crate::{polynomials::TestRank, tests::SquareCircuit};
    type TestRegistryBuilder<'a> = RegistryBuilder<'a, Fp, TestRank>;

    #[test]
    fn test_omega_j_multiplicative_order() {
        /// Return the 2^k multiplicative order of f (assumes f is a 2^k root of unity).
        fn order<F: Field>(mut f: F) -> usize {
            let mut order = 0;
            while f != F::ONE {
                f = f.square();
                order += 1;
            }
            1 << order
        }
        assert_eq!(CircuitIndex::new(0).omega_j::<Fp>(), Fp::ONE);
        assert_eq!(CircuitIndex::new(1).omega_j::<Fp>(), -Fp::ONE);
        assert_eq!(order(CircuitIndex::new(0).omega_j::<Fp>()), 1);
        assert_eq!(order(CircuitIndex::new(1).omega_j::<Fp>()), 2);
        assert_eq!(order(CircuitIndex::new(2).omega_j::<Fp>()), 4);
        assert_eq!(order(CircuitIndex::new(3).omega_j::<Fp>()), 4);
        assert_eq!(order(CircuitIndex::new(4).omega_j::<Fp>()), 8);
        assert_eq!(order(CircuitIndex::new(5).omega_j::<Fp>()), 8);
        assert_eq!(order(CircuitIndex::new(6).omega_j::<Fp>()), 8);
        assert_eq!(order(CircuitIndex::new(7).omega_j::<Fp>()), 8);
    }

    #[test]
    fn test_registry_circuit_consistency() -> Result<()> {
        let registry = TestRegistryBuilder::new()
            .register_circuit(SquareCircuit { times: 2 })?
            .register_circuit(SquareCircuit { times: 5 })?
            .register_circuit(SquareCircuit { times: 10 })?
            .register_circuit(SquareCircuit { times: 11 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .finalize()?;

        let w = Fp::random(&mut ragu_arithmetic::rand::rng());
        let x = Fp::random(&mut ragu_arithmetic::rand::rng());
        let y = Fp::random(&mut ragu_arithmetic::rand::rng());

        let xy_poly = registry.xy(x, y);
        let wy_poly = registry.wy(w, y);
        let wx_poly = registry.wx(w, x);

        let wxy_value = registry.wxy(w, x, y);

        assert_eq!(wxy_value, xy_poly.eval(w));
        assert_eq!(wxy_value, wy_poly.eval(x));
        assert_eq!(wxy_value, wx_poly.eval(y));

        let mut w = Fp::ONE;
        for _ in 0..registry.domain.n() {
            let xy_poly = registry.xy(x, y);
            let wy_poly = registry.wy(w, y);
            let wx_poly = registry.wx(w, x);

            let wxy_value = registry.wxy(w, x, y);

            assert_eq!(wxy_value, xy_poly.eval(w));
            assert_eq!(wxy_value, wy_poly.eval(x));
            assert_eq!(wxy_value, wx_poly.eval(y));

            w *= registry.domain.omega();
        }

        Ok(())
    }

    #[test]
    fn test_wxy_over_domain_consistency() -> Result<()> {
        // Use a non-power-of-two count so the domain has zero-padded slots.
        let registry = TestRegistryBuilder::new()
            .register_circuit(SquareCircuit { times: 2 })?
            .register_circuit(SquareCircuit { times: 5 })?
            .register_circuit(SquareCircuit { times: 10 })?
            .register_circuit(SquareCircuit { times: 11 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .finalize()?;

        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        let evals = registry.wxy_over_domain(x, y);
        let poly = registry.xy(x, y);

        assert_eq!(evals.len(), registry.domain.n());

        // evals[j] must equal m(omega^j, x, y) = poly.eval(omega^j).
        let mut omega_pow = Fp::ONE;
        for (j, eval) in evals.iter().enumerate() {
            assert_eq!(
                *eval,
                poly.eval(omega_pow),
                "evals[{j}] should equal poly.eval(omega^{j})"
            );
            omega_pow *= registry.domain.omega();
        }

        // For each registered circuit i, its evaluation at omega_j(i) lives
        // at the bit-reversed domain position.
        let log2_n = registry.log2_domain();
        for i in 0..registry.num_circuits() {
            let j = bitreverse(i as u32, log2_n) as usize;
            let omega_j = CircuitIndex::new(i).omega_j::<Fp>();
            assert_eq!(evals[j], poly.eval(omega_j));
        }

        // interpolate_xy must agree with `wxy`, which reaches the same value
        // through the independent Lagrange-cache path. Comparing against
        // `poly` here would be vacuous: `xy` is defined as exactly this
        // composition, so such an assertion could never fail.
        let interpolated = registry.interpolate_xy(evals);
        for _ in 0..4 {
            let probe = Fp::random(&mut rand::rng());
            assert_eq!(interpolated.eval(probe), registry.wxy(probe, x, y));
        }

        Ok(())
    }

    #[test]
    fn test_registry_at_consistency() -> Result<()> {
        let registry = TestRegistryBuilder::new()
            .register_circuit(SquareCircuit { times: 2 })?
            .register_circuit(SquareCircuit { times: 5 })?
            .register_circuit(SquareCircuit { times: 10 })?
            .register_circuit(SquareCircuit { times: 11 })?
            .finalize()?;

        let w = Fp::random(&mut ragu_arithmetic::rand::rng());
        let x = Fp::random(&mut ragu_arithmetic::rand::rng());
        let y = Fp::random(&mut ragu_arithmetic::rand::rng());
        let eval_point = Fp::random(&mut ragu_arithmetic::rand::rng());

        let registry_at_w = registry.at(w);

        assert_eq!(
            registry_at_w.x(x).eval(eval_point),
            registry.wx(w, x).eval(eval_point)
        );
        assert_eq!(
            registry_at_w.y(y).eval(eval_point),
            registry.wy(w, y).eval(eval_point)
        );
        assert_eq!(registry_at_w.xy(x, y), registry.wxy(w, x, y));

        // Test with w in domain (omega^j)
        let w_in_domain = registry.domain.omega();
        let registry_at_w_in_domain = registry.at(w_in_domain);

        assert_eq!(
            registry_at_w_in_domain.x(x).eval(eval_point),
            registry.wx(w_in_domain, x).eval(eval_point)
        );
        assert_eq!(
            registry_at_w_in_domain.y(y).eval(eval_point),
            registry.wy(w_in_domain, y).eval(eval_point)
        );
        assert_eq!(
            registry_at_w_in_domain.xy(x, y),
            registry.wxy(w_in_domain, x, y)
        );

        Ok(())
    }

    #[test]
    fn test_out_of_domain_w_uses_interpolation() -> Result<()> {
        let registry = TestRegistryBuilder::new()
            .register_circuit(SquareCircuit { times: 2 })?
            .register_circuit(SquareCircuit { times: 5 })?
            .finalize()?;

        let omega = registry.domain.omega();

        // This isn't in the domain.
        let w = omega + Fp::ONE;

        let x = Fp::from(42u64);
        let y = Fp::from(43u64);
        assert_ne!(registry.at(w).xy(x, y), registry.at(omega).xy(x, y));

        Ok(())
    }

    #[test]
    fn test_all_domain_points_match_interpolation_non_pow2() -> Result<()> {
        // 5 circuits pad the domain to size 8; indices 5..8 carry the zero
        // polynomial. Every domain point — registered (`Assigned` fast path)
        // and padded (`Zero` fast path) — must agree with the interpolation
        // evaluated there, key term included.
        let mut builder = TestRegistryBuilder::new();
        for i in 1..=5 {
            builder = builder.register_circuit(SquareCircuit { times: i })?;
        }
        let registry = builder.finalize()?;
        assert_eq!(registry.domain.n(), 8);

        let x = Fp::random(&mut ragu_arithmetic::rand::rng());
        let y = Fp::random(&mut ragu_arithmetic::rand::rng());
        let xy_poly = registry.xy(x, y);

        let mut w = Fp::ONE;
        for _ in 0..registry.domain.n() {
            assert_eq!(registry.wxy(w, x, y), xy_poly.eval(w));
            w *= registry.domain.omega();
        }

        Ok(())
    }

    #[test]
    fn test_single_circuit_registry() -> Result<()> {
        // Checks that a single circuit can be finalized without bit-shift overflows.
        let _registry = TestRegistryBuilder::new()
            .register_circuit(SquareCircuit { times: 1 })?
            .finalize()?;

        Ok(())
    }

    #[test]
    fn test_omega_j_consistency() -> Result<()> {
        for num_circuits in [2usize, 3, 7, 8, 15, 16, 32] {
            let log2_circuits = num_circuits.next_power_of_two().trailing_zeros();
            let domain = Domain::<Fp>::new(log2_circuits);

            for id in 0..num_circuits {
                let omega_from_function = CircuitIndex::new(id).omega_j::<Fp>();

                let bit_reversal_id = bitreverse(id as u32, Fp::S);
                let position = ((bit_reversal_id as u64) >> (Fp::S - log2_circuits)) as usize;
                let omega_from_finalization = domain.omega().pow([position as u64]);

                assert_eq!(
                    omega_from_function, omega_from_finalization,
                    "Omega mismatch for circuit {} in registry of size {}",
                    id, num_circuits
                );
            }
        }

        Ok(())
    }

    #[test]
    fn test_non_power_of_two_registry_sizes() -> Result<()> {
        for num_circuits in 0..21 {
            let mut builder = TestRegistryBuilder::new();

            for i in 0..num_circuits {
                builder = builder.register_circuit(SquareCircuit { times: i })?;
            }

            let registry = builder.finalize()?;

            // Verify domain size is next power of 2
            let expected_domain_size = num_circuits.next_power_of_two();
            assert_eq!(registry.domain.n(), expected_domain_size);

            let w = Fp::random(&mut ragu_arithmetic::rand::rng());
            let x = Fp::random(&mut ragu_arithmetic::rand::rng());
            let y = Fp::random(&mut ragu_arithmetic::rand::rng());

            let wxy = registry.wxy(w, x, y);
            let xy = registry.xy(x, y);
            assert_eq!(wxy, xy.eval(w), "Failed for num_circuits={}", num_circuits);
        }

        Ok(())
    }

    #[test]
    fn test_circuit_in_domain() -> Result<()> {
        let registry = TestRegistryBuilder::new()
            .register_circuit(SquareCircuit { times: 2 })?
            .register_circuit(SquareCircuit { times: 5 })?
            .register_circuit(SquareCircuit { times: 10 })?
            .register_circuit(SquareCircuit { times: 11 })?
            .finalize()?;

        // All registered circuit indices should be in the domain
        for i in 0..4 {
            assert!(
                registry.circuit_in_domain(CircuitIndex::new(i)),
                "Circuit {} should be in domain",
                i
            );
        }

        // Indices beyond the domain size should not be in the domain
        // The registry has 4 circuits, so domain size is 4 (2^2)
        // CircuitIndex::omega_j uses F::S-bit reversal, which maps indices
        // beyond the domain to non-domain elements
        for i in [1 << 16, 1 << 20, 1 << 30] {
            assert!(
                !registry.circuit_in_domain(CircuitIndex::new(i)),
                "Circuit {} should not be in domain",
                i
            );
        }

        Ok(())
    }

    /// A registry whose circuit count is not a power of two has padded domain
    /// points with nothing explicitly registered. Such an index is *in the
    /// domain* yet carries the zero polynomial, which has $s(X, 0) = 0$ and is
    /// therefore a bonding polynomial, unlike a registered circuit whose
    /// $s(X, 0) = 1$. That is what makes an unregistered in-domain id safe: a
    /// verifier expecting a circuit fixes $\mathbf{k}_0 = 1$, which no bonding
    /// polynomial can satisfy.
    #[test]
    fn test_padded_slot_is_zero_wiring_polynomial() -> Result<()> {
        // 3 circuits => domain size 4 (next power of two), so index 3 is a
        // padded, in-domain, unregistered slot.
        let registry = TestRegistryBuilder::new()
            .register_circuit(SquareCircuit { times: 1 })?
            .register_circuit(SquareCircuit { times: 2 })?
            .register_circuit(SquareCircuit { times: 3 })?
            .finalize()?;

        assert_eq!(registry.num_circuits(), 3);

        let registered = CircuitIndex::new(0);
        let padded = CircuitIndex::new(3);

        // The padded index is past the registered range but still in the domain.
        assert!(usize::from(padded) >= registry.num_circuits());
        assert!(registry.circuit_in_domain(padded));

        // s(X, 0) distinguishes the two: a bonding polynomial has s(X, 0) = 0,
        // whereas a circuit wiring polynomial has s(X, 0) = 1.
        let s_padded = registry.circuit_y(padded, Fp::ZERO);
        let s_registered = registry.circuit_y(registered, Fp::ZERO);
        for x in [Fp::from(7u64), Fp::from(11u64)] {
            assert_eq!(
                s_padded.eval(x),
                Fp::ZERO,
                "padded slot must carry the zero polynomial"
            );
            assert_eq!(
                s_registered.eval(x),
                Fp::ONE,
                "registered circuit must have s(X, 0) = 1"
            );
        }

        Ok(())
    }

    #[test]
    fn test_registry_with_internal_circuits() -> Result<()> {
        // Create a builder
        let builder = TestRegistryBuilder::new();

        // Verify initial state - no circuits registered yet
        assert_eq!(
            builder.num_circuits(),
            0,
            "should start with 0 registered circuits"
        );
        assert_eq!(
            builder.num_internal_circuits(),
            0,
            "no internal circuits registered yet"
        );

        // Register 2 internal circuits
        let builder = builder
            .register_internal_circuit(SquareCircuit { times: 2 })?
            .register_internal_circuit(SquareCircuit { times: 3 })?;

        assert_eq!(
            builder.num_internal_circuits(),
            2,
            "2 internal circuits registered"
        );
        assert_eq!(builder.num_circuits(), 2, "2 total registered circuits");

        // Register 2 application steps
        let builder = builder
            .register_circuit(SquareCircuit { times: 4 })?
            .register_circuit(SquareCircuit { times: 5 })?;

        assert_eq!(
            builder.num_internal_circuits(),
            2,
            "still 2 internal circuits"
        );
        assert_eq!(
            builder.num_circuits(),
            4,
            "now 4 total registered circuits (2 internal + 2 application)"
        );

        // Finalize the registry
        let registry = builder.finalize()?;
        assert_eq!(registry.num_circuits(), 4);

        Ok(())
    }

    #[test]
    fn test_internal_mixed_registration() -> Result<()> {
        // Test circuit count with sequential registration
        let registry = TestRegistryBuilder::new()
            .register_internal_circuit(SquareCircuit { times: 1 })?
            .register_internal_circuit(SquareCircuit { times: 2 })?
            .register_circuit(SquareCircuit { times: 3 })?
            .register_circuit(SquareCircuit { times: 4 })?
            .finalize()?;

        assert_eq!(registry.num_circuits(), 4);

        // Test circuit count with interleaved registration
        let registry2 = TestRegistryBuilder::new()
            .register_circuit(SquareCircuit { times: 3 })?
            .register_internal_circuit(SquareCircuit { times: 1 })?
            .register_circuit(SquareCircuit { times: 4 })?
            .register_internal_circuit(SquareCircuit { times: 2 })?
            .finalize()?;

        assert_eq!(registry2.num_circuits(), 4);

        Ok(())
    }

    #[test]
    fn test_registry_with_internal_steps() -> Result<()> {
        let builder = TestRegistryBuilder::new()
            .register_internal_circuit(SquareCircuit { times: 1 })?
            .register_internal_circuit(SquareCircuit { times: 2 })?
            .register_internal_step(SquareCircuit { times: 3 })?
            .register_internal_step(SquareCircuit { times: 4 })?
            .register_circuit(SquareCircuit { times: 5 })?;

        // num_internal_circuits counts masks + circuits only (not steps)
        assert_eq!(builder.num_internal_circuits(), 2);
        // num_circuits counts all categories
        assert_eq!(builder.num_circuits(), 5);

        let registry = builder.finalize()?;
        assert_eq!(registry.num_circuits(), 5);

        // Verify evaluation consistency
        let w = Fp::random(&mut ragu_arithmetic::rand::rng());
        let x = Fp::random(&mut ragu_arithmetic::rand::rng());
        let y = Fp::random(&mut ragu_arithmetic::rand::rng());

        let wxy = registry.wxy(w, x, y);
        let xy = registry.xy(x, y);
        assert_eq!(wxy, xy.eval(w));

        Ok(())
    }
}
