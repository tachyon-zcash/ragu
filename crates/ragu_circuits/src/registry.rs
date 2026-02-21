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
//! to encode all circuits for both PCD and for application circuits.
//!
//! The [`RegistryBuilder`] structure is used to construct a new [`Registry`] by
//! inserting circuits and performing a [`finalize`](RegistryBuilder::finalize) step
//! to compile the added circuits into a registry polynomial representation that can
//! be efficiently evaluated at different restrictions.

use blake2b_simd::Params;
use ff::{Field, FromUniformBytes, PrimeField};
use ragu_arithmetic::{Domain, bitreverse};
use ragu_core::{Error, Result};

use alloc::{boxed::Box, collections::btree_map::BTreeMap, vec::Vec};

use crate::{
    Circuit, CircuitExt, CircuitObject,
    floor_plan::FloorPlan,
    floor_planner::RoutineSlot,
    polynomials::{Rank, structured, unstructured},
    routines::RoutineRegistry,
    s::MemoCache,
    staging::{Stage, StageExt},
};

/// Represents a simple numeric index of a circuit in the registry.
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
/// Circuits are organized into three categories:
/// - Internal masks: stage masks and final masks for internal stages
/// - Internal circuits: system circuits and internal steps
/// - Application steps: user-defined application step circuits
///
/// During finalization, circuits are concatenated in registration order,
/// ensuring internal masks can be optimized separately from circuits
/// while maintaining proper PCD indexing.
pub struct RegistryBuilder<'params, F: PrimeField, R: Rank> {
    internal_masks: Vec<Box<dyn CircuitObject<F, R> + 'params>>,
    internal_circuits: Vec<Box<dyn CircuitObject<F, R> + 'params>>,
    application_steps: Vec<Box<dyn CircuitObject<F, R> + 'params>>,
    /// Routine registries for each category, chained in finalize() to match circuit order.
    internal_mask_registries: Vec<RoutineRegistry>,
    internal_circuit_registries: Vec<RoutineRegistry>,
    application_registries: Vec<RoutineRegistry>,
}

impl<F: PrimeField, R: Rank> Default for RegistryBuilder<'_, F, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, F: PrimeField, R: Rank> RegistryBuilder<'params, F, R> {
    /// Creates a new empty [`Registry`] builder.
    pub fn new() -> Self {
        Self {
            internal_masks: Vec::new(),
            internal_circuits: Vec::new(),
            application_steps: Vec::new(),
            internal_mask_registries: Vec::new(),
            internal_circuit_registries: Vec::new(),
            application_registries: Vec::new(),
        }
    }

    /// Returns the number of internal circuits (masks + circuits).
    pub fn num_internal_circuits(&self) -> usize {
        self.internal_masks.len() + self.internal_circuits.len()
    }

    /// Returns the total number of circuits across all categories.
    pub fn num_circuits(&self) -> usize {
        self.num_internal_circuits() + self.application_steps.len()
    }

    /// Returns the log2 of the smallest power-of-2 domain size that fits all circuits.
    pub fn log2_circuits(&self) -> u32 {
        self.num_circuits().next_power_of_two().trailing_zeros()
    }

    /// Registers an application step circuit.
    pub fn register_circuit<C>(self, circuit: C) -> Result<Self>
    where
        C: Circuit<F> + 'params,
    {
        self.register_circuit_with_registry(circuit, RoutineRegistry::new())
    }

    /// Registers an application step circuit with its routine registry for floor planning.
    pub fn register_circuit_with_registry<C>(
        mut self,
        circuit: C,
        routine_registry: RoutineRegistry,
    ) -> Result<Self>
    where
        C: Circuit<F> + 'params,
    {
        self.application_steps.push(circuit.into_object()?);
        self.application_registries.push(routine_registry);
        Ok(self)
    }

    /// Registers an internal circuit.
    pub fn register_internal_circuit<C>(self, circuit: C) -> Result<Self>
    where
        C: Circuit<F> + 'params,
    {
        self.register_internal_circuit_with_registry(circuit, RoutineRegistry::new())
    }

    /// Registers an internal circuit with its routine registry for floor planning.
    pub fn register_internal_circuit_with_registry<C>(
        mut self,
        circuit: C,
        routine_registry: RoutineRegistry,
    ) -> Result<Self>
    where
        C: Circuit<F> + 'params,
    {
        self.internal_circuits.push(circuit.into_object()?);
        self.internal_circuit_registries.push(routine_registry);
        Ok(self)
    }

    /// Registers an internal stage mask.
    pub fn register_internal_mask<S>(mut self) -> Result<Self>
    where
        S: Stage<F, R>,
    {
        self.internal_masks.push(S::mask()?);
        self.internal_mask_registries.push(RoutineRegistry::new());
        Ok(self)
    }

    /// Registers an internal final stage mask.
    pub fn register_internal_final_mask<S>(mut self) -> Result<Self>
    where
        S: Stage<F, R>,
    {
        self.internal_masks.push(S::final_mask()?);
        self.internal_mask_registries.push(RoutineRegistry::new());
        Ok(self)
    }

    /// Builds the [`Registry`].
    ///
    /// Circuits are concatenated in the following order for proper indexing:
    /// 1. Internal masks: Stage enforcement masks and final masks
    /// 2. Internal circuits: System circuits and internal steps
    /// 3. Application steps: User-defined step circuits
    ///
    /// This ordering ensures internal masks can be optimized separately while
    /// maintaining proper PCD indexing where internal items occupy indices
    /// $0 \ldots N$ and application steps occupy indices $N$ onward.
    pub fn finalize(self) -> Result<Registry<'params, F, R>>
    where
        F: FromUniformBytes<64>,
    {
        let total_circuits = self.num_circuits();
        if total_circuits > R::num_coeffs() {
            return Err(Error::CircuitBoundExceeded(total_circuits));
        }

        let log2_circuits = self.log2_circuits();
        let domain = Domain::<F>::new(log2_circuits);

        let circuits: Vec<_> = self
            .internal_masks
            .into_iter()
            .chain(self.internal_circuits)
            .chain(self.application_steps)
            .collect();

        // Compute floor plans for each circuit.
        let floor_plans: Vec<Vec<RoutineSlot>> = circuits
            .iter()
            .map(|circuit| crate::floor_planner::floor_plan(circuit.routine_records()))
            .collect();

        // Build omega^j -> i lookup table.
        let mut omega_lookup = BTreeMap::new();

        for i in 0..circuits.len() {
            // Rather than assigning the `i`th circuit to `omega^i` in the final
            // domain, we will assign it to `omega^j` where `j` is the
            // `log2_circuits` bit-reversal of `i`. This has the property that
            // `omega^j` = `F::ROOT_OF_UNITY^m` where `m` is the `F::S` bit
            // reversal of `i`, which can be computed independently of `omega`
            // and the actual (ideal) choice of `log2_circuits`. In effect, this
            // is *implicitly* performing domain extensions as smaller domains
            // become exhausted.
            let j = bitreverse(i as u32, log2_circuits) as usize;
            let omega_j = OmegaKey::from(domain.omega().pow([j as u64]));
            omega_lookup.insert(omega_j, i);
        }

        // Compute type-based floor plan from routine registries for inter-circuit memoization.
        let routine_registries: Vec<RoutineRegistry> = self
            .internal_mask_registries
            .into_iter()
            .chain(self.internal_circuit_registries)
            .chain(self.application_registries)
            .collect();
        let registry_refs: Vec<&RoutineRegistry> = routine_registries.iter().collect();
        let type_floor_plan = FloorPlan::from_registries(&registry_refs, R::n());

        // Create provisional registry (circuits still have placeholder K)
        let mut registry = Registry {
            domain,
            circuits,
            floor_plans,
            type_floor_plan,
            omega_lookup,
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
/// Concretely, we retroactively inject the registry key into each member circuit
/// of `m` as a special wire `key_wire`, enforced by a simple linear constraint
/// `key_wire = k`. This binds each circuit's wiring polynomial to the registry
/// polynomial, and thus the entire registry polynomial to the Fiat-Shamir
/// transcript without self-reference. The key randomizes the wiring polynomial
/// directly.
///
/// The key is computed during [`RegistryBuilder::finalize`] and used during
/// polynomial evaluations of [`CircuitObject`].
///
/// [#78]: https://github.com/tachyon-zcash/ragu/issues/78
/// [`CircuitObject`]: crate::CircuitObject
pub struct Key<F: Field> {
    /// Registry digest value
    val: F,
    /// Cached inverse of digest
    inv: F,
}

impl<F: Field> Default for Key<F> {
    fn default() -> Self {
        Self::new(F::ONE)
    }
}

impl<F: Field> Key<F> {
    /// Creates a new registry key from a field element, panic if zero.
    pub fn new(val: F) -> Self {
        let inv = val.invert().expect("registry digest should never be zero");
        Self { val, inv }
    }

    /// Returns the registry key value.
    pub fn value(&self) -> F {
        self.val
    }

    /// Returns the cached inverse of the registry key.
    pub fn inverse(&self) -> F {
        self.inv
    }
}

/// Represents a collection of circuits over a particular field, some of which
/// may make reference to the others or be executed in similar contexts. The
/// circuits are combined together using an interpolation polynomial so that
/// they can be queried efficiently.
pub struct Registry<'params, F: PrimeField, R: Rank> {
    domain: Domain<F>,
    circuits: Vec<Box<dyn CircuitObject<F, R> + 'params>>,

    /// Per-circuit floor plans computed during finalization (DFS-based positioning).
    floor_plans: Vec<Vec<RoutineSlot>>,

    /// Type-based floor plan for inter-circuit memoization.
    type_floor_plan: FloorPlan,

    /// Maps from the OmegaKey (which represents some `omega^j`) to the index `i`
    /// of the circuits vector.
    omega_lookup: BTreeMap<OmegaKey, usize>,

    /// Registry key used to bind circuits to this registry.
    key: Key<F>,
}

/// Represents a key for identifying a unique $\omega^j$ value where $\omega$ is
/// a $2^k$-th root of unity.
#[derive(Ord, PartialOrd, PartialEq, Eq)]
struct OmegaKey(u64);

impl<F: PrimeField> From<F> for OmegaKey {
    fn from(f: F) -> Self {
        // Multiplication by 5 ensures the least significant 64 bits of the
        // field element can be used as a key for all elements of order 2^k.
        // TODO: This only holds for the Pasta curves. See issue #51
        let product = f.double().double() + f;

        let bytes = product.to_repr();
        let byte_slice = bytes.as_ref();

        OmegaKey(u64::from_le_bytes(
            byte_slice[..8]
                .try_into()
                .expect("field representation is at least 8 bytes"),
        ))
    }
}

impl<F: PrimeField, R: Rank> Registry<'_, F, R> {
    /// Assembles a [`Trace`](crate::Trace) into a [`structured::Polynomial`] using
    /// this registry's key and the floor plan for the specified circuit.
    pub fn assemble(
        &self,
        trace: &crate::rx::Trace<F>,
        circuit: CircuitIndex,
    ) -> Result<structured::Polynomial<F, R>> {
        trace.assemble_with_key(&self.key, &self.floor_plans[usize::from(circuit)])
    }

    /// Returns the registry digest value.
    ///
    /// This is the binding key computed during
    /// [`RegistryBuilder::finalize`] that ties each circuit's wiring
    /// polynomial to this registry.
    pub fn digest(&self) -> F {
        self.key.value()
    }

    /// Returns a slice of the circuit objects in this registry.
    pub fn circuits(&self) -> &[Box<dyn CircuitObject<F, R> + '_>] {
        &self.circuits
    }

    /// Returns the type-based floor plan for inter-circuit memoization.
    pub fn type_floor_plan(&self) -> &FloorPlan {
        &self.type_floor_plan
    }

    /// Evaluate the registry polynomial unrestricted at $W$.
    pub fn xy(&self, x: F, y: F) -> unstructured::Polynomial<F, R> {
        let mut coeffs = unstructured::Polynomial::default();
        for (i, circuit) in self.circuits.iter().enumerate() {
            let j = bitreverse(i as u32, self.domain.log2_n()) as usize;
            coeffs[j] = circuit.sxy(x, y, &self.key, &self.floor_plans[i]);
        }
        // Convert from the Lagrange basis.
        let domain = &self.domain;
        domain.ifft(&mut coeffs[..domain.n()]);

        coeffs
    }

    /// Index the $i$th circuit to field element $\omega^j$ as $w$, and evaluate
    /// the registry polynomial unrestricted at $X$.
    ///
    /// Wraps [`Registry::wy`]. See [`CircuitIndex::omega_j`] for more details.
    pub fn circuit_y(&self, i: CircuitIndex, y: F) -> structured::Polynomial<F, R> {
        let w: F = i.omega_j();
        self.wy(w, y)
    }

    /// Returns true if the circuit's $\omega^j$ value is in the registry domain.
    ///
    /// See [`CircuitIndex::omega_j`] for details on the $\omega^j$ mapping.
    pub fn circuit_in_domain(&self, i: CircuitIndex) -> bool {
        let w: F = i.omega_j();
        self.domain.contains(w)
    }

    /// Evaluate the registry polynomial unrestricted at $X$.
    pub fn wy(&self, w: F, y: F) -> structured::Polynomial<F, R> {
        self.w(
            w,
            structured::Polynomial::default,
            |circuit, floor_plan, circuit_coeff, poly| {
                let mut tmp = circuit.sy(y, &self.key, floor_plan);
                tmp.scale(circuit_coeff);
                poly.add_assign(&tmp);
            },
        )
    }

    /// Evaluate the registry polynomial unrestricted at $Y$.
    pub fn wx(&self, w: F, x: F) -> unstructured::Polynomial<F, R> {
        self.w(
            w,
            unstructured::Polynomial::default,
            |circuit, floor_plan, circuit_coeff, poly| {
                let mut tmp = circuit.sx(x, &self.key, floor_plan);
                tmp.scale(circuit_coeff);
                poly.add_unstructured(&tmp);
            },
        )
    }

    /// Evaluate the registry polynomial at the provided point.
    pub fn wxy(&self, w: F, x: F, y: F) -> F {
        self.w(
            w,
            || F::ZERO,
            |circuit, floor_plan, circuit_coeff, poly| {
                *poly += circuit.sxy(x, y, &self.key, floor_plan) * circuit_coeff;
            },
        )
    }

    /// Evaluates the registry polynomial with inter-circuit memoization.
    ///
    /// Routines at the same canonical position share cached contributions
    /// across circuits during Lagrange interpolation. Result is identical
    /// to [`wxy`](Self::wxy).
    pub fn wxy_combined(&self, w: F, x: F, y: F) -> F {
        let ell = self.domain.ell(w, self.domain.n());

        let mut result = F::ZERO;

        if let Some(ell) = ell {
            // Lagrange interpolation with shared cache
            let mut cache = MemoCache::new();

            for (j, coeff) in ell.iter().enumerate() {
                let i = bitreverse(j as u32, self.domain.log2_n()) as usize;
                if let Some(circuit) = self.circuits.get(i) {
                    let sxy = circuit.sxy_with_cache(
                        x,
                        y,
                        &self.key,
                        &self.floor_plans[i],
                        &self.type_floor_plan,
                        &mut cache,
                    );
                    result += sxy * coeff;
                }
            }
        } else if let Some(i) = self.omega_lookup.get(&OmegaKey::from(w)) {
            // w in domain: single circuit, no memoization benefit
            if let Some(circuit) = self.circuits.get(*i) {
                result = circuit.sxy(x, y, &self.key, &self.floor_plans[*i]);
            }
        }

        result
    }

    /// Computes the polynomial restricted at $W$ based on the provided
    /// closures.
    fn w<T>(
        &self,
        w: F,
        init: impl FnOnce() -> T,
        add_poly: impl Fn(&dyn CircuitObject<F, R>, &[RoutineSlot], F, &mut T),
    ) -> T {
        // Compute the Lagrange coefficients for the provided `w`.
        let ell = self.domain.ell(w, self.domain.n());

        let mut result = init();

        if let Some(ell) = ell {
            // The provided `w` was not in the domain, and `ell` are the
            // coefficients we need to use to separate each (partial) circuit
            // evaluation.
            for (j, coeff) in ell.iter().enumerate() {
                let i = bitreverse(j as u32, self.domain.log2_n()) as usize;
                if let Some(circuit) = self.circuits.get(i) {
                    add_poly(&**circuit, &self.floor_plans[i], *coeff, &mut result);
                }
            }
        } else if let Some(i) = self.omega_lookup.get(&OmegaKey::from(w)) {
            if let Some(circuit) = self.circuits.get(*i) {
                add_poly(&**circuit, &self.floor_plans[*i], F::ONE, &mut result);
            }
        } else {
            // In this case, the circuit is not defined and defaults to the zero polynomial.
        }

        result
    }
}

impl<F: PrimeField + FromUniformBytes<64>, R: Rank> Registry<'_, F, R> {
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
    use super::{CircuitIndex, OmegaKey, RegistryBuilder};
    use crate::polynomials::TestRank;
    use crate::tests::SquareCircuit;
    use alloc::collections::BTreeSet;
    use alloc::collections::btree_map::BTreeMap;
    use ff::Field;
    use ff::PrimeField;
    use ragu_arithmetic::{Domain, bitreverse};
    use ragu_core::Result;
    use ragu_pasta::Fp;
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

        let w = Fp::random(&mut rand::rng());
        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

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
    fn test_omega_lookup_correctness() -> Result<()> {
        let log2_circuits = 8;
        let domain = Domain::<Fp>::new(log2_circuits);
        let domain_size = 1 << log2_circuits;

        let mut omega_lookup = BTreeMap::new();
        let mut omega_power = Fp::ONE;

        for i in 0..domain_size {
            omega_lookup.insert(OmegaKey::from(omega_power), i);
            omega_power *= domain.omega();
        }

        omega_power = Fp::ONE;
        for i in 0..domain_size {
            let looked_up_index = omega_lookup.get(&OmegaKey::from(omega_power)).copied();

            assert_eq!(
                looked_up_index,
                Some(i),
                "Failed to lookup omega^{} correctly",
                i
            );

            omega_power *= domain.omega();
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
    fn test_omega_key_uniqueness() {
        let max_circuits = 1024;
        let mut seen_keys = BTreeSet::new();

        for i in 0..max_circuits {
            let omega = CircuitIndex::new(i).omega_j::<Fp>();
            let key = OmegaKey::from(omega);

            assert!(
                !seen_keys.contains(&key),
                "OmegaKey collision at index {}",
                i
            );
            seen_keys.insert(key);
        }
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

            let w = Fp::random(&mut rand::rng());
            let x = Fp::random(&mut rand::rng());
            let y = Fp::random(&mut rand::rng());

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

    #[test]
    #[should_panic = "registry digest should never be zero"]
    fn zero_registry_key_panics() {
        use ff::Field;
        let _ = super::Key::new(<Fp as Field>::ZERO);
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
        assert_eq!(registry.circuits().len(), 4);

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

        assert_eq!(registry.circuits().len(), 4);

        // Test circuit count with interleaved registration
        let registry2 = TestRegistryBuilder::new()
            .register_circuit(SquareCircuit { times: 3 })?
            .register_internal_circuit(SquareCircuit { times: 1 })?
            .register_circuit(SquareCircuit { times: 4 })?
            .register_internal_circuit(SquareCircuit { times: 2 })?
            .finalize()?;

        assert_eq!(registry2.circuits().len(), 4);

        Ok(())
    }

    /// wxy_combined produces identical results to wxy (both in and out of domain).
    #[test]
    fn test_wxy_combined_equals_wxy() -> Result<()> {
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

        let w = Fp::random(&mut rand::rng());
        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        // Test out-of-domain
        assert_eq!(registry.wxy(w, x, y), registry.wxy_combined(w, x, y));

        // Test in-domain
        let w_in_domain = registry.domain.omega();
        assert_eq!(
            registry.wxy(w_in_domain, x, y),
            registry.wxy_combined(w_in_domain, x, y)
        );

        Ok(())
    }
}
