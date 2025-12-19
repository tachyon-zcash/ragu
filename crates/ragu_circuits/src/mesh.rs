//! Management of polynomials that encode large sets of circuit polynomials for
//! efficient querying.
//!
//! ## Overview
//!
//! Individual circuits in Ragu are represented by a bivariate polynomial
//! $s_i(X, Y)$. Multiple circuits are used over any particular field throughout
//! Ragu's PCD construction, and so the [`Mesh`] structure represents a larger
//! polynomial $m(W, X, Y)$ that interpolates such that $m(\omega^i, X, Y) =
//! s_i(X, Y)$ for some $\omega \in \mathbb{F}$ of sufficiently high $2^k$ order
//! to encode all circuits for both PCD and for application circuits.
//!
//! The [`MeshBuilder`] structure is used to construct a new [`Mesh`] by
//! inserting circuits and performing a [`finalize`](MeshBuilder::finalize) step
//! to compile the added circuits into a mesh polynomial representation that can
//! be efficiently evaluated at different restrictions.

use arithmetic::{Domain, PoseidonPermutation, bitreverse};
use ff::PrimeField;
use ragu_core::{Error, Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{Element, poseidon::Sponge};

use alloc::{boxed::Box, collections::btree_map::BTreeMap, vec::Vec};

use crate::{
    Circuit, CircuitExt, CircuitObject,
    polynomials::{Rank, structured, unstructured},
};

/// Represents a simple numeric index of a circuit in the mesh.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(transparent)]
pub struct CircuitIndex(u32);

impl CircuitIndex {
    /// Creates a new circuit index.
    pub fn new(index: usize) -> Self {
        Self(index.try_into().unwrap())
    }

    /// Returns $\omega^j$ field element that corresponds to this $i$th circuit index.
    ///
    /// The $i$th circuit added to any [`Mesh`] (for a given [`PrimeField`] `F`) is
    /// assigned the domain element of smallest multiplicative order not yet
    /// assigned to any circuit prior to $i$. This corresponds with $\Omega^{f(i)}$
    /// where $f(i)$ is the [`S`](PrimeField::S)-bit reversal of `i` and $\Omega$ is
    /// the primitive [root of unity](PrimeField::ROOT_OF_UNITY) of order $2^{S}$ in
    /// `F`.
    ///
    /// Notably, the result of this function does not depend on the actual size of
    /// the [`Mesh`]'s interpolation polynomial domain.
    pub fn omega_j<F: PrimeField>(self) -> F {
        let bit_reversal_id = bitreverse(self.0, F::S);
        F::ROOT_OF_UNITY.pow([bit_reversal_id.into()])
    }
}

/// Builder for constructing a new [`Mesh`].
pub struct MeshBuilder<'params, F: PrimeField, R: Rank> {
    circuits: Vec<Box<dyn CircuitObject<F, R> + 'params>>,
}

impl<F: PrimeField, R: Rank> Default for MeshBuilder<'_, F, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, F: PrimeField, R: Rank> MeshBuilder<'params, F, R> {
    /// Creates a new empty [`Mesh`] builder.
    pub fn new() -> Self {
        Self {
            circuits: Vec::new(),
        }
    }

    /// Returns the number of circuits currently registered in this builder.
    pub fn num_circuits(&self) -> usize {
        self.circuits.len()
    }

    /// Returns the log2 of the smallest power-of-2 domain size that fits all circuits.
    pub fn log2_circuits(&self) -> u32 {
        self.circuits.len().next_power_of_two().trailing_zeros()
    }

    /// Registers a new circuit.
    pub fn register_circuit<C>(self, circuit: C) -> Result<Self>
    where
        C: Circuit<F> + 'params,
    {
        self.register_circuit_object(circuit.into_object()?)
    }

    /// Registers a new circuit using a bare circuit object.
    pub fn register_circuit_object(
        mut self,
        circuit: Box<dyn CircuitObject<F, R> + 'params>,
    ) -> Result<Self> {
        let id = self.circuits.len();
        if id >= R::num_coeffs() {
            return Err(Error::CircuitBoundExceeded(id));
        }

        self.circuits.push(circuit);

        Ok(self)
    }

    /// Builds the final [`Mesh`].
    pub fn finalize<P: PoseidonPermutation<F>>(self, poseidon: &P) -> Result<Mesh<'params, F, R>> {
        let log2_circuits = self.log2_circuits();
        let domain = Domain::<F>::new(log2_circuits);

        // Build omega^j -> i lookup table.
        let mut omega_lookup = BTreeMap::new();

        for i in 0..self.circuits.len() {
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

        // Create provisional mesh (circuits still have placeholder K).
        let mut mesh = Mesh {
            domain,
            circuits: self.circuits,
            omega_lookup,
            key: F::ONE,
        };

        // Set mesh key to H(M(w, x, y))
        mesh.key = mesh.compute_mesh_digest(poseidon);

        Ok(mesh)
    }
}

/// Represents a collection of circuits over a particular field, some of which
/// may make reference to the others or be executed in similar contexts. The
/// circuits are combined together using an interpolation polynomial so that
/// they can be queried efficiently.
pub struct Mesh<'params, F: PrimeField, R: Rank> {
    domain: Domain<F>,
    circuits: Vec<Box<dyn CircuitObject<F, R> + 'params>>,

    /// Maps from the OmegaKey (which represents some `omega^j`) to the index `i`
    /// of the circuits vector.
    omega_lookup: BTreeMap<OmegaKey, usize>,

    /// Key used to unpredictably change the mesh polynomial's evaluation at
    /// non-trivial points.
    key: F,
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

impl<F: PrimeField, R: Rank> Mesh<'_, F, R> {
    /// Return the constraint system key for this mesh, used by the proof
    /// generator.
    // TODO(ebfull): We should ensure that this detail is not leaked outside of the Mesh.
    pub fn get_key(&self) -> F {
        self.key
    }

    /// Evaluate the mesh polynomial unrestricted at $W$.
    pub fn xy(&self, x: F, y: F) -> unstructured::Polynomial<F, R> {
        let mut coeffs = unstructured::Polynomial::default();
        for (i, circuit) in self.circuits.iter().enumerate() {
            let j = bitreverse(i as u32, self.domain.log2_n()) as usize;
            coeffs[j] = circuit.sxy(x, y, self.key);
        }
        // Convert from the Lagrange basis.
        let domain = &self.domain;
        domain.ifft(&mut coeffs[..domain.n()]);

        coeffs
    }

    /// Index the $i$th circuit to field element $\omega^j$ as $w$, and evaluate
    /// the mesh polynomial unrestricted at $X$.
    ///
    /// Wraps [`Mesh::wy`]. See [`CircuitIndex::omega_j`] for more details.
    pub fn circuit_y(&self, i: CircuitIndex, y: F) -> structured::Polynomial<F, R> {
        let w: F = i.omega_j();
        self.wy(w, y)
    }

    /// Evaluate the mesh polynomial unrestricted at $X$.
    pub fn wy(&self, w: F, y: F) -> structured::Polynomial<F, R> {
        self.w(
            w,
            structured::Polynomial::default,
            |circuit, circuit_coeff, poly| {
                let mut tmp = circuit.sy(y, self.key);
                tmp.scale(circuit_coeff);
                poly.add_assign(&tmp);
            },
        )
    }

    /// Evaluate the mesh polynomial unrestricted at $Y$.
    pub fn wx(&self, w: F, x: F) -> unstructured::Polynomial<F, R> {
        self.w(
            w,
            unstructured::Polynomial::default,
            |circuit, circuit_coeff, poly| {
                let mut tmp = circuit.sx(x, self.key);
                tmp.scale(circuit_coeff);
                poly.add_assign(&tmp);
            },
        )
    }

    /// Evaluate the mesh polynomial at the provided point.
    pub fn wxy(&self, w: F, x: F, y: F) -> F {
        self.w(
            w,
            || F::ZERO,
            |circuit, circuit_coeff, poly| {
                *poly += circuit.sxy(x, y, self.key) * circuit_coeff;
            },
        )
    }

    /// Computes the polynomial restricted at $W$ based on the provided
    /// closures.
    fn w<T>(
        &self,
        w: F,
        init: impl FnOnce() -> T,
        add_poly: impl Fn(&dyn CircuitObject<F, R>, F, &mut T),
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
                    add_poly(&**circuit, *coeff, &mut result);
                }
            }
        } else if let Some(i) = self.omega_lookup.get(&OmegaKey::from(w)) {
            if let Some(circuit) = self.circuits.get(*i) {
                add_poly(&**circuit, F::ONE, &mut result);
            }
        } else {
            // In this case, the circuit is not defined and defaults to the zero polynomial.
        }

        result
    }

    /// Compute a digest of this mesh.
    fn compute_mesh_digest<P: PoseidonPermutation<F>>(&self, poseidon: &P) -> F {
        Emulator::emulate_wireless((), |dr, _| {
            // Placeholder "nothing-up-my-sleeve challenges" (small primes).
            let mut w = F::from(2u64);
            let mut x = F::from(3u64);
            let mut y = F::from(5u64);

            let mut sponge = Sponge::<'_, _, P>::new(dr, poseidon);
            for _ in 0..6 {
                let eval = Element::constant(dr, self.wxy(w, x, y));
                sponge.absorb(dr, &eval)?;
                w = *sponge.squeeze(dr)?.value().take();
                x = *sponge.squeeze(dr)?.value().take();
                y = *sponge.squeeze(dr)?.value().take();
            }

            Ok(*sponge.squeeze(dr)?.value().take())
        })
        .expect("mesh digest computation should always succeed")
    }
}

#[cfg(test)]
mod tests {
    use super::{CircuitIndex, MeshBuilder, OmegaKey};
    use crate::polynomials::R;
    use crate::tests::SquareCircuit;
    use alloc::collections::BTreeSet;
    use alloc::collections::btree_map::BTreeMap;
    use arithmetic::{Cycle, Domain, bitreverse};
    use ff::Field;
    use ff::PrimeField;
    use ragu_core::Result;
    use ragu_pasta::{Fp, Pasta};
    use rand::thread_rng;

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

    type TestRank = R<8>;

    #[test]
    fn test_mesh_circuit_consistency() -> Result<()> {
        let poseidon = Pasta::baked().circuit_poseidon();

        let mesh = MeshBuilder::<Fp, TestRank>::new()
            .register_circuit(SquareCircuit { times: 2 })?
            .register_circuit(SquareCircuit { times: 5 })?
            .register_circuit(SquareCircuit { times: 10 })?
            .register_circuit(SquareCircuit { times: 11 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .finalize(poseidon)?;

        let w = Fp::random(thread_rng());
        let x = Fp::random(thread_rng());
        let y = Fp::random(thread_rng());

        let xy_poly = mesh.xy(x, y);
        let wy_poly = mesh.wy(w, y);
        let wx_poly = mesh.wx(w, x);

        let wxy_value = mesh.wxy(w, x, y);

        assert_eq!(wxy_value, xy_poly.eval(w));
        assert_eq!(wxy_value, wy_poly.eval(x));
        assert_eq!(wxy_value, wx_poly.eval(y));

        let mut w = Fp::ONE;
        for _ in 0..mesh.domain.n() {
            let xy_poly = mesh.xy(x, y);
            let wy_poly = mesh.wy(w, y);
            let wx_poly = mesh.wx(w, x);

            let wxy_value = mesh.wxy(w, x, y);

            assert_eq!(wxy_value, xy_poly.eval(w));
            assert_eq!(wxy_value, wy_poly.eval(x));
            assert_eq!(wxy_value, wx_poly.eval(y));

            w *= mesh.domain.omega();
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
    fn test_single_circuit_mesh() -> Result<()> {
        let poseidon = Pasta::baked().circuit_poseidon();

        // Checks that a single circuit can be finalized without bit-shift overflows.
        let _mesh = MeshBuilder::<Fp, TestRank>::new()
            .register_circuit(SquareCircuit { times: 1 })?
            .finalize(poseidon)?;

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
                    "Omega mismatch for circuit {} in mesh of size {}",
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
    fn test_non_power_of_two_mesh_sizes() -> Result<()> {
        let poseidon = Pasta::baked().circuit_poseidon();

        type TestRank = crate::polynomials::R<8>;
        for num_circuits in 0..21 {
            let mut builder = MeshBuilder::<Fp, TestRank>::new();

            for i in 0..num_circuits {
                builder = builder.register_circuit(SquareCircuit { times: i })?;
            }

            let mesh = builder.finalize(poseidon)?;

            // Verify domain size is next power of 2
            let expected_domain_size = num_circuits.next_power_of_two();
            assert_eq!(mesh.domain.n(), expected_domain_size);

            let w = Fp::random(thread_rng());
            let x = Fp::random(thread_rng());
            let y = Fp::random(thread_rng());

            let wxy = mesh.wxy(w, x, y);
            let xy = mesh.xy(x, y);
            assert_eq!(wxy, xy.eval(w), "Failed for num_circuits={}", num_circuits);
        }

        Ok(())
    }
}
