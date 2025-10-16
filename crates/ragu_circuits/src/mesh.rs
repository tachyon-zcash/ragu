//! A [`Mesh`] manages multiple circuits over a field, allowing them to share
//! a common domain for efficient polynomial evaluation.

use crate::{
    Circuit, CircuitExt, CircuitObject,
    polynomials::{Rank, structured, unstructured},
};
use ahash::RandomState;
use alloc::{boxed::Box, vec::Vec};
use arithmetic::Domain;
use arithmetic::bitreverse;
use ff::PrimeField;
use hashbrown::HashMap;
use ragu_core::{Error, Result};

/// Builder for constructing a mesh of circuits.
///
/// Represents a collection of circuits over a particular field,
/// some of which may make reference to the others or be executed
/// in similar contexts.
pub struct MeshBuilder<'params, F: PrimeField, R: Rank> {
    circuits: Vec<Box<dyn CircuitObject<F, R> + 'params>>,
}

impl<'params, F: PrimeField, R: Rank> MeshBuilder<'params, F, R> {
    /// Initialize a new mesh object.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            circuits: Vec::new(),
        }
    }

    /// Registers a circuit in the mesh.
    pub fn register_circuit<C>(mut self, circuit: C) -> Result<Self>
    where
        C: Circuit<F> + Send + 'params,
    {
        let id = self.circuits.len();
        if id >= (R::num_coeffs()) {
            return Err(Error::CircuitBoundExceeded(id));
        }

        self.circuits.push(circuit.into_object()?);

        Ok(self)
    }

    /// Determines minimal power-of-2 domain k and maps circuits from maximal domain 2^S to 2^k.
    ///
    /// The domain is "rolling" in the sense that this construction supports incremental
    /// circuit registration into the mesh, without knowing the final domain size k. When `k`
    /// is later determined during finalization, bit-reversal automatically maps each
    /// circuit to its correct position in the finalized domain.
    pub fn finalize(self) -> Result<Mesh<'params, F, R>> {
        // Compute the smallest power-of-2 domain size that fits all circuits.
        let log2_circuits = self.circuits.len().next_power_of_two().trailing_zeros();

        let domain = Domain::<F>::new(log2_circuits);
        let domain_size = 1 << log2_circuits;
        let mut reordered = Vec::with_capacity(domain_size);
        reordered.extend((0..domain_size).map(|_| None));

        let mut omega_lsb_lookup =
            HashMap::with_capacity_and_hasher(domain_size, RandomState::new());

        for (id, circuit) in self.circuits.into_iter().enumerate() {
            // Omega values are precomputed in the maximal field domain 2^S (where S = F::S), independent of final domain 2^k.
            // The key property is circuit synthesis can compute omega^i for the jth circuit at
            // compile-time as: "omega^i where i = bit_reverse(j, S)". This is a pure function that doesn't
            // rely on a mesh construction.
            //
            // During finalization, when 'k' is determined, the circuit's position becomes:
            // "position = bit_reverse(j, S) >> (S - k)".
            //
            // We perform a mapping to the actual position in the smaller domain, effectively compressing
            // the 2^S-slot domain to 2^k-slot domain (where k = log2_circuits).
            let bit_reversal_id = bitreverse(id as u32, F::S);

            // Cast to u64 to avoid overflow: in a single circuit mesh setting (log2_circuits = 0),
            // right shifting by (F::S - log2_circuits) = 32 overflows a u32.
            let position = ((bit_reversal_id as u64) >> (F::S - log2_circuits)) as usize;

            // Builds O(1) omega lookup table.
            let omega_at_position = domain.omega().pow([position as u64]);
            let omega_lsb = Mesh::<F, R>::field_to_lsb(&omega_at_position);
            omega_lsb_lookup.insert(omega_lsb, position);

            // TODO: By virtue of the reindexed vector being typed "Option<Box<_>>", it contains
            // gaps (that can be collapsed) when # circuits < domain size. These are inherently
            // sparse indices right now.

            // Shuffle the circuit by moving each circuit to it's bit-reversed position.
            reordered[position] = Some(circuit);
        }

        Ok(Mesh {
            domain,
            circuits: reordered,
            omega_lsb_lookup,
        })
    }
}

/// A finalized mesh ready for polynomial evaluation.
pub struct Mesh<'params, F: PrimeField, R: Rank> {
    domain: Domain<F>,
    circuits: Vec<Option<Box<dyn CircuitObject<F, R> + 'params>>>,
    omega_lsb_lookup: HashMap<u64, usize, RandomState>,
}

impl<F: PrimeField, R: Rank> Mesh<'_, F, R> {
    /// Computes a hash key from a field element for omega lookups.
    ///
    /// For field elements of multiplicative order 2^k (omega values),
    /// this uniquely identifies each element.
    fn field_to_lsb(f: &F) -> u64 {
        let product = f.double().double() + f;
        let bytes = product.to_repr();
        let byte_slice = bytes.as_ref();

        u64::from_le_bytes(
            byte_slice[..8]
                .try_into()
                .expect("field representation is at least 8 bytes"),
        )
    }

    /// Returns the index of the circuit for the provided omega^{i} value using constant lookup.
    fn get_circuit_from_omega(&self, w: F) -> Option<usize> {
        let w_lsb = Self::field_to_lsb(&w);
        self.omega_lsb_lookup.get(&w_lsb).copied()
    }

    /// Evaluate the mesh polynomial unrestricted at $W$.
    pub fn xy(&self, x: F, y: F) -> unstructured::Polynomial<F, R> {
        let mut coeffs = unstructured::Polynomial::default();
        for (circuit_opt, lc) in self.circuits.iter().zip(coeffs.iter_mut()) {
            if let Some(circuit) = circuit_opt {
                *lc = circuit.sxy(x, y);
            }
        }
        // Convert from the Lagrange basis.
        let domain = &self.domain;
        domain.ifft(&mut coeffs[..domain.n()]);

        coeffs
    }

    /// Evaluate the mesh polynomial unrestricted at $X$.
    pub fn wy(&self, w: F, y: F) -> structured::Polynomial<F, R> {
        self.w(
            w,
            structured::Polynomial::default,
            |circuit, circuit_coeff, poly| {
                let mut tmp = circuit.sy(y);
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
                let mut tmp = circuit.sx(x);
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
                *poly += circuit.sxy(x, y) * circuit_coeff;
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
        let ell = self.domain.ell(w, self.circuits.len());

        let mut result = init();

        if let Some(ell) = ell {
            // The provided `w` was not in the domain, and `ell` are the
            // coefficients we need to use to separate each (partial) circuit
            // evaluation.
            for (circuit_opt, circuit_coeff) in self.circuits.iter().zip(ell) {
                if let Some(circuit) = circuit_opt {
                    add_poly(&**circuit, circuit_coeff, &mut result);
                }
            }
        } else if let Some(i) = self.get_circuit_from_omega(w) {
            if let Some(circuit) = &self.circuits[i] {
                add_poly(&**circuit, F::ONE, &mut result);
            }
        } else {
            // In this case, the circuit is not defined and defaults to the zero polynomial.
        }

        result
    }
}

/// Returns the omega value for a given circuit ID in the maximal field domain.    
pub fn compute_circuit_omega<F: PrimeField>(id: u32) -> F {
    let bit_reversal_id = bitreverse(id, F::S);
    F::ROOT_OF_UNITY.pow([bit_reversal_id as u64])
}

#[cfg(test)]
mod tests {
    use crate::mesh::compute_circuit_omega;
    use crate::{
        Circuit,
        mesh::{Mesh, MeshBuilder},
        polynomials::R,
    };
    use ahash::RandomState;
    use arithmetic::{Domain, bitreverse};
    use ff::Field;
    use ff::PrimeField;
    use hashbrown::HashMap;
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
        gadgets::{GadgetKind, Kind},
    };
    use ragu_pasta::Fp;
    use ragu_primitives::Element;
    use rand::thread_rng;

    struct SquareCircuit {
        times: usize,
    }

    impl Circuit<Fp> for SquareCircuit {
        type Instance<'instance> = Fp;
        type Output = Kind![Fp; Element<'_, _>];
        type Witness<'witness> = Fp;
        type Aux<'witness> = ();

        fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Self::Instance<'instance>>,
        ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
            Element::alloc(dr, instance)
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<(
            <Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>,
            DriverValue<D, Self::Aux<'witness>>,
        )> {
            let mut a = Element::alloc(dr, witness)?;

            for _ in 0..self.times {
                a = a.square(dr)?;
            }

            Ok((a, D::just(|| ())))
        }
    }

    type TestRank = R<8>;

    #[test]
    fn test_mesh_circuit_consistency() -> Result<()> {
        let mesh = MeshBuilder::<Fp, TestRank>::new()
            .register_circuit(SquareCircuit { times: 2 })?
            .register_circuit(SquareCircuit { times: 5 })?
            .register_circuit(SquareCircuit { times: 10 })?
            .register_circuit(SquareCircuit { times: 11 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .register_circuit(SquareCircuit { times: 19 })?
            .finalize()?;

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

        let mut omega_lsb_lookup =
            HashMap::with_capacity_and_hasher(domain_size, RandomState::new());
        let mut omega_power = Fp::ONE;

        for i in 0..domain_size {
            let hash = Mesh::<Fp, R<8>>::field_to_lsb(&omega_power);
            omega_lsb_lookup.insert(hash, i);
            omega_power *= domain.omega();
        }

        omega_power = Fp::ONE;
        for i in 0..domain_size {
            let hash = Mesh::<Fp, R<10>>::field_to_lsb(&omega_power);
            let looked_up_index = omega_lsb_lookup.get(&hash).copied();

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
        // Checks that a single circuit can be finalized without bit-shift overflows.
        let _mesh = MeshBuilder::<Fp, TestRank>::new()
            .register_circuit(SquareCircuit { times: 1 })?
            .finalize()?;

        Ok(())
    }

    #[test]
    fn test_compute_circuit_omega_consistency() -> Result<()> {
        for num_circuits in [2usize, 3, 7, 8, 15, 16, 32] {
            let log2_circuits = num_circuits.next_power_of_two().trailing_zeros();
            let domain = Domain::<Fp>::new(log2_circuits);

            for id in 0..num_circuits {
                let omega_from_function = compute_circuit_omega::<Fp>(id as u32);

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
}
