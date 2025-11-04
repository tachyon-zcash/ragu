//! Management of polynomials that encode large sets of circuit polynomials for
//! efficient querying.

use arithmetic::Domain;
use arithmetic::bitreverse;
use ff::PrimeField;
use ragu_core::{Error, Result};

use alloc::{boxed::Box, collections::btree_map::BTreeMap, vec::Vec};

use crate::{
    Circuit, CircuitExt, CircuitObject,
    polynomials::{Rank, structured, unstructured},
};

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

    /// Registers a new circuit.
    pub fn register_circuit<C>(mut self, circuit: C) -> Result<Self>
    where
        C: Circuit<F> + 'params,
    {
        self.circuits.push(circuit.into_object()?);

        Ok(self)
    }

    /// Registers a new circuit using a bare circuit object.
    pub fn register_circuit_object<C>(
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
    pub fn finalize(self) -> Result<Mesh<'params, F, R>> {
        // Compute the smallest power-of-2 domain size that fits all circuits.
        let log2_circuits = self.circuits.len().next_power_of_two().trailing_zeros();

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

        Ok(Mesh {
            domain,
            circuits: self.circuits,
            omega_lookup,
        })
    }
}

/// Represents a collection of circuits over a particular field, some of which
/// may make reference to the others or be executed in similar contexts. The
/// circuits are combined together using an interpolation polynomial so that
/// they can be queried efficiently.
pub struct Mesh<'params, F: PrimeField, R: Rank> {
    domain: Domain<F>,
    circuits: Vec<Box<dyn CircuitObject<F, R> + 'params>>,

    // Maps from the OmegaKey (which represents some `omega^j`) to the index `i`
    // of the circuits vector.
    omega_lookup: BTreeMap<OmegaKey, usize>,
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
    /// Evaluate the mesh polynomial unrestricted at $W$.
    pub fn xy(&self, x: F, y: F) -> unstructured::Polynomial<F, R> {
        let mut coeffs = unstructured::Polynomial::default();
        for (i, circuit) in self.circuits.iter().enumerate() {
            let j = bitreverse(i as u32, self.domain.log2_n()) as usize;
            coeffs[j] = circuit.sxy(x, y);
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
}

/// Returns $\omega^j$ that corresponds to the $i$th circuit added to a Mesh.
pub fn omega_j<F: PrimeField>(id: u32) -> F {
    let bit_reversal_id = bitreverse(id, F::S);
    F::ROOT_OF_UNITY.pow([bit_reversal_id as u64])
}

#[cfg(test)]
mod tests {
    use super::{MeshBuilder, OmegaKey, omega_j};
    use crate::{Circuit, polynomials::R};
    use alloc::collections::btree_map::BTreeMap;
    use arithmetic::{Domain, bitreverse};
    use ff::Field;
    use ff::PrimeField;
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
        // Checks that a single circuit can be finalized without bit-shift overflows.
        let _mesh = MeshBuilder::<Fp, TestRank>::new()
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
                let omega_from_function = omega_j::<Fp>(id as u32);

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
