//! TODO(ebfull): Collections of circuits.

use arithmetic::Domain;
use ff::PrimeField;
use ragu_core::{Error, Result};

use alloc::{boxed::Box, vec::Vec};

use crate::{
    Circuit, CircuitExt, CircuitObject,
    polynomials::{Rank, structured, unstructured},
};

/// A collection of circuits over a particular field, some of which may make
/// reference to the others or be executed in similar contexts.
pub struct Mesh<'params, F: PrimeField, R: Rank> {
    domain: Domain<F>,
    current_omega: F,
    circuits: Vec<Box<dyn CircuitObject<F, R> + 'params>>,
}

impl<'params, F: PrimeField, R: Rank> Mesh<'params, F, R> {
    /// Initialize a new mesh with the supported number of circuits.
    ///
    /// # Panics
    ///
    /// Panics if the provided `log2_circuits` exceeds [`R::RANK`](Rank::RANK).
    pub fn new(log2_circuits: u32) -> Self {
        assert!(log2_circuits <= R::RANK);

        Self {
            domain: Domain::new(log2_circuits),
            current_omega: F::ONE,
            circuits: Vec::new(),
        }
    }

    /// Adds a bare circuit to this mesh. Returns the point of the mesh domain
    /// that the circuit is assigned to.
    pub fn add_bare_circuit<C>(&mut self, circuit: C) -> Result<F>
    where
        C: Circuit<F> + Send + 'params,
    {
        self.add_circuit_object(circuit.into_object()?)
    }

    /// Adds a custom circuit object to this mesh.
    pub fn add_circuit_object(
        &mut self,
        circuit: Box<dyn CircuitObject<F, R> + 'params>,
    ) -> Result<F> {
        if self.circuits.len() >= self.domain.n() {
            return Err(Error::CircuitBoundExceeded(self.domain.n()));
        }

        let omega = self.current_omega;
        self.current_omega *= self.domain.omega();

        self.circuits.push(circuit);

        Ok(omega)
    }

    /// Returns the index of the circuit for the provided $\omega^i$ value, or
    /// `None` if there is no such circuit or the provided value is not in the
    /// domain.
    fn get_circuit_from_omega(&self, w: F) -> Option<usize> {
        // TODO(ebfull): This could use a lookup table. In the pasta curves the
        // most efficient method would be to hash based on the least significant
        // 32 bits, as this is guaranteed to be unique for all field elements of
        // order 2^k.

        let mut cur = F::ONE;
        for i in 0..self.circuits.len() {
            if cur == w {
                return Some(i);
            }
            cur *= self.domain.omega();
        }

        None
    }

    /// Evaluate the mesh polynomial unrestricted at $W$.
    pub fn xyz(&self, x: F, y: F, z: F) -> unstructured::Polynomial<F, R> {
        let mut coeffs = unstructured::Polynomial::default();
        for (circuit, lc) in self.circuits.iter().zip(coeffs.iter_mut()) {
            *lc = circuit.sxy(x, y);
        }
        // Convert from the Lagrange basis.
        self.domain.ifft(&mut coeffs[..self.domain.n()]);
        coeffs[0] += R::txz(x, z);

        coeffs
    }

    /// Evaluate the mesh polynomial unrestricted at $X$.
    pub fn wyz(&self, w: F, y: F, z: F) -> structured::Polynomial<F, R> {
        self.w(
            w,
            || R::tz(z),
            |circuit, circuit_coeff, poly| {
                let mut tmp = circuit.sy(y);
                tmp.scale(circuit_coeff);
                poly.add_assign(&tmp);
            },
        )
    }

    /// Evaluate the mesh polynomial unrestricted at $Y$.
    pub fn wxz(&self, w: F, x: F, z: F) -> unstructured::Polynomial<F, R> {
        self.w(
            w,
            || {
                let mut poly = unstructured::Polynomial::default();
                poly[0] = R::txz(x, z);
                poly
            },
            |circuit, circuit_coeff, poly| {
                let mut tmp = circuit.sx(x);
                tmp.scale(circuit_coeff);
                poly.add_assign(&tmp);
            },
        )
    }

    /// Evaluate the mesh polynomial unrestricted at $Z$.
    pub fn wxy(&self, w: F, x: F, y: F) -> structured::Polynomial<F, R> {
        self.w(
            w,
            || R::tx(x),
            |circuit, circuit_coeff, poly| {
                *poly.constant_term() += circuit.sxy(x, y) * circuit_coeff;
            },
        )
    }

    /// Evaluate the mesh polynomial at the provided point.
    pub fn wxyz(&self, w: F, x: F, y: F, z: F) -> F {
        self.w(
            w,
            || R::txz(x, z),
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
            for (circuit, circuit_coeff) in self.circuits.iter().zip(ell) {
                add_poly(&**circuit, circuit_coeff, &mut result);
            }
        } else if let Some(i) = self.get_circuit_from_omega(w) {
            add_poly(&*self.circuits[i], F::ONE, &mut result);
        } else {
            // In this case, the circuit is not defined and defaults to the zero polynomial.
        }

        result
    }
}

#[test]
fn test_mesh_circuit_consistency() {
    use ff::Field;
    use ragu_core::{
        Result,
        drivers::{Driver, Witness},
        gadgets::{GadgetKind, Kind},
    };
    use ragu_pasta::Fp;
    use ragu_primitives::Element;
    use rand::thread_rng;

    use crate::polynomials::R;

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
            instance: Witness<D, Self::Instance<'instance>>,
        ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
            Element::alloc(dr, instance)
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: Witness<D, Self::Witness<'witness>>,
        ) -> Result<(
            <Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>,
            Witness<D, Self::Aux<'witness>>,
        )> {
            let mut a = Element::alloc(dr, witness)?;

            for _ in 0..self.times {
                a = a.square(dr)?;
            }

            Ok((a, D::just(|| ())))
        }
    }

    type TestRank = R<8>;

    let mut mesh = Mesh::<Fp, TestRank>::new(3);

    mesh.add_bare_circuit(SquareCircuit { times: 2 }).unwrap();
    mesh.add_bare_circuit(SquareCircuit { times: 5 }).unwrap();
    mesh.add_bare_circuit(SquareCircuit { times: 10 }).unwrap();
    mesh.add_bare_circuit(SquareCircuit { times: 11 }).unwrap();
    mesh.add_bare_circuit(SquareCircuit { times: 19 }).unwrap();

    let w = Fp::random(thread_rng());
    let x = Fp::random(thread_rng());
    let y = Fp::random(thread_rng());
    let z = Fp::random(thread_rng());

    let xyz_poly = mesh.xyz(x, y, z);
    let wyz_poly = mesh.wyz(w, y, z);
    let wxz_poly = mesh.wxz(w, x, z);
    let wxy_poly = mesh.wxy(w, x, y);

    let wxyz_value = mesh.wxyz(w, x, y, z);

    assert_eq!(wxyz_value, xyz_poly.eval(w));
    assert_eq!(wxyz_value, wyz_poly.eval(x));
    assert_eq!(wxyz_value, wxz_poly.eval(y));
    assert_eq!(wxyz_value, wxy_poly.eval(z));

    let mut w = Fp::ONE;
    for _ in 0..mesh.domain.n() {
        let xyz_poly = mesh.xyz(x, y, z);
        let wyz_poly = mesh.wyz(w, y, z);
        let wxz_poly = mesh.wxz(w, x, z);
        let wxy_poly = mesh.wxy(w, x, y);

        let wxyz_value = mesh.wxyz(w, x, y, z);

        assert_eq!(wxyz_value, xyz_poly.eval(w));
        assert_eq!(wxyz_value, wyz_poly.eval(x));
        assert_eq!(wxyz_value, wxz_poly.eval(y));
        assert_eq!(wxyz_value, wxy_poly.eval(z));

        w *= mesh.domain.omega();
    }
}
