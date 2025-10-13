//! TODO(ebfull): Collections of circuits.

use arithmetic::Domain;
use ff::PrimeField;
use ragu_core::{Error, Result};

use alloc::{boxed::Box, vec::Vec};

use crate::{
    Circuit, CircuitExt, CircuitObject,
    polynomials::{Rank, structured, unstructured},
};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;

/// A collection of circuits over a particular field, some of which may make
/// reference to the others or be executed in similar contexts.
pub struct Mesh<'params, F: PrimeField, R: Rank> {
    domain: Domain<F>,
    current_omega: F,
    circuits: Vec<Box<dyn CircuitObject<F, R> + 'params>>,
    // Internal circuit lookup registry
    circuit_tags: BTreeMap<String, F>,
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
            circuit_tags: BTreeMap::new(),
        }
    }

    /// Registers a bare circuit to this mesh with a custom tag for internal lookups.
    /// Returns the point of the mesh domain that the circuit is assigned to.
    ///
    /// Returns an error if:
    /// - The circuit count exceeds the mesh capacity
    /// - A circuit with the same tag already exists
    pub fn register_circuit<C>(&mut self, tag: impl Into<String>, circuit: C) -> Result<F>
    where
        C: Circuit<F> + Send + 'params + 'static,
    {
        let tag = tag.into();

        if self.circuit_tags.contains_key(&tag) {
            return Err(Error::DuplicateCircuitTag(tag));
        }

        let omega = self.current_omega;

        let circuit_obj = circuit.into_circuit_object(omega)?;

        self.current_omega *= self.domain.omega();
        self.circuits.push(circuit_obj);
        self.circuit_tags.insert(tag, omega);

        Ok(omega)
    }

    /// Internal circuit registry lookup by index.
    pub fn get_circuit_by_index(&self, index: usize) -> Option<(F, &dyn CircuitObject<F, R>)> {
        let circuit = self.circuits.get(index)?;
        let omega = self.circuit_tags.get(&format!("circuit_{}", index))?;
        Some((*omega, &**circuit))
    }

    /// Internal circuit registry lookup by tag.
    pub fn get_circuit_by_tag(&self, tag: &str) -> Option<(F, &dyn CircuitObject<F, R>)> {
        let omega = *self.circuit_tags.get(tag)?;
        let index = self.get_circuit_from_omega(omega)?;
        let circuit = self.circuits.get(index)?;
        Some((omega, &**circuit))
    }

    /// Returns an iterator over all registered circuit tags.
    pub fn circuit_tags(&self) -> impl Iterator<Item = &String> {
        self.circuit_tags.keys()
    }

    /// Returns the omega value for a given circuit tag.
    pub fn get_omega_by_tag(&self, tag: &str) -> Option<F> {
        self.circuit_tags.get(tag).copied()
    }

    /// Checks if a circuit tag exists in the mesh.
    pub fn has_circuit(&self, tag: &str) -> bool {
        self.circuit_tags.contains_key(tag)
    }

    /// Returns the total number of registered circuits.
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
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
    pub fn xy(&self, x: F, y: F) -> unstructured::Polynomial<F, R> {
        let mut coeffs = unstructured::Polynomial::default();
        for (circuit, lc) in self.circuits.iter().zip(coeffs.iter_mut()) {
            *lc = circuit.sxy(x, y);
        }
        // Convert from the Lagrange basis.
        self.domain.ifft(&mut coeffs[..self.domain.n()]);

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

/// Marker type to disambiguate trait impl for regular circuits.
pub struct RegularCircuit;

/// Marker type to disambiguate trait impl for closures.
pub struct OmegaCircuit;

/// Trait for converting types into `CircuitObjects`, with optional omega parameter.
pub trait IntoCircuitObject<F: PrimeField, R: Rank, Marker = ()> {
    /// `CircuitObject` conversion method.
    fn into_circuit_object(self, omega: F) -> Result<Box<dyn CircuitObject<F, R>>>;
}

/// Implementation for regular circuits – ignores omega and synthesizes immediately.
impl<F: PrimeField, R: Rank, C> IntoCircuitObject<F, R, RegularCircuit> for C
where
    C: Circuit<F> + Send + 'static,
{
    fn into_circuit_object(self, _omega: F) -> Result<Box<dyn CircuitObject<F, R>>> {
        self.into_object()
    }
}

/// Implementation for closures - receives omega for lazy evaluation.
impl<F: PrimeField, R: Rank, Func> IntoCircuitObject<F, R, OmegaCircuit> for Func
where
    Func: FnOnce(F) -> Result<Box<dyn CircuitObject<F, R>>>,
{
    fn into_circuit_object(self, omega: F) -> Result<Box<dyn CircuitObject<F, R>>> {
        self(omega)
    }
}

#[test]
fn test_mesh_circuit_consistency() {
    use ff::Field;
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
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

    let mut mesh = Mesh::<Fp, TestRank>::new(3);

    mesh.register_circuit("square_circuit_one", SquareCircuit { times: 2 })
        .unwrap();
    mesh.register_circuit("square_circuit_two", SquareCircuit { times: 5 })
        .unwrap();
    mesh.register_circuit("square_circuit_three", SquareCircuit { times: 10 })
        .unwrap();
    mesh.register_circuit("square_circuit_four", SquareCircuit { times: 11 })
        .unwrap();
    mesh.register_circuit("square_circuit_five", SquareCircuit { times: 19 })
        .unwrap();

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
}
