//! Common abstraction for orchestrating revdot claims.

use alloc::{borrow::Cow, vec::Vec};
use ff::PrimeField;
use ragu_circuits::{
    mesh::{CircuitIndex, Mesh},
    polynomials::{Rank, structured},
};

pub mod native;

use crate::circuits::InternalCircuitIndex;
use native::Processor;

/// Processor that builds polynomial vectors for revdot claims.
///
/// Accumulates (a, b) polynomial pairs for each claim type, using
/// the mesh polynomial to transform rx polynomials appropriately.
pub struct Builder<'m, 'rx, F: PrimeField, R: Rank> {
    pub(crate) mesh: &'m Mesh<'m, F, R>,
    pub(crate) num_application_steps: usize,
    pub(crate) y: F,
    pub(crate) z: F,
    pub(crate) tz: structured::Polynomial<F, R>,
    /// The accumulated `a` polynomials for revdot claims.
    pub a: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
    /// The accumulated `b` polynomials for revdot claims.
    pub b: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
}

impl<'m, 'rx, F: PrimeField, R: Rank> Builder<'m, 'rx, F, R> {
    /// Create a new claim builder.
    pub fn new(mesh: &'m Mesh<'m, F, R>, num_application_steps: usize, y: F, z: F) -> Self {
        Self {
            mesh,
            num_application_steps,
            y,
            z,
            tz: R::tz(z),
            a: Vec::new(),
            b: Vec::new(),
        }
    }

    fn circuit_impl(
        &mut self,
        circuit_id: CircuitIndex,
        rx: Cow<'rx, structured::Polynomial<F, R>>,
    ) {
        let sy = self.mesh.circuit_y(circuit_id, self.y);
        let mut b = rx.as_ref().clone();
        b.dilate(self.z);
        b.add_assign(&sy);
        b.add_assign(&self.tz);

        self.a.push(rx);
        self.b.push(Cow::Owned(b));
    }
}

impl<'m, 'rx, F: PrimeField, R: Rank> Processor<&'rx structured::Polynomial<F, R>, CircuitIndex>
    for Builder<'m, 'rx, F, R>
{
    fn raw_claim(
        &mut self,
        a: &'rx structured::Polynomial<F, R>,
        b: &'rx structured::Polynomial<F, R>,
    ) {
        self.a.push(Cow::Borrowed(a));
        self.b.push(Cow::Borrowed(b));
    }

    fn circuit(&mut self, circuit_id: CircuitIndex, rx: &'rx structured::Polynomial<F, R>) {
        self.circuit_impl(circuit_id, Cow::Borrowed(rx));
    }

    fn internal_circuit(
        &mut self,
        id: InternalCircuitIndex,
        mut rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
    ) {
        let circuit_id = id.circuit_index(self.num_application_steps);
        let first = rxs.next().expect("must provide at least one rx polynomial");

        let rx = match rxs.next() {
            None => Cow::Borrowed(first),
            Some(second) => {
                let mut sum = first.clone();
                sum.add_assign(second);
                for rx in rxs {
                    sum.add_assign(rx);
                }
                Cow::Owned(sum)
            }
        };

        self.circuit_impl(circuit_id, rx);
    }

    fn stage(
        &mut self,
        id: InternalCircuitIndex,
        mut rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
    ) -> Result<(), ragu_core::Error> {
        let first = rxs.next().expect("must provide at least one rx polynomial");

        let circuit_id = id.circuit_index(self.num_application_steps);
        let sy = self.mesh.circuit_y(circuit_id, self.y);

        let a = match rxs.next() {
            None => Cow::Borrowed(first),
            Some(second) => Cow::Owned(structured::Polynomial::fold(
                core::iter::once(first)
                    .chain(core::iter::once(second))
                    .chain(rxs),
                self.z,
            )),
        };

        self.a.push(a);
        self.b.push(Cow::Owned(sy));
        Ok(())
    }
}
