//! Claim builders for accumulating (a, b) polynomial pairs.
//!
//! Two concrete builders for different contexts:
//! - [`ClaimBuilder`]: Native context (prover/verifier) with mesh/dilate helpers
//! - [`CircuitClaimBuilder`]: Circuit context with sum/fold helpers

use alloc::{borrow::Cow, vec::Vec};
use core::borrow::Borrow;

use ff::PrimeField;
use ragu_circuits::{
    mesh::{CircuitIndex, Mesh},
    polynomials::{Rank, structured},
};
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Element;

use crate::internal_circuits::InternalCircuitIndex;

/// Native claim builder with mesh context.
///
/// Used by prover ([`crate::fuse`]) and verifier ([`crate::verify`]).
pub struct ClaimBuilder<'m, 'rx, F: PrimeField, R: Rank> {
    circuit_mesh: &'m Mesh<'m, F, R>,
    num_application_steps: usize,
    y: F,
    z: F,
    tz: structured::Polynomial<F, R>,
    a: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
    b: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
}

impl<'m, 'rx, F: PrimeField, R: Rank> ClaimBuilder<'m, 'rx, F, R> {
    /// Create a new claim builder.
    pub fn new(circuit_mesh: &'m Mesh<'m, F, R>, num_application_steps: usize, y: F, z: F) -> Self {
        Self {
            circuit_mesh,
            num_application_steps,
            y,
            z,
            tz: R::tz(z),
            a: Vec::new(),
            b: Vec::new(),
        }
    }

    /// Get references to the accumulated polynomial vectors.
    pub fn polys(
        &self,
    ) -> (
        &[Cow<'rx, structured::Polynomial<F, R>>],
        &[Cow<'rx, structured::Polynomial<F, R>>],
    ) {
        (&self.a, &self.b)
    }

    /// Add a raw claim directly without transformation.
    pub fn raw(
        &mut self,
        a: &'rx structured::Polynomial<F, R>,
        b: &'rx structured::Polynomial<F, R>,
    ) {
        self.a.push(Cow::Borrowed(a));
        self.b.push(Cow::Borrowed(b));
    }

    /// Add a circuit claim with mesh polynomial transformation.
    ///
    /// Computes b = rx.dilate(z) + mesh(circuit_id, y) + tz.
    pub fn circuit(&mut self, circuit_id: CircuitIndex, rx: &'rx structured::Polynomial<F, R>) {
        self.circuit_owned(circuit_id, Cow::Borrowed(rx));
    }

    /// Like [`circuit`](Self::circuit), but takes ownership of the polynomial.
    pub fn circuit_owned(
        &mut self,
        circuit_id: CircuitIndex,
        rx: Cow<'rx, structured::Polynomial<F, R>>,
    ) {
        let sy = self.circuit_mesh.circuit_y(circuit_id, self.y);
        let mut b = rx.as_ref().clone();
        b.dilate(self.z);
        b.add_assign(&sy);
        b.add_assign(&self.tz);

        self.a.push(rx);
        self.b.push(Cow::Owned(b));
    }

    /// Add an internal circuit claim, summing multiple stage polynomials.
    ///
    /// Computes a = sum(rxs), b = sum(rxs).dilate(z) + mesh(id, y) + tz.
    pub fn internal_circuit(
        &mut self,
        id: InternalCircuitIndex,
        rxs: &[&'rx structured::Polynomial<F, R>],
    ) {
        assert!(!rxs.is_empty(), "must provide at least one rx polynomial");
        let circuit_id = id.circuit_index(self.num_application_steps);

        let rx: Cow<'rx, _> = if rxs.len() == 1 {
            Cow::Borrowed(rxs[0])
        } else {
            let mut sum = rxs[0].clone();
            for rx in &rxs[1..] {
                sum.add_assign(rx);
            }
            Cow::Owned(sum)
        };

        self.circuit_owned(circuit_id, rx);
    }

    /// Add a stage claim for batching stage polynomial verification.
    ///
    /// Computes a = fold(rxs, z), b = mesh(id, y).
    pub fn stage(&mut self, id: InternalCircuitIndex, rxs: &[&'rx structured::Polynomial<F, R>]) {
        assert!(!rxs.is_empty(), "must provide at least one rx polynomial");

        let circuit_id = id.circuit_index(self.num_application_steps);
        let sy = self.circuit_mesh.circuit_y(circuit_id, self.y);

        let a: Cow<'rx, _> = if rxs.len() == 1 {
            Cow::Borrowed(rxs[0])
        } else {
            Cow::Owned(structured::Polynomial::fold(rxs.iter().copied(), self.z))
        };

        self.a.push(a);
        self.b.push(Cow::Owned(sy));
    }
}

/// Circuit claim builder for in-circuit verification.
///
/// Used in-circuit by [`crate::internal_circuits::compute_v`].
pub struct CircuitClaimBuilder<'dr, D: Driver<'dr>> {
    z: Element<'dr, D>,
    txz: Element<'dr, D>,
    ax: Vec<Element<'dr, D>>,
    bx: Vec<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr>> CircuitClaimBuilder<'dr, D> {
    /// Create a new circuit claim builder.
    pub fn new(z: Element<'dr, D>, txz: Element<'dr, D>) -> Self {
        Self {
            z,
            txz,
            ax: Vec::new(),
            bx: Vec::new(),
        }
    }

    /// Get the accumulated element vectors.
    pub fn into_vecs(self) -> (Vec<Element<'dr, D>>, Vec<Element<'dr, D>>) {
        (self.ax, self.bx)
    }

    /// Add a raw claim directly.
    pub fn raw(&mut self, ax: &Element<'dr, D>, bx: &Element<'dr, D>) {
        self.ax.push(ax.clone());
        self.bx.push(bx.clone());
    }

    /// Add an application circuit claim.
    ///
    /// Pushes (ax, bx + mesh + txz).
    pub fn application(
        &mut self,
        dr: &mut D,
        ax: &Element<'dr, D>,
        bx: &Element<'dr, D>,
        mesh: &Element<'dr, D>,
    ) {
        self.ax.push(ax.clone());
        self.bx.push(bx.add(dr, mesh).add(dr, &self.txz));
    }

    /// Add an internal circuit claim, summing multiple evaluations.
    ///
    /// Pushes (sum(ax_evals), sum(bx_evals) + mesh + txz).
    pub fn internal<'b>(
        &'b mut self,
        dr: &mut D,
        ax_evals: impl IntoIterator<Item = &'b Element<'dr, D>>,
        bx_evals: impl IntoIterator<Item = &'b Element<'dr, D>>,
        mesh: &'b Element<'dr, D>,
    ) {
        self.ax.push(Element::sum(dr, ax_evals));
        self.bx
            .push(Element::sum(dr, bx_evals).add(dr, mesh).add(dr, &self.txz));
    }

    /// Add a stage claim, folding multiple evaluations.
    ///
    /// Pushes (fold(ax_evals, z), mesh).
    pub fn stage<I>(&mut self, dr: &mut D, ax_evals: I, mesh: &Element<'dr, D>) -> Result<()>
    where
        I: IntoIterator<Item: Borrow<Element<'dr, D>>>,
        I::IntoIter: DoubleEndedIterator,
    {
        self.ax
            .push(Element::fold(dr, ax_evals.into_iter(), &self.z)?);
        self.bx.push(mesh.clone());
        Ok(())
    }
}
