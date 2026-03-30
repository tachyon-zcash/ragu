//! Test harness for building a [`Registry`].
//!
//! [`RegistryBuilder`] concatenates circuits from different categories in a
//! fixed order, so callers cannot know the final [`CircuitIndex`] at
//! registration time. This module provides [`TestRegistryBuilder`], which
//! returns opaque [`Handle`] values and resolves them to the correct
//! [`CircuitIndex`] when querying the finalized registry.
//!
//! All circuits must be registered before any bonding objects.

use ff::{FromUniformBytes, PrimeField};
use ragu_circuits::{
    BondingObject, Circuit, Trace,
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryBuilder},
};
use ragu_core::Result;

/// Opaque handle to an entry registered in a [`TestRegistryBuilder`].
#[derive(Clone, Copy)]
pub struct Handle {
    index: usize,
}

impl Handle {
    fn resolve(self) -> CircuitIndex {
        CircuitIndex::new(self.index)
    }
}

/// Builder for constructing a [`TestRegistry`].
///
/// Wraps [`RegistryBuilder`] and returns opaque handles instead of raw
/// [`CircuitIndex`] values, so that tests do not depend on the order in
/// which circuit and bonding-object categories are concatenated into the
/// final index space.
pub struct TestRegistryBuilder<'p, F: PrimeField, R: Rank> {
    inner: Option<RegistryBuilder<'p, F, R>>,
    num_circuits: usize,
    num_bonding: usize,
}

impl<'p, F: FromUniformBytes<64>, R: Rank> Default for TestRegistryBuilder<'p, F, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'p, F: FromUniformBytes<64>, R: Rank> TestRegistryBuilder<'p, F, R> {
    /// Creates a new empty builder.
    pub fn new() -> Self {
        Self {
            inner: Some(RegistryBuilder::new()),
            num_circuits: 0,
            num_bonding: 0,
        }
    }

    /// Registers a circuit and returns an opaque handle.
    pub fn register_circuit<C: Circuit<F> + 'p>(&mut self, circuit: C) -> Result<Handle> {
        let handle = Handle {
            index: self.num_circuits,
        };
        let builder = self
            .inner
            .take()
            .expect("builder poisoned by a prior failed registration");
        self.inner = Some(builder.register_internal_circuit(circuit)?);
        self.num_circuits += 1;
        Ok(handle)
    }

    /// Registers a bonding object and returns an opaque handle.
    pub fn register_bonding(&mut self, bonding: BondingObject<'p, F, R>) -> Handle {
        let handle = Handle {
            index: self.num_circuits + self.num_bonding,
        };
        let builder = self
            .inner
            .take()
            .expect("builder poisoned by a prior failed registration");
        self.inner = Some(builder.register_bonding(bonding));
        self.num_bonding += 1;
        handle
    }

    /// Finalizes the builder into a [`TestRegistry`].
    pub fn finalize(self) -> Result<TestRegistry<'p, F, R>> {
        Ok(TestRegistry {
            inner: self
                .inner
                .expect("builder poisoned by a prior failed registration")
                .finalize()?,
        })
    }
}

/// A finalized registry wrapper that maps opaque handles to the correct
/// [`CircuitIndex`] for each registry operation.
pub struct TestRegistry<'p, F: PrimeField, R: Rank> {
    inner: Registry<'p, F, R>,
}

impl<F: PrimeField, R: Rank> TestRegistry<'_, F, R> {
    /// Assembles a [`Trace`] into a polynomial for the entry identified
    /// by `handle`, using the registry's key and floor plan. `alpha` is
    /// written to `d[0]` of the resulting polynomial; pass a random field
    /// element in production or `F::ZERO` in tests.
    pub fn assemble(
        &self,
        trace: &Trace<F>,
        handle: Handle,
        alpha: F,
    ) -> Result<sparse::Polynomial<F, R>> {
        self.inner
            .assemble_with_alpha(trace, handle.resolve(), alpha)
    }

    /// Returns $s(X, y)$ for the entry at `handle`.
    pub fn y(&self, handle: Handle, y: F) -> sparse::Polynomial<F, R> {
        self.inner.circuit_y(handle.resolve(), y)
    }

    /// Evaluates $s(x, y)$ for the entry at `handle`.
    pub fn xy(&self, handle: Handle, x: F, y: F) -> F {
        self.inner.circuit_xy(handle.resolve(), x, y)
    }
}
