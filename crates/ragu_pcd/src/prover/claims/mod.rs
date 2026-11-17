//! Polynomial construction for revdot claims.
use alloc::{borrow::Cow, vec::Vec};
use core::{borrow::Borrow, marker::PhantomData};

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry},
};
use udon::field::Field;
/// Processor that builds polynomial vectors for revdot claims.
///
/// Accumulates (a, b) polynomial pairs for each claim type, using
/// the registry polynomial to transform rx polynomials appropriately.
///
/// The type parameter `A` determines what is stored in the `a` vector:
/// - Verify path: `A = Cow<'rx, Polynomial>` (plain polynomial references)
/// - Fuse path: `A = TrackedPoly<'rx, FoldKey, F, R>` (polynomial +
///   commitment decomposition; see `fuse::claims`)
pub struct Builder<'m, 'rx, A, F: Field, R: Rank, B: Backend> {
    pub registry: &'m Registry<'m, F, R>,
    pub y: F,
    pub z: F,
    pub tz: sparse::Polynomial<F, R>,
    /// The accumulated `a` polynomials.
    pub a: Vec<A>,
    /// The accumulated `b` polynomials for revdot claims.
    pub b: Vec<Cow<'rx, sparse::Polynomial<F, R>>>,
    backend: PhantomData<B>,
}

impl<'m, 'rx, A, F: Field, R: Rank, B: Backend> Builder<'m, 'rx, A, F, R, B>
where
    A: Borrow<sparse::Polynomial<F, R>>,
{
    /// Create a new claim builder.
    pub fn new(registry: &'m Registry<'m, F, R>, y: F, z: F) -> Self {
        Self {
            registry,
            y,
            z,
            tz: R::tz(z),
            a: Vec::new(),
            b: Vec::new(),
            backend: PhantomData,
        }
    }

    /// Push a circuit claim. Computes `b` from `a.borrow()` (the polynomial).
    pub fn circuit_impl(&mut self, circuit_id: CircuitIndex, a: A) {
        let rx = a.borrow();
        let sy = B::registry_circuit_y(self.registry, circuit_id, self.y);
        let mut b = rx.clone();
        b.dilate(self.z);
        b.add_assign(&sy);
        b.add_assign(&self.tz);
        self.a.push(a);
        self.b.push(Cow::Owned(b));
    }

    /// Push a bonding claim. There is no dilation and no $t(z)$, so
    /// $b = s\_{y}$ and $k(y) = 0$.
    pub fn bonding_impl(&mut self, circuit_id: CircuitIndex, a: A) {
        let sy = B::registry_circuit_y(self.registry, circuit_id, self.y);
        self.a.push(a);
        self.b.push(Cow::Owned(sy));
    }

    /// Horner-fold groups of polynomials. Each group is first summed, then
    /// the sums are Horner-folded with $z$.
    ///
    /// The fold gives group `i` coefficient $z^{n-1-i}$. Callers that track
    /// commitment decompositions must assign the same coefficients to the
    /// corresponding source keys.
    ///
    /// Folding is sound because the revdot identity for bonding polynomials is
    /// linear in the trace.
    pub fn fold_bonding_groups(
        &self,
        groups: impl Iterator<Item = impl Iterator<Item = &'rx sparse::Polynomial<F, R>>>,
    ) -> Cow<'rx, sparse::Polynomial<F, R>> {
        Cow::Owned(sparse::Polynomial::fold(
            groups.map(|g| sum_polynomials(g)),
            self.z,
        ))
    }
}

mod native;
mod nested;

use crate::protocol::claims::sum_polynomials;
