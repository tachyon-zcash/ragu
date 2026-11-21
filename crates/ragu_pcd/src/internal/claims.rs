//! Common abstraction for orchestrating revdot claims.
//!
//! # Revdot claims
//!
//! A **revdot claim** asserts that two polynomials $a(X)$ and $b(X)$ satisfy
//! a reversed inner product on their coefficient vectors (see
//! [`sparse::Polynomial::revdot`]). In the proof system, each circuit stage
//! produces a claim of the form
//!
//! $$\operatorname{revdot}(a(X), b(X)) = k(Y),$$
//!
//! where $k(Y)$ is the public-input polynomial restricted at a verifier
//! challenge. Verifiers check these claims, and the folding machinery reduces
//! many such claims into a single claim plus a bounded set of error terms.
//!
//! This module provides helpers to build the $(a, b)$ pairs for each claim
//! and to aggregate them across proof components.

use alloc::{borrow::Cow, vec::Vec};
use core::{borrow::Borrow, marker::PhantomData};

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry},
};
use udon::field::Field;

/// Sum an iterator of polynomials, borrowing if only one element.
///
/// Returns `Cow::Borrowed` for a single polynomial, `Cow::Owned` for multiple.
/// Panics if the iterator is empty.
pub fn sum_polynomials<'rx, F: Field, R: Rank>(
    mut rxs: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>,
) -> Cow<'rx, sparse::Polynomial<F, R>> {
    let first = rxs.next().expect("must provide at least one rx polynomial");
    match rxs.next() {
        None => Cow::Borrowed(first),
        Some(second) => {
            let mut sum = first.clone();
            sum.add_assign(second);
            for rx in rxs {
                sum.add_assign(rx);
            }
            Cow::Owned(sum)
        }
    }
}

/// Trait for providing claim component values from sources.
///
/// This trait abstracts over what a "source" provides. For polynomial contexts
/// (verify, fuse), it provides polynomial references. For evaluation contexts
/// (`compute_v`), it provides single element evaluations (at $xz$).
///
/// Implementors provide access to rx values for all proofs they manage. The
/// `RxComponent` associated type defines which components can be requested.
pub trait Source {
    /// The type identifying which rx component to retrieve.
    type RxComponent: Copy;

    /// Opaque type for rx values.
    type Rx;

    /// Type for application circuit identifiers.
    type AppCircuitId;

    /// Get an iterator over rx values for all proofs for the given component.
    fn rx(&self, component: Self::RxComponent) -> impl Iterator<Item = Self::Rx>;

    /// Get an iterator over the application circuit claims this source
    /// folds, each paired with the rxs its trace sums: the step's own
    /// polynomial and the application stage's, in that order.
    fn applications(&self) -> impl Iterator<Item = (Self::AppCircuitId, [Self::Rx; 2])>;
}

/// Processor that builds polynomial vectors for revdot claims.
///
/// Accumulates (a, b) polynomial pairs for each claim type, using
/// the registry polynomial to transform rx polynomials appropriately.
/// A claim's `b` that depends on a circuit's restriction is only recorded
/// here; [`finish`](Self::finish) computes them all and returns the
/// [`Claims`].
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
    a: Vec<A>,
    /// How to obtain each claim's `b` polynomial, in claim order.
    b: Vec<Side<'rx, F, R>>,
    backend: PhantomData<B>,
}

/// A claim's `b` polynomial, or the circuit restriction it is derived from.
enum Side<'rx, F: Field, R: Rank> {
    /// The polynomial itself.
    Given(Cow<'rx, sparse::Polynomial<F, R>>),
    /// $r(zX) + s\_y + t(z)$ for the claim's own trace $r$ and the circuit's
    /// restriction $s\_y$.
    Circuit(CircuitIndex),
    /// The circuit's restriction $s\_y$.
    Bonding(CircuitIndex),
}

/// The polynomial pairs of a list of revdot claims, in claim order.
pub struct Claims<'rx, A, F: Field, R: Rank> {
    /// The claims' `a` polynomials.
    pub a: Vec<A>,
    /// The claims' `b` polynomials.
    pub b: Vec<Cow<'rx, sparse::Polynomial<F, R>>>,
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

    /// Push a claim whose `b` is given directly.
    pub fn raw_impl(&mut self, a: A, b: Cow<'rx, sparse::Polynomial<F, R>>) {
        self.a.push(a);
        self.b.push(Side::Given(b));
    }

    /// Push a circuit claim, whose `b` is $r(zX) + s\_y + t(z)$ for the
    /// polynomial $r$ that `a` borrows.
    pub fn circuit_impl(&mut self, circuit_id: CircuitIndex, a: A) {
        self.a.push(a);
        self.b.push(Side::Circuit(circuit_id));
    }

    /// Push a bonding claim. There is no dilation and no $t(z)$, so
    /// $b = s\_{y}$ and $k(y) = 0$.
    pub fn bonding_impl(&mut self, circuit_id: CircuitIndex, a: A) {
        self.a.push(a);
        self.b.push(Side::Bonding(circuit_id));
    }

    /// Computes every claim's `b` and returns the claims.
    ///
    /// Each circuit is restricted once, however many claims name it, and
    /// the restrictions and then the claims are independent work for the
    /// backend.
    pub fn finish(self) -> Claims<'rx, A, F, R>
    where
        A: Sync,
    {
        let Self {
            registry,
            y,
            z,
            tz,
            a,
            b,
            ..
        } = self;

        let mut circuits: Vec<usize> = b
            .iter()
            .filter_map(|side| match side {
                Side::Given(_) => None,
                Side::Circuit(id) | Side::Bonding(id) => Some(usize::from(*id)),
            })
            .collect();
        circuits.sort_unstable();
        circuits.dedup();
        let restrictions: Vec<sparse::Polynomial<F, R>> = B::map(circuits.iter(), |&circuit| {
            B::registry_circuit_y(registry, CircuitIndex::new(circuit), y)
        })
        .collect();
        let restriction = |id: CircuitIndex| {
            let position = circuits
                .binary_search(&usize::from(id))
                .expect("every named circuit was restricted");
            &restrictions[position]
        };

        let b = B::map(b.into_iter().zip(&a), |(side, a)| match side {
            Side::Given(b) => b,
            Side::Circuit(id) => {
                let mut b = a.borrow().clone();
                b.dilate(z);
                b.add_assign(restriction(id));
                b.add_assign(&tz);
                Cow::Owned(b)
            }
            Side::Bonding(id) => Cow::Owned(restriction(id).clone()),
        })
        .collect();

        Claims { a, b }
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
