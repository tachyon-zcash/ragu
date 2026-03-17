//! Common abstraction for orchestrating revdot claims.

use ff::{Field, PrimeField};
use ragu_circuits::{
    polynomials::{Rank, structured},
    registry::{CircuitIndex, Registry},
};

use alloc::{borrow::Cow, vec::Vec};
use core::borrow::Borrow;

/// Sum an iterator of polynomials, borrowing if only one element.
///
/// Returns `Cow::Borrowed` for a single polynomial, `Cow::Owned` for multiple.
/// Panics if the iterator is empty.
pub fn sum_polynomials<'rx, F: Field, R: Rank>(
    mut rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
) -> Cow<'rx, structured::Polynomial<F, R>> {
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

    /// Get an iterator over application circuit info for all proofs.
    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId>;
}

/// Either a per-proof value iterator or a single zero.
pub(crate) enum KyIter<A, B> {
    Value(A),
    Zero(B),
}

impl<T, A: Iterator<Item = T>, B: Iterator<Item = T>> Iterator for KyIter<A, B> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        match self {
            Self::Value(a) => a.next(),
            Self::Zero(b) => b.next(),
        }
    }
}

/// Trait for providing $k(y)$ values for claim verification.
pub(crate) trait KySource {
    /// The $k(y)$ value type.
    type Item: Clone;

    /// Returns $k(y)$ values in claim order.
    fn ky_values(&self) -> impl Iterator<Item = Self::Item>;

    /// The zero value for stage claims.
    fn zero(&self) -> Self::Item;

    /// Returns $k(y)$ values in claim order, followed by infinite zeros.
    fn padded_ky_values(&self) -> impl Iterator<Item = Self::Item> {
        let zero = self.zero();
        self.ky_values().chain(core::iter::repeat(zero))
    }
}

/// Processor that builds polynomial vectors for revdot claims.
///
/// Accumulates (a, b) polynomial pairs for each claim type, using
/// the registry polynomial to transform rx polynomials appropriately.
///
/// The type parameter `A` determines what is stored in the `a` vector:
/// - Verify path: `A = Cow<'rx, Polynomial>` (plain polynomial references)
/// - Fuse path: `A = TrackedPoly<'rx, FuseAtom, F, R>` (polynomial +
///   commitment decomposition; see `fuse::claims`)
pub struct Builder<'m, 'rx, A, F: PrimeField, R: Rank> {
    pub registry: &'m Registry<'m, F, R>,
    pub y: F,
    pub z: F,
    pub tz: structured::Polynomial<F, R>,
    /// The accumulated `a` polynomials.
    pub a: Vec<A>,
    /// The accumulated `b` polynomials for revdot claims.
    pub b: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
}

impl<'m, 'rx, A, F: PrimeField, R: Rank> Builder<'m, 'rx, A, F, R>
where
    A: Borrow<structured::Polynomial<F, R>>,
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
        }
    }

    /// Push a circuit claim. Computes `b` from `a.borrow()` (the polynomial).
    pub fn circuit_impl(&mut self, circuit_id: CircuitIndex, a: A) {
        let rx = a.borrow();
        let sy = self.registry.circuit_y(circuit_id, self.y);
        let mut b = rx.clone();
        b.dilate(self.z);
        b.add_assign(&sy);
        b.add_assign(&self.tz);
        self.a.push(a);
        self.b.push(Cow::Owned(b));
    }

    /// Push a stage claim. `b` is just `sy` (no rx transformation).
    pub fn stage_impl(&mut self, circuit_id: CircuitIndex, a: A) {
        let sy = self.registry.circuit_y(circuit_id, self.y);
        self.a.push(a);
        self.b.push(Cow::Owned(sy));
    }

    /// Horner-fold polynomial references. Returns `Cow::Borrowed` for a single
    /// element, `Cow::Owned` for multiple.
    ///
    /// The fold gives item `i` coefficient `z^(n-1-i)`. Callers that track
    /// commitment decompositions must assign the same coefficients to the
    /// corresponding source keys.
    pub fn fold_stage_polys(
        &self,
        mut rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
    ) -> Cow<'rx, structured::Polynomial<F, R>> {
        let first = rxs.next().expect("must provide at least one rx polynomial");
        match rxs.next() {
            None => Cow::Borrowed(first),
            Some(second) => Cow::Owned(structured::Polynomial::fold(
                core::iter::once(first)
                    .chain(core::iter::once(second))
                    .chain(rxs),
                self.z,
            )),
        }
    }
}
