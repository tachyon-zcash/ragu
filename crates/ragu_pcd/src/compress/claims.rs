//! The revdot claims evaluated from openings.
//!
//! The decider builds each claim's $a$ and $b$ as polynomials through
//! [`claims::Builder`] and checks $\operatorname{revdot}(a, b) = k(y)$. The
//! compressed verifier holds no polynomials, only each committed
//! polynomial's openings at a point $r$ and at $rz$, so this module runs
//! the same [`native::claims::build`] and [`nested::claims::build`] with a
//! processor over those openings, producing each claim's $(a(r), b(r))$
//! and its target: $a(r)$ sums the openings at $r$, and $b(r)$ is either a
//! committed polynomial's own opening, the openings at $rz$ plus the
//! circuit's wiring restriction and $t(z)$ at $r$, or that restriction
//! alone. The compressor, holding the polynomials, uses the builder itself;
//! both sides enumerate the claims through the same `build`, so the order
//! and the targets line up.
//!
//! [`claims::Builder`]: crate::internal::claims::Builder

use alloc::vec::Vec;
use core::iter::{empty, once};

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::Result;

use crate::{
    Proof,
    internal::{
        claims::Source,
        ky::{NativeKy, NestedKy},
        native, nested,
    },
};

/// A committed polynomial's openings at the query point and at its dilation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Opened<F> {
    /// The value at $r$.
    pub at_r: F,
    /// The value at $rz$.
    pub at_rz: F,
}

/// A claim pinning wires of a committed stage polynomial $Q$ to expected
/// values: with $E = \sum_j e_j X^{d_j}$ over the wires' degrees and
/// $M = \sum_j \sigma^j X^{N - 1 - d_j}$ for a verifier challenge $\sigma$,
/// $\operatorname{revdot}(Q - E, M) = \sum_j \sigma^j (Q\[d_j\] - e_j)$, which
/// is zero exactly when every wire holds its expected value, with
/// overwhelming probability over $\sigma$. Its target is zero.
#[derive(Clone, Debug)]
pub(crate) struct Masked<Id, F> {
    /// The stage polynomial.
    pub poly: Id,
    /// The expected value at each wire, by coefficient degree.
    pub wires: Vec<(usize, F)>,
    /// The challenge weighting the wires.
    pub sigma: F,
}

impl<Id, F: Field> Masked<Id, F> {
    /// $E(r)$.
    pub(crate) fn expected_at(&self, r: F) -> F {
        self.wires.iter().fold(F::ZERO, |acc, &(degree, expected)| {
            acc + expected * r.pow_vartime([degree as u64])
        })
    }

    /// $M(r)$.
    pub(crate) fn mask_at<R: Rank>(&self, r: F) -> F {
        let (mut acc, mut weight) = (F::ZERO, F::ONE);
        for &(degree, _) in &self.wires {
            acc += weight * r.pow_vartime([(R::num_coeffs() - 1 - degree) as u64]);
            weight *= self.sigma;
        }
        acc
    }

    /// $E$ as a polynomial.
    pub(crate) fn expected<R: Rank>(&self) -> sparse::Polynomial<F, R> {
        let mut coeffs = alloc::vec![F::ZERO; R::num_coeffs()];
        for &(degree, expected) in &self.wires {
            coeffs[degree] = expected;
        }
        sparse::Polynomial::from_coeffs(coeffs)
    }

    /// $M$ as a polynomial.
    pub(crate) fn mask<R: Rank>(&self) -> sparse::Polynomial<F, R> {
        let mut coeffs = alloc::vec![F::ZERO; R::num_coeffs()];
        let mut weight = F::ONE;
        for &(degree, _) in &self.wires {
            coeffs[R::num_coeffs() - 1 - degree] = weight;
            weight *= self.sigma;
        }
        sparse::Polynomial::from_coeffs(coeffs)
    }
}

/// One claim evaluated at $r$: $a(r)$, $b(r)$ and the target $k(y)$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Evaluated<F> {
    /// $a(r)$.
    pub a: F,
    /// $b(r)$.
    pub b: F,
    /// The target $k(y)$.
    pub k: F,
}

/// The decider's polynomial [`Source`] over one proof, the raw accumulator
/// claim included: what the compressor feeds
/// [`claims::Builder`](crate::internal::claims::Builder).
pub(crate) struct NativePolys<'a, C: Cycle, R: Rank>(pub &'a Proof<C, R>);

impl<'a, C: Cycle, R: Rank> Source for NativePolys<'a, C, R> {
    type RxComponent = native::RxComponent;
    type Rx = &'a sparse::Polynomial<C::CircuitField, R>;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: native::RxComponent) -> impl Iterator<Item = Self::Rx> {
        once(&self.0[component])
    }

    fn app_circuits(&self) -> impl Iterator<Item = CircuitIndex> {
        once(self.0.circuit_id())
    }
}

/// The nested counterpart of [`NativePolys`].
pub(crate) struct NestedPolys<'a, C: Cycle, R: Rank>(pub &'a Proof<C, R>);

impl<'a, C: Cycle, R: Rank> Source for NestedPolys<'a, C, R> {
    type RxComponent = nested::RxComponent;
    type Rx = &'a sparse::Polynomial<C::ScalarField, R>;
    type AppCircuitId = ();

    fn rx(&self, component: nested::RxComponent) -> impl Iterator<Item = Self::Rx> {
        once(&self.0[component])
    }

    fn app_circuits(&self) -> impl Iterator<Item = ()> {
        empty()
    }
}

/// A [`Source`] over one proof's native openings.
struct NativeOpenings<G> {
    circuit_id: CircuitIndex,
    open: G,
}

impl<F, G: Fn(native::RxComponent) -> Opened<F>> Source for NativeOpenings<&G> {
    type RxComponent = native::RxComponent;
    type Rx = Opened<F>;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: native::RxComponent) -> impl Iterator<Item = Opened<F>> {
        once((self.open)(component))
    }

    fn app_circuits(&self) -> impl Iterator<Item = CircuitIndex> {
        once(self.circuit_id)
    }
}

/// A [`Source`] over one proof's nested openings.
struct NestedOpenings<G> {
    open: G,
}

impl<F, G: Fn(nested::RxComponent) -> Opened<F>> Source for NestedOpenings<&G> {
    type RxComponent = nested::RxComponent;
    type Rx = Opened<F>;
    type AppCircuitId = ();

    fn rx(&self, component: nested::RxComponent) -> impl Iterator<Item = Opened<F>> {
        once((self.open)(component))
    }

    fn app_circuits(&self) -> impl Iterator<Item = ()> {
        empty()
    }
}

/// The processor over openings: the evaluation counterpart of
/// [`claims::Builder`](crate::internal::claims::Builder).
struct Evaluator<F, S> {
    z: F,
    /// $t(z, X)$ at $r$.
    tz: F,
    /// A circuit's wiring restriction $s(X, y)$ at $r$.
    restriction: S,
    claims: Vec<Evaluated<F>>,
}

impl<F: Field, S: Fn(CircuitIndex) -> F> Evaluator<F, S> {
    fn push(&mut self, a: F, b: F) {
        self.claims.push(Evaluated { a, b, k: F::ZERO });
    }

    /// A circuit claim over the sum of `rxs`: $b = a(zX) + s(X, y) + t(z, X)$.
    fn circuit(&mut self, circuit: CircuitIndex, rxs: impl Iterator<Item = Opened<F>>) {
        let (a, dilated) = rxs.fold((F::ZERO, F::ZERO), |(a, dilated), rx| {
            (a + rx.at_r, dilated + rx.at_rz)
        });
        let b = dilated + (self.restriction)(circuit) + self.tz;
        self.push(a, b);
    }

    /// A bonding claim over the Horner fold of per-group sums under $z$, as
    /// [`sparse::Polynomial::fold`](ragu_circuits::polynomials::sparse::Polynomial::fold)
    /// weights it: $b = s(X, y)$.
    fn bonding(
        &mut self,
        circuit: CircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Opened<F>>>,
    ) {
        let a = groups.fold(F::ZERO, |acc, group| {
            acc * self.z + group.fold(F::ZERO, |sum, rx| sum + rx.at_r)
        });
        let b = (self.restriction)(circuit);
        self.push(a, b);
    }
}

impl<F: Field, S: Fn(CircuitIndex) -> F> native::claims::Processor<Opened<F>, CircuitIndex>
    for Evaluator<F, S>
{
    fn raw_claim(&mut self, a: Opened<F>, b: Opened<F>) {
        self.push(a.at_r, b.at_r);
    }

    fn circuit_claim(&mut self, circuit_id: CircuitIndex, rx: Opened<F>) {
        self.circuit(circuit_id, once(rx));
    }

    fn internal_circuit_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = Opened<F>>,
    ) {
        self.circuit(id.circuit_index(), rxs);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Opened<F>>>,
    ) -> Result<()> {
        self.bonding(id.circuit_index(), groups);
        Ok(())
    }
}

impl<F: Field, S: Fn(CircuitIndex) -> F> nested::claims::Processor<Opened<F>> for Evaluator<F, S> {
    fn raw_claim(&mut self, a: Opened<F>, b: Opened<F>) {
        self.push(a.at_r, b.at_r);
    }

    fn internal_circuit_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        rxs: impl Iterator<Item = Opened<F>>,
    ) {
        self.circuit(id.circuit_index(), rxs);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Opened<F>>>,
    ) -> Result<()> {
        self.bonding(id.circuit_index(), groups);
        Ok(())
    }
}

/// The native claims of a proof whose application circuit is `circuit_id`,
/// evaluated at `r` from `open`, the openings of each committed polynomial,
/// and `restriction`, each circuit's wiring restriction $s(X, y)$ at `r`;
/// then the `masked` wire claims, in their order.
pub(crate) fn native<R: Rank, F: Field>(
    circuit_id: CircuitIndex,
    r: F,
    z: F,
    open: impl Fn(native::RxComponent) -> Opened<F>,
    restriction: impl Fn(CircuitIndex) -> F,
    targets: &NativeKy<F>,
    masked: &[Masked<native::RxComponent, F>],
) -> Result<Vec<Evaluated<F>>> {
    let mut evaluator = Evaluator {
        z,
        tz: R::tz(z).eval(r),
        restriction,
        claims: Vec::new(),
    };
    native::claims::build(
        &NativeOpenings {
            circuit_id,
            open: &open,
        },
        &mut evaluator,
    )?;
    let mut claims = with_targets(evaluator.claims, native::claims::ky_values(targets));
    claims.extend(masked.iter().map(|masked| Evaluated {
        a: open(masked.poly).at_r - masked.expected_at(r),
        b: masked.mask_at::<R>(r),
        k: F::ZERO,
    }));
    Ok(claims)
}

/// The nested claims of a proof, evaluated at `r` from `open` and
/// `restriction` as [`native()`] takes them, then the `masked` wire claims.
pub(crate) fn nested<R: Rank, F: Field>(
    r: F,
    z: F,
    open: impl Fn(nested::RxComponent) -> Opened<F>,
    restriction: impl Fn(CircuitIndex) -> F,
    targets: &NestedKy<F>,
    masked: &[Masked<nested::RxComponent, F>],
) -> Result<Vec<Evaluated<F>>> {
    let mut evaluator = Evaluator {
        z,
        tz: R::tz(z).eval(r),
        restriction,
        claims: Vec::new(),
    };
    nested::claims::build(&NestedOpenings { open: &open }, &mut evaluator)?;
    let mut claims = with_targets(evaluator.claims, nested::claims::ky_values(targets));
    claims.extend(masked.iter().map(|masked| Evaluated {
        a: open(masked.poly).at_r - masked.expected_at(r),
        b: masked.mask_at::<R>(r),
        k: F::ZERO,
    }));
    Ok(claims)
}

/// Pairs the evaluated claims with their targets, in claim order.
fn with_targets<F>(
    mut claims: Vec<Evaluated<F>>,
    targets: impl Iterator<Item = F>,
) -> Vec<Evaluated<F>> {
    for (claim, k) in claims.iter_mut().zip(targets) {
        claim.k = k;
    }
    claims
}

#[cfg(test)]
#[path = "../../tests/compress_claims.rs"]
mod tests;
