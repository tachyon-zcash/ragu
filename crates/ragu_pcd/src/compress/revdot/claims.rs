//! The revdot claims as the compressed verifier sees them: by shape.
//!
//! The decider builds each claim's $a$ and $b$ as polynomials through
//! [`claims::Builder`] and checks $\operatorname{revdot}(a, b) = k(y)$. The
//! compressed verifier holds no polynomials, only the components'
//! commitments, so this module runs the same [`native::claims::build`] and
//! [`nested::claims::build`] with a processor that records each claim's
//! [`Shape`]: which components its $a$ sums, with what weights, and what
//! [`Kind`] of $b$ goes with it, a committed polynomial of its own, the
//! dilated $a$ plus the circuit's wiring restriction and $t(z, X)$, or that
//! restriction alone. The [`fold`](super::fold) derives the
//! commitments it opens from the shapes, and the verifier evaluates the
//! public parts itself. The compressor, holding the polynomials, uses the
//! builder for the claims and the shapes for their kinds; both sides
//! enumerate the claims through the same `build`, so the order and the
//! targets line up.
//!
//! [`claims::Builder`]: crate::internal::claims::Builder

use alloc::{vec, vec::Vec};
use core::iter::{empty, once};

use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::Result;
use udon::field::Field;

use crate::internal::{
    claims::Source,
    native::{self, APPLICATION_SLOTS},
    nested,
};

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
    /// A claim over `poly` pinning the wire at each of `degrees` to the
    /// value at the same position of `values`.
    ///
    /// # Panics
    ///
    /// Panics if the lists differ in length or a degree repeats. Both lists
    /// come from the verifier's own code, the degrees from the stage layouts
    /// and the values from the instance and the registry, so either is a
    /// programming error rather than a malformed proof: zipping would
    /// silently drop the tail of the longer list, and a repeated degree
    /// would make [`mask`](Self::mask) overwrite the weight that
    /// [`mask_at`](Self::mask_at) sums.
    pub(crate) fn new(poly: Id, degrees: Vec<usize>, values: Vec<F>, sigma: F) -> Self {
        assert_eq!(
            degrees.len(),
            values.len(),
            "a wire binding needs one value per wire"
        );
        for (i, degree) in degrees.iter().enumerate() {
            assert!(
                !degrees[..i].contains(degree),
                "a wire binding lists degree {degree} twice"
            );
        }
        Masked {
            poly,
            wires: degrees.into_iter().zip(values).collect(),
            sigma,
        }
    }

    /// $E(r)$.
    pub(crate) fn expected_at(&self, r: F) -> F {
        self.wires.iter().fold(F::ZERO, |acc, &(degree, expected)| {
            acc + expected * r.pow_u64(degree as u64)
        })
    }

    /// $M(r)$.
    pub(crate) fn mask_at<R: Rank>(&self, r: F) -> F {
        let (mut acc, mut weight) = (F::ZERO, F::ONE);
        for &(degree, _) in &self.wires {
            acc += weight * r.pow_u64((R::num_coeffs() - 1 - degree) as u64);
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

/// What a claim's $b$ is, beside the committed components its shape lists.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Kind {
    /// $b$ is the committed polynomial the shape's `b` lists; $k = c$.
    Raw,
    /// $b = a(zX) + s(X, y) + t(z, X)$ for the circuit's wiring restriction
    /// $s$.
    Circuit(CircuitIndex),
    /// $b = s(X, y)$; $k = 0$.
    Bonding(CircuitIndex),
    /// The wire binding at this position of the verifier's list: $a = Q -
    /// E$ over the stage polynomial the shape's `a` lists, $b = M$, $k = 0$.
    Masked(usize),
}

/// A claim's committed structure: $a$, and a raw claim's $b$, as weighted
/// sums of components.
#[derive(Clone, Debug)]
pub(crate) struct Shape<Id, F> {
    pub kind: Kind,
    pub a: Vec<(F, Id)>,
    pub b: Vec<(F, Id)>,
}

/// A [`Source`] over one proof's native components, by identity.
struct NativeIds {
    circuit_ids: [CircuitIndex; APPLICATION_SLOTS],
}

impl Source for NativeIds {
    type RxComponent = native::RxComponent;
    type Rx = native::RxComponent;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: native::RxComponent) -> impl Iterator<Item = native::RxComponent> {
        once(component)
    }

    fn app_circuits(&self, slot: usize) -> impl Iterator<Item = CircuitIndex> {
        once(self.circuit_ids[slot])
    }
}

impl native::claims::ApplicationSource for NativeIds {
    type IsBundle = bool;

    fn is_split_bundle(&self) -> impl Iterator<Item = bool> {
        once(native::is_split_bundle(self.circuit_ids))
    }
}

/// A [`Source`] over one proof's nested components, by identity.
struct NestedIds;

impl Source for NestedIds {
    type RxComponent = nested::RxComponent;
    type Rx = nested::RxComponent;
    type AppCircuitId = ();

    fn rx(&self, component: nested::RxComponent) -> impl Iterator<Item = nested::RxComponent> {
        once(component)
    }

    fn app_circuits(&self, _: usize) -> impl Iterator<Item = ()> {
        empty()
    }
}

/// The processor over component identities: the structural counterpart of
/// [`claims::Builder`](crate::internal::claims::Builder).
struct Shaper<Id, F> {
    z: F,
    shapes: Vec<Shape<Id, F>>,
}

impl<Id, F: Field> Shaper<Id, F> {
    fn push(&mut self, kind: Kind, a: Vec<(F, Id)>, b: Vec<(F, Id)>) {
        self.shapes.push(Shape { kind, a, b });
    }

    /// A circuit claim over the sum of `rxs`.
    fn circuit(&mut self, circuit: CircuitIndex, rxs: impl Iterator<Item = Id>) {
        let a = rxs.map(|rx| (F::ONE, rx)).collect();
        self.push(Kind::Circuit(circuit), a, Vec::new());
    }

    /// A bonding claim over the Horner fold of per-group sums under $z$, as
    /// [`sparse::Polynomial::fold`](ragu_circuits::polynomials::sparse::Polynomial::fold)
    /// weights it.
    fn bonding(
        &mut self,
        circuit: CircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Id>>,
    ) {
        let mut a: Vec<(F, Id)> = Vec::new();
        for group in groups {
            for (weight, _) in &mut a {
                *weight *= self.z;
            }
            a.extend(group.map(|rx| (F::ONE, rx)));
        }
        self.push(Kind::Bonding(circuit), a, Vec::new());
    }
}

impl<Id, F: Field> native::claims::Processor<Id, CircuitIndex> for Shaper<Id, F> {
    fn raw_claim(&mut self, a: Id, b: Id) {
        self.push(Kind::Raw, vec![(F::ONE, a)], vec![(F::ONE, b)]);
    }

    fn circuit_claim(&mut self, circuit_id: CircuitIndex, rxs: impl Iterator<Item = Id>) {
        self.circuit(circuit_id, rxs);
    }

    fn internal_circuit_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = Id>,
    ) {
        self.circuit(id.circuit_index(), rxs);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Id>>,
    ) -> Result<()> {
        self.bonding(id.circuit_index(), groups);
        Ok(())
    }

    fn application_bonding_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = (Id, bool)>,
    ) -> Result<()> {
        self.bonding(
            id.circuit_index(),
            rxs.map(|(rx, is_bundle)| once(rx).filter(move |_| is_bundle)),
        );
        Ok(())
    }
}

impl<Id, F: Field> nested::claims::Processor<Id> for Shaper<Id, F> {
    fn raw_claim(&mut self, a: Id, b: Id) {
        self.push(Kind::Raw, vec![(F::ONE, a)], vec![(F::ONE, b)]);
    }

    fn internal_circuit_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        rxs: impl Iterator<Item = Id>,
    ) {
        self.circuit(id.circuit_index(), rxs);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Id>>,
    ) -> Result<()> {
        self.bonding(id.circuit_index(), groups);
        Ok(())
    }
}

/// The wire bindings' shapes, after the decider's claims.
fn with_masked<Id: Copy, F: Field>(
    mut shapes: Vec<Shape<Id, F>>,
    masked: &[Masked<Id, F>],
) -> Vec<Shape<Id, F>> {
    shapes.extend(masked.iter().enumerate().map(|(m, masked)| Shape {
        kind: Kind::Masked(m),
        a: vec![(F::ONE, masked.poly)],
        b: Vec::new(),
    }));
    shapes
}

/// The shapes of the native claims of a proof whose application slots run
/// `circuit_ids`, in the decider's order, then the `masked` wire claims in
/// theirs.
pub(crate) fn native_shapes<F: Field>(
    circuit_ids: [CircuitIndex; APPLICATION_SLOTS],
    z: F,
    masked: &[Masked<native::RxComponent, F>],
) -> Result<Vec<Shape<native::RxComponent, F>>> {
    let mut shaper = Shaper {
        z,
        shapes: Vec::new(),
    };
    native::claims::build(&NativeIds { circuit_ids }, &mut shaper)?;
    Ok(with_masked(shaper.shapes, masked))
}

/// The shapes of the nested claims of a proof, as [`native_shapes`] lists
/// them.
pub(crate) fn nested_shapes<F: Field>(
    z: F,
    masked: &[Masked<nested::RxComponent, F>],
) -> Result<Vec<Shape<nested::RxComponent, F>>> {
    let mut shaper = Shaper {
        z,
        shapes: Vec::new(),
    };
    nested::claims::build(&NestedIds, &mut shaper)?;
    Ok(with_masked(shaper.shapes, masked))
}

#[cfg(test)]
#[path = "../../../tests/compress_claims.rs"]
mod tests;
