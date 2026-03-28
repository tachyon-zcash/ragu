//! Fuse-path claim source and commitment tracking.
//!
//! In the fuse pipeline the `A` polynomials need to carry their corresponding
//! commitments so that `_06_ab` can compute `a_commitment` via a small MSM
//! over known child-proof commitments instead of a full polynomial-degree MSM.
//!
//! Each polynomial entering the claims pipeline is tagged with a [`FoldKey`]
//! key — a `(`[`Side`]`, `[`RxComponent`]`)` pair identifying which child
//! proof and component it came from. As polynomials are summed and folded,
//! the corresponding [`CommitmentDecomposition`] accumulates the linear
//! combination of those keys, so the final commitment can be resolved
//! directly from the child proofs.

use alloc::{borrow::Cow, vec::Vec};
use core::borrow::Borrow;

use ff::{Field, PrimeField};
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::Result;

use crate::{
    Proof,
    internal::{
        claims::{Builder, Source, sum_polynomials},
        fold_revdot::{self, Foldable},
        native::{InternalCircuitIndex, RxComponent, claims::Processor},
    },
};

/// Tracks how a polynomial decomposes as a linear combination of source
/// polynomials, so that the corresponding commitment can be computed from
/// the source commitments via a small MSM.
///
/// Each term `(key, coefficient)` records that this polynomial includes
/// `coefficient * source[key]`. The same key may appear multiple times;
/// duplicates are summed during resolution. The key type `K` is chosen by
/// the caller (the fuse path uses [`FoldKey`]).
#[derive(Clone)]
pub(super) struct CommitmentDecomposition<K, F: Field> {
    pub(super) terms: Vec<(K, F)>,
}

impl<K, F: Field> Default for CommitmentDecomposition<K, F> {
    fn default() -> Self {
        Self { terms: Vec::new() }
    }
}

impl<K: Copy, F: Field> CommitmentDecomposition<K, F> {
    /// Decomposition for a single source polynomial with coefficient one.
    pub(super) fn single(key: K) -> Self {
        Self {
            terms: Vec::from([(key, F::ONE)]),
        }
    }
}

/// A polynomial paired with its [`CommitmentDecomposition`].
///
/// In the fuse pipeline, the `A` polynomials need to carry their
/// corresponding commitments so that `a_commitment` can be computed cheaply.
/// Rather than materializing the commitment at each fold step, we track the
/// linear combination of source polynomials and resolve to commitments once
/// at the end. Implements [`Foldable`] so it flows through [`fold_inner`]
/// / [`fold_outer`] transparently.
///
/// The polynomial is held as a [`Cow`] to avoid cloning borrowed polynomials
/// during claim building; the fold itself always produces owned results.
///
/// [`Cow`]: alloc::borrow::Cow
/// [`fold_inner`]: crate::internal::fold_revdot::fold_inner
/// [`fold_outer`]: crate::internal::fold_revdot::fold_outer
#[derive(Clone)]
pub(super) struct TrackedPoly<'a, K, F: Field, R: Rank> {
    pub(super) poly: Cow<'a, sparse::Polynomial<F, R>>,
    pub(super) decomp: CommitmentDecomposition<K, F>,
}

impl<K, F: Field, R: Rank> Default for TrackedPoly<'_, K, F, R> {
    fn default() -> Self {
        Self {
            poly: Default::default(),
            decomp: Default::default(),
        }
    }
}

impl<'a, K: Copy, F: Field, R: Rank> TrackedPoly<'a, K, F, R> {
    pub(super) fn new(
        poly: Cow<'a, sparse::Polynomial<F, R>>,
        decomp: CommitmentDecomposition<K, F>,
    ) -> Self {
        Self { poly, decomp }
    }

    pub(super) fn single(poly: Cow<'a, sparse::Polynomial<F, R>>, key: K) -> Self {
        Self::new(poly, CommitmentDecomposition::single(key))
    }
}

impl<K: Copy, F: Field, R: Rank> Foldable<F> for TrackedPoly<'_, K, F, R> {
    fn fold_scale(&mut self, by: F) {
        self.poly.to_mut().scale(by);
        for (_, coeff) in &mut self.decomp.terms {
            *coeff *= by;
        }
    }
    fn fold_add_assign(&mut self, other: &Self) {
        self.poly.to_mut().add_assign(&other.poly);
        self.decomp.terms.extend_from_slice(&other.decomp.terms);
    }
}

impl<K, F: Field, R: Rank> Borrow<sparse::Polynomial<F, R>> for TrackedPoly<'_, K, F, R> {
    fn borrow(&self) -> &sparse::Polynomial<F, R> {
        &self.poly
    }
}

/// A polynomial reference paired with a key that identifies the corresponding
/// commitment in the child proofs.
///
/// The fuse pipeline threads these through the claims builder so that each
/// `A` polynomial retains a link back to its commitment.
pub(super) struct Atom<'rx, K, F: Field, R: Rank> {
    pub(super) key: K,
    pub(super) poly: &'rx sparse::Polynomial<F, R>,
}

// Manual Copy/Clone: derive(Copy) would add spurious F: Copy and R: Copy bounds.
// Atom only holds a reference (always Copy) and a K (bounded K: Copy here).
impl<K: Copy, F: Field, R: Rank> Clone for Atom<'_, K, F, R> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<K: Copy, F: Field, R: Rank> Copy for Atom<'_, K, F, R> {}

/// Identifies which of the two child proofs a polynomial came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Side {
    Left,
    Right,
}

/// Key identifying a polynomial and its corresponding commitment within the
/// fuse pipeline: which child proof, and which component of that proof.
pub(super) type FoldKey = (Side, RxComponent);

/// The two child proofs being fused. Provides [`Atom`]-tagged rx values
/// for claim building, and resolves [`FoldKey`] keys back to their
/// commitments for the MSM in `_06_ab`.
pub(super) struct FuseProofSource<'rx, C: Cycle, R: Rank> {
    pub(super) left: &'rx Proof<C, R>,
    pub(super) right: &'rx Proof<C, R>,
}

impl<'rx, C: Cycle, R: Rank> FuseProofSource<'rx, C, R> {
    /// Look up the commitment for a [`FoldKey`] in the corresponding child
    /// proof.
    pub(super) fn get(&self, (side, component): FoldKey) -> C::HostCurve {
        let proof = match side {
            Side::Left => self.left,
            Side::Right => self.right,
        };
        match component {
            RxComponent::AbA => proof.ab.native.a_commitment,
            RxComponent::AbB => proof.ab.native.b_commitment,
            RxComponent::Rx(idx) => proof[idx].commitment,
        }
    }
}

impl<'rx, C: Cycle, R: Rank> Source for FuseProofSource<'rx, C, R> {
    type RxComponent = RxComponent;
    type Rx = Atom<'rx, FoldKey, C::CircuitField, R>;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
        [
            Atom {
                key: (Side::Left, component),
                poly: self.left.native_rx(component),
            },
            Atom {
                key: (Side::Right, component),
                poly: self.right.native_rx(component),
            },
        ]
        .into_iter()
    }

    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
        [
            self.left.application.circuit_id,
            self.right.application.circuit_id,
        ]
        .into_iter()
    }
}

/// [`Builder`] specialized for the fuse pipeline, where `A`
/// polynomials carry [`CommitmentDecomposition`]s via [`TrackedPoly`].
pub(super) type FuseBuilder<'m, 'rx, F, R> =
    Builder<'m, 'rx, TrackedPoly<'rx, FoldKey, F, R>, F, R>;

/// Fuse-path [`Processor`] implementation.
///
/// Each method pairs the polynomial with a [`CommitmentDecomposition`] that
/// records how it decomposes as a linear combination of child-proof
/// polynomials (and therefore their commitments). The decomposition is
/// consumed in `_06_ab` to compute `a_commitment` via MSM.
impl<'m, 'rx, F: PrimeField, R: Rank> Processor<Atom<'rx, FoldKey, F, R>, CircuitIndex>
    for Builder<'m, 'rx, TrackedPoly<'rx, FoldKey, F, R>, F, R>
{
    fn raw_claim(&mut self, a: Atom<'rx, FoldKey, F, R>, b: Atom<'rx, FoldKey, F, R>) {
        self.a
            .push(TrackedPoly::single(Cow::Borrowed(a.poly), a.key));
        self.b.push(Cow::Borrowed(b.poly));
    }

    fn circuit(&mut self, circuit_id: CircuitIndex, rx: Atom<'rx, FoldKey, F, R>) {
        self.circuit_impl(
            circuit_id,
            TrackedPoly::single(Cow::Borrowed(rx.poly), rx.key),
        );
    }

    fn internal_circuit(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = Atom<'rx, FoldKey, F, R>>,
    ) {
        let atoms: Vec<_> = rxs.collect();
        // Plain sum: poly = sum_i rx_i, so each constituent has coefficient 1.
        let decomp = CommitmentDecomposition {
            terms: atoms.iter().map(|a| (a.key, F::ONE)).collect(),
        };
        let circuit_id = id.circuit_index();
        let poly = sum_polynomials(atoms.iter().map(|a| a.poly));
        self.circuit_impl(circuit_id, TrackedPoly::new(poly, decomp));
    }

    fn bonding(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = Atom<'rx, FoldKey, F, R>>,
    ) -> Result<()> {
        let tracked: Vec<_> = rxs
            .map(|a| TrackedPoly::single(Cow::Borrowed(a.poly), a.key))
            .collect();
        let folded = fold_revdot::fold(&tracked, self.z);
        self.bonding_impl(id.circuit_index(), folded);
        Ok(())
    }
}
