//! The nested polynomial commitment batch: which nested polynomials a fuse
//! step opens, at which points, and in what order.
//!
//! This mirrors the native batch (`STATIC_F_QUERIES`, `compute_f`,
//! `compute_p`) for the scalar field. There are no application-circuit
//! queries: every nested circuit is internal, with a fixed registry index.
//!
//! The prover-side `compute_f` and `compute_p` phases consume these
//! definitions, and so does the test that holds them to their meaning. A
//! nested `compute_v` circuit will consume the same ones, which is what keeps
//! the prover and the circuit from drifting.

use ragu_arithmetic::{Cycle, ff::PrimeField};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;
use ragu_primitives::vec::ConstLen;

use super::{InternalCircuitIndex, RxComponent, RxIndex, challenge};
use crate::Proof;

/// Length type for a proof's own nested rx components.
pub type OwnRxLen = ConstLen<{ RxIndex::NUM_OWN }>;

/// Length type for the nested internal circuits, one registry index each.
pub type InternalLen = ConstLen<{ InternalCircuitIndex::NUM }>;

/// Static prefix of the nested polynomial-query order used to construct the
/// nested quotient polynomial $f_n(X)$.
///
/// The `Registry*` queries form the chain that ties a child's committed
/// $m_n(W, x_c, y_c)$ restriction to the current step's fresh $w_n$
/// restrictions, exactly as the native chain does for $m(W, x_c, y_c)$.
pub enum StaticFQuery {
    /// Left child proof $p_n(u_n) = v_n$ check.
    LeftP,
    /// Right child proof $p_n(u_n) = v_n$ check.
    RightP,
    /// Left child `registry_xy` polynomial queried at the current $w_n$.
    LeftRegistryXyAtW,
    /// Right child `registry_xy` polynomial queried at the current $w_n$.
    RightRegistryXyAtW,
    /// Current $m_n(w_n, x_0, Y)$ queried at the left child's $y_n$.
    RegistryWx0AtLeftY,
    /// Current $m_n(w_n, x_1, Y)$ queried at the right child's $y_n$.
    RegistryWx1AtRightY,
    /// Current $m_n(w_n, x_0, Y)$ queried at the current $y_n$.
    RegistryWx0AtY,
    /// Current $m_n(w_n, x_1, Y)$ queried at the current $y_n$.
    RegistryWx1AtY,
    /// Current $m_n(w_n, X, y_n)$ queried at the left child's $x_n$.
    RegistryWyAtLeftX,
    /// Current $m_n(w_n, X, y_n)$ queried at the right child's $x_n$.
    RegistryWyAtRightX,
    /// Current $m_n(w_n, X, y_n)$ queried at the current $x_n$.
    RegistryWyAtX,
    /// Current `registry_xy` polynomial queried at the current $w_n$.
    RegistryXyAtW,
    /// Left child $a$ polynomial queried at $x_n z_n$.
    LeftAbAAtXz,
    /// Left child $b$ polynomial queried at $x_n$.
    LeftAbBAtX,
    /// Right child $a$ polynomial queried at $x_n z_n$.
    RightAbAAtXz,
    /// Right child $b$ polynomial queried at $x_n$.
    RightAbBAtX,
    /// Current accumulator $a$ polynomial queried at $x_n z_n$.
    CurrentAAtXz,
    /// Current accumulator $b$ polynomial queried at $x_n$.
    CurrentBAtX,
}

/// Ordered static prefix for the nested quotient polynomial queries.
pub const STATIC_F_QUERIES: [StaticFQuery; 18] = [
    StaticFQuery::LeftP,
    StaticFQuery::RightP,
    StaticFQuery::LeftRegistryXyAtW,
    StaticFQuery::RightRegistryXyAtW,
    StaticFQuery::RegistryWx0AtLeftY,
    StaticFQuery::RegistryWx1AtRightY,
    StaticFQuery::RegistryWx0AtY,
    StaticFQuery::RegistryWx1AtY,
    StaticFQuery::RegistryWyAtLeftX,
    StaticFQuery::RegistryWyAtRightX,
    StaticFQuery::RegistryWyAtX,
    StaticFQuery::RegistryXyAtW,
    StaticFQuery::LeftAbAAtXz,
    StaticFQuery::LeftAbBAtX,
    StaticFQuery::RightAbAAtXz,
    StaticFQuery::RightAbBAtX,
    StaticFQuery::CurrentAAtXz,
    StaticFQuery::CurrentBAtX,
];

/// Number of nested-curve points the batch folds into $P_n$: $f_n$, then
/// for each child its own rx commitments, $a$, $b$, `registry_xy` and $p$,
/// then the current step's two `registry_wx`, `registry_wy`, $a$, $b$ and
/// `registry_xy`. See [`Batch::evaluated`] for the order.
pub const NUM_BATCHED_POINTS: usize = 1 + 2 * (RxIndex::NUM_OWN + 4) + 6;

/// The nested challenges of a child proof, derived from its native ones.
#[derive(Clone, Copy)]
pub struct ChildChallenges<F> {
    pub x: F,
    pub y: F,
    pub u: F,
}

impl<F: PrimeField> ChildChallenges<F> {
    /// Derives a child's nested $x$, $y$ and $u$ (see [`challenge`]).
    pub fn of<C: Cycle<ScalarField = F>, R: Rank>(proof: &Proof<C, R>) -> Result<Self> {
        Ok(Self {
            x: challenge::<C>(proof.x())?,
            y: challenge::<C>(proof.y())?,
            u: challenge::<C>(proof.u())?,
        })
    }
}

/// The nested challenges one fuse step's openings are at: the current
/// step's, and each child's.
#[derive(Clone, Copy)]
pub struct Challenges<F> {
    pub w: F,
    pub x: F,
    pub y: F,
    pub z: F,
    pub left: ChildChallenges<F>,
    pub right: ChildChallenges<F>,
}

/// Everything one fuse step's nested batch opens: the two children and the
/// current step's committed nested polynomials.
pub struct Batch<'a, C: Cycle, R: Rank> {
    pub left: &'a Proof<C, R>,
    pub right: &'a Proof<C, R>,
    /// Current $m_n(w_n, x_0, Y)$.
    pub registry_wx0: &'a sparse::Polynomial<C::ScalarField, R>,
    /// Current $m_n(w_n, x_1, Y)$.
    pub registry_wx1: &'a sparse::Polynomial<C::ScalarField, R>,
    /// Current $m_n(w_n, X, y_n)$.
    pub registry_wy: &'a sparse::Polynomial<C::ScalarField, R>,
    /// Current $m_n(W, x_n, y_n)$.
    pub registry_xy: &'a sparse::Polynomial<C::ScalarField, R>,
    /// Current accumulator $a$.
    pub a: &'a sparse::Polynomial<C::ScalarField, R>,
    /// Current accumulator $b$.
    pub b: &'a sparse::Polynomial<C::ScalarField, R>,
}

impl<'a, C: Cycle, R: Rank> Batch<'a, C, R> {
    /// Every opening the quotient polynomial $f_n$ covers, as
    /// `(polynomial, point)` pairs, in the order that fixes each one's weight
    /// in $\alpha_n$: the static prefix, then each child's own rx polynomials
    /// at $x_n z_n$, then the current `registry_xy` at each nested internal
    /// circuit's $\omega^j$.
    pub fn queries(
        &self,
        ch: Challenges<C::ScalarField>,
    ) -> impl Iterator<Item = (&'a sparse::Polynomial<C::ScalarField, R>, C::ScalarField)> + '_
    {
        let (left, right) = (self.left, self.right);
        let xz = ch.x * ch.z;
        let omega_j = |id: InternalCircuitIndex| -> C::ScalarField { id.circuit_index().omega_j() };

        STATIC_F_QUERIES
            .iter()
            .map(move |query| match query {
                StaticFQuery::LeftP => (left.nested_p_poly(), ch.left.u),
                StaticFQuery::RightP => (right.nested_p_poly(), ch.right.u),
                StaticFQuery::LeftRegistryXyAtW => (left.nested_registry_xy_poly(), ch.w),
                StaticFQuery::RightRegistryXyAtW => (right.nested_registry_xy_poly(), ch.w),
                StaticFQuery::RegistryWx0AtLeftY => (self.registry_wx0, ch.left.y),
                StaticFQuery::RegistryWx1AtRightY => (self.registry_wx1, ch.right.y),
                StaticFQuery::RegistryWx0AtY => (self.registry_wx0, ch.y),
                StaticFQuery::RegistryWx1AtY => (self.registry_wx1, ch.y),
                StaticFQuery::RegistryWyAtLeftX => (self.registry_wy, ch.left.x),
                StaticFQuery::RegistryWyAtRightX => (self.registry_wy, ch.right.x),
                StaticFQuery::RegistryWyAtX => (self.registry_wy, ch.x),
                StaticFQuery::RegistryXyAtW => (self.registry_xy, ch.w),
                StaticFQuery::LeftAbAAtXz => (&left[RxComponent::AbA], xz),
                StaticFQuery::LeftAbBAtX => (&left[RxComponent::AbB], ch.x),
                StaticFQuery::RightAbAAtXz => (&right[RxComponent::AbA], xz),
                StaticFQuery::RightAbBAtX => (&right[RxComponent::AbB], ch.x),
                StaticFQuery::CurrentAAtXz => (self.a, xz),
                StaticFQuery::CurrentBAtX => (self.b, ch.x),
            })
            .chain(
                [left, right]
                    .into_iter()
                    .flat_map(move |proof| RxIndex::OWN.iter().map(move |&id| (&proof[id], xz))),
            )
            .chain(
                InternalCircuitIndex::ALL
                    .iter()
                    .map(move |&id| (self.registry_xy, omega_j(id))),
            )
    }

    /// The polynomials the batch evaluates at $u_n$ and folds into $p_n$
    /// after $f_n$, in that order: for each child its own rx polynomials,
    /// $a$, $b$, `registry_xy` and $p$; then the current step's
    /// `registry_wx0`, `registry_wx1`, `registry_wy`, $a$, $b$ and
    /// `registry_xy`.
    ///
    /// The nested `eval` bridge stage writes its values in this order, and
    /// [`Batch::commitments`] lists the matching commitments.
    pub fn evaluated(
        &self,
    ) -> impl Iterator<Item = &'a sparse::Polynomial<C::ScalarField, R>> + '_ {
        [self.left, self.right]
            .into_iter()
            .flat_map(|proof| {
                RxIndex::OWN.iter().map(move |&id| &proof[id]).chain([
                    &proof[RxComponent::AbA],
                    &proof[RxComponent::AbB],
                    proof.nested_registry_xy_poly(),
                    proof.nested_p_poly(),
                ])
            })
            .chain([
                self.registry_wx0,
                self.registry_wx1,
                self.registry_wy,
                self.a,
                self.b,
                self.registry_xy,
            ])
    }

    /// The commitments of [`Batch::evaluated`], in the same order, given the
    /// current step's commitments the batch does not hold itself.
    pub fn commitments(
        &self,
        current: CurrentCommitments<C::NestedCurve>,
    ) -> impl Iterator<Item = C::NestedCurve> + '_ {
        [self.left, self.right]
            .into_iter()
            .flat_map(|proof| {
                RxIndex::OWN
                    .iter()
                    .map(move |&id| proof.nested_rx_commitment(id))
                    .chain([
                        proof.nested_a_commitment(),
                        proof.nested_b_commitment(),
                        proof.nested_registry_xy_commitment(),
                        proof.nested_p_commitment(),
                    ])
            })
            .chain([
                current.registry_wx0,
                current.registry_wx1,
                current.registry_wy,
                current.a,
                current.b,
                current.registry_xy,
            ])
    }
}

/// The current step's nested-curve commitments to the polynomials at the
/// tail of [`Batch::evaluated`].
#[derive(Clone, Copy)]
pub struct CurrentCommitments<P> {
    pub registry_wx0: P,
    pub registry_wx1: P,
    pub registry_wy: P,
    pub a: P,
    pub b: P,
    pub registry_xy: P,
}
