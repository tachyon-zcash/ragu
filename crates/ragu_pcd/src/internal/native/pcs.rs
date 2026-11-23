//! The native polynomial commitment batch: the static prefix of the queries
//! a fuse step opens, at which points, and in what order.
//!
//! This mirrors the nested batch ([`nested::pcs`](super::super::nested::pcs))
//! for the circuit field. The prover-side `compute_f` and the native
//! `compute_v` circuit both read it, which keeps them from drifting.

/// Static prefix of the polynomial-query order used to construct and verify
/// the fuse quotient polynomial $f(X)$.
///
/// These queries are consumed by both the prover-side `compute_f` path and the
/// `compute_v` circuit. Keeping this prefix in one ordered list prevents the
/// two implementations from drifting independently; the dynamic suffixes are
/// still driven by [`RxIndex::ALL`](super::RxIndex::ALL) and [`InternalCircuitIndex::ALL`](super::InternalCircuitIndex::ALL).
pub(crate) enum StaticFQuery {
    /// Left child proof $p(u)=v$ check.
    LeftP,
    /// Right child proof $p(u)=v$ check.
    RightP,
    /// Left child registry-xy polynomial queried at the current $w$.
    LeftRegistryXyAtW,
    /// Right child registry-xy polynomial queried at the current $w$.
    RightRegistryXyAtW,
    /// Current $m(w, x_0, Y)$ queried at the left child's $y$.
    RegistryWx0AtLeftY,
    /// Current $m(w, x_1, Y)$ queried at the right child's $y$.
    RegistryWx1AtRightY,
    /// Current $m(w, x_0, Y)$ queried at the current $y$.
    RegistryWx0AtY,
    /// Current $m(w, x_1, Y)$ queried at the current $y$.
    RegistryWx1AtY,
    /// Current $m(w, X, y)$ queried at the left child's $x$.
    RegistryWyAtLeftX,
    /// Current $m(w, X, y)$ queried at the right child's $x$.
    RegistryWyAtRightX,
    /// Current $m(w, X, y)$ queried at the current $x$.
    RegistryWyAtX,
    /// Current registry-xy polynomial queried at the current $w$.
    RegistryXyAtW,
    /// Current registry-xy polynomial queried at the step's own circuit id:
    /// the selector restriction of the step's application claim.
    RegistryXyAtCircuitId,
    /// Left child $a$ polynomial queried at $xz$.
    LeftAbAAtXz,
    /// Left child $b$ polynomial queried at $x$.
    LeftAbBAtX,
    /// Right child $a$ polynomial queried at $xz$.
    RightAbAAtXz,
    /// Right child $b$ polynomial queried at $x$.
    RightAbBAtX,
    /// Current accumulator $a$ polynomial queried at $xz$.
    CurrentAAtXz,
    /// Current accumulator $b$ polynomial queried at $x$.
    CurrentBAtX,
    /// The step's own application rx queried at $xz$.
    CurrentApplicationAtXz,
    /// The step's own application stage rx queried at $xz$.
    CurrentApplicationStageAtXz,
    /// The step's own fold randomizer $a_r$ queried at $xz$.
    RandomizerAAtXz,
    /// The step's own fold randomizer $b_r$ queried at $x$.
    RandomizerBAtX,
}

/// Ordered static prefix for fuse quotient polynomial queries.
pub(crate) const STATIC_F_QUERIES: [StaticFQuery; 23] = [
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
    StaticFQuery::RegistryXyAtCircuitId,
    StaticFQuery::LeftAbAAtXz,
    StaticFQuery::LeftAbBAtX,
    StaticFQuery::RightAbAAtXz,
    StaticFQuery::RightAbBAtX,
    StaticFQuery::CurrentAAtXz,
    StaticFQuery::CurrentBAtX,
    StaticFQuery::CurrentApplicationAtXz,
    StaticFQuery::CurrentApplicationStageAtXz,
    StaticFQuery::RandomizerAAtXz,
    StaticFQuery::RandomizerBAtX,
];
