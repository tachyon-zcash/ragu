//! Proof corruption utilities for fuzz-testing the verifier.
//!
//! [`Corruption`] names one edit to a finished [`Proof`], and
//! [`Proof::corrupt`] applies it and reports whether the verifier is obliged
//! to notice. The vocabulary covers what
//! [`verify`](crate::Application::verify) actually reads: the application
//! metadata, every challenge and bridge commitment the unified instance
//! carries, and an individual coefficient of any native or nested polynomial
//! a revdot claim folds.
//!
//! # Why a corruption is not always a rejection
//!
//! A proof's polynomials are blinded, so most of their coefficients are
//! degrees of freedom no check binds; moving one of those is not forgery and
//! the verifier accepting afterwards is correct. Asserting rejection there
//! would fail an honest verifier. So [`Proof::corrupt`] returns a
//! [`Binding`], and a harness asserts rejection only for
//! [`Binding::MustReject`].
//!
//! The classification is derived, not guessed:
//!
//! * **Instance edits** — challenges, bridge commitments, headers, the
//!   circuit id, and anything that moves the derived $c = \operatorname{revdot}(A, B)$
//!   or $v = p(u)$ — change $k(y)$, which the verifier evaluates by Horner at
//!   a $y$ it samples fresh. The polynomials the claims fold do not move with
//!   it, so the claim breaks unless the fresh $y$ is a root of the difference:
//!   a Schwartz–Zippel event of probability under $4n/|\mathbb{F}|$.
//! * **The `registry_xy` polynomial** is compared against
//!   $m(w, x, y)$ at a $w$ the verifier samples fresh, so any change to it is
//!   caught on the same grounds.
//! * **A native rx coefficient, or a nested one whose component enters a
//!   circuit claim**, is caught when the coefficient sits in $[0, n)$. A
//!   circuit claim checks $\operatorname{revdot}(a, a(zX) + s\_y + t\_z) = k(y)$,
//!   where the verifier — not the prover — supplies $t\_z$. Perturbing
//!   coefficient $i$ of $a$ by $\delta$ moves the left side by
//!   $$\delta \left( a\_{4n-1-i}(z^i + z^{4n-1-i}) + s\_{y,4n-1-i} - z^{2n-1-i} - z^{2n+i} \right),$$
//!   and for $i < n$ the exponent $2n + i$ of that last term — which comes
//!   from $t\_z$ and is thus outside the prover's reach — is matched by no
//!   other term, so the bracket is a nonzero polynomial in the fresh $z$.
//! * **Everything else** — a coefficient at $i \ge n$, or any coefficient of
//!   a component that only ever appears in bonding claims (every `Bridge*`
//!   and child-stage polynomial, whose $b$ side is $s\_y$ alone) — is
//!   [`Binding::Unbound`]: the claim moves only where $s\_y$ happens to be
//!   occupied, which the wiring polynomial decides and this module does not
//!   model.
//!
//! `bridge_alpha` has no variant: single-proof verification never reads it,
//! the cached bridge polynomials it derived being materialized in the proof
//! already. Neither do the native commitment caches, for the same reason —
//! only the eight nested-curve bridge commitments reach the unified instance.
//!
//! Nor is there a variant for the `registry_wx0`, `registry_wx1` and
//! `registry_wy` polynomials the `TODO` in `verify.rs` is about:
//! a [`Proof`] does not carry them, so there is nothing here to corrupt. When
//! those checks land, the polynomials they check want variants alongside
//! [`Corruption::RegistryXyCoeff`].

use alloc::vec;

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};

use crate::{Application, Proof};

// The corruption vocabulary names proof components, and the names it uses are
// the ones `internal` uses. Those enums are *not* re-exported here, and the
// duplication below is deliberate.
//
// `internal` is a private module. Re-exporting its enums would make them
// public API of the crate whenever this feature is on, which drags
// `#![deny(missing_docs)]` onto production files and, more to the point,
// means a fuzzing feature decides what the crate publishes. Mirroring keeps
// every fuzzing-driven change inside this module.
//
// Drift is a compile error, not a silent gap: the mappings in
// `crate::proof::fuzz` match these exhaustively, so a variant added to
// `internal` without a counterpart here fails to build.

/// Identifies which of the two child proofs a component came from.
///
/// Mirrors `internal::Side`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The left child.
    Left,
    /// The right child.
    Right,
}

/// A native-field polynomial component of a proof.
///
/// Mirrors `internal::native::RxComponent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxComponent {
    /// The `a` polynomial from the AB proof (revdot claim).
    AbA,
    /// The `b` polynomial from the AB proof (revdot claim).
    AbB,
    /// An rx polynomial component indexed by [`NativeRx`].
    Rx(NativeRx),
}

/// Which native-field rx polynomial of a proof to address.
///
/// Mirrors `internal::native::RxIndex`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeRx {
    /// The application circuit's rx polynomial.
    Application,
    /// The `hashes_1` circuit's rx polynomial.
    Hashes1,
    /// The `hashes_2` circuit's rx polynomial.
    Hashes2,
    /// The `inner_collapse` circuit's rx polynomial.
    InnerCollapse,
    /// The `outer_collapse` circuit's rx polynomial.
    OuterCollapse,
    /// The `compute_v` circuit's rx polynomial.
    ComputeV,
    /// The `preamble` stage's rx polynomial.
    Preamble,
    /// The `inner_error` stage's rx polynomial.
    InnerError,
    /// The `outer_error` stage's rx polynomial.
    OuterError,
    /// The `query` stage's rx polynomial.
    Query,
    /// The `eval` stage's rx polynomial.
    Eval,
}

impl Side {
    const fn from_internal(v: crate::internal::Side) -> Self {
        match v {
            crate::internal::Side::Left => Self::Left,
            crate::internal::Side::Right => Self::Right,
        }
    }
}

impl NativeRx {
    /// The number of native rx polynomial components.
    pub const NUM: usize = crate::internal::native::RxIndex::NUM;

    /// All variants, in the canonical order `internal` defines.
    ///
    /// Derived from `internal::native::RxIndex::ALL` rather than restated.
    /// That order is not cosmetic — it drives the `Write` impl for `RxValues`
    /// and the evaluation order in `poly_queries` — and a hand-copied list
    /// could drift from it silently, which an exhaustive `match` would not
    /// catch.
    pub const ALL: [Self; Self::NUM] = Self::derive_all();

    const fn derive_all() -> [Self; Self::NUM] {
        let src = crate::internal::native::RxIndex::ALL;
        let mut out = [Self::Application; Self::NUM];
        let mut i = 0;
        while i < Self::NUM {
            out[i] = Self::from_internal(src[i]);
            i += 1;
        }
        out
    }

    const fn from_internal(v: crate::internal::native::RxIndex) -> Self {
        use crate::internal::native::RxIndex as I;
        match v {
            I::Application => Self::Application,
            I::Hashes1 => Self::Hashes1,
            I::Hashes2 => Self::Hashes2,
            I::InnerCollapse => Self::InnerCollapse,
            I::OuterCollapse => Self::OuterCollapse,
            I::ComputeV => Self::ComputeV,
            I::Preamble => Self::Preamble,
            I::InnerError => Self::InnerError,
            I::OuterError => Self::OuterError,
            I::Query => Self::Query,
            I::Eval => Self::Eval,
        }
    }
}

/// Which bridge stage a child proof's rx polynomial comes from.
///
/// Mirrors `internal::nested::ChildBridgeKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildBridgeKind {
    /// Child proof's `BridgeSPrime` rx polynomial.
    SPrime,
    /// Child proof's `BridgeInnerError` rx polynomial.
    InnerError,
    /// Child proof's `BridgeOuterError` rx polynomial.
    OuterError,
    /// Child proof's `BridgeAB` rx polynomial.
    AB,
    /// Child proof's `BridgeQuery` rx polynomial.
    Query,
    /// Child proof's `BridgeEval` rx polynomial.
    Eval,
}

impl ChildBridgeKind {
    /// All kinds in the canonical slot order `internal` defines.
    ///
    /// Derived, not restated: this order is the source of truth for the
    /// relative position of `ChildBridge` entries in the nested `ALL`, and is
    /// pinned by `test_nested_registry_digest` — re-ordering it changes the
    /// nested registry digest.
    pub const ALL: [Self; 6] = Self::derive_all();

    const fn derive_all() -> [Self; 6] {
        let src = crate::internal::nested::ChildBridgeKind::ALL;
        let mut out = [Self::SPrime; 6];
        let mut i = 0;
        while i < 6 {
            out[i] = Self::from_internal(src[i]);
            i += 1;
        }
        out
    }

    const fn from_internal(v: crate::internal::nested::ChildBridgeKind) -> Self {
        use crate::internal::nested::ChildBridgeKind as I;
        match v {
            I::SPrime => Self::SPrime,
            I::InnerError => Self::InnerError,
            I::OuterError => Self::OuterError,
            I::AB => Self::AB,
            I::Query => Self::Query,
            I::Eval => Self::Eval,
        }
    }
}

/// Which nested-field rx polynomial of a proof to address.
///
/// Mirrors `internal::nested::RxIndex`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NestedRx {
    /// EndoscalingStep circuit rx polynomial (indexed by step number).
    EndoscalingStep(u32),
    /// EndoscalarStage rx polynomial.
    EndoscalarStage,
    /// PointsStage rx polynomial.
    PointsStage,
    /// Bridge `preamble` rx polynomial.
    BridgePreamble,
    /// Bridge `s_prime` rx polynomial.
    BridgeSPrime,
    /// Bridge `inner_error` rx polynomial.
    BridgeInnerError,
    /// Bridge `outer_error` rx polynomial.
    BridgeOuterError,
    /// Bridge `ab` rx polynomial.
    BridgeAB,
    /// Bridge `query` rx polynomial.
    BridgeQuery,
    /// Bridge `f` rx polynomial.
    BridgeF,
    /// Bridge `eval` rx polynomial.
    BridgeEval,
    /// Child proof's `PointsStage` rx polynomial (per-side, for copying).
    ChildPointsStage(Side),
    /// Child proof's bridge rx polynomial (per-side, for copying),
    /// keyed by which bridge stage it comes from.
    ChildBridge(ChildBridgeKind, Side),
}

/// Whether [`verify`](crate::Application::verify) is obliged to reject a
/// corrupted proof.
///
/// See the [module documentation](self) for how each [`Corruption`] is
/// classified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// The corruption moved a value some verifier check binds, so `verify`
    /// must not accept — except with negligible probability over the
    /// randomness the verifier samples for itself.
    MustReject,
    /// The corruption moved nothing any verifier check binds — a blinding
    /// coefficient, a value that happened not to change, or a coefficient
    /// outside the region the claim's $t\_z$ term reaches. Acceptance is the
    /// correct outcome and a harness must not assert otherwise.
    Unbound,
}

/// One of the eleven verifier challenges the unified instance carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Challenge {
    /// The `w` challenge.
    W,
    /// The `y` challenge, which also feeds the `registry_xy` check.
    Y,
    /// The `z` challenge.
    Z,
    /// The `mu` challenge.
    Mu,
    /// The `nu` challenge.
    Nu,
    /// The `mu'` challenge.
    MuPrime,
    /// The `nu'` challenge.
    NuPrime,
    /// The `x` challenge, which also feeds the `registry_xy` check.
    X,
    /// The `alpha` challenge.
    Alpha,
    /// The `u` challenge, at which `p` is opened.
    U,
    /// The `pre_beta` challenge.
    PreBeta,
}

impl Challenge {
    /// All variants, in the order the unified instance writes them.
    pub const ALL: [Self; 11] = [
        Self::W,
        Self::Y,
        Self::Z,
        Self::Mu,
        Self::Nu,
        Self::MuPrime,
        Self::NuPrime,
        Self::X,
        Self::Alpha,
        Self::U,
        Self::PreBeta,
    ];
}

/// One of the eight nested-curve commitments the unified instance carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeCommitment {
    /// The bridge `preamble` commitment.
    Preamble,
    /// The bridge `s'` commitment.
    SPrime,
    /// The bridge `inner_error` commitment.
    InnerError,
    /// The bridge `outer_error` commitment.
    OuterError,
    /// The bridge `ab` commitment.
    AB,
    /// The bridge `query` commitment.
    Query,
    /// The bridge `f` commitment.
    F,
    /// The bridge `eval` commitment.
    Eval,
}

impl BridgeCommitment {
    /// All variants, in the order the unified instance writes them.
    pub const ALL: [Self; 8] = [
        Self::Preamble,
        Self::SPrime,
        Self::InnerError,
        Self::OuterError,
        Self::AB,
        Self::Query,
        Self::F,
        Self::Eval,
    ];
}

/// Targeted corruption of a single proof component.
///
/// Apply one with [`Proof::corrupt`]; apply several in sequence for a
/// coordinated mutation, in which case the proof must reject if *any* of them
/// reported [`Binding::MustReject`].
pub enum Corruption<C: Cycle> {
    /// Set `circuit_id` to the given index. Out-of-domain indices are
    /// rejected outright; in-domain ones move `omega_j` in the instance and
    /// select a different wiring polynomial.
    CircuitId(u32),
    /// Add `delta` to one element of a child header.
    HeaderElement {
        /// Which child header to edit.
        side: Side,
        /// The element's position; out of range is a no-op.
        index: usize,
        /// What to add.
        delta: C::CircuitField,
    },
    /// Resize a child header to the given length, which the verifier checks
    /// against `HEADER_SIZE`.
    HeaderLen {
        /// Which child header to resize.
        side: Side,
        /// The new length.
        len: usize,
    },
    /// Exchange the left and right child headers, which reorders both
    /// `application_ky` and `unified_bridge_ky`.
    SwapHeaders,
    /// Overwrite a verifier challenge.
    Challenge(Challenge, C::CircuitField),
    /// Negate a bridge commitment, moving its $y$ coordinate in the instance.
    NegateBridgeCommitment(BridgeCommitment),
    /// Add `delta` to one coefficient of a native rx polynomial, or of the
    /// `a` / `b` polynomials of the raw revdot claim.
    NativeCoeff {
        /// Which polynomial.
        component: RxComponent,
        /// The coefficient's index; out of range is a no-op.
        coeff: usize,
        /// What to add.
        delta: C::CircuitField,
    },
    /// Add `delta` to one coefficient of the `registry_xy` polynomial.
    RegistryXyCoeff {
        /// The coefficient's index; out of range is a no-op.
        coeff: usize,
        /// What to add.
        delta: C::CircuitField,
    },
    /// Add `delta` to one coefficient of the `p` polynomial.
    PCoeff {
        /// The coefficient's index; out of range is a no-op.
        coeff: usize,
        /// What to add.
        delta: C::CircuitField,
    },
    /// Add `delta` to one coefficient of a nested rx polynomial.
    NestedCoeff {
        /// Which polynomial.
        index: NestedRx,
        /// The coefficient's index; out of range is a no-op.
        coeff: usize,
        /// What to add.
        delta: C::ScalarField,
    },
}

impl<C: Cycle> core::fmt::Debug for Corruption<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Corruption::CircuitId(id) => write!(f, "CircuitId({id})"),
            Corruption::HeaderElement { side, index, .. } => {
                write!(f, "HeaderElement {{ side: {side:?}, index: {index} }}")
            }
            Corruption::HeaderLen { side, len } => {
                write!(f, "HeaderLen {{ side: {side:?}, len: {len} }}")
            }
            Corruption::SwapHeaders => write!(f, "SwapHeaders"),
            Corruption::Challenge(which, _) => write!(f, "Challenge({which:?})"),
            Corruption::NegateBridgeCommitment(which) => {
                write!(f, "NegateBridgeCommitment({which:?})")
            }
            Corruption::NativeCoeff {
                component, coeff, ..
            } => write!(
                f,
                "NativeCoeff {{ component: {component:?}, coeff: {coeff} }}"
            ),
            Corruption::RegistryXyCoeff { coeff, .. } => {
                write!(f, "RegistryXyCoeff {{ coeff: {coeff} }}")
            }
            Corruption::PCoeff { coeff, .. } => write!(f, "PCoeff {{ coeff: {coeff} }}"),
            Corruption::NestedCoeff { index, coeff, .. } => {
                write!(f, "NestedCoeff {{ index: {index:?}, coeff: {coeff} }}")
            }
        }
    }
}

/// A polynomial that is `delta` at `coeff` and zero elsewhere, or `None` when
/// the edit would be a no-op — a zero delta, or an index past the rank's
/// capacity.
fn monomial<F: Field, R: Rank>(coeff: usize, delta: F) -> Option<sparse::Polynomial<F, R>> {
    if delta == F::ZERO || coeff >= R::num_coeffs() {
        return None;
    }
    let mut coeffs = vec![F::ZERO; coeff + 1];
    coeffs[coeff] = delta;
    Some(sparse::Polynomial::from_coeffs(coeffs))
}

/// Whether a coefficient of a polynomial folded into a *circuit* claim is one
/// the verifier's own $t\_z$ term reaches. See the [module
/// documentation](self).
fn in_tz_reach<R: Rank>(coeff: usize) -> bool {
    coeff < R::n()
}

/// Whether the nested component named by `index` is folded into a circuit
/// claim at all. The rest appear only in bonding claims, whose `b` side is
/// $s\_y$ alone.
fn nested_enters_circuit_claim(index: NestedRx) -> bool {
    matches!(
        index,
        NestedRx::EndoscalingStep(_) | NestedRx::EndoscalarStage | NestedRx::PointsStage
    )
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Apply a [`Corruption`] to this proof, reporting whether
    /// [`verify`](crate::Application::verify) is obliged to reject afterwards.
    #[doc(hidden)]
    pub fn corrupt(&mut self, corruption: Corruption<C>) -> Binding {
        match corruption {
            Corruption::CircuitId(id) => {
                let id = CircuitIndex::from_u32(id);
                if self.circuit_id == id {
                    return Binding::Unbound;
                }
                self.circuit_id = id;
                Binding::MustReject
            }

            Corruption::HeaderElement { side, index, delta } => {
                let header = match side {
                    Side::Left => &mut self.left_header,
                    Side::Right => &mut self.right_header,
                };
                match header.get_mut(index) {
                    Some(element) if delta != C::CircuitField::ZERO => {
                        *element += delta;
                        Binding::MustReject
                    }
                    _ => Binding::Unbound,
                }
            }

            Corruption::HeaderLen { side, len } => {
                let header = match side {
                    Side::Left => &mut self.left_header,
                    Side::Right => &mut self.right_header,
                };
                if header.len() == len {
                    return Binding::Unbound;
                }
                header.resize(len, C::CircuitField::ZERO);
                Binding::MustReject
            }

            Corruption::SwapHeaders => {
                if self.left_header == self.right_header {
                    return Binding::Unbound;
                }
                core::mem::swap(&mut self.left_header, &mut self.right_header);
                Binding::MustReject
            }

            Corruption::Challenge(which, value) => {
                let slot = match which {
                    Challenge::W => &mut self.w,
                    Challenge::Y => &mut self.y,
                    Challenge::Z => &mut self.z,
                    Challenge::Mu => &mut self.mu,
                    Challenge::Nu => &mut self.nu,
                    Challenge::MuPrime => &mut self.mu_prime,
                    Challenge::NuPrime => &mut self.nu_prime,
                    Challenge::X => &mut self.x,
                    Challenge::Alpha => &mut self.alpha,
                    Challenge::U => &mut self.u,
                    Challenge::PreBeta => &mut self.pre_beta,
                };
                if *slot == value {
                    return Binding::Unbound;
                }
                *slot = value;
                Binding::MustReject
            }

            Corruption::NegateBridgeCommitment(which) => {
                let point = self.bridge_commitment_mut(which);
                let negated = -*point;
                if negated == *point {
                    // The identity, and points of order two, negate to
                    // themselves; the instance would not move.
                    return Binding::Unbound;
                }
                *point = negated;
                Binding::MustReject
            }

            Corruption::NativeCoeff {
                component,
                coeff,
                delta,
            } => {
                let Some(delta) = monomial::<_, R>(coeff, delta) else {
                    return Binding::Unbound;
                };
                match component {
                    // `a` and `b` reach the verifier only through the derived
                    // `c = revdot(a, b)` the instance carries: the raw claim
                    // that folds them recomputes its own k(y) from the same
                    // two polynomials and so is tautological. Whether `c`
                    // moved is decided exactly, by looking.
                    RxComponent::AbA | RxComponent::AbB => {
                        let before = self.c();
                        self.native_component_mut(component).add_assign(&delta);
                        if self.c() == before {
                            Binding::Unbound
                        } else {
                            Binding::MustReject
                        }
                    }
                    RxComponent::Rx(_) => {
                        self.native_component_mut(component).add_assign(&delta);
                        if in_tz_reach::<R>(coeff) {
                            Binding::MustReject
                        } else {
                            Binding::Unbound
                        }
                    }
                }
            }

            Corruption::RegistryXyCoeff { coeff, delta } => {
                let Some(delta) = monomial::<_, R>(coeff, delta) else {
                    return Binding::Unbound;
                };
                self.native_registry_xy_poly_mut().add_assign(&delta);
                Binding::MustReject
            }

            Corruption::PCoeff { coeff, delta } => {
                let Some(delta) = monomial::<_, R>(coeff, delta) else {
                    return Binding::Unbound;
                };
                // `p` is opened at `u` into the instance's `v` and folded
                // into no claim, so the corruption binds exactly when `v`
                // moves — which it does not when `u` is zero.
                let before = self.v();
                self.native_p_poly_mut().add_assign(&delta);
                if self.v() == before {
                    Binding::Unbound
                } else {
                    Binding::MustReject
                }
            }

            Corruption::NestedCoeff {
                index,
                coeff,
                delta,
            } => {
                let Some(delta) = monomial::<_, R>(coeff, delta) else {
                    return Binding::Unbound;
                };
                self.nested_rx_mut(index).add_assign(&delta);
                if nested_enters_circuit_claim(index) && in_tz_reach::<R>(coeff) {
                    Binding::MustReject
                } else {
                    Binding::Unbound
                }
            }
        }
    }

    /// The number of coefficients a polynomial of this proof's rank carries,
    /// so a harness can bound the coefficient indices it chooses.
    #[doc(hidden)]
    pub fn num_coeffs() -> usize {
        R::num_coeffs()
    }

    /// The number of coefficients at the low end that a circuit claim's
    /// $t\_z$ term reaches, so a harness can steer toward corruptions whose
    /// rejection is asserted.
    #[doc(hidden)]
    pub fn num_bound_coeffs() -> usize {
        R::n()
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Create the synthesized dummy proof used to bootstrap recursion.
    #[doc(hidden)]
    pub fn test_dummy_proof(&self) -> Proof<C, R> {
        self.dummy_proof()
    }
}

impl NestedRx {
    /// The number of nested rx components.
    pub const NUM: usize = crate::internal::nested::RxIndex::NUM;

    /// All variants, in the canonical order `internal` defines.
    ///
    /// Derived from `internal::nested::RxIndex::ALL` for the same reason as
    /// [`NativeRx::ALL`], and more urgently: this order is pinned by
    /// `test_nested_registry_digest`, so restating it by hand would put a
    /// consensus-relevant ordering in two places.
    pub const ALL: [Self; Self::NUM] = Self::derive_all();

    const fn derive_all() -> [Self; Self::NUM] {
        let src = crate::internal::nested::RxIndex::ALL;
        let mut out = [Self::EndoscalarStage; Self::NUM];
        let mut i = 0;
        while i < Self::NUM {
            out[i] = Self::from_internal(src[i]);
            i += 1;
        }
        out
    }

    const fn from_internal(v: crate::internal::nested::RxIndex) -> Self {
        use crate::internal::nested::RxIndex as I;
        match v {
            I::EndoscalingStep(n) => Self::EndoscalingStep(n),
            I::EndoscalarStage => Self::EndoscalarStage,
            I::PointsStage => Self::PointsStage,
            I::BridgePreamble => Self::BridgePreamble,
            I::BridgeSPrime => Self::BridgeSPrime,
            I::BridgeInnerError => Self::BridgeInnerError,
            I::BridgeOuterError => Self::BridgeOuterError,
            I::BridgeAB => Self::BridgeAB,
            I::BridgeQuery => Self::BridgeQuery,
            I::BridgeF => Self::BridgeF,
            I::BridgeEval => Self::BridgeEval,
            I::ChildPointsStage(s) => Self::ChildPointsStage(Side::from_internal(s)),
            I::ChildBridge(k, s) => {
                Self::ChildBridge(ChildBridgeKind::from_internal(k), Side::from_internal(s))
            }
        }
    }
}
