//! Framework-side state surfaced to [`Step::witness`](crate::step::Step::witness) impls.
//!
//! [`FrameworkHooks`] bundles the framework's hook-specific state that a step
//! body interacts with through [`StepCtx`](crate::step::StepCtx). It carries two
//! hooks:
//!
//! * [`enforce_polynomial_query`](FrameworkHooks::enforce_polynomial_query) — a
//!   polynomial-query claim sink: steps that need to verify a
//!   polynomial-commitment opening — i.e. that the polynomial committed to by
//!   `com` evaluates to `y` at point `x` — reach it via
//!   [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query),
//!   which delegates here.
//! * [`derive_challenge`](FrameworkHooks::derive_challenge) — derives a
//!   challenge from any gadget entirely outside the circuit and returns a nested
//!   curve point plus the two scalar field elements `challenge_x` and
//!   `claimed_y`.
//!
//! The framework collects the resulting outputs through the adapter's `Aux` for
//! later fuse-time processing. New framework hooks (e.g. transcript threading)
//! belong on this type as well.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, Point};

/// Container for framework-side state threaded through a
/// [`Step::witness`](crate::step::Step::witness) invocation.
///
/// Currently holds only the polynomial-commitment opening-claim sink.
/// The framework's adapter constructs this, passes it to the step, then
/// surfaces [`into_outputs`](Self::into_outputs) through its `Aux` for later
/// fuse-time processing.
pub struct FrameworkHooks<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    poly_query_claims: Vec<DriverValue<D, (C, D::F, D::F)>>,
    /// Challenges derived via [`FrameworkHooks::derive_challenge`], tracked here
    /// so `fuse()` can consume them in future work.
    derived_challenges: Vec<DriverValue<D, (C, D::F, D::F)>>,
}

/// Aggregate of every hook's accumulated output, returned by
/// [`FrameworkHooks::into_outputs`]. Adding a new hook means adding a field
/// here, which forces every drain site to acknowledge it.
pub struct FrameworkHookOutputs<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Polynomial-commitment opening claims raised via
    /// [`FrameworkHooks::enforce_polynomial_query`].
    pub poly_query_claims: DriverValue<D, Vec<(C, D::F, D::F)>>,
    /// Derived-challenge triples raised via
    /// [`FrameworkHooks::derive_challenge`].
    pub derived_challenges: DriverValue<D, Vec<(C, D::F, D::F)>>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> FrameworkHooks<'dr, D, C> {
    /// Creates a new, empty hook container.
    pub fn new() -> Self {
        Self {
            poly_query_claims: Vec::new(),
            derived_challenges: Vec::new(),
        }
    }

    /// Records a claim that the polynomial committed to by `com` evaluates to
    /// `y` at the point `x`.
    pub fn enforce_polynomial_query(
        &mut self,
        _dr: &mut D,
        com: Point<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        let triple =
            D::try_just(|| Ok((com.value().take(), *x.value().take(), *y.value().take())))?;
        self.poly_query_claims.push(triple);
        Ok(())
    }

    /// Derives a challenge from `gadget`. The real derivation happens entirely
    /// in the framework, *outside the circuit*; the step author only reasons
    /// about the three returned values — a nested curve point, the challenge
    /// point `challenge_x`, and the claimed evaluation `claimed_y` — and trusts
    /// the framework to derive them. The triple is tracked on this container so
    /// that `fuse()` can process it later.
    pub fn derive_challenge<G: Gadget<'dr, D>>(
        &mut self,
        _dr: &mut D,
        _gadget: G,
    ) -> Result<(Point<'dr, D, C>, Element<'dr, D>, Element<'dr, D>)> {
        // Real out-of-circuit derivation + push onto `self.derived_challenges`
        // is future framework work.
        todo!("framework-side challenge derivation")
    }

    /// Consumes the container and returns every hook's accumulated output.
    pub fn into_outputs(self) -> FrameworkHookOutputs<'dr, D, C> {
        fn drain<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>>(
            triples: Vec<DriverValue<D, (C, D::F, D::F)>>,
        ) -> DriverValue<D, Vec<(C, D::F, D::F)>> {
            triples.into_iter().fold(D::just(Vec::new), |acc, triple| {
                acc.and_then(|mut v| {
                    triple.map(|t| {
                        v.push(t);
                        v
                    })
                })
            })
        }

        FrameworkHookOutputs {
            poly_query_claims: drain::<D, C>(self.poly_query_claims),
            derived_challenges: drain::<D, C>(self.derived_challenges),
        }
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Default for FrameworkHooks<'dr, D, C> {
    fn default() -> Self {
        Self::new()
    }
}
