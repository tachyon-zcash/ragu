//! Framework-side state surfaced to [`Step::witness`](crate::step::Step::witness) impls.
//!
//! [`FrameworkHooks`] bundles the framework's hook-specific state that a step
//! body interacts with through [`StepCtx`](crate::step::StepCtx). Today the
//! only hook is a polynomial-query claim sink: steps that need to verify a
//! polynomial-commitment opening — i.e. that the polynomial committed to by
//! `com` evaluates to `y` at point `x` — reach it via
//! [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query),
//! which delegates to [`FrameworkHooks::enforce_polynomial_query`]. The
//! framework collects the resulting claims through the adapter's `Aux` for
//! later fuse-time processing. New framework hooks (e.g. transcript threading)
//! belong on this type as well.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
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
}

/// Aggregate of every hook's accumulated output, returned by
/// [`FrameworkHooks::into_outputs`]. Adding a new hook means adding a field
/// here, which forces every drain site to acknowledge it.
pub struct FrameworkHookOutputs<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Polynomial-commitment opening claims raised via
    /// [`FrameworkHooks::enforce_polynomial_query`].
    pub poly_query_claims: DriverValue<D, Vec<(C, D::F, D::F)>>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> FrameworkHooks<'dr, D, C> {
    /// Creates a new, empty hook container.
    pub fn new() -> Self {
        Self {
            poly_query_claims: Vec::new(),
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

    /// Consumes the container and returns every hook's accumulated output.
    pub fn into_outputs(self) -> FrameworkHookOutputs<'dr, D, C> {
        let poly_query_claims =
            self.poly_query_claims
                .into_iter()
                .fold(D::just(Vec::new), |acc, triple| {
                    acc.and_then(|mut v| {
                        triple.map(|t| {
                            v.push(t);
                            v
                        })
                    })
                });
        FrameworkHookOutputs { poly_query_claims }
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Default for FrameworkHooks<'dr, D, C> {
    fn default() -> Self {
        Self::new()
    }
}
