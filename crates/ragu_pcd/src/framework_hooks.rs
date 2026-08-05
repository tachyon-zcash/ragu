//! Framework-side state behind the hooks a step reaches through
//! [`StepCtx`](crate::step::StepCtx); the wire forms live in
//! [`instance`].
//!
//! Nothing a hook produces is enforced here. It lands in the application
//! circuit's instance, padded to the [`HookLayout`], and the parent fuse — or
//! [`Application::verify`](crate::Application::verify), for a proof that is
//! never fused — discharges it.

use alloc::{vec, vec::Vec};

use ragu_arithmetic::{Cycle, eval, ff::Field};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, allocator::Standard, vec::Len};

use crate::{
    instance,
    poly_commitment::{HANDLE_WIRES, PolyHandle},
    proof::PolyQuery,
};

/// A polynomial a step witnessed: the handle it was handed back, the commitment
/// that handle encodes, and the coefficients the fuse folds. The commitment is
/// kept because a [`PolyQuery`] records one and a handle cannot be turned back
/// into a point.
struct Witnessed<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    handle: PolyHandle<'dr, D, C>,
    commitment: DriverValue<D, C::HostCurve>,
    coefficients: DriverValue<D, Vec<C::CircuitField>>,
}

/// An enforced query: the wires the instance carries, and the commitment the
/// [`PolyQuery`] will record — resolved at the call, where the polynomial
/// behind the handle is looked up anyway.
struct Queried<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    wires: instance::PolyQuery<'dr, D, C>,
    commitment: DriverValue<D, C::HostCurve>,
}

/// Accumulates hook wires during one [`Step::witness`](crate::step::Step::witness)
/// run; the adapter drains it into a [`FrameworkAux`].
pub(crate) struct FrameworkHooks<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    poly_queries: Vec<Queried<'dr, D, C>>,
    witnessed_polys: Vec<Witnessed<'dr, D, C>>,
    hook_layout: HookLayout,
    params: &'dr C::Params,
}

/// Every hook's output as plain values, for the fuse. Every list is in call
/// order and padded to the application's [`HookLayout`].
pub(crate) struct FrameworkAux<C: Cycle> {
    /// Coefficient vectors; the commitments are not here, the builder derives
    /// those from these.
    pub witness_polys: Vec<Vec<C::CircuitField>>,
    pub poly_queries: Vec<PolyQuery<C::HostCurve>>,
}

/// An application's [`HookLayout`] as type-level lengths on a marker type;
/// usually written as [`crate::AppHooks`].
pub trait HookConfig: Send + Sync + 'static {
    /// Polynomial witnesses committed per step.
    type PolyWitnesses: Len;
    /// Polynomial queries enforced per step.
    type PolyQueries: Len;

    /// These lengths as the value the circuits are built from.
    fn layout() -> HookLayout {
        HookLayout {
            witness_polys: Self::PolyWitnesses::len(),
            poly_queries: Self::PolyQueries::len(),
        }
    }
}

/// A [`HookConfig`]'s lengths as a value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HookLayout {
    /// [`witness_polynomial`](crate::step::StepCtx::witness_polynomial) calls.
    pub witness_polys: usize,
    /// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) calls.
    pub poly_queries: usize,
}

impl HookLayout {
    /// Instance elements the handles and poly-queries occupy.
    pub const fn poly_query_instance_len(&self) -> usize {
        self.witness_polys * HANDLE_WIRES + self.poly_queries * (HANDLE_WIRES + 2)
    }
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> FrameworkHooks<'dr, D, C> {
    pub(crate) fn witnessed_polys(&self) -> impl Iterator<Item = &PolyHandle<'dr, D, C>> {
        self.witnessed_polys.iter().map(|w| &w.handle)
    }

    pub(crate) fn poly_queries(&self) -> impl Iterator<Item = &instance::PolyQuery<'dr, D, C>> {
        self.poly_queries.iter().map(|queried| &queried.wires)
    }

    /// Reads each hook's wires back out as plain values, for the fuse.
    /// [`pad_to_layout`](Self::pad_to_layout) filled each list to the layout.
    pub(crate) fn into_values(self) -> Result<DriverValue<D, FrameworkAux<C>>> {
        D::try_just(move || {
            Ok(FrameworkAux {
                witness_polys: self
                    .witnessed_polys
                    .into_iter()
                    .map(|w| w.coefficients.take())
                    .collect(),
                poly_queries: self
                    .poly_queries
                    .into_iter()
                    .map(|q| PolyQuery {
                        com: q.commitment.take(),
                        x: *q.wires.x.value().take(),
                        y: *q.wires.y.value().take(),
                    })
                    .collect(),
            })
        })
    }

    pub(crate) fn new(hook_layout: HookLayout, params: &'dr C::Params) -> Self {
        Self {
            poly_queries: Vec::new(),
            witnessed_polys: Vec::new(),
            hook_layout,
            params,
        }
    }

    pub(crate) fn witness_polynomial<R: Rank>(
        &mut self,
        dr: &mut D,
        polynomial: DriverValue<D, sparse::Polynomial<C::CircuitField, R>>,
    ) -> Result<PolyHandle<'dr, D, C>> {
        let (handle, commitment) = PolyHandle::new(dr, self.params, &polynomial)?;
        // The rank goes no further. What a *proof* carries the coefficients at
        // is the application's rank, which the fuse applies.
        self.witnessed_polys.push(Witnessed {
            handle: handle.clone(),
            commitment,
            coefficients: polynomial.map(|p| p.iter_coeffs().collect()),
        });
        Ok(handle)
    }

    pub(crate) fn evaluate(
        &self,
        handle: &PolyHandle<'dr, D, C>,
        x: DriverValue<D, C::CircuitField>,
    ) -> Result<DriverValue<D, C::CircuitField>> {
        let found = self.witnessed_of(handle)?;
        D::try_just(move || {
            let (_, coefficients) = found.take();
            Ok(eval(&coefficients, x.take()))
        })
    }

    /// The commitment and coefficients behind `handle`.
    fn witnessed_of(
        &self,
        handle: &PolyHandle<'dr, D, C>,
    ) -> Result<DriverValue<D, (C::HostCurve, Vec<C::CircuitField>)>> {
        D::try_just(|| {
            let sought = handle.value().take();
            self.witnessed_polys
                .iter()
                .find(|w| w.handle.value().take() == sought)
                .map(|w| {
                    (
                        *w.commitment.as_ref().take(),
                        w.coefficients.as_ref().take().clone(),
                    )
                })
                .ok_or_else(|| {
                    Error::InvalidWitness(
                        "poly-query rejected: the commitment names no polynomial this step witnessed"
                            .into(),
                    )
                })
        })
    }

    pub(crate) fn enforce_poly_query(
        &mut self,
        handle: &PolyHandle<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        let found = self.witnessed_of(handle)?;
        let commitment = found.clone().map(|(commitment, _)| commitment);
        let at = x.value();
        let claimed = y.value();
        D::try_just(move || {
            let (_, coefficients) = found.take();
            if eval(&coefficients, *at.take()) == *claimed.take() {
                Ok(())
            } else {
                Err(Error::InvalidWitness(
                    "poly-query rejected: the polynomial does not evaluate to the claimed value at the claimed point"
                        .into(),
                ))
            }
        })?;

        self.poly_queries.push(Queried {
            commitment,
            wires: instance::PolyQuery {
                com: handle.clone(),
                x,
                y,
            },
        });
        Ok(())
    }

    /// Fills whatever the body left unused up to the [`HookLayout`]. The
    /// polynomials go first, because a padding query has to name one and the
    /// body may have witnessed none.
    pub(crate) fn pad_to_layout<R: Rank>(&mut self, dr: &mut D) -> Result<()> {
        // The constant $1$, whose commitment is `g[0]` — which is what the
        // builder derives for every padded polynomial.
        let pad_poly = D::just(|| sparse::Polynomial::<_, R>::from_coeffs(vec![D::F::ONE]));
        while self.witnessed_polys.len() < self.hook_layout.witness_polys {
            self.witness_polynomial(dr, pad_poly.clone())?;
        }

        // One opening of the first polynomial at zero, repeated: the wires are
        // allocated once however many queries are left to fill.
        if self.poly_queries.len() < self.hook_layout.poly_queries {
            let first = self
                .witnessed_polys
                .first()
                .expect("a layout affording a query affords a polynomial");
            let handle = first.handle.clone();
            let constant_term = first
                .coefficients
                .as_ref()
                .map(|c| c.first().copied().unwrap_or(D::F::ZERO));

            let allocator = &mut Standard::new();
            let x = Element::alloc(dr, allocator, D::just(|| D::F::ZERO))?;
            let y = Element::alloc(dr, allocator, constant_term)?;
            while self.poly_queries.len() < self.hook_layout.poly_queries {
                self.enforce_poly_query(&handle, x.clone(), y.clone())?;
            }
        }

        Ok(())
    }
}
