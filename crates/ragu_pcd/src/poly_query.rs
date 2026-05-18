//! Polynomial-query claim collection for [`Step`](crate::step::Step) impls.
//!
//! A `Step::witness` impl receives a `pq: &mut PolyQueryClaims<...>`
//! parameter alongside its driver. Steps that need to verify a
//! polynomial-commitment opening — i.e. that the polynomial committed to by
//! `com` evaluates to `y` at point `x` — call
//! `pq.enforce_polynomial_query(dr, com, x, y, coefficients)`. The framework
//! collects the resulting claims through the adapter's `Aux` for later
//! fuse-time batching into the step's `(P, u, v)` tuple via the
//! [PCS aggregation protocol]. Steps that don't need polynomial-query
//! verification simply ignore the parameter.
//!
//! Coefficients are stored as a flat `Vec<F>` rather than a typed
//! `sparse::Polynomial<F, R>` because `R: Rank` is an application-wide
//! parameter (carried on [`Adapter`](crate::step::internal::adapter::Adapter)
//! / [`Application`](crate::Application)) and the [`Step`](crate::step::Step)
//! trait is `R`-polymorphic. The fuse pipeline re-forms the typed
//! polynomial at the call site where `R` is known.
//!
//! [PCS aggregation protocol]: https://tachyon.z.cash/ragu/protocol/core/accumulation/pcs.html#pcs-aggregation

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, Point};

/// A single polynomial-commitment opening claim, with the polynomial it opens.
///
/// The framework needs the polynomial coefficients (not just the claim
/// instance) so it can build the alpha-batched quotient $f(X)$ and evaluate
/// $p(u)$ during the fuse pipeline's PCS aggregation.
pub struct PolyQueryClaim<F: ff::PrimeField, C: CurveAffine<Base = F>> {
    /// Commitment to the polynomial.
    pub com: C,
    /// Point at which the polynomial is opened.
    pub x: F,
    /// Claimed evaluation $p(x) = y$.
    pub y: F,
    /// Coefficients of the polynomial $p(X)$ being opened, little-endian
    /// (`coefficients[i]` is the coefficient of $X^i$).
    pub coefficients: Vec<F>,
}

/// Sink for polynomial-commitment opening claims raised by a
/// [`Step::witness`](crate::step::Step::witness) invocation.
///
/// Wires aren't carried out of `witness()`, so each recorded claim's
/// `(com, x, y, coefficients)` data is extracted up-front and accumulated
/// into a single `DriverValue`. The framework's adapter constructs this
/// sink, passes it to the step, then surfaces [`into_inner`](Self::into_inner)
/// through its `Aux` for batching into $(P, u, v)$ during fuse.
pub struct PolyQueryClaims<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>>
where
    D::F: ff::PrimeField,
{
    claims: DriverValue<D, Vec<PolyQueryClaim<D::F, C>>>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> PolyQueryClaims<'dr, D, C>
where
    D::F: ff::PrimeField,
{
    /// Creates a new, empty claim collector.
    pub fn new() -> Self {
        Self {
            claims: D::just(Vec::new),
        }
    }

    /// Records a claim that the polynomial with the given `coefficients`,
    /// committed to by `com`, evaluates to `y` at the point `x`.
    ///
    /// `coefficients` carries the polynomial coefficients (little-endian) to
    /// the framework so the fuse pipeline can batch the opening claim into
    /// the step's $(P, u, v)$ accumulator. The step itself does not need to
    /// use `coefficients` in-circuit.
    pub fn enforce_polynomial_query(
        &mut self,
        _dr: &mut D,
        com: Point<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
        coefficients: DriverValue<D, Vec<D::F>>,
    ) -> Result<()> {
        let claim = D::try_just(|| {
            Ok(PolyQueryClaim {
                com: com.value().take(),
                x: *x.value().take(),
                y: *y.value().take(),
                coefficients: coefficients.take(),
            })
        })?;
        let current = core::mem::replace(&mut self.claims, D::just(Vec::new));
        self.claims = current.and_then(|mut v| {
            claim.map(|c| {
                v.push(c);
                v
            })
        });
        Ok(())
    }

    /// Consumes the sink and returns the accumulated claim values.
    pub fn into_inner(self) -> DriverValue<D, Vec<PolyQueryClaim<D::F, C>>> {
        self.claims
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Default for PolyQueryClaims<'dr, D, C>
where
    D::F: ff::PrimeField,
{
    fn default() -> Self {
        Self::new()
    }
}
