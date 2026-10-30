use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
    pasta::{Eq, EqAffine, Fp, Pasta, PastaParams},
};
use ragu_primitives::{Element, poseidon::Sponge};
use udon::{curve::Affine as _, field::Field};

use super::poly_commitment::PolyHandle;

pub(crate) type PolyQuery = (Eq, Fp, Fp);

/// A polynomial witnessed by the current step, together with its commitment.
struct Witnessed<'dr, D: Driver<'dr, F = Fp>> {
    handle: PolyHandle<'dr, D, Pasta>,
    commitment: DriverValue<D, EqAffine>,
    coefficients: DriverValue<D, Vec<Fp>>,
}

/// A poly-query recorded by the current step.
struct Queried<'dr, D: Driver<'dr, F = Fp>> {
    commitment: DriverValue<D, EqAffine>,
    x: Element<'dr, D>,
    y: Element<'dr, D>,
}

/// Unconfigured framework state threaded through one step invocation.
pub(crate) struct FrameworkHooks<'dr, D: Driver<'dr, F = Fp>> {
    witnessed_polynomials: Vec<Witnessed<'dr, D>>,
    poly_queries: Vec<Queried<'dr, D>>,
    params: &'dr PastaParams,
}

impl<'dr, D: Driver<'dr, F = Fp>> FrameworkHooks<'dr, D> {
    pub(crate) fn new(params: &'dr PastaParams) -> Self {
        Self {
            witnessed_polynomials: Vec::new(),
            poly_queries: Vec::new(),
            params,
        }
    }

    pub(crate) fn witness_polynomial<R: Rank>(
        &mut self,
        dr: &mut D,
        polynomial: DriverValue<D, sparse::Polynomial<Fp, R>>,
    ) -> Result<PolyHandle<'dr, D, Pasta>> {
        let (handle, commitment) = PolyHandle::new(dr, self.params, &polynomial)?;
        self.witnessed_polynomials.push(Witnessed {
            handle: handle.clone(),
            commitment,
            coefficients: polynomial.map(|p| p.iter_coeffs().collect()),
        });
        Ok(handle)
    }

    pub(crate) fn evaluate(
        &self,
        handle: &PolyHandle<'dr, D, Pasta>,
        x: DriverValue<D, Fp>,
    ) -> Result<DriverValue<D, Fp>> {
        let found = self.witnessed_of(handle)?;
        Ok(D::just(move || {
            let (_, coefficients) = found.take();
            eval(&coefficients, x.take())
        }))
    }

    pub(crate) fn enforce_poly_query(
        &mut self,
        handle: &PolyHandle<'dr, D, Pasta>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        let found = self.witnessed_of(handle)?;
        let commitment = found.as_ref().map(|(commitment, _)| *commitment);
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

        self.poly_queries.push(Queried { commitment, x, y });
        Ok(())
    }

    pub(crate) fn derive_challenge(
        &mut self,
        dr: &mut D,
        inputs: &[Element<'dr, D>],
    ) -> Result<Element<'dr, D>> {
        let mut sponge = Sponge::new(dr, Pasta::circuit_poseidon(self.params));
        let domain = Element::constant(dr, Fp::from_u128(DOMAIN_TAG));
        sponge.absorb(dr, &domain)?;
        for input in inputs {
            sponge.absorb(dr, input)?;
        }
        sponge.squeeze(dr)
    }

    /// Finds the commitment and coefficients named by `handle`.
    fn witnessed_of(
        &self,
        handle: &PolyHandle<'dr, D, Pasta>,
    ) -> Result<DriverValue<D, (EqAffine, Vec<Fp>)>> {
        D::try_just(|| {
            let sought = handle.value().take();
            self.witnessed_polynomials
                .iter()
                .find(|witnessed| witnessed.handle.value().take() == sought)
                .map(|witnessed| {
                    (
                        *witnessed.commitment.as_ref().take(),
                        witnessed.coefficients.as_ref().take().clone(),
                    )
                })
                .ok_or_else(|| {
                    Error::InvalidWitness(
                        "evaluation rejected: the handle names no polynomial this step witnessed"
                            .into(),
                    )
                })
        })
    }

    /// Drains the recorded poly-queries in invocation order.
    pub(crate) fn into_outputs(self) -> DriverValue<D, Vec<PolyQuery>> {
        D::just(move || {
            self.poly_queries
                .into_iter()
                .map(|query| {
                    let Queried { commitment, x, y } = query;
                    (
                        commitment.take().to_projective(),
                        *x.value().take(),
                        *y.value().take(),
                    )
                })
                .collect()
        })
    }
}

/// $p(x)$ by Horner's rule, from the constant term up.
fn eval(coefficients: &[Fp], x: Fp) -> Fp {
    coefficients
        .iter()
        .rev()
        .fold(Fp::ZERO, |acc, coefficient| acc * x + *coefficient)
}

/// Absorbed before every challenge input so an empty input still has a domain.
const DOMAIN_TAG: u128 = u64::from_le_bytes(*b"raguchal") as u128;
