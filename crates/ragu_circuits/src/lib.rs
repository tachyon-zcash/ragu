//! # `ragu_circuits`
//!
//! This crate contains traits and utilities for synthesizing arithmetic
//! circuits into polynomials for the Ragu project. This API is re-exported (as
//! necessary) in other crates and so this crate is only intended to be used
//! internally by Ragu.

#![cfg_attr(not(test), no_std)]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

extern crate alloc;

mod ky;
mod metrics;
pub mod polynomials;
pub mod registry;
mod rx;
mod s;
pub mod staging;
mod trivial;

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "unstable-test-fixtures"))]
#[doc(hidden)]
pub mod test_fixtures;

use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
};
use ragu_primitives::io::Write;

use alloc::{boxed::Box, vec::Vec};

use polynomials::{Rank, structured, unstructured};

/// Core trait for arithmetic circuits.
pub trait Circuit<F: Field>: Sized + Send + Sync {
    /// The type of data that is needed to construct the expected output of this
    /// circuit.
    type Instance<'source>: Send;

    /// The type of data that is needed to compute a satisfying witness for this
    /// circuit.
    type Witness<'source>: Send;

    /// Represents a gadget that can be serialized and represents the output of
    /// a circuit computation.
    type Output: Write<F>;

    /// Auxiliary data produced during the computation of the
    /// [`witness`](Circuit::witness) method that may be useful, such as
    /// interstitial witness material that is needed for future synthesis.
    type Aux<'source>: Send;

    /// Given an instance type for this circuit, use the provided [`Driver`] to
    /// return a `Self::Output` gadget that the _some_ corresponding witness
    /// should have produced as a result of the [`witness`](Circuit::witness)
    /// method. This can be seen as "short-circuiting" the computation involving
    /// the witness, which a verifier would not have in its possession.
    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>>
    where
        Self: 'dr;

    /// Given a witness type for this circuit, perform a computation using the
    /// provided [`Driver`] and return the `Self::Output` gadget that the verifier's
    /// instance should produce as a result of the
    /// [`instance`](Circuit::instance) method.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr;
}

/// Extension trait for all circuits.
pub trait CircuitExt<F: Field>: Circuit<F> {
    /// Given a polynomial [`Rank`], convert this circuit into a boxed
    /// [`CircuitObject`] that provides methods for evaluating the $s(X, Y)$
    /// polynomial for this circuit.
    fn into_object<'a, R: Rank>(self) -> Result<Box<dyn CircuitObject<F, R> + 'a>>
    where
        Self: 'a,
    {
        let metrics = metrics::eval(&self)?;

        if metrics.num_linear_constraints > R::num_coeffs() {
            return Err(Error::LinearBoundExceeded(R::num_coeffs()));
        }

        if metrics.num_multiplication_constraints > R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }

        struct ProcessedCircuit<C> {
            circuit: C,
            metrics: metrics::CircuitMetrics,
        }

        impl<F: Field, C: Circuit<F>, R: Rank> CircuitObject<F, R> for ProcessedCircuit<C> {
            fn sxy(&self, x: F, y: F, key: F) -> F {
                s::sxy::eval::<_, _, R>(&self.circuit, x, y, key)
                    .expect("should succeed if metrics succeeded")
            }
            fn sx(&self, x: F, key: F) -> unstructured::Polynomial<F, R> {
                s::sx::eval(&self.circuit, x, key).expect("should succeed if metrics succeeded")
            }
            fn sy(&self, y: F, key: F) -> structured::Polynomial<F, R> {
                s::sy::eval(&self.circuit, y, key, self.metrics.num_linear_constraints)
                    .expect("should succeed if metrics succeeded")
            }
            fn constraint_counts(&self) -> (usize, usize) {
                (
                    self.metrics.num_multiplication_constraints,
                    self.metrics.num_linear_constraints,
                )
            }
        }

        let circuit = ProcessedCircuit {
            circuit: self,
            metrics,
        };
        Ok(Box::new(circuit))
    }

    /// Computes the witness polynomial $r(X)$ given a witness for the circuit.
    fn rx<'witness, R: Rank>(
        &self,
        witness: Self::Witness<'witness>,
        key: F,
    ) -> Result<(structured::Polynomial<F, R>, Self::Aux<'witness>)> {
        rx::eval(self, witness, key)
    }

    /// Computes the public input polynomial $k(Y)$ for the given instance.
    fn ky(&self, instance: Self::Instance<'_>) -> Result<Vec<F>> {
        ky::eval(self, instance)
    }
}

impl<F: Field, C: Circuit<F>> CircuitExt<F> for C {}

/// A trait for (partially) evaluating $s(X, Y)$ for some circuit.
///
/// See [`CircuitExt::into_object`].
pub trait CircuitObject<F: Field, R: Rank>: Send + Sync {
    /// Evaluates the polynomial $s(x, y)$ for some $x, y \in \mathbb{F}$.
    fn sxy(&self, x: F, y: F, key: F) -> F;

    /// Computes the polynomial restriction $s(x, Y)$ for some $x \in \mathbb{F}$.
    fn sx(&self, x: F, key: F) -> unstructured::Polynomial<F, R>;

    /// Computes the polynomial restriction $s(X, y)$ for some $y \in \mathbb{F}$.
    fn sy(&self, y: F, key: F) -> structured::Polynomial<F, R>;

    /// Returns the number of constraints: `(multiplication, linear)`.
    fn constraint_counts(&self) -> (usize, usize);
}
