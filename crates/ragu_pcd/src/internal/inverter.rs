//! Batch inversion of the quotient denominators the `compute_v` circuits
//! need, on either side of the cycle.

use alloc::{vec, vec::Vec};

use ragu_arithmetic::ff::Field;
use ragu_circuits::registry::CircuitIndex;
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;

/// Batch inverter for computing denominators.
///
/// Computes differences `(base - value)` for each added value and accumulates
/// their field representations for batch inversion. After calling
/// [`invert`](Self::invert), the inverted differences can be retrieved using
/// the returned indices.
pub(crate) struct Inverter<'dr, D: Driver<'dr>> {
    /// Base [`Element`] from which differences are computed.
    ///
    /// Each call to [`add`](Self::add) subtracts the provided value from this
    /// base.
    base: Element<'dr, D>,

    /// Accumulated difference [`Element`]s: `(base - value)` for each added
    /// value.
    ///
    /// These differences will be batch-inverted when [`invert`](Self::invert)
    /// is called.
    differences: Vec<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr, F: ragu_arithmetic::ff::PrimeField>> Inverter<'dr, D> {
    /// Creates a batch inverter with the provided base [`Element`].
    ///
    /// The base represents a fixed evaluation point (e.g., $u$ or $y$
    /// coordinate) from which all added values will be subtracted. This allows
    /// efficient batch inversion of differences $(u - x_i)$ using Montgomery's
    /// trick.
    pub(crate) fn with_base(base: Element<'dr, D>) -> Self {
        Self {
            base,
            differences: Vec::new(),
        }
    }

    /// Adds a value to subtract from the base: computes `(base - value)`.
    ///
    /// Returns an index that can be used to retrieve the inverted difference
    /// after calling [`invert`](Self::invert).
    pub(crate) fn add(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<usize> {
        let index = self.differences.len();
        let diff = self.base.sub(dr, value);
        self.differences.push(diff);
        Ok(index)
    }

    /// Adds a constant field value to subtract from the base: computes `(base -
    /// constant)`.
    ///
    /// This is a convenience method for adding known field values (such as
    /// fixed points in the FFT domain) without first wrapping them in an
    /// [`Element`]. It creates a constant [`Element`] internally and calls
    /// [`add`](Self::add).
    ///
    /// Returns an index that can be used to retrieve the inverted difference
    /// after calling [`invert`](Self::invert).
    pub(crate) fn add_constant(&mut self, dr: &mut D, value: D::F) -> Result<usize> {
        let constant = Element::constant(dr, value);
        self.add(dr, &constant)
    }

    /// Adds an internal circuit's $\omega^j$ value to subtract from the base:
    /// the FFT domain element of the circuit's registry index.
    pub(crate) fn add_circuit(&mut self, dr: &mut D, circuit: CircuitIndex) -> Result<usize> {
        self.add_constant(dr, circuit.omega_j())
    }

    /// Performs batch inversion on all accumulated differences.
    ///
    /// Consumes the inverter and returns a vector of inverted [`Element`]s.
    /// Each difference [`Element`] is inverted using [`Element::invert_with`]
    /// with the batch-inverted field value as advice.
    ///
    /// During proving, this function batch inverts the accumulated field values
    /// using Montgomery's trick and uses them as advice for constraint
    /// generation. During verification, the field values are not available, but
    /// the inversion constraints are still enforced through the [`Element`]
    /// wiring.
    pub(crate) fn invert(self, dr: &mut D) -> Result<Vec<Element<'dr, D>>> {
        let mut advice = D::just(|| {
            let mut differences = self
                .differences
                .iter()
                .map(|diff| **diff.value().snag())
                .collect::<Vec<_>>();

            let mut scratch = vec![D::F::ZERO; differences.len()];
            ragu_arithmetic::ff::BatchInverter::invert_with_external_scratch(
                &mut differences,
                &mut scratch,
            );

            differences.into_iter()
        });

        self.differences
            .into_iter()
            .map(|e| e.invert_with(dr, advice.as_mut().map(|e| e.next().unwrap())))
            .collect()
    }
}
