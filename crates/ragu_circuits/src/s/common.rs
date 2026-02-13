//! Shared types for wire evaluation during polynomial synthesis.
//!
//! # Design
//!
//! The [`sx`] and [`sxy`] evaluators compute polynomial coefficients directly
//! as field elements during circuit synthesis. Since both evaluators produce
//! immediate field element results, they can share the same wire representation
//! types defined here.
//!
//! In contrast, [`sy`] requires deferred computation through a virtual wire
//! system with reference counting, because $s(X, y)$ coefficients cannot be
//! computed in streaming order during synthesis (see [`sy`] module
//! documentation).
//!
//! ### Immediate Evaluation
//!
//! Both [`sx`] and [`sxy`] evaluate the wiring polynomial by interpreting
//! circuit synthesis operations directly. Wires become evaluated monomials
//! (field elements) rather than indices, and linear combinations become
//! immediate field arithmetic.
//!
//! ### `ONE` Wire Evaluation
//!
//! The `ONE` wire corresponds to the $c$ wire from gate 0, with monomial
//! $x^{4n-1}$. Since [`Driver::ONE`] must be a compile-time constant, it cannot
//! hold this computed value. Instead, [`WireEval::One`] serves as a sentinel
//! that [`WireEvalSum::add_term`] resolves to the cached $x^{4n - 1}$ value
//! at runtime.
//!
//! [`sx`]: super::sx
//! [`sxy`]: super::sxy
//! [`sy`]: super::sy
//! [`Driver::ONE`]: ragu_core::drivers::Driver::ONE

use core::marker::PhantomData;
use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, FromDriver, LinearExpression},
    routines::RoutineId,
};

use crate::floor_plan::RegistryPosition;

use alloc::{collections::BTreeMap, vec::Vec};

/// Cached polynomial contribution from a routine at a canonical floor plan position.
///
/// On cache hit, the `output_wires` can be used to reconstruct the output gadget
/// without re-executing the routine, enabling full memoization.
#[derive(Clone, Debug)]
pub struct CachedRoutine<F> {
    /// The routine's contribution to the polynomial evaluation.
    pub contribution: F,

    /// Number of multiplication gates consumed by this routine.
    pub num_multiplications: usize,

    /// Number of linear constraints consumed by this routine.
    pub num_constraints: usize,

    /// Output wire values for reconstructing the output gadget on cache hit.
    pub output_wires: Vec<WireEval<F>>,
}

/// Cache for routine contributions, keyed by `(RoutineId, canonical_position)`.
#[derive(Default, Clone)]
pub struct MemoCache<F> {
    entries: BTreeMap<(RoutineId, RegistryPosition), CachedRoutine<F>>,
}

impl<F: Clone> MemoCache<F> {
    /// Creates an empty cache.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Retrieves a cached routine contribution by canonical position.
    pub fn get(
        &self,
        routine_id: &RoutineId,
        canonical_position: RegistryPosition,
    ) -> Option<&CachedRoutine<F>> {
        self.entries.get(&(*routine_id, canonical_position))
    }

    /// Stores a routine contribution in the cache.
    pub fn insert(
        &mut self,
        routine_id: RoutineId,
        canonical_position: RegistryPosition,
        entry: CachedRoutine<F>,
    ) {
        self.entries.insert((routine_id, canonical_position), entry);
    }
}

/// Represents a wire's evaluated monomial during polynomial synthesis.
///
/// In the wiring polynomial $s(X, Y)$, each wire corresponds to a monomial
/// $x^j$ for some exponent $j$. When evaluating $s(x, y)$ at concrete points,
/// wires become field elements rather than indices.
///
/// # Variants
///
/// - `Value(F)` — Holds the evaluated monomial for a wire from [`Driver::mul`],
///   or a linear combination of such evaluations from [`Driver::add`].
///
/// - `One` — Represents the ONE wire. This variant exists because `Driver::ONE`
///   must be a compile-time constant, but the `ONE` wire's actual evaluation
///   (e.g., $x^{4n-1}$) depends on the evaluation point.
///   [`WireEvalSum::add_term`] resolves `One` to the cached evaluation at
///   runtime.
///
/// [`Driver::mul`]: ragu_core::drivers::Driver::mul
/// [`Driver::add`]: ragu_core::drivers::Driver::add
/// [`WireEvalSum::add_term`]: WireEvalSum::add_term
#[derive(Clone, Debug)]
pub enum WireEval<F> {
    Value(F),
    One,
}

/// An accumulator for linear combinations of [`WireEval`]s during polynomial
/// evaluation.
///
/// Implements [`LinearExpression`] to support [`Driver::add`], which builds
/// linear combinations of wires. The accumulator tracks both the running sum
/// and the context needed to resolve [`WireEval::One`] variants.
///
/// [`Driver::add`]: ragu_core::drivers::Driver::add
pub(super) struct WireEvalSum<F: Field> {
    /// Running sum of accumulated wire evaluations.
    pub(super) value: F,

    /// Cached evaluation of the `ONE` wire, used to resolve [`WireEval::One`].
    one: F,

    /// Coefficient multiplier for subsequently added terms.
    gain: Coeff<F>,
}

impl<F: Field> WireEvalSum<F> {
    pub(super) fn new(one: F) -> Self {
        Self {
            value: F::ZERO,
            one,
            gain: Coeff::One,
        }
    }
}

impl<F: Field> LinearExpression<WireEval<F>, F> for WireEvalSum<F> {
    fn add_term(mut self, wire_eval: &WireEval<F>, coeff: Coeff<F>) -> Self {
        self.value += match wire_eval {
            WireEval::Value(v) => *v,
            WireEval::One => self.one,
        } * (coeff * self.gain).value();
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain = self.gain * coeff;
        self
    }
}

/// Extracts wire values from a gadget for caching.
///
/// Used on cache miss to capture output wires from the executed routine.
/// The extracted wires can later be replayed via [`GadgetKind::from_cached_wires`].
///
/// [`GadgetKind::from_cached_wires`]: ragu_core::gadgets::GadgetKind::from_cached_wires
pub struct WireExtractor<F> {
    wires: Vec<WireEval<F>>,
}

impl<F> WireExtractor<F> {
    /// Creates a new wire extractor.
    pub fn new() -> Self {
        Self { wires: Vec::new() }
    }

    /// Consumes the extractor and returns the collected wires.
    pub fn into_wires(self) -> Vec<WireEval<F>> {
        self.wires
    }
}

impl<F> Default for WireExtractor<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'dr, F: Field, D: Driver<'dr, F = F, Wire = WireEval<F>>> FromDriver<'dr, 'dr, D>
    for WireExtractor<F>
{
    type NewDriver = PhantomData<F>;

    fn convert_wire(&mut self, wire: &WireEval<F>) -> Result<()> {
        self.wires.push(wire.clone());
        Ok(())
    }
}
