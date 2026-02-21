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

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Error, Result,
    drivers::{Driver, FromDriver, LinearExpression},
};

use alloc::{collections::BTreeMap, vec::Vec};
use core::marker::PhantomData;

use crate::{floor_plan::RegistryPosition, routines::RoutineId};

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
///
/// Used for inter-circuit memoization: when evaluating multiple circuits,
/// routines at the same canonical position can reuse cached contributions.
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
    /// Evaluated monomial value.
    Value(F),
    /// Sentinel for the ONE wire.
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
/// The extracted wires can later be replayed via [`WireInjector`] and [`map_gadget`].
///
/// [`map_gadget`]: ragu_core::gadgets::GadgetKind::map_gadget
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

/// Injects cached wire values into a gadget template.
///
/// This is the reverse of [`WireExtractor`]: where the extractor captures wires
/// from a gadget into a cache, the injector reconstructs a gadget from cached
/// wires. Used on cache hit to avoid re-executing routines.
///
/// The injector implements [`FromDriver`] to convert from a wire-erased driver
/// (with `Wire = ()`) to a target driver with `Wire = WireEval<F>`, popping
/// cached wires in the same order that [`map_gadget`] visits them.
///
/// [`map_gadget`]: ragu_core::gadgets::GadgetKind::map_gadget
pub struct WireInjector<'a, F, TD> {
    wires: core::slice::Iter<'a, WireEval<F>>,
    _marker: PhantomData<TD>,
}

impl<'a, F, TD> WireInjector<'a, F, TD> {
    /// Creates a new wire injector from a slice of cached wires.
    pub fn new(wires: &'a [WireEval<F>]) -> Self {
        Self {
            wires: wires.iter(),
            _marker: PhantomData,
        }
    }

    /// Returns true if all cached wires have been consumed.
    pub fn is_exhausted(&self) -> bool {
        self.wires.len() == 0
    }
}

impl<
    'dr,
    'new_dr,
    F: Field,
    D: Driver<'dr, F = F, Wire = ()>,
    TD: Driver<'new_dr, F = F, Wire = WireEval<F>>,
> FromDriver<'dr, 'new_dr, D> for WireInjector<'_, F, TD>
{
    type NewDriver = TD;

    fn convert_wire(&mut self, _wire: &()) -> Result<WireEval<F>> {
        self.wires
            .next()
            .cloned()
            .ok_or_else(|| Error::InvalidWitness("wire cache underflow".into()))
    }
}
