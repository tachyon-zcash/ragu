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
    convert::WireMap,
    drivers::{DriverTypes, LinearExpression},
};

use alloc::{collections::BTreeMap, vec::Vec};
use core::marker::PhantomData;

use crate::{RoutineFingerprint, floor_plan::RegistryPosition};

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

/// Cache for routine contributions, keyed by `(RoutineFingerprint, canonical_position)`.
///
/// Used for inter-circuit memoization: when evaluating multiple circuits,
/// routines at the same canonical position can reuse cached contributions.
#[derive(Default, Clone)]
pub struct MemoCache<F> {
    entries: BTreeMap<(RoutineFingerprint, RegistryPosition), CachedRoutine<F>>,
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
        fingerprint: &RoutineFingerprint,
        canonical_position: RegistryPosition,
    ) -> Option<&CachedRoutine<F>> {
        self.entries.get(&(*fingerprint, canonical_position))
    }

    /// Stores a routine contribution in the cache.
    pub fn insert(
        &mut self,
        fingerprint: RoutineFingerprint,
        canonical_position: RegistryPosition,
        entry: CachedRoutine<F>,
    ) {
        self.entries
            .insert((fingerprint, canonical_position), entry);
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
pub(crate) struct WireEvalSum<F: Field> {
    /// Running sum of accumulated wire evaluations.
    pub(crate) value: F,

    /// Cached evaluation of the `ONE` wire, used to resolve [`WireEval::One`].
    one: F,

    /// Coefficient multiplier for subsequently added terms.
    gain: Coeff<F>,
}

impl<F: Field> WireEvalSum<F> {
    pub(crate) fn new(one: F) -> Self {
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
pub struct WireExtractor<F, Src: DriverTypes> {
    wires: Vec<WireEval<F>>,
    _marker: PhantomData<Src>,
}

impl<F, Src: DriverTypes> WireExtractor<F, Src> {
    /// Creates a new wire extractor.
    pub fn new() -> Self {
        Self {
            wires: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Consumes the extractor and returns the collected wires.
    pub fn into_wires(self) -> Vec<WireEval<F>> {
        self.wires
    }
}

impl<F, Src: DriverTypes> Default for WireExtractor<F, Src> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field, Src: DriverTypes<ImplField = F, ImplWire = WireEval<F>>> WireMap<F>
    for WireExtractor<F, Src>
{
    type Src = Src;
    type Dst = PhantomData<F>;

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
/// The injector implements [`WireMap`] to convert from a wire-erased driver
/// (with `Wire = ()`) to a target driver with `Wire = WireEval<F>`, popping
/// cached wires in the same order that [`map_gadget`] visits them.
///
/// [`map_gadget`]: ragu_core::gadgets::GadgetKind::map_gadget
pub struct WireInjector<'a, F, Src: DriverTypes, Dst: DriverTypes> {
    wires: core::slice::Iter<'a, WireEval<F>>,
    _marker: PhantomData<(Src, Dst)>,
}

impl<'a, F, Src: DriverTypes, Dst: DriverTypes> WireInjector<'a, F, Src, Dst> {
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
    F: Field,
    Src: DriverTypes<ImplField = F, ImplWire = ()>,
    Dst: DriverTypes<ImplField = F, ImplWire = WireEval<F>>,
> WireMap<F> for WireInjector<'_, F, Src, Dst>
{
    type Src = Src;
    type Dst = Dst;

    fn convert_wire(&mut self, _wire: &()) -> Result<WireEval<F>> {
        self.wires
            .next()
            .cloned()
            .ok_or_else(|| Error::InvalidWitness("wire cache underflow".into()))
    }
}
