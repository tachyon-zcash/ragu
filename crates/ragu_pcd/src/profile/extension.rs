//! What a profile adds on one side of the cycle, and the registry slots its
//! hooks fill with it.

use alloc::vec::Vec;

use ragu_circuits::{
    BondingObject, Circuit, WithAux,
    polynomials::{Rank, sparse},
    registry::RegistryBuilder,
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
};
use ragu_primitives::{Element, WithSuffix};
use udon::field::Field;

/// A registry slot a profile's circuit hook fills with one internal circuit.
///
/// The hook receives the slot and returns it [`Registered`], which only
/// [`register`](Self::register) produces, so a hook registers one circuit
/// and nothing else, and the layout's indices stay the registry's.
pub struct CircuitSlot<'params, F: Field, R: Rank>(RegistryBuilder<'params, F, R>);

impl<'params, F: Field, R: Rank> CircuitSlot<'params, F, R> {
    /// The slot of `registry`'s next internal circuit.
    pub(crate) fn new(registry: RegistryBuilder<'params, F, R>) -> Self {
        CircuitSlot(registry)
    }

    /// Registers `circuit` as the slot's internal circuit, with a constant
    /// zero appended to its public output.
    ///
    /// The prover names the application circuit's registry slot in the
    /// proof, and the verifier checks only that it lies in the registry's
    /// domain, so every slot but a step's must be unable to satisfy an
    /// application instance. An application instance's linear coefficient
    /// is its output header's suffix, never zero, while a circuit whose last
    /// public output is a constant zero has no wire in that row, so no trace
    /// gives it a linear term. The fuse's circuits end their outputs so, and
    /// this appends the same zero to every extension circuit's, including
    /// one without an output, whose first constraint would otherwise take
    /// the row. The statement and binding circuits' $k(y)$ targets append
    /// the zero too; a circuit without an output keeps $k(y) = 1$. The
    /// profile's prover traces the circuit as it handed it over, without the
    /// zero, which adds no gate: the trace is the registered circuit's.
    ///
    /// # Errors
    ///
    /// Propagates the registry's error.
    pub fn register<C: Circuit<F> + 'params>(
        self,
        circuit: C,
    ) -> Result<Registered<'params, F, R>> {
        self.0
            .register_internal_circuit(Suffixed(circuit))
            .map(Registered)
    }
}

/// A registry slot a profile's bonding hook fills with one bonding, a
/// stage's mask or a final mask.
///
/// The hook receives the slot and returns it [`Registered`], which only
/// [`register`](Self::register) produces, so a hook registers one bonding
/// and nothing else.
pub struct BondingSlot<'params, F: Field, R: Rank>(RegistryBuilder<'params, F, R>);

impl<'params, F: Field, R: Rank> BondingSlot<'params, F, R> {
    /// The slot of `registry`'s next bonding.
    pub(crate) fn new(registry: RegistryBuilder<'params, F, R>) -> Self {
        BondingSlot(registry)
    }

    /// Registers `bonding` as the slot's bonding.
    pub fn register(self, bonding: BondingObject<'params, F, R>) -> Registered<'params, F, R> {
        Registered(self.0.register_bonding(bonding))
    }
}

/// A slot a hook filled: the registry with the slot's one entry registered.
pub struct Registered<'params, F: Field, R: Rank>(RegistryBuilder<'params, F, R>);

impl<'params, F: Field, R: Rank> Registered<'params, F, R> {
    /// The registry, with the entry.
    pub(crate) fn into_registry(self) -> RegistryBuilder<'params, F, R> {
        self.0
    }
}

/// A circuit with a constant zero appended to its public output; see
/// [`CircuitSlot::register`].
struct Suffixed<C>(C);

impl<F: Field, C: Circuit<F>> Circuit<F> for Suffixed<C> {
    type Instance<'source> = C::Instance<'source>;
    type Witness<'source> = C::Witness<'source>;
    type Output = Kind![F; @WithSuffix<'_, _, C::Output>];
    type Aux<'source> = C::Aux<'source>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        let output = self.0.instance(dr, instance)?;
        Ok(WithSuffix::new(output, Element::zero(dr)))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (output, aux) = self.0.witness(dr, witness)?.into_parts();
        Ok(WithAux::new(
            WithSuffix::new(output, Element::zero(dr)),
            aux,
        ))
    }
}

/// An extension's polynomials for one proof: its circuits' rx polynomials
/// in circuit order, then its stages' in stage order.
#[derive(Clone, Debug)]
pub struct ExtensionRxs<F: Field, R: Rank> {
    /// The circuits' polynomials.
    pub circuits: Vec<sparse::Polynomial<F, R>>,
    /// The stages' polynomials.
    pub stages: Vec<sparse::Polynomial<F, R>>,
}

impl<F: Field, R: Rank> Default for ExtensionRxs<F, R> {
    fn default() -> Self {
        ExtensionRxs {
            circuits: Vec::new(),
            stages: Vec::new(),
        }
    }
}

/// What a profile adds on one side of the cycle: internal circuits beyond
/// the fuse's own and the stages they load.
///
/// The circuits are registered as internal circuits after the fuse's and
/// the bondings, the stages' masks then the final masks, after the fuse's
/// masks, so that the registry's order stays circuits first. Each circuit
/// and each stage has an rx polynomial in the proof; a final mask, the
/// final mask of its circuits' last stage, binds the rx polynomials of the
/// circuits it names, as the fuse's final masks do, and has none. A circuit's claim takes its own rx polynomial and the
/// stages it loads, with $k(y) = 1$ as the fuse's steps have, since an
/// extension circuit carries no instance of its own; the statement
/// circuit's $k(y)$ is instead the output header it exposes, and the
/// binding circuit's the other side's stage commitments it exposes. Every
/// extension circuit's output ends with the zero its slot appends (see
/// [`CircuitSlot::register`]), which those two $k(y)$ values include and
/// which leaves $k(y) = 1$ as it is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extension {
    /// Each circuit's stages, by index among the stages, in the order the
    /// circuit loads them, which is the order of their gates: a stage's
    /// gates follow its parent's, so the indices number the stages in gate
    /// order and each list is strictly increasing. Its last entry is then
    /// the stage whose final mask covers the circuit's gates.
    pub circuits: Vec<Vec<u32>>,
    /// The number of stages.
    pub stages: usize,
    /// Each final mask's circuits, by index among the circuits, all with the
    /// same last stage.
    pub final_masks: Vec<Vec<u32>>,
    /// The statement circuit, by index among the circuits, for an extension
    /// that verifies a compressed proof: the circuit whose public output is
    /// the output header of the proof it verified, so that its claim's
    /// $k(y)$ binds the proof's own output header to it. `None` for any
    /// other extension, and always on the nested side.
    ///
    /// The statement binds the header's fields only. A profile that declares
    /// one registers the decompression step, whose output proof carries the
    /// verified header with the constant one in both online slots, and a
    /// step consuming that proof cannot tell it from one a registered step
    /// produced. Before declaring a statement, either every header a
    /// decompressed statement can carry must treat its slots as padding, or
    /// the statement must also expose the compressed proof's online
    /// commitments for the decompression step to hold its output slots to
    /// (see [`NUM_ONLINE_FP_POLYS`](crate::header::NUM_ONLINE_FP_POLYS)).
    pub statement: Option<u32>,
    /// The binding circuit, for an extension whose circuits take values the
    /// other side's extension computes: the circuit whose public output is
    /// its recomputation of the other side's stages, so that its claim's
    /// $k(y)$ holds it to the commitments the proof carries for them.
    /// `None` for an extension that binds nothing.
    pub binding: Option<Binding>,
}

/// An extension's binding circuit: the circuit, by index among the
/// extension's circuits, whose public output is one point per stage of
/// `stages`, the other side's extension stages by index in that extension,
/// each the circuit's recomputation of that stage's commitment. The
/// claim's $k(y)$ is the $k(y)$ of those stages' commitments as the proof
/// carries them, so the claim holds only if the recomputation matches: the
/// values the circuit's side took from the other side are the ones the
/// other side's stages hold.
///
/// The circuit recomputes a commitment from the stage's values, so the
/// other side commits a bound stage unblinded, and the commitment then
/// hides nothing of the values, or the circuit takes the stage's blinding
/// as a witness and adds its term. The profile must ensure that the output
/// order matches `stages` and that each commitment is recomputed from the
/// values its circuits actually use for that stage. This agreement is part
/// of the trusted setup: a mismatched association can accept unintended
/// statements even when the exposed commitments match the claim's target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The binding circuit, by index among the extension's circuits.
    pub circuit: u32,
    /// The other side's extension stages the circuit's output points
    /// recompute, by index among that extension's stages, in output order.
    pub stages: Vec<u32>,
}

impl Extension {
    /// No circuits and no stages.
    pub const EMPTY: Self = Extension {
        circuits: Vec::new(),
        stages: 0,
        final_masks: Vec::new(),
        statement: None,
        binding: None,
    };

    /// Whether the extension adds nothing.
    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty() && self.stages == 0 && self.final_masks.is_empty()
    }

    /// The rx polynomials the extension adds: one per circuit and one per
    /// stage.
    pub fn rx(&self) -> usize {
        self.circuits.len() + self.stages
    }

    /// The bondings the extension registers: the stages' masks, then the
    /// final masks.
    pub fn bondings(&self) -> usize {
        self.stages + self.final_masks.len()
    }

    /// The internal circuits the extension registers: its circuits and its
    /// bondings.
    pub fn internal(&self) -> usize {
        self.circuits.len() + self.bondings()
    }

    /// The circuits a final mask binds, for `bonding` an index among the
    /// bondings past the stages' masks.
    pub fn final_mask(&self, bonding: usize) -> &[u32] {
        &self.final_masks[bonding - self.stages]
    }

    /// Whether the declaration is well formed: every index the circuits,
    /// final masks, statement and binding name exists; each circuit lists
    /// its stages in strictly increasing order, so in gate order with no
    /// stage twice (see [`circuits`](Self::circuits)); neither a final mask
    /// names a circuit twice nor the binding a stage twice; the statement
    /// and binding circuits differ and the binding names at least one stage;
    /// every circuit that loads a stage is named by exactly one final mask
    /// and a circuit that loads none by no final mask; and a final mask's
    /// circuits share their last stage. A stage's final mask confines the
    /// traces of the circuits whose last stage it is to the gates after it,
    /// so a circuit under no final mask has a trace that can reach into the
    /// stages it loads, and one under another stage's, or whose list ends
    /// in a stage before the last it loads, is checked against the wrong
    /// gates. Whether the binding's stages exist is the other extension's
    /// to say, which [`Profile::check`](super::Profile::check) asks.
    pub fn is_consistent(&self) -> bool {
        fn distinct(values: &[u32]) -> bool {
            values
                .iter()
                .enumerate()
                .all(|(i, value)| !values[..i].contains(value))
        }
        let in_range = self
            .circuits
            .iter()
            .flatten()
            .all(|&stage| (stage as usize) < self.stages)
            && self
                .final_masks
                .iter()
                .flatten()
                .all(|&circuit| (circuit as usize) < self.circuits.len())
            && self
                .statement
                .is_none_or(|circuit| (circuit as usize) < self.circuits.len())
            && self.binding.as_ref().is_none_or(|binding| {
                (binding.circuit as usize) < self.circuits.len()
                    && self.statement != Some(binding.circuit)
                    && !binding.stages.is_empty()
                    && distinct(&binding.stages)
            });
        // In gate order, which leaves `last()` the stage whose final mask
        // covers the circuit, and names no stage twice.
        let increasing = |stages: &[u32]| stages.windows(2).all(|pair| pair[0] < pair[1]);
        in_range
            && self.circuits.iter().all(|stages| increasing(stages))
            && self.final_masks.iter().all(|mask| distinct(mask))
            && self.circuits.iter().enumerate().all(|(circuit, stages)| {
                let masks = self
                    .final_masks
                    .iter()
                    .filter(|mask| mask.contains(&(circuit as u32)))
                    .count();
                masks == usize::from(!stages.is_empty())
            })
            && self.final_masks.iter().all(|mask| {
                let mut last = mask
                    .iter()
                    .map(|&circuit| self.circuits[circuit as usize].last());
                last.next()
                    .is_some_and(|first| last.all(|stage| stage == first))
            })
    }
}
