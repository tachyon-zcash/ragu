//! Evaluate the [`Step`] circuit and fill the application slots.
//!
//! This creates a witness for the step circuit given the two input [`Pcd`](crate::Pcd)s and
//! the step witness and fills the proof's application polynomials: the shared
//! stage, committed once per fuse, and the slots. A step registered on its
//! own fills every slot with its one claim over an empty stage; a bundle's
//! first fragment fills the first slot with the other fragment's [`Slot`]
//! beside it. Both export the same connection values for one common stage.

use alloc::vec::Vec;

use ragu_circuits::{
    Circuit, CircuitExt, Trace, WithAux,
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging,
};
use ragu_core::{Cycle, Error, Result};
use ragu_primitives::shared::Shared;
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application, Header,
    internal::{ky, native::APPLICATION_SLOTS},
    proof::{ProofBuilder, builder::ApplicationRxs},
    step::{Step, internal::adapter::Adapter},
};

/// A fragment trace prepared for the other application slot.
/// Both fragments use the same children, headers and shared stage; proving
/// checks these values against the registered bundle before folding them.
pub(crate) struct Slot<C: Cycle, R: Rank> {
    pub(crate) circuit: CircuitIndex,
    pub(crate) rx: sparse::Polynomial<C::CircuitField, R>,
    /// The connection values exported by this fragment, which must equal
    /// the other fragment's values in the common stage.
    pub(crate) shared: Vec<C::CircuitField>,
    /// The slot's encoded left, right and output headers, which must equal
    /// the step's for the slot's claim to hold.
    pub(crate) headers: [Vec<C::CircuitField>; 3],
}

impl<C: Cycle, R: Rank> Clone for Slot<C, R> {
    fn clone(&self) -> Self {
        Slot {
            circuit: self.circuit,
            rx: self.rx.clone(),
            shared: self.shared.clone(),
            headers: self.headers.clone(),
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Trace and assemble one registered fragment before proving its bundle.
    /// Its headers and shared values must match the primary fragment's.
    pub(crate) fn slot<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: <S::Left as Header<C::CircuitField>>::Data,
        right: <S::Right as Header<C::CircuitField>>::Data,
    ) -> Result<(
        Slot<C, R>,
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
    )> {
        let bundle = S::INDEX.bundle(&self.application_bundles)?;
        let trace = Adapter::<C, S, R, HEADER_SIZE>::new(step, bundle, self.shared_size)?
            .trace((left, right, witness))?;
        self.assemble_slot::<RNG, S>(rng, trace)
    }

    /// Assemble an independently prepared fragment, including its automatic
    /// wire bindings and the shared values exported by the adapter.
    pub(crate) fn assemble_slot<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        traced: WithAux<
            Trace<C::CircuitField>,
            <Adapter<C, S, R, HEADER_SIZE> as Circuit<C::CircuitField>>::Aux<'source>,
        >,
    ) -> Result<(
        Slot<C, R>,
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
    )> {
        let (trace, aux) = traced.into_parts();
        let circuit = S::INDEX.circuit_index(self.num_application_steps)?;
        let rx = self.native_registry.assemble(&trace, circuit, &mut *rng)?;
        let ((left_header, right_header), output_data, step_aux, shared) = aux;
        let output_header = ky::output_header::<C, S::Output, HEADER_SIZE>(output_data.clone())?;
        Ok((
            Slot {
                circuit,
                rx,
                shared,
                headers: [
                    left_header.into_inner(),
                    right_header.into_inner(),
                    output_header,
                ],
            },
            output_data,
            step_aux,
        ))
    }

    pub(super) fn compute_application_proof<RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        first: Slot<C, R>,
        slots: Vec<Slot<C, R>>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let bundle = S::INDEX.bundle(&self.application_bundles)?;
        let shared_size = if crate::internal::native::is_split_bundle(bundle) {
            self.shared_size
        } else {
            0
        };
        if first.shared.len() != S::Shared::num_values()? || first.shared.len() > shared_size {
            return Err(Error::InvalidWitness(
                "the shared gadget does not fit this bundle".into(),
            ));
        }
        let primary = S::INDEX.circuit_index(self.num_application_steps)?;
        let repeated = bundle.iter().all(|id| *id == primary);

        // A step registered on its own fills every slot with its one claim,
        // so it takes no slots; a bundle's fragments must all be supplied, in
        // the registered order. The registry decides which case applies, not
        // the caller: a fragment proved alone is refused here, and a prover
        // that bypasses this check is refused by the bundle constants every
        // fragment's circuit carries.
        if slots.is_empty() {
            if !repeated {
                return Err(Error::InvalidWitness(
                    "a bundle fragment cannot be proved alone; supply every fragment".into(),
                ));
            }
        } else if slots.len() != APPLICATION_SLOTS - 1 {
            return Err(Error::InvalidWitness(
                "a bundle fills every application slot explicitly".into(),
            ));
        }
        if first.circuit != primary
            || primary != bundle[0]
            || slots
                .iter()
                .zip(&bundle[1..])
                .any(|(slot, id)| slot.circuit != *id)
        {
            return Err(Error::InvalidWitness(
                "application slots do not match the registered bundle".into(),
            ));
        }

        // The shared stage, committed once: every slot's claim adds it to
        // the slot's own polynomial, so a fragment traced against other
        // shared values would not satisfy its circuit.
        let stage_rx = staging::stage_rx::<_, R>(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            1,
            shared_size,
            &first.shared,
        )?;
        let [left_header, right_header, output_header] = first.headers;

        let rxs = if slots.is_empty() {
            ApplicationRxs::Repeated(first.rx)
        } else {
            let mut rxs = Vec::with_capacity(APPLICATION_SLOTS);
            rxs.push(first.rx);
            for slot in slots {
                if slot.shared != first.shared {
                    return Err(Error::InvalidWitness(
                        "a slot's shared stage differs from the step's".into(),
                    ));
                }
                if slot.headers[0] != left_header
                    || slot.headers[1] != right_header
                    || slot.headers[2] != output_header
                {
                    return Err(Error::InvalidWitness(
                        "a slot's headers differ from the step's".into(),
                    ));
                }
                rxs.push(slot.rx);
            }
            ApplicationRxs::PerSlot(rxs)
        };

        builder.set_circuit_ids(bundle);
        builder.set_left_header(left_header);
        builder.set_right_header(right_header);
        builder.set_native_application_rxs(rxs);
        builder.set_native_application_stage_rx(stage_rx);

        Ok(())
    }
}
