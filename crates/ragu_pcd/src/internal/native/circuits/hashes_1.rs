//! First hash circuit for Fiat-Shamir derivations.
//!
//! ## Operations
//!
//! ### Hashes
//!
//! This circuit performs the first portion of the Fiat-Shamir transcript,
//! invoking $3$ Poseidon permutations:
//! - Initialize the transcript with domain separation tag.
//! - Absorb [`bridge_preamble_commitment`].
//! - Squeeze [$w$] challenge.
//! - Absorb [`bridge_s_prime_commitment`].
//! - Squeeze [$y$] and [$z$] challenges.
//! - Absorb [`bridge_inner_error_commitment`].
//! - Call [`Transcript::save_state`] to capture the transcript state for resumption
//!   in [`hashes_2`][super::hashes_2]. This applies a permutation (the third) since we're at the
//!   absorb-to-squeeze boundary.
//! - Verify the saved state matches the witnessed value from [`outer_error`][super::super::stages::outer_error].
//!
//! The squeezed $w, y, z$ challenges are set in the unified instance by this
//! circuit. **The rest of the transcript computations are performed in the
//! [`hashes_2`][super::hashes_2] circuit.** The sponge state is witnessed in
//! the [`outer_error`][super::super::stages::outer_error] stage and verified here to
//! enable resumption in `hashes_2`.
//!
//! This circuit also enforces the children's unified $k(y)$ values against
//! the [`outer_error`][super::super::stages::outer_error] stage, using the
//! $y$ it just derived. The step's own application $k(y)$ is computed in
//! [`collapse`][super::collapse]; splitting the work keeps
//! both circuits within their gate budgets as the unified instance grows.
//!
//! ### Valid circuit ID
//!
//! The step's own circuit ID in the [`preamble`][super::super::stages::preamble]
//! is enforced to be a valid root of unity in the registry domain (the domain
//! over which circuits are indexed). Other circuits can thus assume this check
//! has been performed. A child's circuit ID is its own step's, checked by that
//! step and bound to this step's preamble through the child's exported
//! instance.
//!
//! ## Staging
//!
//! This circuit is a multi-stage circuit based on the
//! [`outer_error`][super::super::stages::outer_error] stage, which inherits in the
//! following chain:
//! - [`preamble`][super::super::stages::preamble] (unenforced)
//! - [`outer_error`][super::super::stages::outer_error] (unenforced)
//!
//! ## Instance
//!
//! The instance is special for this internal circuit: it contains a
//! concatenation of the unified instance and the step's own output header and
//! circuit ID from the [`preamble`][super::super::stages::preamble] stage. The
//! step folds its own application claim against those wires, so its output
//! header is bound inside the step; the parent, which reads this proof's
//! output header and circuit ID as one of its children's, binds its preamble
//! copies to this instance when it folds this circuit's claim. That is the
//! header-carry check: each edge's header is checked once by the step that
//! produced it and once by the step that consumes it, and this instance
//! bridges the two. The other internal circuits mainly use the unified
//! instance only, to avoid the overhead of witnessing the header in circuits
//! that do not use the preamble stage.
//!
//! The output is wrapped in a [`WithSuffix`] with a zero element appended. This
//! ensures the instance serialization matches the $k(y)$ computation for
//! `unified_ky`, which is defined as $k(y)$ over `(unified, 0)`. The trailing
//! zero aligns the internal circuit's instance with the expected format for
//! $k(y)$ verification.
//!
//! [`bridge_preamble_commitment`]: unified::Output::bridge_preamble_commitment
//! [`bridge_hash_commitment`]: unified::Output::bridge_hash_commitment
//! [`bridge_s_prime_commitment`]: unified::Output::bridge_s_prime_commitment
//! [`bridge_inner_error_commitment`]: unified::Output::bridge_inner_error_commitment
//! [$w$]: unified::Output::w
//! [$y$]: unified::Output::y
//! [$z$]: unified::Output::z
//! [`WithSuffix`]: ragu_primitives::suffix::WithSuffix
//! [`Transcript::save_state`]: crate::internal::transcript::Transcript::save_state

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt, WithSuffix,
    allocator::Standard,
    io::Write,
    vec::{ConstLen, FixedVec},
};

use super::super::{
    stages::{outer_error as native_outer_error, preamble as native_preamble},
    unified::{self, OutputBuilder},
};
use crate::{
    RAGU_TAG,
    internal::{fold_revdot, transcript::Transcript},
    profile::ProfiledCycle,
};

/// Public output of the first hash circuit.
///
/// This circuit uniquely includes the step's own output header and circuit
/// ID alongside the unified instance. They are needed as instance data so
/// the step that consumes this proof can check its copies of them against
/// the ones this step's application claim was folded with.
///
/// Other internal circuits use only the [`unified::Output`] to avoid the
/// overhead of witnessing headers in circuits that do not require them.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize> {
    /// The unified instance shared across internal circuits.
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
    /// The step's own output header.
    #[ragu(gadget)]
    pub output_header: FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>,
    /// The step's own circuit ID, as its domain point.
    #[ragu(gadget)]
    pub circuit_id: Element<'dr, D>,
}

/// First hash circuit for Fiat-Shamir challenge derivation.
///
/// The [module-level documentation] describes the operations performed by this
/// circuit.
///
/// [module-level documentation]: self
pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    params: &'params C::Params,
    log2_circuits: u32,
    _marker: PhantomData<(R, FP)>,
}

impl<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<'params, C, R, HEADER_SIZE, FP>
{
    /// Creates a new multi-stage circuit.
    ///
    /// # Parameters
    ///
    /// - `params`: Curve cycle parameters providing Poseidon configuration.
    /// - `log2_circuits`: Log₂ of the registry domain size (number of circuits).
    ///   Used to verify circuit IDs are valid roots of unity.
    pub fn new(
        params: &'params C::Params,
        log2_circuits: u32,
    ) -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            params,
            log2_circuits,
            _marker: PhantomData,
        })
    }
}

/// Witness data for the first hash circuit.
///
/// Combines the unified instance with stage witnesses needed to perform the
/// Fiat-Shamir derivations and transcript-state verification.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    /// The unified instance containing expected challenge values and
    /// accumulated coverage from prior circuits.
    pub unified: unified::Instance<C>,

    /// Witness for the [`preamble`](super::super::stages::preamble) stage
    /// (unenforced).
    ///
    /// Provides the step's own output header and circuit ID (included in
    /// this circuit's instance, the circuit ID also for the root-of-unity
    /// check).
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,

    /// Witness for the [`outer_error`](super::super::stages::outer_error) stage
    /// (unenforced).
    ///
    /// Provides the saved sponge state used to verify resumption into
    /// [`hashes_2`](super::hashes_2).
    pub outer_error_witness: &'a native_outer_error::Witness<C, FP>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    MultiStageCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, FP>
{
    type Last = native_outer_error::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, FP>;
    type Output = Kind![C::CircuitField; WithSuffix<'_, _, Output<'_, _, C, HEADER_SIZE>>];
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let builder = builder
            .skip_stage::<super::super::stages::points::BindingStage<C::NestedCurve, C::Profile>>(
            )?;
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (outer_error, builder) =
            builder.add_stage::<native_outer_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let outer_error =
            outer_error.unenforced(dr, witness.as_ref().map(|w| w.outer_error_witness))?;

        // Verify the step's circuit ID is a valid root of unity in the
        // registry domain.
        preamble
            .own
            .circuit_id
            .enforce_root_of_unity(dr, self.log2_circuits)?;

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        // Create a transcript for all challenge derivations
        let mut transcript = Transcript::new(dr, C::circuit_poseidon(self.params), RAGU_TAG)?;

        // Derive w by absorbing bridge_preamble_commitment and squeezing
        let w = {
            let bridge_preamble_commitment = unified_output
                .bridge_preamble_commitment
                .receive(dr, allocator)?;
            bridge_preamble_commitment.write(dr, &mut transcript)?;
            transcript.challenge(dr)?
        };
        unified_output.w.provide(w.clone());

        // Expose the bridge-hash commitment without absorbing it into the
        // transcript. The parent binds it to the bridge-hash stage it folds
        // (see `bind_beta`).
        unified_output
            .bridge_hash_commitment
            .receive(dr, allocator)?;

        // Derive (y, z) by absorbing bridge_s_prime_commitment and squeezing twice
        let (y, z) = {
            let bridge_s_prime_commitment = unified_output
                .bridge_s_prime_commitment
                .receive(dr, allocator)?;
            bridge_s_prime_commitment.write(dr, &mut transcript)?;
            let y = transcript.challenge(dr)?;
            let z = transcript.challenge(dr)?;
            (y, z)
        };
        unified_output.y.provide(y.clone());
        unified_output.z.provide(z);

        for (child, staged) in [
            (&preamble.left, &outer_error.left),
            (&preamble.right, &outer_error.right),
        ] {
            let (unified_ky, unified_bridge_ky) = child.unified_ky_values(dr, &y)?;
            unified_ky.enforce_equal(dr, &staged.unified)?;
            unified_bridge_ky.enforce_equal(dr, &staged.unified_bridge)?;
        }

        // Absorb bridge_inner_error_commitment and verify saved transcript state
        {
            let bridge_inner_error_commitment = unified_output
                .bridge_inner_error_commitment
                .receive(dr, allocator)?;
            bridge_inner_error_commitment.write(dr, &mut transcript)?;

            // save_state() applies a permutation (since there's pending absorbed data)
            // and returns the raw state, ready for squeeze-mode resumption in hashes_2.
            transcript
                .save_state(dr)
                .expect("save_state should succeed after absorbing")
                .enforce_equal(dr, &outer_error.sponge_state)?;
        }

        // The step's own output header and circuit ID from the preamble +
        // unified instance. The parent's `unified_bridge_ky` for this proof
        // holds its preamble copies to these wires.
        let (unified, updated) = unified_output.finish_no_suffix(dr, allocator)?;
        let output = Output {
            unified,
            output_header: preamble.own.output_header,
            circuit_id: preamble.own.circuit_id,
        };

        let zero = Element::zero(dr);
        Ok(WithAux::new(WithSuffix::new(output, zero), updated))
    }
}
