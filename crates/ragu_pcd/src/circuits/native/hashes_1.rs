//! First hash circuit for Fiat-Shamir derivations.
//!
//! ## Operations
//!
//! ### Hashes
//!
//! This circuit performs the first portion of the Fiat-Shamir transcript,
//! invoking $3$ Poseidon permutations:
//! - Initialize the sponge.
//! - Absorb [`nested_preamble_commitment`].
//! - Squeeze [$w$] challenge.
//! - Absorb [`nested_s_prime_commitment`].
//! - Squeeze [$y$] and [$z$] challenges.
//! - Absorb [`nested_error_m_commitment`].
//! - Call [`Sponge::save_state`] to capture the transcript state for resumption
//!   in [`hashes_2`][super::hashes_2]. This applies a permutation (the third) since we're at the
//!   absorb-to-squeeze boundary.
//! - Verify the saved state matches the witnessed value from [`error_n`][super::stages::error_n].
//!
//! The squeezed $w, y, z$ challenges are set in the unified instance by this
//! circuit. **The rest of the transcript computations are performed in the
//! [`hashes_2`][super::hashes_2] circuit.** The sponge state is witnessed in
//! the [`error_n`][super::stages::error_n] stage and verified here to
//! enable resumption in `hashes_2`.
//!
//! ### $k(y)$ evaluations
//!
//! This circuit also is responsible for using the derived $y$ value to compute
//! the $k(y)$ (public input polynomial evaluations) for the child proofs. These
//! are witnessed in the [`error_n`][super::stages::error_n] stage and
//! enforced to be consistent by this circuit.
//!
//! ### Valid circuit IDs
//!
//! The circuit IDs in the [`preamble`][super::stages::preamble] are
//! enforced to be valid roots of unity in the registry domain (the domain over
//! which circuits are indexed). Other circuits can thus assume this check has
//! been performed.
//!
//! ## Staging
//!
//! This circuit is a multi-stage circuit based on the
//! [`error_n`][super::stages::error_n] stage, which inherits in the
//! following chain:
//! - [`preamble`][super::stages::preamble] (unenforced)
//! - [`error_n`][super::stages::error_n] (unenforced)
//!
//! ## Public Inputs
//!
//! The public inputs are special for this internal circuit: they contain a
//! concatenation of the unified instance and the `left` and `right` child
//! proofs' output headers from the [`preamble`][super::stages::preamble]
//! stage (i.e., the headers that the
//! child steps produced, not the headers they consumed). This allows the
//! verifier to ensure consistency with the headers enforced on the application
//! (step) circuit. The other internal circuits mainly use the unified instance
//! only to avoid the extra overhead of witnessing the `left`/`right` output
//! headers in circuits that do not use the preamble stage.
//!
//! The output is wrapped in a [`WithSuffix`] with a zero element appended. This
//! ensures the public input serialization matches the $k(y)$ computation for
//! `unified_ky`, which is defined as $k(y)$ over `(unified, 0)`. The trailing
//! zero aligns the internal circuit's public inputs with the expected format
//! for $k(y)$ verification.
//!
//! [`nested_preamble_commitment`]: unified::Output::nested_preamble_commitment
//! [`nested_s_prime_commitment`]: unified::Output::nested_s_prime_commitment
//! [`nested_error_m_commitment`]: unified::Output::nested_error_m_commitment
//! [$w$]: unified::Output::w
//! [$y$]: unified::Output::y
//! [$z$]: unified::Output::z
//! [`WithSuffix`]: crate::components::suffix::WithSuffix
//! [`Sponge::save_state`]: ragu_primitives::poseidon::Sponge::save_state

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt,
    io::Write,
    poseidon::Sponge,
    vec::{ConstLen, FixedVec},
};

use core::marker::PhantomData;

use super::{
    stages::{error_n as native_error_n, preamble as native_preamble},
    unified::{self, OutputBuilder},
};
use crate::components::{fold_revdot, root_of_unity, suffix::WithSuffix};

pub(crate) use super::InternalCircuitIndex::Hashes1Circuit as CIRCUIT_ID;

/// Public output of the first hash circuit.
///
/// This circuit uniquely includes the `left` and `right` output headers from
/// the child proofs alongside the unified instance. The headers are needed as
/// public inputs so the verifier can check consistency with the application
/// (step) circuit's headers.
///
/// Other internal circuits use only the [`unified::Output`] to avoid the
/// overhead of witnessing headers in circuits that do not require them.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize> {
    /// The unified instance shared across internal circuits.
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
    /// The left child proof's output header.
    #[ragu(gadget)]
    pub left_header: FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>,
    /// The right child proof's output header.
    #[ragu(gadget)]
    pub right_header: FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>,
}

/// First hash circuit for Fiat-Shamir challenge derivation.
///
/// See the [module-level documentation] for details on the operations
/// performed by this circuit.
///
/// [module-level documentation]: self
pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    params: &'params C::Params,
    log2_circuits: u32,
    _marker: PhantomData<(R, FP)>,
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
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
/// Fiat-Shamir derivations and $k(y)$ consistency checks.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    /// The unified instance containing expected challenge values.
    pub unified_instance: &'a unified::Instance<C>,

    /// Witness for the [`preamble`](super::stages::preamble) stage
    /// (unenforced).
    ///
    /// Provides output headers and data for computing $k(y)$ evaluations.
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,

    /// Witness for the [`error_n`](super::stages::error_n) stage
    /// (unenforced).
    ///
    /// Provides the saved sponge state and pre-computed $k(y)$ values for
    /// consistency verification.
    pub error_n_witness: &'a native_error_n::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    MultiStageCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, FP>
{
    type Final = native_error_n::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, FP>;
    type Output = Kind![C::CircuitField; WithSuffix<'_, _, Output<'_, _, C, HEADER_SIZE>>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.view().map(|w| w.preamble_witness))?;
        let error_n = error_n.unenforced(dr, witness.view().map(|w| w.error_n_witness))?;

        // Verify circuit IDs are valid roots of unity in the registry domain.
        root_of_unity::enforce(dr, preamble.left.circuit_id.clone(), self.log2_circuits)?;
        root_of_unity::enforce(dr, preamble.right.circuit_id.clone(), self.log2_circuits)?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Create a single long-lived sponge for all challenge derivations
        let mut sponge = Sponge::new(dr, C::circuit_poseidon(self.params));

        // Derive w by absorbing nested_preamble_commitment and squeezing
        let w = {
            let nested_preamble_commitment = unified_output
                .nested_preamble_commitment
                .get(dr, unified_instance)?;
            nested_preamble_commitment.write(dr, &mut sponge)?;
            sponge.squeeze(dr)?
        };
        unified_output.w.set(w.clone());

        // Derive (y, z) by absorbing nested_s_prime_commitment and squeezing twice
        let (y, z) = {
            let nested_s_prime_commitment = unified_output
                .nested_s_prime_commitment
                .get(dr, unified_instance)?;
            nested_s_prime_commitment.write(dr, &mut sponge)?;
            let y = sponge.squeeze(dr)?;
            let z = sponge.squeeze(dr)?;
            (y, z)
        };
        unified_output.y.set(y.clone());
        unified_output.z.set(z);

        // Compute k(y) values from preamble and enforce equality with staged
        // values.
        {
            let left_application_ky = preamble.left.application_ky(dr, &y)?;
            let right_application_ky = preamble.right.application_ky(dr, &y)?;

            left_application_ky.enforce_equal(dr, &error_n.left.application)?;
            right_application_ky.enforce_equal(dr, &error_n.right.application)?;

            let (left_unified_ky, left_unified_bridge_ky) =
                preamble.left.unified_ky_values(dr, &y)?;
            let (right_unified_ky, right_unified_bridge_ky) =
                preamble.right.unified_ky_values(dr, &y)?;

            left_unified_ky.enforce_equal(dr, &error_n.left.unified)?;
            right_unified_ky.enforce_equal(dr, &error_n.right.unified)?;
            left_unified_bridge_ky.enforce_equal(dr, &error_n.left.unified_bridge)?;
            right_unified_bridge_ky.enforce_equal(dr, &error_n.right.unified_bridge)?;
        }

        // Absorb nested_error_m_commitment and verify saved sponge state
        {
            let nested_error_m_commitment = unified_output
                .nested_error_m_commitment
                .get(dr, unified_instance)?;
            nested_error_m_commitment.write(dr, &mut sponge)?;

            // save_state() applies a permutation (since there's pending absorbed data)
            // and returns the raw state, ready for squeeze-mode resumption in hashes_2.
            sponge
                .save_state(dr)
                .expect("save_state should succeed after absorbing")
                .enforce_equal(dr, &error_n.sponge_state)?;
        }

        // Output headers from preamble + unified instance. Verification with
        // `unified_bridge_ky` ensures preamble headers match ApplicationProof
        // headers.
        let output = Output {
            left_header: preamble.left.output_header,
            right_header: preamble.right.output_header,
            unified: unified_output.finish_no_suffix(dr, unified_instance)?,
        };

        let zero = Element::zero(dr);
        Ok((WithSuffix::new(output, zero), D::just(|| ())))
    }
}
