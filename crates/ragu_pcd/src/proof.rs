use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, structured},
    staging::StageExt,
};
use ragu_core::{
    drivers::emulator::Emulator,
    maybe::{Always, Maybe, MaybeKind},
};
use ragu_primitives::{
    Element, GadgetExt, Point, Sponge,
    vec::{CollectFixed, Len},
};
use rand::rngs::OsRng;

use alloc::{vec, vec::Vec};

use crate::{
    Application,
    components::fold_revdot::{self, ErrorTermsLen},
    header::Header,
    internal_circuits::{self, NUM_REVDOT_CLAIMS, dummy},
};

/// Represents a recursive proof for the correctness of some computation.
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) preamble: PreambleProof<C, R>,
    pub(crate) internal_circuits: InternalCircuits<C, R>,
    pub(crate) application: ApplicationProof<C, R>,
}

pub(crate) struct ApplicationProof<C: Cycle, R: Rank> {
    pub(crate) circuit_id: usize,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,
    pub(crate) rx: structured::Polynomial<C::CircuitField, R>,
}

pub(crate) struct PreambleProof<C: Cycle, R: Rank> {
    pub(crate) native_preamble_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_preamble_blind: C::CircuitField,
    /// This can be computed using native_preamble_rx / native_preamble_blind
    pub(crate) native_preamble_commitment: C::HostCurve,

    pub(crate) nested_preamble_blind: C::ScalarField,
    /// This can be computed using native_preamble_commitment
    pub(crate) nested_preamble_rx: structured::Polynomial<C::ScalarField, R>,
    /// This can be computed using nested_preamble_rx / nested_preamble_blind
    pub(crate) nested_preamble_commitment: C::NestedCurve,
}

pub(crate) struct InternalCircuits<C: Cycle, R: Rank> {
    /// This can be computed using PreambleProof::nested_preamble_commitment
    pub(crate) w: C::CircuitField,
    pub(crate) c: C::CircuitField,
    pub(crate) c_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) mu: C::CircuitField,
    pub(crate) nu: C::CircuitField,
}

impl<C: Cycle, R: Rank> Clone for Proof<C, R> {
    fn clone(&self) -> Self {
        Proof {
            preamble: self.preamble.clone(),
            internal_circuits: self.internal_circuits.clone(),
            application: self.application.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for ApplicationProof<C, R> {
    fn clone(&self) -> Self {
        ApplicationProof {
            circuit_id: self.circuit_id,
            left_header: self.left_header.clone(),
            right_header: self.right_header.clone(),
            rx: self.rx.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for PreambleProof<C, R> {
    fn clone(&self) -> Self {
        PreambleProof {
            native_preamble_rx: self.native_preamble_rx.clone(),
            native_preamble_commitment: self.native_preamble_commitment,
            native_preamble_blind: self.native_preamble_blind,
            nested_preamble_rx: self.nested_preamble_rx.clone(),
            nested_preamble_commitment: self.nested_preamble_commitment,
            nested_preamble_blind: self.nested_preamble_blind,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for InternalCircuits<C, R> {
    fn clone(&self) -> Self {
        InternalCircuits {
            w: self.w,
            c: self.c,
            c_rx: self.c_rx.clone(),
            mu: self.mu,
            nu: self.nu,
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data<'_>) -> Pcd<'_, C, R, H> {
        Pcd { proof: self, data }
    }
}

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<'source, C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    /// The recursive proof for the accompanying data.
    pub proof: Proof<C, R>,

    /// Arbitrary data encoded into a [`Header`].
    pub data: H::Data<'source>,
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Clone for Pcd<'_, C, R, H> {
    fn clone(&self) -> Self {
        Pcd {
            proof: self.proof.clone(),
            data: self.data.clone(),
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Creates a trivial proof for the empty [`Header`] implementation `()`.
    /// This may or may not be identical to any previously constructed (trivial)
    /// proof, and so is not guaranteed to be freshly randomized.
    pub fn trivial(&self) -> Proof<C, R> {
        use internal_circuits::stages;

        // Preamble rx polynomial
        let native_preamble_rx =
            stages::native::preamble::Stage::<C, R>::rx(()).expect("preamble rx should not fail");
        let native_preamble_blind = C::CircuitField::ONE;
        let native_preamble_commitment =
            native_preamble_rx.commit(self.params.host_generators(), native_preamble_blind);

        // Nested preamble rx polynomial
        let nested_preamble_rx =
            stages::nested::preamble::Stage::<C::HostCurve, R>::rx(native_preamble_commitment)
                .expect("nested preamble rx should not fail");
        let nested_preamble_blind = C::ScalarField::ONE;
        let nested_preamble_commitment =
            nested_preamble_rx.commit(self.params.nested_generators(), nested_preamble_blind);

        // Compute w = H(nested_preamble_commitment)
        let circuit_poseidon = self.params.circuit_poseidon();
        let w: C::CircuitField =
            Emulator::emulate_wireless(nested_preamble_commitment, |dr, comm| {
                let point = Point::alloc(dr, comm)?;
                let mut sponge = Sponge::new(dr, circuit_poseidon);
                point.write(dr, &mut sponge)?;
                Ok(*sponge.squeeze(dr)?.value().take())
            })
            .expect("w computation should not fail");

        // Generate dummy values for mu, nu, and error_terms (for now – these will be derived challenges)
        let mu = C::CircuitField::random(OsRng);
        let nu = C::CircuitField::random(OsRng);
        let mu_inv = mu.invert().unwrap();
        let error_terms = ErrorTermsLen::<NUM_REVDOT_CLAIMS>::range()
            .map(|_| C::CircuitField::random(OsRng))
            .collect_fixed()
            .expect("error_terms collection should not fail");

        // Compute c, the folded revdot product claim, by invoking the routine within a wireless emulator.
        let c = Emulator::emulate_wireless((mu, nu, mu_inv, error_terms.clone()), |dr, _| {
            let mu = Element::alloc(dr, Always::maybe_just(|| mu))?;
            let nu = Element::alloc(dr, Always::maybe_just(|| nu))?;

            let error_terms = error_terms
                .iter()
                .map(|&et| Element::alloc(dr, Always::maybe_just(|| et)))
                .try_collect_fixed()?;

            // TODO: Use zeros for ky_values for now.
            let ky_values = (0..NUM_REVDOT_CLAIMS)
                .map(|_| Element::zero(dr))
                .collect_fixed()?;

            Ok(*fold_revdot::compute_c::<_, NUM_REVDOT_CLAIMS>(
                dr,
                &mu,
                &nu,
                &error_terms,
                &ky_values,
            )?
            .value()
            .take())
        })
        .expect("c should not fail");

        // Create unified instance and compute c_rx
        let unified_instance = internal_circuits::unified::Instance {
            nested_preamble_commitment,
            w,
            c,
            mu,
            nu,
        };
        let internal_circuit_c =
            internal_circuits::c::Circuit::<C, R, NUM_REVDOT_CLAIMS>::new(circuit_poseidon);
        let internal_circuit_c_witness = internal_circuits::c::Witness {
            unified_instance: &unified_instance,
            error_terms,
        };
        let (c_rx, _) = internal_circuit_c
            .rx::<R>(internal_circuit_c_witness, self.circuit_mesh.get_key())
            .expect("c_rx computation should not fail");

        // Application rx polynomial
        let application_rx = dummy::Circuit
            .rx((), self.circuit_mesh.get_key())
            .expect("should not fail")
            .0;

        Proof {
            preamble: PreambleProof {
                native_preamble_rx,
                native_preamble_commitment,
                native_preamble_blind,
                nested_preamble_rx,
                nested_preamble_commitment,
                nested_preamble_blind,
            },
            internal_circuits: InternalCircuits { w, c, c_rx, mu, nu },
            application: ApplicationProof {
                rx: application_rx,
                circuit_id: internal_circuits::index(self.num_application_steps, dummy::CIRCUIT_ID),
                left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
            },
        }
    }
}
