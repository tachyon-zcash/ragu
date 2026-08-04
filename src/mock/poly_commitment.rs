//! Handles to the commitments behind witnessed polynomials — mirrors
//! `ragu_pcd::poly_commitment`.
//!
//! A polynomial's name is its commitment. In real ragu a step's circuit runs
//! over the circuit field and cannot hold the host-curve commitment itself, so
//! [`StepCtx::witness_polynomial`](crate::ctx::StepCtx::witness_polynomial)
//! hands back a [`PolyHandle`]: the commitment's compressed encoding split
//! across two circuit-field elements. The mock computes the same two wires
//! from the same real commitment, so mock and real agree on a polynomial's
//! handle for the same generators.

use ragu_arithmetic::{ff::PrimeField as _, group::GroupEncoding as _};
use ragu_core::{Error, Result};
use ragu_pasta::{Eq, Fp};
pub use ragu_pcd::HANDLE_WIRES;

/// Mirrors `ragu_pcd::PolyHandle`, driverlessly: the two `Fp` wires with no
/// gadget around them. Only the framework constructs handles — a step obtains
/// one from
/// [`StepCtx::witness_polynomial`](crate::ctx::StepCtx::witness_polynomial).
#[derive(Clone, Debug)]
pub struct PolyHandle {
    wires: [Fp; HANDLE_WIRES],
}

impl PolyHandle {
    pub(crate) fn from_wires(wires: [Fp; HANDLE_WIRES]) -> Self {
        Self { wires }
    }

    /// The handle's instance wires. In real ragu a step reads these by
    /// `Write`-ing the gadget (`handle.write(dr, &mut sink)` emits exactly
    /// these two elements); the mock has no gadget system, so this method —
    /// named after the real crate's internal `PolyHandle::wires` — is the
    /// driverless equivalent.
    #[must_use]
    pub fn wires(&self) -> [Fp; HANDLE_WIRES] {
        self.wires
    }
}

/// The commitment's compressed encoding, split across two field elements.
/// Same math as `ragu_pcd`'s `poly_commitment::handle`, so mock and real
/// agree on the wires for the same polynomial and generators.
pub(crate) fn handle(commitment: Eq) -> Result<[Fp; HANDLE_WIRES]> {
    let repr = commitment.to_bytes();
    let Ok(repr) = <[u8; 32]>::try_from(repr.as_ref()) else {
        return Err(Error::InvalidWitness(
            "only 32-byte point encodings are supported".into(),
        ));
    };
    let (lo, hi) = repr.split_at(16);

    #[expect(
        clippy::expect_used,
        reason = "split_at(16) of 32 bytes yields 16-byte halves"
    )]
    let limb =
        |bytes: &[u8]| Fp::from_u128(u128::from_le_bytes(bytes.try_into().expect("16 bytes")));
    Ok([limb(lo), limb(hi)])
}
