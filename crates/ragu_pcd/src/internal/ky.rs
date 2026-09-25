//! The $k(y)$ values a proof's public data determines, the targets of its
//! revdot claims, computed one way for every verifier: the decider on an
//! uncompressed proof and the compressed verifier on a compressed one.

use alloc::vec::Vec;
use core::iter::once;

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::{polynomials::Rank, registry::CircuitIndex};
use ragu_core::{
    Result,
    drivers::emulator::{Emulator, Wireless},
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;

use super::{
    native::{
        self,
        stages::preamble::{ProofInputs, encode_output_header},
        unified as native_unified,
    },
    nested::{self, unified as nested_unified},
};
use crate::{Pcd, Proof, header::Header};

/// The targets of one proof's native revdot claims at one $y$.
///
/// The circuit claims' targets are $k(y)$ values: each circuit's $k(Y)$ has
/// the circuit's public inputs as coefficients, so the verifier computes
/// $k(y)$ from the instance. The raw claim's target is different: $c$ is the
/// accumulator's own value, folded alongside $a$ and $b$, and depends on
/// neither public inputs nor $y$. [`native_ky`] fills the $k(y)$ targets and
/// leaves `c` as `None`, which omits the raw claim; the decider verifies that
/// way, deriving $c$ from the very polynomials the claim would check. The
/// compressed verifier sets `c` to the value the instance carries.
pub struct NativeKy<F> {
    /// The accumulator value $c$, the raw claim's target, or `None` to omit
    /// the raw claim.
    pub c: Option<F>,
    /// The unified internal circuits' $k(y)$.
    pub unified: F,
    /// The `hashes_1` circuit's $k(y)$, over the unified instance and the
    /// child headers.
    pub unified_bridge: F,
    /// The application circuit's $k(y)$.
    pub application: F,
}

impl<F: Field> native::claims::KySource for NativeKy<F> {
    type Ky = F;

    fn raw_c(&self) -> impl Iterator<Item = F> {
        self.c.into_iter()
    }

    fn application_ky(&self) -> impl Iterator<Item = F> {
        once(self.application)
    }

    fn unified_bridge_ky(&self) -> impl Iterator<Item = F> {
        once(self.unified_bridge)
    }

    fn unified_ky(&self) -> impl Iterator<Item = F> + Clone {
        once(self.unified)
    }

    fn ones(&self) -> impl Iterator<Item = F> + Clone {
        once(F::ONE)
    }

    fn zero(&self) -> F {
        F::ZERO
    }
}

/// The targets of one proof's nested revdot claims at one nested $y$: the
/// nested unified instance's $k(y)$, and the nested accumulator's own value
/// $c_n$ for the raw claim, which both verifiers check.
pub struct NestedKy<F> {
    /// The nested accumulator value $c_n$, the raw claim's target.
    pub c: F,
    /// The nested unified instance's $k(y)$.
    pub unified: F,
}

impl<F: Field> nested::claims::KySource for NestedKy<F> {
    type Ky = F;

    fn raw_c(&self) -> impl Iterator<Item = F> {
        once(self.c)
    }

    fn ones(&self) -> impl Iterator<Item = F> + Clone {
        once(F::ONE)
    }

    fn unified_ky(&self) -> impl Iterator<Item = F> + Clone {
        once(self.unified)
    }

    fn zero(&self) -> F {
        F::ZERO
    }
}

/// The native $k(y)$ values of `pcd` at `y`, read off the proof's public
/// data and the header data.
pub fn native_ky<C: Cycle, R: Rank, H: Header<C::CircuitField>, const HEADER_SIZE: usize>(
    pcd: &Pcd<C, R, H>,
    y: C::CircuitField,
) -> Result<NativeKy<C::CircuitField>> {
    Emulator::emulate_wireless((pcd.proof(), pcd.data().clone(), y), |dr, witness| {
        let (proof, data, y) = witness.cast();
        let y = Element::alloc(dr, &mut (), y)?;
        let proof_inputs =
            ProofInputs::<_, C, HEADER_SIZE>::alloc_for_verify::<R, H>(dr, proof, data)?;

        let (unified, unified_bridge) = proof_inputs.unified_ky_values(dr, &y)?;
        let application = proof_inputs.application_ky(dr, &y)?;
        Ok(NativeKy {
            c: None,
            unified: *unified.value().take(),
            unified_bridge: *unified_bridge.value().take(),
            application: *application.value().take(),
        })
    })
}

/// The nested unified instance's $k(y)$ of `proof` at the nested `y`, with
/// $c_n$ and $v_n$ derived from the proof's polynomials.
pub fn nested_ky<C: Cycle, R: Rank>(
    proof: &Proof<C, R>,
    y: C::ScalarField,
) -> Result<C::ScalarField> {
    Emulator::emulate_wireless((proof.nested_instance()?, y), |dr, witness| {
        let (instance, y) = witness.cast();
        let y = Element::alloc(dr, &mut (), y)?;
        let output =
            nested_unified::Output::<_, C::HostCurve>::alloc(dr, &mut (), instance.as_ref())?;
        Ok(*output.ky(dr, &y)?.value().take())
    })
}

/// The step's output header for `data`: the `HEADER_SIZE` field elements
/// the application circuit's instance carries.
pub fn output_header<C: Cycle, H: Header<C::CircuitField>, const HEADER_SIZE: usize>(
    data: H::Data,
) -> Result<Vec<C::CircuitField>> {
    Emulator::<Wireless<Always<()>, C::CircuitField>>::emulate_wireless(data, |_, data| {
        let header = encode_output_header::<
            Emulator<Wireless<Always<()>, C::CircuitField>>,
            H,
            HEADER_SIZE,
        >(data)?;
        Ok(header.take().to_vec())
    })
}

/// The parts of a proof's public data its native $k(y)$ values depend on,
/// as a compressed proof's instance carries them, the output header as
/// [`output_header`] encodes it.
pub struct NativeParts<'a, C: Cycle> {
    pub left_header: &'a [C::CircuitField],
    pub right_header: &'a [C::CircuitField],
    pub output_header: &'a [C::CircuitField],
    pub circuit_id: CircuitIndex,
    pub unified: &'a native_unified::Instance<C>,
}

/// The native $k(y)$ values at `y` from an instance's parts, as
/// [`native_ky`] computes them from a proof.
pub fn native_ky_of<C: Cycle, const HEADER_SIZE: usize>(
    parts: NativeParts<'_, C>,
    y: C::CircuitField,
) -> Result<NativeKy<C::CircuitField>> {
    Emulator::emulate_wireless((parts, y), |dr, witness| {
        let (parts, y) = witness.cast();
        let y = Element::alloc(dr, &mut (), y)?;
        let proof_inputs = ProofInputs::<_, C, HEADER_SIZE>::alloc_from_parts(
            dr,
            parts.as_ref().map(|p| p.left_header),
            parts.as_ref().map(|p| p.right_header),
            parts.as_ref().map(|p| p.output_header),
            parts.as_ref().map(|p| p.circuit_id.omega_j()),
            parts.as_ref().map(|p| p.unified),
        )?;

        let (unified, unified_bridge) = proof_inputs.unified_ky_values(dr, &y)?;
        let application = proof_inputs.application_ky(dr, &y)?;
        Ok(NativeKy {
            c: None,
            unified: *unified.value().take(),
            unified_bridge: *unified_bridge.value().take(),
            application: *application.value().take(),
        })
    })
}

/// The nested unified instance's $k(y)$ at the nested `y` from the
/// instance's values, as [`nested_ky`] computes it from a proof.
pub fn nested_ky_of<C: Cycle>(
    instance: &nested_unified::Instance<C::HostCurve>,
    y: C::ScalarField,
) -> Result<C::ScalarField> {
    Emulator::emulate_wireless((instance, y), |dr, witness| {
        let (instance, y) = witness.cast();
        let y = Element::alloc(dr, &mut (), y)?;
        let output = nested_unified::Output::<_, C::HostCurve>::alloc(dr, &mut (), instance)?;
        Ok(*output.ky(dr, &y)?.value().take())
    })
}
