//! The $k(y)$ values a proof's public data determines, the targets of its
//! revdot claims, computed one way for every verifier: the decider on an
//! uncompressed proof and the compressed verifier on a compressed one.

use alloc::vec::Vec;
use core::iter::once;

use ragu_circuits::{horner::Horner, polynomials::Rank, registry::CircuitIndex};
use ragu_core::{
    Cycle, Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    maybe::{Always, Maybe},
};
use ragu_primitives::{Element, GadgetExt, Point};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use super::{
    native::{
        self,
        stages::preamble::{ProofInputs, encode_output_header},
        unified as native_unified,
    },
    nested::{self, unified as nested_unified},
};
use crate::{
    Pcd, Proof,
    header::Header,
    profile::{Binding, Profile, ProfiledCycle},
};

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
    /// The statement circuit's $k(y)$, for a profile whose native extension
    /// has one; `None` for a profile without one.
    pub statement: Option<F>,
    /// The binding circuit's $k(y)$, for a profile whose native extension
    /// has one; `None` for a profile without one.
    pub binding: Option<F>,
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

    fn statement_ky(&self) -> impl Iterator<Item = F> + Clone {
        self.statement.into_iter()
    }

    fn binding_ky(&self) -> impl Iterator<Item = F> + Clone {
        self.binding.into_iter()
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
    /// The binding circuit's $k(y)$, for a profile whose nested extension
    /// has one; `None` for a profile without one.
    pub binding: Option<F>,
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

    fn binding_ky(&self) -> impl Iterator<Item = F> + Clone {
        self.binding.into_iter()
    }

    fn zero(&self) -> F {
        F::ZERO
    }
}

/// The values a binding names, by stage: `stage` at each of the binding's
/// stage indices, in its order, and none for a profile without a binding.
pub fn bound<T>(binding: Option<&Binding>, stage: impl Fn(u32) -> T) -> Vec<T> {
    binding.map_or_else(Vec::new, |binding| {
        binding.stages.iter().map(|&j| stage(j)).collect()
    })
}

/// The commitments the native binding circuit of a proof in profile `P`
/// recomputes: the nested extension stages its binding names, as
/// `commitment` gives them.
pub fn native_bound<P: Profile, T>(commitment: impl Fn(nested::RxIndex) -> T) -> Vec<T> {
    bound(P::native_extension().binding.as_ref(), |j| {
        commitment(nested::RxIndex::ExtensionStage(j))
    })
}

/// The commitments the nested binding circuit of a proof in profile `P`
/// recomputes: the native extension stages its binding names, as
/// `commitment` gives them.
pub fn nested_bound<P: Profile, T>(commitment: impl Fn(native::RxIndex) -> T) -> Vec<T> {
    bound(P::nested_extension().binding.as_ref(), |j| {
        commitment(native::RxIndex::ExtensionStage(j))
    })
}

/// A binding circuit's $k(y)$ in circuit: the $k(y)$ of its public output,
/// the points it exposes, which the verifier computes over `points`, the
/// commitments the circuit must have recomputed, so that the claim holds
/// only if it did. `None` for no points, which a profile without a binding
/// has.
pub fn binding_ky<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    y: &Element<'dr, D>,
    points: &[Point<'dr, D, P>],
) -> Result<Option<Element<'dr, D>>> {
    if points.is_empty() {
        return Ok(None);
    }
    let mut ky = Horner::new(y);
    for point in points {
        GadgetExt::write(point, dr, &mut ky)?;
    }
    ky.finish_ky(dr).map(Some)
}

/// [`binding_ky`] over points allocated from `points`, `count` of them.
pub fn binding_ky_alloc<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    y: &Element<'dr, D>,
    count: usize,
    points: DriverValue<D, &[P]>,
) -> Result<Option<Element<'dr, D>>> {
    let points = (0..count)
        .map(|i| Point::alloc(dr, points.as_ref().map(|p| p[i])))
        .collect::<Result<Vec<_>>>()?;
    binding_ky(dr, y, &points)
}

/// [`binding_ky`] natively, at `y`.
pub fn binding_ky_of<F: Field, P: Affine<Base = F>>(points: &[P], y: F) -> Result<Option<F>> {
    Emulator::emulate_wireless((points, y), |dr, witness| {
        let (points, y) = witness.cast();
        let y = Element::alloc(dr, &mut (), y)?;
        let count = points.as_ref().map(|p| p.len()).take();
        Ok(binding_ky_alloc(dr, &y, count, points)?.map(|ky| *ky.value().take()))
    })
}

/// The native $k(y)$ values of `pcd` at `y`, read off the proof's public
/// data and the header data.
pub fn native_ky<
    C: ProfiledCycle,
    R: Rank,
    H: Header<C::CircuitField>,
    const HEADER_SIZE: usize,
>(
    pcd: &Pcd<C, R, H>,
    y: C::CircuitField,
) -> Result<NativeKy<C::CircuitField>> {
    Emulator::emulate_wireless((pcd.proof(), pcd.data().clone(), y), |dr, witness| {
        let (proof, data, y) = witness.cast();
        let y = Element::alloc(dr, &mut (), y)?;
        let bound = proof
            .as_ref()
            .map(|proof| native_bound::<C::Profile, _>(|index| proof.nested_rx_commitment(index)));
        let proof_inputs =
            ProofInputs::<_, C, HEADER_SIZE>::alloc_for_verify::<R, H>(dr, proof, data)?;

        let (unified, unified_bridge) = proof_inputs.unified_ky_values(dr, &y)?;
        let application = proof_inputs.application_ky(dr, &y)?;
        let statement = proof_inputs.statement_ky::<C::Profile>(dr, &y)?;
        let count = bound.as_ref().map(|bound| bound.len()).take();
        let binding = binding_ky_alloc(dr, &y, count, bound.as_ref().map(|b| b.as_slice()))?;
        Ok(NativeKy {
            c: None,
            unified: *unified.value().take(),
            unified_bridge: *unified_bridge.value().take(),
            application: *application.value().take(),
            statement: statement.map(|ky| *ky.value().take()),
            binding: binding.map(|ky| *ky.value().take()),
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
    /// The nested extension stage commitments the native binding circuit
    /// recomputes, in its output order; none for a profile without one.
    pub nested_bound: &'a [C::NestedCurve],
}

/// The native $k(y)$ values at `y` from an instance's parts, as
/// [`native_ky`] computes them from a proof.
pub fn native_ky_of<C: ProfiledCycle, const HEADER_SIZE: usize>(
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
        let statement = proof_inputs.statement_ky::<C::Profile>(dr, &y)?;
        let count = parts.as_ref().map(|p| p.nested_bound.len()).take();
        let binding = binding_ky_alloc(dr, &y, count, parts.as_ref().map(|p| p.nested_bound))?;
        Ok(NativeKy {
            c: None,
            unified: *unified.value().take(),
            unified_bridge: *unified_bridge.value().take(),
            application: *application.value().take(),
            statement: statement.map(|ky| *ky.value().take()),
            binding: binding.map(|ky| *ky.value().take()),
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
