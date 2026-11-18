//! The $k(y)$ values a proof's public data determines, the targets of its
//! revdot claims, computed one way for every verifier: the decider on an
//! uncompressed proof and the compressed verifier on a compressed one.

use alloc::vec::Vec;
use core::iter::once;

#[cfg(any(test, feature = "test-utils"))]
use ragu_circuits::polynomials::Rank;
use ragu_circuits::{horner::Horner, registry::CircuitIndex};
use ragu_core::{
    Cycle, Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    maybe::{Always, Maybe},
};
#[cfg(any(test, feature = "test-utils"))]
use ragu_primitives::vec::ConstLen;
use ragu_primitives::{Element, GadgetExt, Point, vec::FixedVec};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use super::{
    native::{
        self, online,
        stages::preamble::{ProofInputs, encode_output_header},
        unified as native_unified,
    },
    nested::{self, unified as nested_unified},
};
#[cfg(test)]
use crate::Pcd;
#[cfg(any(test, feature = "test-utils"))]
use crate::Proof;
use crate::{
    header::Header,
    profile::{Binding, Profile, ProfiledCycle},
};

/// The targets of one proof's native revdot claims at one $y$.
///
/// The circuit claims' targets are $k(y)$ values: each circuit's $k(Y)$ has
/// the circuit's public inputs as coefficients, so the verifier computes
/// $k(y)$ from the instance. The raw claim's target is different: $c$ is the
/// accumulator's own value, folded alongside $a$ and $b$, and depends on
/// neither public inputs nor $y$. `native_ky_from_header` fills the $k(y)$
/// targets and leaves `c` as `None`, which omits the raw claim; the decider
/// verifies that way, deriving $c$ from the very polynomials the claim would
/// check. The compressed verifier sets `c` to the value the instance carries.
pub struct NativeKy<F> {
    /// The accumulator value $c$, the raw claim's target, or `None` to omit
    /// the raw claim.
    pub c: Option<F>,
    /// The unified internal circuits' $k(y)$.
    pub unified: F,
    /// The `hashes_1` circuit's $k(y)$, over the unified instance and the
    /// child headers.
    pub unified_bridge: F,
    /// The `compute_v` circuit's $k(y)$, over the unified instance and the
    /// online openings.
    pub compute_v_bridge: F,
    /// The `bind_endoscalar` circuit's $k(y)$, over the unified instance,
    /// the online Fq commitments the step exports for its native binding
    /// and the actual nested online commitment points; the unified $k(y)$
    /// for a profile that exports neither.
    pub bind_endoscalar: F,
    /// Native online helper challenges, sums and foreign commitment points.
    pub online_helper: Option<F>,
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

    fn compute_v_bridge_ky(&self) -> impl Iterator<Item = F> {
        once(self.compute_v_bridge)
    }

    fn online_helper_ky(&self) -> impl Iterator<Item = F> {
        self.online_helper.into_iter()
    }

    fn bind_endoscalar_ky(&self) -> impl Iterator<Item = F> {
        once(self.bind_endoscalar)
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
    /// Compute-v's unified instance followed by the online helper values.
    pub compute_v: F,
    /// The online helper's challenge and sum target, when active.
    pub online_helper: Option<F>,
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

    fn compute_v_ky(&self) -> impl Iterator<Item = F> {
        once(self.compute_v)
    }

    fn online_helper_ky(&self) -> impl Iterator<Item = F> {
        self.online_helper.into_iter()
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
/// exposes: the nested extension stages its binding names, as `commitment`
/// gives them, then the proof's own online Fq polynomials it names, in
/// that order, as `online` gives the commitments the proof exports (see
/// [`bound_commitments`](nested::online::bound_commitments)).
pub fn native_bound<P: Profile, T>(
    commitment: impl Fn(nested::RxIndex) -> T,
    online: impl Fn(usize) -> T,
) -> Vec<T> {
    let binding = crate::profile::native_extension::<P>().binding;
    let mut points = bound(binding.as_ref(), |j| {
        commitment(nested::RxIndex::ExtensionStage(j))
    });
    if let Some(binding) = &binding {
        points.extend((0..binding.online.len()).map(online));
    }
    points
}

/// The commitments the nested binding circuit of a proof in profile `P`
/// exposes: the native extension stages its binding names, as `commitment`
/// gives them, then the proof's own online slots it names, as `online`
/// gives their commitments.
pub fn nested_bound<P: Profile, T>(
    commitment: impl Fn(native::RxIndex) -> T,
    online: impl Fn(usize) -> T,
) -> Vec<T> {
    let binding = crate::profile::nested_extension::<P>().binding;
    let mut points = bound(binding.as_ref(), |j| {
        commitment(native::RxIndex::ExtensionStage(j))
    });
    if let Some(binding) = &binding {
        points.extend(binding.online.iter().map(|&slot| online(slot as usize)));
    }
    points
}

/// The actual nested online Input, Query and Eval stage commitments, in
/// deadline order. These targets bind transcript copies to the walked rxs.
pub fn nested_online_stages<P: Profile, T>(commitment: impl Fn(nested::RxIndex) -> T) -> Vec<T> {
    (0..<crate::profile::online::stages::Present<P, crate::profile::online::stages::Nested, 3> as ragu_primitives::vec::Len>::len())
        .map(|i| commitment(nested::RxIndex::ExtensionStage(i as u32)))
        .collect()
}

/// The actual native online Input, Query and Eval commitments, in deadline order.
pub fn native_online_stages<P: Profile, T>(commitment: impl Fn(native::RxIndex) -> T) -> Vec<T> {
    (0..<crate::profile::online::stages::Present<P, crate::profile::online::stages::Native, 3> as ragu_primitives::vec::Len>::len())
        .map(|i| commitment(native::RxIndex::ExtensionStage(i as u32))).collect()
}

/// Allocates the profile-fixed online stage points for a native claim target.
pub fn nested_online_stage_points<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile>(
    dr: &mut D,
    points: DriverValue<D, &[C]>,
) -> Result<
    ragu_primitives::vec::FixedVec<
        Point<'dr, D, C>,
        crate::profile::online::stages::Present<P, crate::profile::online::stages::Nested, 3>,
    >,
> {
    ragu_primitives::vec::FixedVec::try_from_fn(|i| Point::alloc(dr, points.as_ref().map(|p| p[i])))
}

/// Finishes `ky`, the Horner evaluation of an extension circuit's public
/// output, as the circuit's $k(y)$: the constant zero its registry slot
/// appends to the output (see [`CircuitSlot`](crate::profile::CircuitSlot)),
/// then the trailing one. A circuit without an output keeps $k(y) = 1$.
pub fn finish_extension_ky<'dr, D: Driver<'dr>>(
    mut ky: Horner<'_, 'dr, D>,
    dr: &mut D,
) -> Result<Element<'dr, D>> {
    Element::zero(dr).write(dr, &mut ky)?;
    ky.finish_ky(dr)
}

/// A binding circuit's $k(y)$ in circuit: the $k(y)$ of its public output,
/// the points it exposes, then the elements, and the zero its slot
/// appends, which the verifier computes over `points`, the commitments
/// the circuit must have recomputed or taken, and `elements`, the
/// openings it must have taken, so that the claim holds only if it did.
/// `None` for no points, which a profile without a binding has.
pub fn binding_ky<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    y: &Element<'dr, D>,
    points: &[Point<'dr, D, P>],
    elements: &[Element<'dr, D>],
) -> Result<Option<Element<'dr, D>>> {
    if points.is_empty() {
        return Ok(None);
    }
    let mut ky = Horner::new(y);
    for point in points {
        GadgetExt::write(point, dr, &mut ky)?;
    }
    for element in elements {
        element.write(dr, &mut ky)?;
    }
    finish_extension_ky(ky, dr).map(Some)
}

/// [`binding_ky`] over points allocated from `points`, `count` of them,
/// and elements allocated from `elements`, every one.
pub fn binding_ky_alloc<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    y: &Element<'dr, D>,
    count: usize,
    points: DriverValue<D, &[P]>,
    elements: DriverValue<D, &[D::F]>,
) -> Result<Option<Element<'dr, D>>> {
    let points = (0..count)
        .map(|i| Point::alloc(dr, points.as_ref().map(|p| p[i])))
        .collect::<Result<Vec<_>>>()?;
    let len = elements.as_ref().map(|e| e.len()).take();
    let elements = (0..len)
        .map(|i| Element::alloc(dr, &mut (), elements.as_ref().map(|e| e[i])))
        .collect::<Result<Vec<_>>>()?;
    binding_ky(dr, y, &points, &elements)
}

/// [`ProofInputs::bind_endoscalar_ky`] over points allocated from
/// `points`, the online Fq commitments a proof in profile `P` exports.
pub fn bind_endoscalar_ky_alloc<'dr, D, C, P, const HEADER_SIZE: usize>(
    dr: &mut D,
    inputs: &ProofInputs<'dr, D, C, HEADER_SIZE>,
    y: &Element<'dr, D>,
    unified_ky: &Element<'dr, D>,
    points: DriverValue<D, &[C::NestedCurve]>,
) -> Result<Element<'dr, D>>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: ProfiledCycle,
    P: Profile,
{
    let points = (0..nested::online::bound_commitments::<P>().len())
        .map(|i| Point::alloc(dr, points.as_ref().map(|p| p[i])))
        .collect::<Result<Vec<_>>>()?;
    inputs.bind_endoscalar_ky(dr, y, unified_ky, &points)
}

/// [`binding_ky`] natively, at `y`.
pub fn binding_ky_of<F: Field, P: Affine<Base = F>>(
    points: &[P],
    elements: &[F],
    y: F,
) -> Result<Option<F>> {
    Emulator::emulate_wireless((points, elements, y), |dr, witness| {
        let (points, elements, y) = witness.cast();
        let y = Element::alloc(dr, &mut (), y)?;
        let count = points.as_ref().map(|p| p.len()).take();
        Ok(binding_ky_alloc(dr, &y, count, points, elements)?.map(|ky| *ky.value().take()))
    })
}

/// The native $k(y)$ values of `pcd` at `y`, read off the proof's public
/// data and the header data.
#[cfg(test)]
pub fn native_ky<
    C: ProfiledCycle,
    R: Rank,
    H: Header<C::CircuitField>,
    const HEADER_SIZE: usize,
>(
    pcd: &Pcd<C, R, H>,
    y: C::CircuitField,
) -> Result<NativeKy<C::CircuitField>> {
    native_ky_from_header::<C, R, HEADER_SIZE>(
        pcd.proof(),
        output_header::<C, H, HEADER_SIZE>(pcd.data().clone())?.try_into()?,
        y,
    )
}

/// The native targets with an already encoded output header. Verification
/// encodes the header separately so application errors remain distinct from
/// malformed proof points.
#[cfg(any(test, feature = "test-utils"))]
pub fn native_ky_from_header<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize>(
    proof: &Proof<C, R>,
    output_header: FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
    y: C::CircuitField,
) -> Result<NativeKy<C::CircuitField>> {
    Emulator::emulate_wireless((proof, output_header, y), |dr, witness| {
        let (proof, output_header, y) = witness.cast();
        let y = Element::alloc(dr, &mut (), y)?;
        let bound = proof.as_ref().map(|proof| {
            native_bound::<C::Profile, _>(
                |index| proof.nested_rx_commitment(index),
                |i| proof.online_fq_commitments[i],
            )
        });
        let exported = proof
            .as_ref()
            .map(|proof| proof.online_fq_commitments.as_slice());
        let proof_inputs = ProofInputs::<_, C, HEADER_SIZE>::alloc::<R>(
            dr,
            proof.as_ref().map(|p| *p),
            output_header.as_ref(),
        )?;

        let (unified, unified_bridge) = proof_inputs.unified_ky_values(dr, &y)?;
        let online_stages = proof.as_ref().map(|proof| {
            nested_online_stages::<C::Profile, _>(|index| proof.nested_rx_commitment(index))
        });
        let online_stages = nested_online_stage_points::<_, _, C::Profile>(
            dr,
            online_stages.as_ref().map(|p| p.as_slice()),
        )?;
        let compute_v_bridge = proof_inputs.compute_v_bridge_ky(dr, &y, &online_stages)?;
        let online_helper = proof_inputs.online_helper_ky(dr, &y)?;
        let bind_endoscalar = bind_endoscalar_ky_alloc::<_, _, C::Profile, HEADER_SIZE>(
            dr,
            &proof_inputs,
            &y,
            &unified,
            exported,
        )?;
        let application = proof_inputs.application_ky(dr, &y)?;
        let statement = proof_inputs.statement_ky::<C::Profile>(dr, &y)?;
        let count = bound.as_ref().map(|bound| bound.len()).take();
        let binding = binding_ky_alloc(
            dr,
            &y,
            count,
            bound.as_ref().map(|b| b.as_slice()),
            bound.as_ref().map(|_| -> &[C::CircuitField] { &[] }),
        )?;
        Ok(NativeKy {
            c: None,
            unified: *unified.value().take(),
            unified_bridge: *unified_bridge.value().take(),
            compute_v_bridge: *compute_v_bridge.value().take(),
            bind_endoscalar: *bind_endoscalar.value().take(),
            online_helper: online_helper.map(|ky| *ky.value().take()),
            application: *application.value().take(),
            statement: statement.map(|ky| *ky.value().take()),
            binding: binding.map(|ky| *ky.value().take()),
        })
    })
}

/// The nested unified instance's $k(y)$ of `proof` at the nested `y`, with
/// $c_n$ and $v_n$ derived from the proof's polynomials.
#[cfg(any(test, feature = "test-utils"))]
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
    /// The online openings the proof's `compute_v` exported.
    pub online: &'a online::Queries<C::CircuitField>,
    pub circuit_id: CircuitIndex,
    pub unified: &'a native_unified::Instance<C>,
    /// The points the native binding circuit exposes, in its output
    /// order ([`native_bound`]); none for a profile without one.
    pub nested_bound: &'a [C::NestedCurve],
    /// The online Fq commitments the step exports; none for a profile
    /// whose native binding names none.
    pub online_fq: &'a [C::NestedCurve],
    /// The actual nested online stages, for the compute-v transcript-copy target.
    pub nested_online_stages: &'a [C::NestedCurve],
    /// Common targets for the nested online walk points.
    pub nested_online_commitments: &'a [C::NestedCurve],
    /// Native online helper sums.
    pub native_online_fold: &'a [C::CircuitField],
    pub native_mesh_claims: &'a [C::CircuitField],
}

/// The native $k(y)$ values at `y` from an instance's parts, as
/// the decider's `native_ky_from_header` computes them from a proof and its
/// encoded header.
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
            parts.as_ref().map(|p| p.online),
            parts.as_ref().map(|p| p.circuit_id.omega_j()),
            parts.as_ref().map(|p| p.unified),
            parts.as_ref().map(|p| p.nested_online_commitments),
            parts.as_ref().map(|p| p.native_online_fold),
            parts.as_ref().map(|p| p.native_mesh_claims),
        )?;

        let (unified, unified_bridge) = proof_inputs.unified_ky_values(dr, &y)?;
        let online_stages = nested_online_stage_points::<_, _, C::Profile>(
            dr,
            parts.as_ref().map(|p| p.nested_online_stages),
        )?;
        let compute_v_bridge = proof_inputs.compute_v_bridge_ky(dr, &y, &online_stages)?;
        let online_helper = proof_inputs.online_helper_ky(dr, &y)?;
        let application = proof_inputs.application_ky(dr, &y)?;
        let statement = proof_inputs.statement_ky::<C::Profile>(dr, &y)?;
        let count = parts.as_ref().map(|p| p.nested_bound.len()).take();
        let binding = binding_ky_alloc(
            dr,
            &y,
            count,
            parts.as_ref().map(|p| p.nested_bound),
            parts.as_ref().map(|_| -> &[C::CircuitField] { &[] }),
        )?;
        let bind_endoscalar = bind_endoscalar_ky_alloc::<_, _, C::Profile, HEADER_SIZE>(
            dr,
            &proof_inputs,
            &y,
            &unified,
            parts.as_ref().map(|p| p.online_fq),
        )?;
        Ok(NativeKy {
            c: None,
            unified: *unified.value().take(),
            unified_bridge: *unified_bridge.value().take(),
            compute_v_bridge: *compute_v_bridge.value().take(),
            bind_endoscalar: *bind_endoscalar.value().take(),
            online_helper: online_helper.map(|ky| *ky.value().take()),
            application: *application.value().take(),
            statement: statement.map(|ky| *ky.value().take()),
            binding: binding.map(|ky| *ky.value().take()),
        })
    })
}

/// The nested unified instance's $k(y)$ at the nested `y` from the
/// instance's values, as the decider's `nested_ky` computes it from a proof.
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

/// Values shared by the nested compute-v and online helper targets. The
/// transcript supplies the challenge lifts; only the two sums are carried.
pub fn nested_online_values<C: ProfiledCycle>(
    challenges: &nested::Challenges<C::CircuitField>,
    sums: &[C::ScalarField],
) -> Result<Vec<C::ScalarField>> {
    if C::Profile::NESTED_ONLINE.is_empty() {
        return Ok(Vec::new());
    }
    if sums.len() != 2 {
        return Err(ragu_core::Error::InvalidWitness(
            "online batch requires two sums".into(),
        ));
    }
    Ok(alloc::vec![
        nested::challenge::<C>(challenges.w)?,
        nested::challenge::<C>(challenges.alpha)?,
        nested::challenge::<C>(challenges.pre_beta)?,
        sums[0],
        sums[1],
    ])
}

/// The nested compute-v and online helper claims use the same five values.
/// Compute-v exports the online Fq openings the step exports for its
/// nested binding, `openings`, then the authenticated lifts of w, alpha
/// and beta. The helper exports those lifts, the unified x, y and u, and
/// the same two sums. Compute-v also exports the native online stage
/// commitments, even when this profile has no nested helper. A profile
/// that exports none of them keeps the unified target, `unified_ky`.
#[allow(clippy::too_many_arguments)]
pub fn nested_online_ky<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile>(
    dr: &mut D,
    y: &Element<'dr, D>,
    unified: &nested_unified::Output<'dr, D, C>,
    unified_ky: &Element<'dr, D>,
    openings: &[Element<'dr, D>],
    online_values: &[Element<'dr, D>],
    online_stages: &[Point<'dr, D, C>],
    online_points: &[Point<'dr, D, C>],
    mesh_values: &[Element<'dr, D>],
) -> Result<(Element<'dr, D>, Option<Element<'dr, D>>)> {
    if openings.is_empty() && P::NESTED_ONLINE.is_empty() && P::NATIVE_ONLINE.is_empty() {
        return Ok((unified_ky.clone(), None));
    }
    let mut compute_v = Horner::new(y);
    GadgetExt::write(unified, dr, &mut compute_v)?;
    for value in openings {
        value.write(dr, &mut compute_v)?;
    }
    for value in online_values {
        value.write(dr, &mut compute_v)?;
    }
    for point in online_stages {
        GadgetExt::write(point, dr, &mut compute_v)?;
    }
    for point in online_points {
        GadgetExt::write(point, dr, &mut compute_v)?;
    }
    if let Some(mesh) = P::NESTED_MESH {
        for value in mesh.inherited_values(mesh_values) {
            value.write(dr, &mut compute_v)?;
        }
    }
    let compute_v = compute_v.finish_ky(dr)?;
    if P::NESTED_ONLINE.is_empty() {
        return Ok((compute_v, None));
    }
    let mut helper = Horner::new(y);
    for value in [
        &online_values[0],
        &unified.y,
        &unified.x,
        &online_values[1],
        &unified.u,
        &online_values[2],
        &online_values[3],
        &online_values[4],
    ] {
        value.write(dr, &mut helper)?;
    }
    for point in online_points.iter().take(
        P::NATIVE_ONLINE
            .polynomials
            .iter()
            .take_while(|&&phase| phase == crate::profile::online::Phase::BeforeW)
            .count(),
    ) {
        GadgetExt::write(point, dr, &mut helper)?;
    }
    for value in mesh_values {
        value.write(dr, &mut helper)?;
    }
    Ok((compute_v, Some(finish_extension_ky(helper, dr)?)))
}

/// Host evaluation of the same targets used by the parent's collapse
/// circuit, with `openings` the online Fq openings the step exports.
#[allow(clippy::too_many_arguments)]
pub fn nested_online_ky_of<C: ProfiledCycle>(
    instance: &nested_unified::Instance<C::HostCurve>,
    openings: &[C::ScalarField],
    online_values: &[C::ScalarField],
    online_stages: &[C::HostCurve],
    online_points: &[C::HostCurve],
    mesh_values: &[C::ScalarField],
    y: C::ScalarField,
) -> Result<(C::ScalarField, Option<C::ScalarField>)> {
    Emulator::emulate_wireless(
        (
            instance,
            openings,
            online_values,
            online_stages,
            online_points,
            mesh_values,
            y,
        ),
        |dr, witness| {
            let (instance, openings, online_values, online_stages, online_points, mesh_values, y) =
                witness.cast();
            let y = Element::alloc(dr, &mut (), y)?;
            let output = nested_unified::Output::<_, C::HostCurve>::alloc(dr, &mut (), instance)?;
            let len = openings.as_ref().map(|o| o.len()).take();
            let openings = (0..len)
                .map(|i| Element::alloc(dr, &mut (), openings.as_ref().map(|o| o[i])))
                .collect::<Result<Vec<_>>>()?;
            let online_values = (0..if C::Profile::NESTED_ONLINE.is_empty() {
                0
            } else {
                5
            })
                .map(|i| Element::alloc(dr, &mut (), online_values.as_ref().map(|p| p[i])))
                .collect::<Result<Vec<_>>>()?;
            let online_stages = FixedVec::<
                _,
                crate::profile::online::stages::Present<
                    C::Profile,
                    crate::profile::online::stages::Native,
                    3,
                >,
            >::try_from_fn(|i| {
                Point::alloc(dr, online_stages.as_ref().map(|p| p[i]))
            })?;
            let online_points = FixedVec::<
                _,
                crate::profile::online::stages::PolynomialsLen<
                    C::Profile,
                    crate::profile::online::stages::Native,
                >,
            >::try_from_fn(|i| {
                Point::alloc(dr, online_points.as_ref().map(|p| p[i]))
            })?;
            let mesh_values = (0..C::Profile::NESTED_MESH.map_or(0, |mesh| mesh.claims_len()))
                .map(|i| Element::alloc(dr, &mut (), mesh_values.as_ref().map(|v| v[i])))
                .collect::<Result<Vec<_>>>()?;
            let unified_ky = output.ky(dr, &y)?;
            let (compute_v, helper) = nested_online_ky::<_, _, C::Profile>(
                dr,
                &y,
                &output,
                &unified_ky,
                &openings,
                &online_values,
                &online_stages,
                &online_points,
                &mesh_values,
            )?;
            Ok((
                *compute_v.value().take(),
                helper.map(|value| *value.value().take()),
            ))
        },
    )
}
