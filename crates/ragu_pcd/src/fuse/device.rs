//! The devices a fuse keeps polynomials on.
//!
//! A backend may hold whole polynomials on a device (see
//! [`PolyDevice`]). The fuse opens one per field at its start and hands them
//! from stage to stage; a stage with no device for a field computes that
//! field's work on the host, with the same result.

use alloc::{boxed::Box, vec::Vec};

use ragu_backend::{Backend, Later, PolyDevice, Slot};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{Registry, RegistryAt},
};
use ragu_core::{Cycle, FixedGenerators};
use udon::{curve::Affine, field::Field};

use super::claims::{
    NativeDeviceProcessor, NativeFuseProofSource, NestedDeviceProcessor, NestedFuseProofSource,
};
use crate::{
    internal::{claims::DeviceRecorder, native, nested},
    multicore::par_join,
    profile::ProfiledCycle,
};

/// The polynomials of one field a device holds for the stages that open the
/// batch: the children's, uploaded while the first stages run, and the
/// current step's, uploaded when the batch is first opened.
pub(super) struct Held<'rx, F: Field, R: Rank> {
    /// The children's polynomials, by identity.
    children: Vec<(&'rx sparse::Polynomial<F, R>, Slot)>,
    /// The current step's polynomials, by address, in the order of the list
    /// every call of [`slots`](Self::slots) is given.
    current: Vec<(usize, Slot)>,
    /// The batch's quotient polynomial, once the device has formed it.
    pub(super) f: Option<Slot>,
}

impl<F: Field, R: Rank> Default for Held<'_, F, R> {
    fn default() -> Self {
        Self {
            children: Vec::new(),
            current: Vec::new(),
            f: None,
        }
    }
}

impl<F: Field, R: Rank> Held<'_, F, R> {
    /// The slots of `polys` on `device`.
    ///
    /// `current` lists the current step's polynomials: the same polynomials,
    /// in the same order, in every call, which must stay in place and
    /// unchanged between calls. The first call uploads them. A polynomial
    /// that is neither a child's nor listed there is uploaded for this call
    /// alone.
    ///
    /// # Panics
    ///
    /// Panics if `current` is not the list of an earlier call.
    pub(super) fn slots(
        &mut self,
        device: &mut dyn PolyDevice<F, R>,
        current: &[&sparse::Polynomial<F, R>],
        polys: &[&sparse::Polynomial<F, R>],
    ) -> Vec<Slot> {
        if self.current.is_empty() && !current.is_empty() {
            let slots = device.upload(current);
            self.current = current
                .iter()
                .map(|poly| core::ptr::from_ref(*poly).addr())
                .zip(slots)
                .collect();
        }
        assert!(
            self.current.len() == current.len()
                && self
                    .current
                    .iter()
                    .zip(current)
                    .all(|((known, _), poly)| *known == core::ptr::from_ref(*poly).addr()),
            "the current step's polynomials changed between stages"
        );
        self.resolve(device, polys)
    }

    /// The slots of `polys` on `device`: a polynomial the device does not
    /// hold yet is uploaded for this call alone.
    fn resolve(
        &self,
        device: &mut dyn PolyDevice<F, R>,
        polys: &[&sparse::Polynomial<F, R>],
    ) -> Vec<Slot> {
        let known = |poly: &sparse::Polynomial<F, R>| {
            let child = self
                .children
                .iter()
                .find(|(known, _)| core::ptr::eq(*known, poly));
            let address = core::ptr::from_ref(poly).addr();
            let current = self.current.iter().find(|(known, _)| *known == address);
            child
                .map(|(_, slot)| *slot)
                .or(current.map(|(_, slot)| *slot))
        };
        let slots: Vec<Option<Slot>> = polys.iter().map(|poly| known(poly)).collect();
        if slots.iter().all(Option::is_some) {
            return slots.into_iter().flatten().collect();
        }

        // What the device does not hold, once each.
        let mut strays: Vec<&sparse::Polynomial<F, R>> = Vec::new();
        for (poly, slot) in polys.iter().zip(&slots) {
            if slot.is_none() && !strays.iter().any(|stray| core::ptr::eq(*stray, *poly)) {
                strays.push(poly);
            }
        }
        let uploaded = device.upload(&strays);
        polys
            .iter()
            .zip(slots)
            .map(|(poly, slot)| {
                slot.unwrap_or_else(|| {
                    let index = strays
                        .iter()
                        .position(|stray| core::ptr::eq(*stray, *poly))
                        .expect("every stray was listed");
                    uploaded[index]
                })
            })
            .collect()
    }
}

/// Evaluates each polynomial at its point on `device`, as
/// [`Backend::sparse_eval`] does, from the polynomials the device holds; one
/// that it does not hold is uploaded first.
pub(super) fn evaluations<F: Field, R: Rank>(
    device: &mut dyn PolyDevice<F, R>,
    held: &Held<'_, F, R>,
    openings: &[(&sparse::Polynomial<F, R>, F)],
) -> Vec<F> {
    let polys: Vec<_> = openings.iter().map(|(poly, _)| *poly).collect();
    let slots = held.resolve(device, &polys);
    // One slot of powers for each distinct point.
    let mut points: Vec<(F, Slot)> = Vec::new();
    let pairs: Vec<_> = openings
        .iter()
        .zip(slots)
        .map(|((_, point), slot)| {
            let powers = match points.iter().find(|(known, _)| known == point) {
                Some((_, powers)) => *powers,
                None => {
                    let powers = device.powers(*point);
                    points.push((*point, powers));
                    powers
                }
            };
            (slot, powers)
        })
        .collect();
    device.dot(&pairs)
}

/// The devices of one fuse: the native side's polynomials are over the
/// circuit field and the nested side's over the scalar field. Each side's
/// revdot claims are recorded for its device ahead of the challenges, with
/// the children's polynomials they read uploaded.
pub(super) struct Devices<'rx, C: Cycle, R: Rank> {
    pub(super) native: Option<Box<dyn PolyDevice<C::CircuitField, R>>>,
    pub(super) nested: Option<Box<dyn PolyDevice<C::ScalarField, R>>>,
    /// Each side's wiring matrices at the children's $x$ challenges, asked
    /// for when the fuse started ([`record`](Self::record)).
    pub(super) native_wired: Option<Wired<C::CircuitField>>,
    pub(super) nested_wired: Option<Wired<C::ScalarField>>,
    pub(super) native_claims: Option<DeviceRecorder<'rx, C::CircuitField, R>>,
    pub(super) nested_claims: Option<DeviceRecorder<'rx, C::ScalarField, R>>,
    pub(super) native_held: Held<'rx, C::CircuitField, R>,
    pub(super) nested_held: Held<'rx, C::ScalarField, R>,
}

impl<'rx, C: ProfiledCycle, R: Rank> Devices<'rx, C, R> {
    /// Opens the devices `B` has free.
    pub(super) fn open<B: Backend>() -> Self {
        Self {
            native: B::poly_device(),
            nested: B::poly_device(),
            native_wired: None,
            nested_wired: None,
            native_claims: None,
            nested_claims: None,
            native_held: Held::default(),
            nested_held: Held::default(),
        }
    }

    /// No devices: every stage computes on the host. The fuzzing patcher
    /// drives the stages this way.
    #[cfg_attr(not(feature = "unstable-fuzzing"), allow(dead_code))]
    pub(super) fn none() -> Self {
        Self {
            native: None,
            nested: None,
            native_wired: None,
            nested_wired: None,
            native_claims: None,
            nested_claims: None,
            native_held: Held::default(),
            nested_held: Held::default(),
        }
    }

    /// Records each side's claims for its device and uploads the children's
    /// polynomials they read, with the rest of the children's polynomials
    /// the batch opens. This needs no challenge, and reads only the
    /// children, so it can run while the first stages do.
    ///
    /// A side whose claims cannot be recorded is left for the host, which
    /// reports the failure when it builds them.
    ///
    /// The children's polynomials have their slots when this returns. The
    /// work that stores them there is returned, for each side whose device
    /// leaves it to the caller: it is the long part, and nothing reads the
    /// children from a device before `inner_error`, so the caller runs it
    /// behind the stages before that.
    ///
    /// Each side's registry is also restricted, circuit by circuit, at the
    /// points it is given: the children's $x$ challenges, where `s_prime`
    /// restricts it. A circuit's restriction does not depend on $w$, which
    /// only weighs the circuits against one another, so the device is asked
    /// for it first and computes it under the upload's packing.
    pub(super) fn record(
        &mut self,
        native_source: &NativeFuseProofSource<'rx, C, R>,
        nested_source: &NestedFuseProofSource<'rx, C, R>,
        native_registry: (&Registry<'_, C::CircuitField, R>, [C::CircuitField; 2]),
        nested_registry: (
            &Registry<'_, C::ScalarField, R>,
            Option<[C::ScalarField; 2]>,
        ),
    ) -> [Option<Later<'rx>>; 2] {
        let (native, nested) = (self.native.as_deref_mut(), self.nested.as_deref_mut());
        let (native_wired, nested_wired) = (&mut self.native_wired, &mut self.nested_wired);
        let (native_claims, nested_claims) = par_join!(
            || {
                let device = native?;
                *native_wired = Wired::ask(device, native_registry.0, native_registry.1);
                let mut processor = NativeDeviceProcessor::default();
                native::claims::build::<C::Profile, _, _>(native_source, &mut processor).ok()?;
                for proof in [native_source.left, native_source.right] {
                    processor.recorder.also(
                        native::RxIndex::all::<C::Profile>()
                            .into_iter()
                            .map(move |id| &proof[id])
                            .chain([
                                &proof[native::RxComponent::AbA],
                                &proof[native::RxComponent::AbB],
                                proof.native_registry_xy_poly(),
                                proof.native_p_poly(),
                            ])
                            .chain(proof.online_polynomials()),
                    );
                }
                let work = processor.recorder.upload(device);
                Some((processor.recorder, work))
            },
            || {
                let device = nested?;
                *nested_wired = nested_registry
                    .1
                    .and_then(|points| Wired::ask(device, nested_registry.0, points));
                let mut processor = NestedDeviceProcessor::default();
                nested::claims::build::<C::Profile, _, _>(nested_source, &mut processor).ok()?;
                for proof in [nested_source.left, nested_source.right] {
                    processor.recorder.also(
                        nested::RxIndex::all::<C::Profile>()
                            .into_iter()
                            .map(move |id| &proof[id])
                            .chain([
                                &proof[nested::RxComponent::AbA],
                                &proof[nested::RxComponent::AbB],
                                proof.nested_registry_xy_poly(),
                                proof.nested_p_poly(),
                            ]),
                    );
                }
                let work = processor.recorder.upload(device);
                Some((processor.recorder, work))
            },
        );
        let (native_claims, native_work) = native_claims.unzip();
        let (nested_claims, nested_work) = nested_claims.unzip();
        if let Some(recorder) = &native_claims {
            self.native_held.children = recorder.held();
        }
        if let Some(recorder) = &nested_claims {
            self.nested_held.children = recorder.held();
        }
        self.native_claims = native_claims;
        self.nested_claims = nested_claims;
        [native_work.flatten(), nested_work.flatten()]
    }
}

/// A registry's wiring matrices restricted at two points in $X$, where the
/// device holds them: for each point, the slot of each circuit's
/// restriction, as [`PolyDevice::wiring_x`] returns them.
pub(super) struct Wired<F> {
    points: [F; 2],
    slots: [Vec<Option<Slot>>; 2],
}

impl<F: Field> Wired<F> {
    /// Asks `device` for the restrictions of `registry` at `points`, if it
    /// holds the registry's matrices.
    fn ask<R: Rank>(
        device: &mut dyn PolyDevice<F, R>,
        registry: &Registry<'_, F, R>,
        points: [F; 2],
    ) -> Option<Self> {
        let [x0, x1] = points;
        let slots = [
            device.wiring_x(registry, x0)?,
            device.wiring_x(registry, x1)?,
        ];
        Some(Self { points, slots })
    }

    /// The slots at `point`, if it is one of the two.
    fn at(&self, point: F) -> Option<Vec<Option<Slot>>> {
        let which = self.points.iter().position(|known| *known == point)?;
        Some(self.slots[which].clone())
    }
}

/// Restricts `at` to each of `points` in $X$, as [`RegistryAt::x`] does,
/// with the circuits whose wiring matrices `device` holds restricted there:
/// now, or already in `wired` for a point asked for earlier. Returns `None`
/// if the device holds no matrices for this registry.
///
/// The restrictions come with their commitments over `generators` if the
/// backend commits to them where the device holds them, in the request
/// that reads them back.
#[allow(clippy::type_complexity)]
pub(super) fn registry_x<B, P, R, G, const N: usize>(
    device: &mut dyn PolyDevice<P::Scalar, R>,
    at: &RegistryAt<'_, P::Scalar, R>,
    points: [P::Scalar; N],
    wired: Option<&Wired<P::Scalar>>,
    generators: &G,
) -> Option<([sparse::Polynomial<P::Scalar, R>; N], Option<[P; N]>)>
where
    B: Backend,
    P: Affine,
    R: Rank,
    G: FixedGenerators<P>,
{
    let registry = at.registry();
    let mut parts = Vec::with_capacity(N);
    for x in points {
        let matrices = crate::timing::span("rx.wiring", || {
            wired
                .and_then(|wired| wired.at(x))
                .or_else(|| device.wiring_x(registry, x))
        })?;
        let (held, rest) = crate::timing::span("rx.parts", || {
            at.x_parts(x, |i| matrices.get(i).is_some_and(Option::is_some))
        });
        parts.push((matrices, held, rest));
    }

    // Each restriction is its matrices' combination plus its rest.
    let rests: Vec<_> = parts.iter().map(|(_, _, rest)| rest).collect();
    let rests = crate::timing::span("rx.upload", || device.upload(&rests));
    let jobs: Vec<Vec<(P::Scalar, Slot)>> = parts
        .iter()
        .zip(rests)
        .map(|((matrices, held, _), rest)| {
            held.iter()
                .map(|(i, coeff)| (*coeff, matrices[*i].expect("a held circuit's slot")))
                .chain([(P::Scalar::ONE, rest)])
                .collect()
        })
        .collect();
    let combined = crate::timing::span("rx.lincomb", || device.lincomb(&jobs));
    let committed = crate::timing::span("rx.commit", || {
        B::device_commit::<P, R, G>(device, &combined, generators)
    });
    if let Some((polys, commitments)) = committed
        && commitments.len() == N
    {
        let mut affine = [P::identity(); N];
        P::batch_to_affine(&commitments, &mut affine);
        return Some((polys.try_into().ok()?, Some(affine)));
    }
    let polys = crate::timing::span("rx.download", || device.download(&combined))
        .try_into()
        .ok()?;
    Some((polys, None))
}

/// Evaluates `registry` over its $W$-domain at $(x, y)$, as
/// [`Registry::wxy_over_domain`] does, with the circuits whose wiring
/// matrices `device` holds evaluated there: each is restricted to `x` and
/// the restriction evaluated at `y`. Returns `None` if the device holds no
/// matrices for this registry.
pub(super) fn registry_wxy_over_domain<F: Field, R: Rank>(
    device: &mut dyn PolyDevice<F, R>,
    registry: &Registry<'_, F, R>,
    x: F,
    y: F,
) -> Option<Vec<F>> {
    let matrices = device.wiring_x(registry, x)?;
    let powers = device.powers(y);
    let pairs: Vec<_> = matrices
        .iter()
        .flatten()
        .map(|restriction| (*restriction, powers))
        .collect();
    let mut values = device.dot(&pairs).into_iter();
    let known: Vec<Option<F>> = matrices
        .iter()
        .map(|slot| slot.map(|_| values.next().expect("one value per held circuit")))
        .collect();
    Some(registry.wxy_over_domain_from(x, y, &known))
}
