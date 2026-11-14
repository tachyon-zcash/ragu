//! Polynomial commitments on a CUDA device.
//!
//! A commitment is an MSM over a prefix of one curve's fixed generators. The
//! device keeps a table of window multiples for each generator set it has
//! seen, so a commitment uploads only scalars and their generator indices and
//! needs no doublings. See `gpu/ragu_gpu.cu` for the engine.
//!
//! Every entry point returns `None` when the device cannot be used for the
//! request, and the caller then computes the same result on the CPU. A device
//! result is checked to be a curve point before it is returned.

extern crate std;

use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};
use core::{
    any::{Any, TypeId},
    ffi::c_int,
    marker::PhantomData,
    sync::atomic::{AtomicBool, Ordering},
};
use std::sync::{Arc, Mutex, OnceLock};

use ragu_backend::{PolyDevice, Slot};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{Matrix, Registry},
};
use ragu_core::FixedGenerators;
use udon::{
    curve::{
        Affine, AffineAdapter, AffinePoint, Pallas, PastaCurve, ProjectiveAdapter, ProjectivePoint,
        Vesta,
    },
    field::{
        CanonicalUint, Field, FieldAdapter, PallasBase, PallasScalar, PastaField, PrimeModulus,
    },
};

unsafe extern "C" {
    fn ragu_gpu_poly_init(field: c_int, n: usize, slots: usize) -> c_int;
    fn ragu_gpu_poly_upload_buffer(
        field: c_int,
        words: usize,
        buffer: *mut *mut u64,
        apart: c_int,
    ) -> c_int;
    fn ragu_gpu_poly_upload_staged(
        field: c_int,
        num_slots: usize,
        num_runs: usize,
        num_terms: usize,
        apart: c_int,
    ) -> c_int;
    fn ragu_gpu_poly_join(field: c_int) -> c_int;
    fn ragu_gpu_poly_powers(field: c_int, dst: u32, z: *const u64) -> c_int;
    fn ragu_gpu_poly_lincomb(
        field: c_int,
        jobs: usize,
        dst: *const u32,
        offsets: *const u32,
        srcs: *const u32,
        scalars: *const u64,
    ) -> c_int;
    fn ragu_gpu_poly_dilate_add(
        field: c_int,
        jobs: usize,
        dst: *const u32,
        a: *const u32,
        s: *const u32,
        powers: u32,
        t: u32,
    ) -> c_int;
    fn ragu_gpu_poly_revdot(
        field: c_int,
        pairs: usize,
        a: *const u32,
        b: *const u32,
        reversed: c_int,
        out: *mut u64,
    ) -> c_int;
    fn ragu_gpu_poly_quotients(
        field: c_int,
        jobs: usize,
        dst: u32,
        slots: *const u32,
        points: *const u64,
    ) -> c_int;
    fn ragu_gpu_poly_download_view(
        field: c_int,
        count: usize,
        slots: *const u32,
        view: *mut *const u64,
    ) -> c_int;
    fn ragu_gpu_poly_commit_view(
        field: c_int,
        handle: c_int,
        count: usize,
        slots: *const u32,
        polys: *mut *const u64,
        out: *mut u64,
    ) -> c_int;
    fn ragu_gpu_wiring_register(
        field: c_int,
        n: usize,
        circuits: usize,
        column_chunks: *const u32,
        chunks: usize,
        chunk_terms: *const u32,
        chunk_values: *const u32,
        terms: usize,
        rows: *const u32,
        values: *const u64,
        distinct: usize,
    ) -> c_int;
    fn ragu_gpu_wiring_sy(handle: c_int, powers: u32, dst: u32) -> c_int;
    fn ragu_gpu_register_bases(curve: c_int, xy: *const u64, n: usize) -> c_int;
    fn ragu_gpu_msm_stage(
        handle: c_int,
        counts: *const u32,
        num_msms: usize,
        started: c_int,
        scalars: *mut *mut u64,
        indices: *mut *mut u32,
        starts: *mut u32,
    ) -> c_int;
    fn ragu_gpu_msm_batch_staged(staging: c_int, out: *mut u64) -> c_int;
    fn ragu_gpu_msm_start_staged(staging: c_int) -> c_int;
    fn ragu_gpu_msm_unstage(staging: c_int) -> c_int;
    fn ragu_gpu_msm_ready(ticket: c_int) -> c_int;
    fn ragu_gpu_msm_finish(ticket: c_int, out: *mut u64) -> c_int;
}

/// A Pasta curve the engine has kernels for, with the engine's name for it.
trait DeviceCurve: PastaCurve {
    const ID: c_int;
}

impl DeviceCurve for Pallas {
    const ID: c_int = 0;
}

impl DeviceCurve for Vesta {
    const ID: c_int = 1;
}

// The engine reads staged 32-bit values out of 64-bit words as the host wrote
// them.
const _: () = assert!(cfg!(target_endian = "little"));

/// Requests with fewer terms stay on the CPU, where they finish before a
/// device round trip would: on the host this was measured against, a round
/// trip takes about as long as a CPU MSM of thirty terms.
const MIN_TERMS: usize = 32;

/// The largest generator set given a device table. A table takes 262 KiB per
/// generator.
const MAX_BASES: usize = 1 << 14;

/// The number of generator sets given device tables before further sets are
/// left to the CPU.
const MAX_TABLES: usize = 8;

/// The number of generators compared to recognize a registered set.
const SAMPLES: usize = 32;

/// A generator set's device table.
///
/// A set is recognized by its curve, its address and length, and a spread of
/// its points. The address alone would not do, since a later allocation can
/// reuse it for other points; the samples tell such a set apart unless it
/// agrees with the registered one at every sampled position, which
/// independently derived generators do not.
struct Table {
    curve: c_int,
    address: usize,
    len: usize,
    samples: [[u64; 8]; SAMPLES],
    /// `None` if registration failed; the set is then left to the CPU.
    handle: Option<c_int>,
}

static TABLES: Mutex<Vec<Table>> = Mutex::new(Vec::new());

/// Whether the device is selected. `RAGU_GPU=0` leaves every request to the
/// CPU.
fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("RAGU_GPU").is_none_or(|value| value != "0"))
}

fn as_pasta<P: PastaCurve, C: Affine>(point: &C) -> Option<&AffinePoint<P>> {
    (point as &dyn Any)
        .downcast_ref::<AffineAdapter<P>>()?
        .as_inner()
        .as_affine()
}

/// The stored limbs of a nonidentity point's coordinates.
fn stored_limbs<P: PastaCurve>(point: &AffinePoint<P>) -> [u64; 8] {
    let (x, y) = point.coordinates();
    let (x, y) = (x.montgomery_limbs(), y.montgomery_limbs());
    [x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3]]
}

/// Returns the device table for these generators, building it on first use.
fn table_for<P: DeviceCurve, C: Affine>(bases: &[C]) -> Option<c_int> {
    let len = bases.len();
    let mut samples = [[0; 8]; SAMPLES];
    for (slot, sample) in samples.iter_mut().enumerate() {
        *sample = stored_limbs(as_pasta::<P, C>(&bases[slot * (len - 1) / (SAMPLES - 1)])?);
    }

    let address = bases.as_ptr() as usize;

    let mut tables = TABLES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(table) = tables.iter().find(|table| {
        table.curve == P::ID
            && table.address == address
            && table.len == len
            && table.samples == samples
    }) {
        return table.handle;
    }
    if tables.len() >= MAX_TABLES {
        return None;
    }

    let mut xy = Vec::with_capacity(len * 8);
    let mut valid = true;
    for base in bases {
        match as_pasta::<P, C>(base) {
            Some(point) => {
                let (x, y) = point.coordinates();
                xy.extend_from_slice(&x.to_canonical_uint().limbs());
                xy.extend_from_slice(&y.to_canonical_uint().limbs());
            }
            // The identity has no affine table entry.
            None => valid = false,
        }
    }
    let handle = valid
        // SAFETY: `xy` holds eight limbs for each of the `len` bases.
        .then(|| unsafe { ragu_gpu_register_bases(P::ID, xy.as_ptr(), len) })
        .filter(|handle| *handle >= 0);
    tables.push(Table {
        curve: P::ID,
        address,
        len,
        samples,
        handle,
    });
    handle
}

/// Reads one projective result of the engine: ordinary integers `X, Y, Z`
/// with the point at `(X/Z, Y/Z)` and the identity at `Z = 0`.
///
/// # Panics
///
/// Panics if the coordinates are not reduced or the point is off the curve.
/// Either means the device computed something other than a group operation,
/// and none of its results can then be trusted.
fn read_point<P: PastaCurve>(limbs: &[u64]) -> ProjectivePoint<P> {
    let field = |limbs: &[u64]| {
        PastaField::<P::Base>::from_canonical_uint(CanonicalUint::from_limbs([
            limbs[0], limbs[1], limbs[2], limbs[3],
        ]))
        .expect("the device returns reduced coordinates")
    };
    let (x, y, z) = (field(&limbs[..4]), field(&limbs[4..8]), field(&limbs[8..]));
    match z.invert() {
        None => ProjectivePoint::IDENTITY,
        Some(z_inverse) => {
            AffinePoint::from_xy(x.mul(&z_inverse).reduce(), y.mul(&z_inverse).reduce())
                .expect("the device returns curve points")
                .to_projective()
        }
    }
}

/// Views a run of `F` as the Pasta elements over `M` it is, or returns `None`
/// if `F` is another type.
fn pasta_elements<M: PrimeModulus, F: 'static>(run: &[F]) -> Option<&[PastaField<M>]> {
    if TypeId::of::<F>() != TypeId::of::<FieldAdapter<M>>() {
        return None;
    }
    // SAFETY: `F` and `FieldAdapter<M>` are the same type, as checked above,
    // so the slice is reinterpreted as itself.
    let run = unsafe { &*(core::ptr::from_ref(run) as *const [FieldAdapter<M>]) };
    Some(FieldAdapter::as_slice(run))
}

/// Commitments the device was asked for: the engine's ticket for the
/// request, which is finished when they are read or when this is dropped.
struct Started<P, C> {
    ticket: c_int,
    /// The number of commitments.
    count: usize,
    _marker: PhantomData<fn() -> (P, C)>,
}

impl<P: DeviceCurve, C: Affine> Started<P, C> {
    /// Waits for the commitments and reads them, or returns `None` if the
    /// device failed.
    fn read(mut self) -> Option<Vec<C::Projective>> {
        let mut out = vec![0u64; 12 * self.count];
        let ticket = core::mem::replace(&mut self.ticket, -1);
        // SAFETY: the ticket is of a request this value started and nothing
        // has finished, and `out` has room for one result per polynomial of
        // that request.
        let status = unsafe { ragu_gpu_msm_finish(ticket, out.as_mut_ptr()) };
        if status != 0 {
            return None;
        }
        read_points::<P, C>(&out)
    }
}

/// The commitments the engine wrote to `out`, twelve limbs each.
fn read_points<P: DeviceCurve, C: Affine>(out: &[u64]) -> Option<Vec<C::Projective>> {
    out.chunks_exact(12)
        .map(|limbs| {
            let point = ProjectiveAdapter::new(read_point::<P>(limbs));
            (&point as &dyn Any)
                .downcast_ref::<C::Projective>()
                .copied()
        })
        .collect()
}

/// A request as the engine takes it: the base set's handle, the scalars'
/// limbs and the bases' indices term by term, and where each polynomial's
/// terms begin and the last one's end.
impl<P, C> Drop for Started<P, C> {
    fn drop(&mut self) {
        if self.ticket >= 0 {
            // SAFETY: the ticket is of a request this value started and
            // nothing has finished; a null `out` gives its results up.
            unsafe { ragu_gpu_msm_finish(self.ticket, core::ptr::null_mut()) };
        }
    }
}

impl<P: DeviceCurve, C: Affine> ragu_backend::StartedCommitments<C::Projective> for Started<P, C> {
    fn ready(&mut self) -> bool {
        // SAFETY: the ticket is of a request this value started and nothing
        // has finished.
        unsafe { ragu_gpu_msm_ready(self.ticket) != 0 }
    }

    fn finish(self: Box<Self>) -> Option<Vec<C::Projective>> {
        (*self).read()
    }
}

fn commit_on<P: DeviceCurve, C: Affine, R: Rank>(
    polys: &[&sparse::Polynomial<C::Scalar, R>],
    bases: &[C],
) -> Option<Vec<C::Projective>> {
    let staged = stage::<P, C, R>(polys, bases, false)?;
    let mut out = vec![0u64; 12 * polys.len()];
    // SAFETY: the staging holds a request of one MSM per polynomial, which
    // this call ends, and `out` has room for one result per polynomial.
    let status = unsafe { ragu_gpu_msm_batch_staged(staged.end(), out.as_mut_ptr()) };
    if status != 0 {
        return None;
    }
    read_points::<P, C>(&out)
}

/// Asks the device for the commitments to `polys` and returns without
/// waiting for them, or returns `None` if the device is not used for this
/// request: also while as many requests begun this way on the same curve as
/// the engine takes are unfinished.
fn start_on<P: DeviceCurve, C: Affine, R: Rank>(
    polys: &[&sparse::Polynomial<C::Scalar, R>],
    bases: &[C],
) -> Option<Started<P, C>> {
    let staged = stage::<P, C, R>(polys, bases, true)?;
    // SAFETY: the staging was taken for a started request, and this call
    // ends it.
    let ticket = unsafe { ragu_gpu_msm_start_staged(staged.end()) };
    (ticket >= 0).then_some(Started {
        ticket,
        count: polys.len(),
        _marker: PhantomData,
    })
}

/// A request laid out in the engine's memory and not yet run: the engine's
/// name for its staging, which is given up if this is dropped.
struct Staged(c_int);

impl Staged {
    /// The staging, for the engine call that ends it.
    fn end(self) -> c_int {
        let staging = self.0;
        core::mem::forget(self);
        staging
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // SAFETY: the staging is one the engine gave and nothing has ended.
        unsafe { ragu_gpu_msm_unstage(self.0) };
    }
}

/// The terms of a request below which one thread lays it out: handing so
/// few to other threads takes longer than copying them.
const LAID_BY_ONE: usize = 1 << 16;

/// Lays `polys` out for the engine, in its memory, as a request to run or,
/// with `started`, to start. Returns `None` if the device is not used for
/// them.
///
/// The terms are written once, where the engine sends them to the device
/// from, and a polynomial's runs of coefficients are copied whole.
fn stage<P: DeviceCurve, C: Affine, R: Rank>(
    polys: &[&sparse::Polynomial<C::Scalar, R>],
    bases: &[C],
    started: bool,
) -> Option<Staged> {
    let len = R::num_coeffs();
    if polys.is_empty() || !(SAMPLES..=MAX_BASES).contains(&len) || bases.len() < len {
        return None;
    }

    let stored: usize = polys
        .iter()
        .flat_map(|poly| poly.blocks())
        .map(|(_, run)| run.len())
        .sum();
    if stored < MIN_TERMS || u32::try_from(stored).is_err() {
        return None;
    }
    // The device takes scalars of the curve's own field only.
    pasta_elements::<P::Scalar, C::Scalar>(&[])?;
    let handle = table_for::<P, C>(&bases[..len])?;

    // The whole request fits 32 bits, so each polynomial does.
    let counts: Vec<u32> = polys
        .iter()
        .map(|poly| poly.blocks().map(|(_, run)| run.len() as u32).sum())
        .collect();
    let mut starts = vec![0u32; polys.len()];
    let (mut scalars, mut indices) = (core::ptr::null_mut(), core::ptr::null_mut());
    // SAFETY: `counts` and `starts` have one entry per polynomial, and the
    // two pointers receive the stage.
    let staging = unsafe {
        ragu_gpu_msm_stage(
            handle,
            counts.as_ptr(),
            polys.len(),
            c_int::from(started),
            &mut scalars,
            &mut indices,
            starts.as_mut_ptr(),
        )
    };
    if staging < 0 {
        return None;
    }
    let staged = Staged(staging);

    // Each polynomial's terms have their own stretch of the scalars and of
    // the indices, so the polynomials are laid out independently.
    type Job<'a, F, R> = (&'a sparse::Polynomial<F, R>, &'a mut [u64], &'a mut [u32]);
    let mut jobs: Vec<Job<'_, C::Scalar, R>> = polys
        .iter()
        .zip(counts.iter().zip(&starts))
        .map(|(poly, (count, start))| {
            let (count, start) = (*count as usize, *start as usize);
            // SAFETY: the engine gave this polynomial room for `count`
            // terms from term `start` of the stage on, apart from every
            // other's, in memory that nothing else reads or writes until
            // the staging is ended, which `staged` does after these
            // borrows. Words have no invalid values.
            unsafe {
                (
                    *poly,
                    core::slice::from_raw_parts_mut(scalars.add(4 * start), 4 * count),
                    core::slice::from_raw_parts_mut(indices.add(start), count),
                )
            }
        })
        .collect();
    let lay = |(poly, scalars, indices): &mut Job<'_, C::Scalar, R>| {
        let (mut scalars, mut indices) = (&mut **scalars, &mut **indices);
        for (start, run) in poly.blocks() {
            let run = pasta_elements::<P::Scalar, _>(run).expect("the curve's scalar field");
            let (own, later) = core::mem::take(&mut scalars).split_at_mut(4 * run.len());
            copy_out(own, limbs_of(run));
            scalars = later;
            let (own, later) = core::mem::take(&mut indices).split_at_mut(run.len());
            for (index, position) in own.iter_mut().zip(start as u32..) {
                *index = position;
            }
            indices = later;
        }
        copied_out();
    };
    if stored < LAID_BY_ONE {
        jobs.iter_mut().for_each(lay);
    } else {
        crate::verifier::for_each_mut(&mut jobs, |_, job| lay(job));
    }
    drop(jobs);
    Some(staged)
}

/// Commits to each polynomial over `generators`, or returns `None` if the
/// device is not used for this request.
///
/// A result equals [`sparse::Polynomial::commit`] as a group element.
pub(crate) fn commit_many<C: Affine, R: Rank, G: FixedGenerators<C>>(
    polys: &[&sparse::Polynomial<C::Scalar, R>],
    generators: &G,
) -> Option<Vec<C::Projective>> {
    if !enabled() {
        return None;
    }
    let curve = TypeId::of::<C>();
    if curve == TypeId::of::<AffineAdapter<Pallas>>() {
        commit_on::<Pallas, C, R>(polys, generators.g())
    } else if curve == TypeId::of::<AffineAdapter<Vesta>>() {
        commit_on::<Vesta, C, R>(polys, generators.g())
    } else {
        None
    }
}

/// Polynomials read back from the device, with their commitments.
type Committed<C, R> = (
    Vec<sparse::Polynomial<<C as Affine>::Scalar, R>>,
    Vec<<C as Affine>::Projective>,
);

/// Commits to the polynomials `device` holds in `slots` over `generators`,
/// and reads them back, in one request. Returns `None` if `device` is not a
/// store of this module over the curve's scalar field, or the device is not
/// used for this request.
///
/// The polynomials are what [`PolyDevice::download`] returns for the slots,
/// and each commitment equals [`sparse::Polynomial::commit`] of its
/// polynomial as a group element.
pub(crate) fn device_commit<C: Affine, R: Rank, G: FixedGenerators<C>>(
    device: &mut dyn PolyDevice<C::Scalar, R>,
    slots: &[Slot],
    generators: &G,
) -> Option<Committed<C, R>> {
    if !enabled() || slots.is_empty() {
        return None;
    }
    let curve = TypeId::of::<C>();
    if curve == TypeId::of::<AffineAdapter<Pallas>>() {
        commit_held::<Pallas, PallasScalar, C, R>(device, slots, generators.g())
    } else if curve == TypeId::of::<AffineAdapter<Vesta>>() {
        commit_held::<Vesta, PallasBase, C, R>(device, slots, generators.g())
    } else {
        None
    }
}

/// [`device_commit`] on curve `P`, whose scalar field is `M`.
fn commit_held<P: DeviceCurve, M: DeviceField, C: Affine, R: Rank>(
    device: &mut dyn PolyDevice<C::Scalar, R>,
    slots: &[Slot],
    bases: &[C],
) -> Option<Committed<C, R>> {
    let n = R::num_coeffs();
    if !(SAMPLES..=MAX_BASES).contains(&n) || bases.len() < n {
        return None;
    }
    // Only this module's store of that field has the slots the engine is
    // about to read.
    device
        .as_any_mut()
        .downcast_mut::<Store<M, C::Scalar, R>>()?
        .reads(slots.iter().map(|slot| slot.0));
    let handle = table_for::<P, C>(&bases[..n])?;
    let slots: Vec<u32> = slots.iter().map(|slot| slot.0).collect();
    let mut view = core::ptr::null();
    let mut out = vec![0u64; 12 * slots.len()];
    // SAFETY: `slots` has the stated length, `view` receives where the
    // slots were read back to and `out` has room for one result per slot.
    let status = unsafe {
        ragu_gpu_poly_commit_view(
            M::ID,
            handle,
            slots.len(),
            slots.as_ptr(),
            &mut view,
            out.as_mut_ptr(),
        )
    };
    if status != 0 {
        return None;
    }
    // SAFETY: the engine read the slots back to `view` in the call above,
    // the store's last: `device` is borrowed until this returns.
    let polys = unsafe { Store::<M, C::Scalar, R>::read_back(view, slots.len()) };
    Some((polys, read_points::<P, C>(&out)?))
}

/// Begins [`commit_many`] and returns the commitments to wait for, or `None`
/// if the device is not used for this request.
pub(crate) fn start_many<C: Affine, R: Rank, G: FixedGenerators<C>>(
    polys: &[&sparse::Polynomial<C::Scalar, R>],
    generators: &G,
) -> Option<Box<dyn ragu_backend::StartedCommitments<C::Projective>>> {
    if !enabled() {
        return None;
    }
    let curve = TypeId::of::<C>();
    if curve == TypeId::of::<AffineAdapter<Pallas>>() {
        Some(Box::new(start_on::<Pallas, C, R>(polys, generators.g())?))
    } else if curve == TypeId::of::<AffineAdapter<Vesta>>() {
        Some(Box::new(start_on::<Vesta, C, R>(polys, generators.g())?))
    } else {
        None
    }
}

/// [`commit_many`] for a fixed number of polynomials.
pub(crate) fn commit_batch<C: Affine, R: Rank, G: FixedGenerators<C>, const N: usize>(
    polys: [&sparse::Polynomial<C::Scalar, R>; N],
    generators: &G,
) -> Option<[C::Projective; N]> {
    commit_many(&polys, generators)?.try_into().ok()
}

/// A Pasta field the engine keeps polynomials over, with the engine's name
/// for it.
trait DeviceField: PrimeModulus {
    const ID: c_int;
}

impl DeviceField for PallasBase {
    const ID: c_int = 0;
}

impl DeviceField for PallasScalar {
    const ID: c_int = 1;
}

/// The number of polynomials a store holds: more than one fuse places there.
const STORE_SLOTS: usize = 2048;

/// Whether each field's store is in use. A store serves one caller at a
/// time; a second caller computes on the host.
static STORE_BUSY: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];

/// Ties a store to its field and rank without holding a value of either.
type Marker<M, F, R> = PhantomData<fn() -> (M, F, R)>;

/// One caller's use of a field's polynomial store.
struct Store<M: DeviceField, F, R> {
    /// The next unused slot.
    next: u32,
    /// The slots of uploads the device is taking in apart from the store's
    /// other work, which nothing has read yet.
    apart: Option<core::ops::Range<u32>>,
    /// The last upload whose laying out was left to the caller
    /// ([`PolyDevice::upload_later`]), until it is known to have run.
    later: Option<Arc<Laid>>,
    _marker: Marker<M, F, R>,
}

/// Whether an upload left to the caller has been laid out and handed to the
/// engine: `None` until its work ends, then whether it ran.
#[derive(Default)]
struct Laid {
    ran: Mutex<Option<bool>>,
    ended: std::sync::Condvar,
}

impl Laid {
    /// Waits for the work to end, and returns whether it ran.
    fn wait(&self) -> bool {
        let mut ran = self
            .ran
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            match *ran {
                Some(ran) => return ran,
                None => {
                    ran = self
                        .ended
                        .wait(ran)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
        }
    }
}

/// Marks an upload's work as ended when dropped: as run if it got that far,
/// and otherwise as dropped or failed, so that nothing waits for it forever.
struct Laying(Arc<Laid>, bool);

impl Drop for Laying {
    fn drop(&mut self) {
        *self
            .0
            .ran
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(self.1);
        self.0.ended.notify_all();
    }
}

/// The engine's staging buffer for an upload, and its length in words.
struct Staging(*mut u64, usize);

/// The words of an upload's run table: one per run and one more, padded to
/// four words.
fn run_words(runs: usize) -> usize {
    (runs + 1).next_multiple_of(4)
}

/// Copies `src` into `dst`, a part of a staging buffer: memory that the
/// device reads next and this processor does not. Where the processor can,
/// the copy goes around its cache, which a plain copy would first fill with
/// the lines it is about to overwrite. A thread that has copied this way
/// calls [`copied_out`] before another reads what it wrote.
fn copy_out(dst: &mut [u64], src: &[u64]) {
    assert_eq!(dst.len(), src.len());
    #[cfg(target_arch = "x86_64")]
    if dst.as_ptr().addr().is_multiple_of(16) && dst.len().is_multiple_of(2) {
        use core::arch::x86_64::{__m128i, _mm_loadu_si128, _mm_stream_si128};
        let (to, from) = (
            dst.as_mut_ptr().cast::<__m128i>(),
            src.as_ptr().cast::<__m128i>(),
        );
        for pair in 0..dst.len() / 2 {
            // SAFETY: both slices hold `2 * (pair + 1)` words or more, so
            // the read and the write are inside them; the read is
            // unaligned, and `dst` is aligned to 16 bytes as the store
            // requires. SSE2 is part of every x86-64 processor.
            unsafe { _mm_stream_si128(to.add(pair), _mm_loadu_si128(from.add(pair))) };
        }
        return;
    }
    dst.copy_from_slice(src);
}

/// Makes what this thread wrote with [`copy_out`] visible to every other
/// reader of that memory.
fn copied_out() {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SSE is part of every x86-64 processor.
    unsafe {
        core::arch::x86_64::_mm_sfence()
    };
}

/// A polynomial's numbers of stored coefficients and of the runs they are
/// in.
#[derive(Clone, Copy, Default)]
struct Shape {
    terms: usize,
    runs: usize,
}

/// The Montgomery limbs of a run of field elements, four words each, as they
/// lie in memory: what [`PastaField::montgomery_limbs`] returns for each in
/// turn.
fn limbs_of<M: PrimeModulus>(run: &[PastaField<M>]) -> &[u64] {
    const { assert!(size_of::<PastaField<M>>() == 4 * size_of::<u64>()) };
    const { assert!(align_of::<PastaField<M>>() == align_of::<u64>()) };
    // SAFETY: a `PastaField` is `repr(transparent)` over its four limbs, so
    // a run of them is four times as many words, at the same address and
    // with the same alignment, for as long as the run is borrowed.
    unsafe { core::slice::from_raw_parts(run.as_ptr().cast::<u64>(), 4 * run.len()) }
}

impl<M: DeviceField, F, R> Drop for Store<M, F, R> {
    fn drop(&mut self) {
        // The next caller's slots are these: nothing may still be written
        // to them behind its back.
        if let Some(later) = self.later.take() {
            later.wait();
        }
        if self.apart.take().is_some() {
            // SAFETY: the call takes no pointers.
            unsafe { ragu_gpu_poly_join(M::ID) };
        }
        STORE_BUSY[M::ID as usize].store(false, Ordering::Release);
    }
}

impl<M: DeviceField, F: Field, R: Rank> Store<M, F, R> {
    fn open() -> Option<Self> {
        if STORE_BUSY[M::ID as usize].swap(true, Ordering::AcqRel) {
            return None;
        }
        // From here the store is released when `store` is dropped.
        let store = Self {
            next: 0,
            apart: None,
            later: None,
            _marker: PhantomData,
        };
        // SAFETY: the call takes no pointers.
        let status = unsafe { ragu_gpu_poly_init(M::ID, R::num_coeffs(), STORE_SLOTS) };
        (status == 0).then_some(store)
    }

    fn take(&mut self, count: usize) -> Vec<u32> {
        let first = self.next as usize;
        assert!(first + count <= STORE_SLOTS, "the device store is full");
        self.next = (first + count) as u32;
        (first..first + count).map(|slot| slot as u32).collect()
    }

    /// Stores each polynomial in a new slot; with `apart`, on the stream the
    /// engine keeps for uploads its other work does not wait for.
    fn upload_on(&mut self, polys: &[&sparse::Polynomial<F, R>], apart: bool) -> Vec<Slot> {
        let Some((slots, shapes)) = self.take_for(polys, apart) else {
            return Vec::new();
        };
        Self::send(polys, &slots, &shapes, apart);
        slots.into_iter().map(Slot).collect()
    }

    /// Takes a slot for each polynomial of an upload, on the store's own
    /// stream or apart: the slots, and each polynomial's numbers of terms
    /// and of runs. `None` for no polynomials.
    fn take_for(
        &mut self,
        polys: &[&sparse::Polynomial<F, R>],
        apart: bool,
    ) -> Option<(Vec<u32>, Vec<Shape>)> {
        // The engine takes in one upload apart at a time.
        if apart && let Some(later) = &self.later {
            later.wait();
        }
        let slots = self.take(polys.len());
        if slots.is_empty() {
            return None;
        }
        let shapes: Vec<Shape> = polys
            .iter()
            .map(|poly| {
                poly.blocks()
                    .fold(Shape::default(), |shape, (_, run)| Shape {
                        terms: shape.terms + run.len(),
                        runs: shape.runs + 1,
                    })
            })
            .collect();
        if apart && let (Some(first), Some(last)) = (slots.first(), slots.last()) {
            // Slots are taken in a row, so the uploads taken in apart and
            // not read yet are one range.
            let start = self.apart.as_ref().map_or(*first, |apart| apart.start);
            self.apart = Some(start..last + 1);
        }
        Some((slots, shapes))
    }

    /// Stores the polynomials in the slots [`take_for`](Self::take_for)
    /// took for them. An upload taken in apart goes a piece at a time: the
    /// engine copies one piece to the device while the next is laid out, so
    /// a large upload is on the device soon after its last piece is laid
    /// out, not a whole transfer later.
    fn send(polys: &[&sparse::Polynomial<F, R>], slots: &[u32], shapes: &[Shape], apart: bool) {
        /// About the terms of a piece: a few megabytes.
        const PIECE: usize = 1 << 16;

        let mut first = 0;
        while first < polys.len() {
            let mut last = first;
            let mut piece = Shape::default();
            while last < polys.len()
                && (last == first || !apart || piece.terms + shapes[last].terms <= PIECE)
            {
                piece.terms += shapes[last].terms;
                piece.runs += shapes[last].runs;
                last += 1;
            }
            // The engine's layout: a word per run and one more, padded to
            // four words, then four limbs per term, then the slots.
            let words = run_words(piece.runs) + 4 * piece.terms + (last - first).div_ceil(2);
            let mut buffer = core::ptr::null_mut();
            // SAFETY: `buffer` receives the pointer.
            checked(unsafe {
                ragu_gpu_poly_upload_buffer(M::ID, words, &mut buffer, c_int::from(apart))
            });
            Self::lay_out(
                Staging(buffer, words),
                &polys[first..last],
                &slots[first..last],
                &shapes[first..last],
                apart,
            );
            first = last;
        }
    }

    /// Lays the polynomials out in `staging`, the engine's buffer for this
    /// upload, each in its slot of `slots` and with the shape in `shapes`,
    /// and hands the upload to the engine.
    ///
    /// A polynomial holds its coefficients in runs, and the engine takes
    /// them so: each run is copied whole, limbs as they lie in memory, and
    /// costs one word saying where it goes.
    fn lay_out(
        staging: Staging,
        polys: &[&sparse::Polynomial<F, R>],
        slots: &[u32],
        shapes: &[Shape],
        apart: bool,
    ) {
        let n = R::num_coeffs();
        let terms: usize = shapes.iter().map(|shape| shape.terms).sum();
        let runs: usize = shapes.iter().map(|shape| shape.runs).sum();
        let Staging(buffer, words) = staging;
        // SAFETY: the engine returned a buffer of at least `words` words that
        // stays valid, and that nothing else reads or writes, until its
        // store asks for it again; the store has one caller, which does not
        // ask before this has returned. Words have no invalid values.
        let buffer = unsafe { core::slice::from_raw_parts_mut(buffer, words) };
        let (run_words, rest) = buffer.split_at_mut(run_words(runs));
        let (limbs, slot_words) = rest.split_at_mut(4 * terms);

        // Each polynomial's runs have their own stretch of the run words and
        // of the limbs, so the polynomials are laid out independently.
        let (run_words, last_words) = run_words.split_at_mut(runs);
        last_words.fill((terms as u64) << 32);
        let mut jobs = Vec::with_capacity(polys.len());
        let (mut run_words, mut limbs) = (run_words, limbs);
        let mut before = 0usize;
        for ((poly, slot), shape) in polys.iter().zip(slots).zip(shapes) {
            let (own_runs, later) = run_words.split_at_mut(shape.runs);
            let (own_limbs, later_limbs) = limbs.split_at_mut(4 * shape.terms);
            (run_words, limbs) = (later, later_limbs);
            jobs.push((*poly, *slot, before, own_runs, own_limbs));
            before += shape.terms;
        }
        type Job<'a, F, R> = (
            &'a sparse::Polynomial<F, R>,
            u32,
            usize,
            &'a mut [u64],
            &'a mut [u64],
        );
        let lay = |(poly, slot, before, run_words, limbs): &mut Job<'_, F, R>| {
            let mut limbs = &mut **limbs;
            let mut before = *before;
            for ((start, run), word) in poly.blocks().zip(run_words.iter_mut()) {
                let position = *slot as usize * n + start;
                *word = position as u64 | (before as u64) << 32;
                let (own, later) = core::mem::take(&mut limbs).split_at_mut(4 * run.len());
                copy_out(own, limbs_of(Self::elements(run)));
                limbs = later;
                before += run.len();
            }
            copied_out();
        };
        if apart {
            // An upload taken in apart is laid out beside other work, and
            // copying is bounded by memory, not by the threads at it: one
            // thread does it as soon as many, and leaves the rest to the
            // work it runs beside.
            jobs.iter_mut().for_each(lay);
        } else {
            crate::verifier::for_each_mut(&mut jobs, |_, job| lay(job));
        }
        for (word, pair) in slot_words.iter_mut().zip(slots.chunks(2)) {
            *word = u64::from(pair[0]) | u64::from(pair.get(1).copied().unwrap_or(0)) << 32;
        }

        // SAFETY: the buffer holds the layout above, and every run is inside
        // a slot the store took for this upload.
        checked(unsafe {
            ragu_gpu_poly_upload_staged(M::ID, slots.len(), runs, terms, c_int::from(apart))
        });
    }

    /// Makes the store's calls wait for the uploads taken in apart, if one
    /// of `slots` is theirs: to be called before a call that reads `slots`.
    fn reads(&mut self, slots: impl IntoIterator<Item = u32>) {
        let theirs = self
            .apart
            .as_ref()
            .is_some_and(|apart| slots.into_iter().any(|slot| apart.contains(&slot)));
        if theirs {
            // An upload left to the caller is first waited for.
            if let Some(later) = self.later.take() {
                assert!(later.wait(), "an upload was read whose work was not run");
            }
            // SAFETY: the call takes no pointers.
            checked(unsafe { ragu_gpu_poly_join(M::ID) });
            self.apart = None;
        }
    }

    /// Views a run of `F` as the Pasta elements it is.
    fn elements(run: &[F]) -> &[PastaField<M>] {
        pasta_elements(run).expect("the store's field")
    }

    fn limbs(value: &F) -> [u64; 4] {
        (value as &dyn Any)
            .downcast_ref::<FieldAdapter<M>>()
            .expect("the store's field")
            .as_inner()
            .montgomery_limbs()
    }

    fn element(limbs: &[u64]) -> F {
        let value = FieldAdapter::new(PastaField::<M>::from_montgomery_limbs([
            limbs[0], limbs[1], limbs[2], limbs[3],
        ]));
        *(&value as &dyn Any)
            .downcast_ref::<F>()
            .expect("the store's field")
    }

    /// The polynomials of `count` slots that the engine read back to
    /// `view`, `4n` limbs each: converted where the device's copy landed,
    /// with no copy between.
    ///
    /// # Safety
    ///
    /// `view` is what the engine's last call on this field's store gave for
    /// `count` slots, and the store has made no call since.
    unsafe fn read_back(view: *const u64, count: usize) -> Vec<sparse::Polynomial<F, R>> {
        let n = R::num_coeffs();
        // SAFETY: the engine left `4n` words per slot at `view`, which stay
        // as they are until the store's next call.
        let limbs = unsafe { core::slice::from_raw_parts(view, 4 * n * count) };
        limbs
            .chunks_exact(4 * n)
            .map(|poly| {
                let coeffs: Vec<FieldAdapter<M>> = poly
                    .chunks_exact(4)
                    .map(|limbs| {
                        FieldAdapter::new(PastaField::<M>::from_montgomery_limbs([
                            limbs[0], limbs[1], limbs[2], limbs[3],
                        ]))
                    })
                    .collect();
                let coeffs: Box<dyn Any> = Box::new(coeffs);
                sparse::Polynomial::from_coeffs(
                    *coeffs.downcast::<Vec<F>>().expect("the store's field"),
                )
            })
            .collect()
    }
}

fn checked(status: c_int) {
    assert_eq!(status, 0, "the device failed during a polynomial operation");
}

impl<M: DeviceField, F: Field, R: Rank> PolyDevice<F, R> for Store<M, F, R> {
    fn upload(&mut self, polys: &[&sparse::Polynomial<F, R>]) -> Vec<Slot> {
        self.upload_on(polys, false)
    }

    fn upload_apart(&mut self, polys: &[&sparse::Polynomial<F, R>]) -> Vec<Slot> {
        self.upload_on(polys, true)
    }

    fn upload_later<'a>(
        &mut self,
        polys: &[&'a sparse::Polynomial<F, R>],
    ) -> (Vec<Slot>, Option<ragu_backend::Later<'a>>) {
        let Some((slots, shapes)) = self.take_for(polys, true) else {
            return (Vec::new(), None);
        };
        let laid = Arc::new(Laid::default());
        self.later = Some(laid.clone());
        let handed = slots.iter().copied().map(Slot).collect();
        let polys = polys.to_vec();
        let work: ragu_backend::Later<'a> = Box::new(move || {
            let mut laying = Laying(laid, false);
            Self::send(&polys, &slots, &shapes, true);
            laying.1 = true;
        });
        (handed, Some(work))
    }

    fn powers(&mut self, z: F) -> Slot {
        let slot = self.take(1)[0];
        let z = Self::limbs(&z);
        // SAFETY: `z` holds four words.
        checked(unsafe { ragu_gpu_poly_powers(M::ID, slot, z.as_ptr()) });
        Slot(slot)
    }

    fn lincomb(&mut self, jobs: &[Vec<(F, Slot)>]) -> Vec<Slot> {
        self.reads(jobs.iter().flatten().map(|(_, slot)| slot.0));
        let dst = self.take(jobs.len());
        let mut offsets = Vec::with_capacity(jobs.len() + 1);
        let mut srcs = Vec::new();
        let mut scalars = Vec::new();
        offsets.push(0u32);
        for job in jobs {
            for (scalar, slot) in job {
                srcs.push(slot.0);
                scalars.extend_from_slice(&Self::limbs(scalar));
            }
            offsets.push(srcs.len() as u32);
        }
        // SAFETY: `dst` has one slot per job, `offsets` one entry more,
        // ending at the term count, and `srcs` and `scalars` hold that many
        // terms. A destination is a new slot, so it is not among its sources.
        checked(unsafe {
            ragu_gpu_poly_lincomb(
                M::ID,
                jobs.len(),
                dst.as_ptr(),
                offsets.as_ptr(),
                srcs.as_ptr(),
                scalars.as_ptr(),
            )
        });
        dst.into_iter().map(Slot).collect()
    }

    fn dilate_add(&mut self, jobs: &[(Slot, Slot)], powers: Slot, t: Slot) -> Vec<Slot> {
        self.reads(
            jobs.iter()
                .flat_map(|(a, s)| [a.0, s.0])
                .chain([powers.0, t.0]),
        );
        let dst = self.take(jobs.len());
        let a: Vec<u32> = jobs.iter().map(|(a, _)| a.0).collect();
        let s: Vec<u32> = jobs.iter().map(|(_, s)| s.0).collect();
        // SAFETY: the three arrays have one slot per job.
        checked(unsafe {
            ragu_gpu_poly_dilate_add(
                M::ID,
                jobs.len(),
                dst.as_ptr(),
                a.as_ptr(),
                s.as_ptr(),
                powers.0,
                t.0,
            )
        });
        dst.into_iter().map(Slot).collect()
    }

    fn revdot(&mut self, pairs: &[(Slot, Slot)]) -> Vec<F> {
        self.products(pairs, true)
    }

    fn dot(&mut self, pairs: &[(Slot, Slot)]) -> Vec<F> {
        self.products(pairs, false)
    }

    fn quotients(&mut self, jobs: &[(F, Vec<(F, Slot)>)]) -> Slot {
        let dst = self.take(1)[0];
        // Each job's combination goes to a slot of its own, which is divided
        // in place and given back once the quotients are summed.
        let combinations: Vec<Vec<(F, Slot)>> =
            jobs.iter().map(|(_, terms)| terms.clone()).collect();
        let dividends: Vec<u32> = self
            .lincomb(&combinations)
            .into_iter()
            .map(|slot| slot.0)
            .collect();
        let points: Vec<u64> = jobs
            .iter()
            .flat_map(|(point, _)| Self::limbs(point))
            .collect();
        // SAFETY: `dividends` has one slot per job and `points` four words.
        checked(unsafe {
            ragu_gpu_poly_quotients(M::ID, jobs.len(), dst, dividends.as_ptr(), points.as_ptr())
        });
        // The dividends were the last slots taken.
        self.next -= dividends.len() as u32;
        Slot(dst)
    }

    fn download(&mut self, slots: &[Slot]) -> Vec<sparse::Polynomial<F, R>> {
        self.reads(slots.iter().map(|slot| slot.0));
        let slots: Vec<u32> = slots.iter().map(|slot| slot.0).collect();
        let mut view = core::ptr::null();
        // SAFETY: `slots` has the stated length and `view` receives where
        // the slots were read back to.
        checked(unsafe {
            ragu_gpu_poly_download_view(M::ID, slots.len(), slots.as_ptr(), &mut view)
        });
        // SAFETY: the engine read the slots back to `view` in the call
        // above, the store's last.
        unsafe { Self::read_back(view, slots.len()) }
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn wiring_y(&mut self, registry: &Registry<'_, F, R>, y: F) -> Option<Vec<Option<Slot>>> {
        self.restrict(registry, y, |registered| registered.by_x)
    }

    fn wiring_x(&mut self, registry: &Registry<'_, F, R>, x: F) -> Option<Vec<Option<Slot>>> {
        self.restrict(registry, x, |registered| registered.by_y)
    }
}

/// The longest sum of matrix terms one device thread computes.
const WIRING_CHUNK: usize = 64;

/// A registry's wiring matrices on the device, laid out both ways.
#[derive(Clone)]
struct Registered {
    /// The matrix by degree of $X$, which the powers of $y$ restrict.
    by_x: c_int,
    /// The matrix by constraint, which the powers of $x$ restrict.
    by_y: c_int,
    /// For each circuit of the registry, its position among those with a
    /// matrix.
    positions: Vec<Option<u32>>,
}

/// A registry the device was asked about.
struct Wiring {
    field: c_int,
    /// The registry's address, circuit count and tag, which tell it apart
    /// from any other registry alive with it.
    address: usize,
    circuits: usize,
    tag: [u64; 4],
    /// `None` if registration failed; the registry is then restricted on
    /// the host.
    registered: Option<Registered>,
}

static WIRINGS: Mutex<Vec<Wiring>> = Mutex::new(Vec::new());

impl<M: DeviceField, F: Field, R: Rank> Store<M, F, R> {
    /// Lays the matrices out for the engine and registers them: by degree
    /// of $X$ with the constraint as each term's power, or with `by_y` by
    /// constraint with the degree as the power.
    ///
    /// A circuit's coefficients are few distinct values (ones, small
    /// constants and their negations make up nearly all of them), so a
    /// column's terms are grouped by coefficient and each chunk holds terms
    /// of one: the device then multiplies once per chunk, not once per term.
    fn register(matrices: &[Option<Matrix<F>>], by_y: bool) -> Option<c_int> {
        let n = R::num_coeffs();
        let mut column_chunks = Vec::new();
        let mut chunk_terms = Vec::new();
        let mut chunk_values = Vec::new();
        let mut powers = Vec::new();
        // The distinct coefficients and each one's place among them.
        let mut places = BTreeMap::new();
        let mut values = Vec::new();
        let mut held = 0usize;
        let mut whole = true;
        for matrix in matrices.iter().flatten() {
            held += 1;
            // Every term as its column, its coefficient's place and its
            // power; sorted, a column's terms of one coefficient are
            // together.
            let mut terms: Vec<(u32, u32, u32)> = matrix
                .terms()
                .map(|(row, degree, value)| {
                    let next = places.len() as u32;
                    let place = *places
                        .entry(Self::limbs(value))
                        .or_insert_with_key(|limbs| {
                            values.extend_from_slice(limbs);
                            next
                        });
                    match by_y {
                        false => (degree, place, row),
                        true => (row, place, degree),
                    }
                })
                .collect();
            terms.sort_unstable();
            let mut rest = terms.as_slice();
            for column in 0..n as u32 {
                column_chunks.push(chunk_terms.len() as u32);
                while let Some(&(_, place, _)) = rest.first().filter(|term| term.0 == column) {
                    let run = rest
                        .iter()
                        .take(WIRING_CHUNK)
                        .take_while(|term| term.0 == column && term.1 == place)
                        .count();
                    chunk_terms.push(powers.len() as u32);
                    chunk_values.push(place);
                    powers.extend(rest[..run].iter().map(|term| term.2));
                    rest = &rest[run..];
                }
            }
            // A term beyond the last column would have no chunk.
            whole &= rest.is_empty();
        }
        column_chunks.push(chunk_terms.len() as u32);
        let chunks = chunk_terms.len();
        chunk_terms.push(powers.len() as u32);

        (whole && held > 0 && chunks > 0 && u32::try_from(powers.len()).is_ok())
            // SAFETY: the arrays have the lengths the engine reads:
            // `held * n + 1` column offsets ending at `chunks`, `chunks + 1`
            // chunk offsets ending at the term count, one coefficient place
            // per chunk, one power per term, and four words per distinct
            // coefficient.
            .then(|| unsafe {
                ragu_gpu_wiring_register(
                    M::ID,
                    n,
                    held,
                    column_chunks.as_ptr(),
                    chunks,
                    chunk_terms.as_ptr(),
                    chunk_values.as_ptr(),
                    powers.len(),
                    powers.as_ptr(),
                    values.as_ptr(),
                    values.len() / 4,
                )
            })
            .filter(|handle| *handle >= 0)
    }

    /// Returns the device matrices of `registry`, extracting and uploading
    /// them on first use.
    fn wiring(registry: &Registry<'_, F, R>) -> Option<Registered> {
        let address = core::ptr::from_ref(registry) as usize;
        let (circuits, tag) = registry.wiring_key();
        let tag = Self::limbs(&tag);
        let mut wirings = WIRINGS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(known) = wirings.iter().find(|known| {
            known.field == M::ID
                && known.address == address
                && known.circuits == circuits
                && known.tag == tag
        }) {
            return known.registered.clone();
        }

        let matrices = registry.wiring_matrices();
        let mut held = 0u32;
        let positions = matrices
            .iter()
            .map(|matrix| {
                matrix.as_ref().map(|_| {
                    held += 1;
                    held - 1
                })
            })
            .collect();
        let registered = Self::register(&matrices, false).and_then(|by_x| {
            Some(Registered {
                by_x,
                by_y: Self::register(&matrices, true)?,
                positions,
            })
        });
        wirings.push(Wiring {
            field: M::ID,
            address,
            circuits,
            tag,
            registered: registered.clone(),
        });
        registered
    }

    /// Restricts every held circuit of `registry` with the powers of
    /// `point`, through the matrix `select` picks.
    fn restrict(
        &mut self,
        registry: &Registry<'_, F, R>,
        point: F,
        select: impl Fn(&Registered) -> c_int,
    ) -> Option<Vec<Option<Slot>>> {
        let registered = Self::wiring(registry)?;
        let held = registered.positions.iter().flatten().count();
        let powers = self.powers(point);
        // One slot for each circuit the matrix holds, in a row. The engine
        // queues the request: a later call that reads the store waits for it.
        let dst = self.take(held);
        // SAFETY: the engine checks the slots against its store.
        checked(unsafe {
            ragu_gpu_wiring_sy(
                select(&registered),
                powers.0,
                dst.first().copied().unwrap_or(0),
            )
        });
        Some(
            registered
                .positions
                .iter()
                .map(|position| position.map(|position| Slot(dst[position as usize])))
                .collect(),
        )
    }

    fn products(&mut self, pairs: &[(Slot, Slot)], reversed: bool) -> Vec<F> {
        self.reads(pairs.iter().flat_map(|(a, b)| [a.0, b.0]));
        let a: Vec<u32> = pairs.iter().map(|(a, _)| a.0).collect();
        let b: Vec<u32> = pairs.iter().map(|(_, b)| b.0).collect();
        let mut out = vec![0u64; 4 * pairs.len()];
        // SAFETY: `a` and `b` have one slot per pair and `out` four words.
        checked(unsafe {
            ragu_gpu_poly_revdot(
                M::ID,
                pairs.len(),
                a.as_ptr(),
                b.as_ptr(),
                c_int::from(reversed),
                out.as_mut_ptr(),
            )
        });
        out.chunks_exact(4).map(Self::element).collect()
    }
}

/// Opens the polynomial store of `F`, or returns `None` if the device is not
/// used for this field and rank or the store is in use.
pub(crate) fn poly_device<F: Field, R: Rank>() -> Option<Box<dyn PolyDevice<F, R>>> {
    if !enabled() {
        return None;
    }
    let field = TypeId::of::<F>();
    if field == TypeId::of::<FieldAdapter<PallasBase>>() {
        Some(Box::new(Store::<PallasBase, F, R>::open()?))
    } else if field == TypeId::of::<FieldAdapter<PallasScalar>>() {
        Some(Box::new(Store::<PallasScalar, F, R>::open()?))
    } else {
        None
    }
}
