//! # `ragu_backend`
//!
//! Computational backend interfaces for Ragu.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::fmt::Debug;

use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryAt},
};
use ragu_core::FixedGenerators;
use udon::{curve::Affine, fft::Domain, field::Field};

/// Commitments a backend has begun computing behind its caller, as
/// [`Backend::sparse_commit_many_start`] returns them.
///
/// Dropping one gives the commitments up.
pub trait StartedCommitments<T>: Send {
    /// Whether [`finish`](Self::finish) would return without waiting.
    fn ready(&mut self) -> bool;

    /// Waits for the commitments and returns them in the order of the
    /// polynomials, or returns `None` if the backend could not complete
    /// them; the caller then commits through
    /// [`Backend::sparse_commit_many`].
    fn finish(self: Box<Self>) -> Option<Vec<T>>;
}

/// Work a [`PolyDevice`] has left for its caller to run: see
/// [`PolyDevice::upload_later`].
pub type Later<'a> = Box<dyn FnOnce() + Send + 'a>;

/// A polynomial held by a [`PolyDevice`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot(pub u32);

/// Whole-polynomial arithmetic on a device that keeps the polynomials.
///
/// A prover that combines many polynomials and needs only a few scalars and
/// a few combined polynomials back can hold the operands here instead of
/// computing every intermediate on the host. Each method names the host
/// computation it stands for, on polynomials as dense coefficient vectors of
/// length [`Rank::num_coeffs`].
///
/// # Correctness
///
/// Every result must be exactly the field elements of that host computation.
///
/// # Panics
///
/// A device that fails after [`Backend::poly_device`] returned it has no
/// host fallback, and its methods panic.
pub trait PolyDevice<F: Field, R: Rank>: Send {
    /// The device as a value of its own type, by which the backend that
    /// opened it recognises it in [`Backend::device_commit`].
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any;

    /// Stores each polynomial in a new slot.
    fn upload(&mut self, polys: &[&sparse::Polynomial<F, R>]) -> Vec<Slot>;

    /// [`upload`](Self::upload) for polynomials the caller does not need at
    /// once: a device may take them in apart from the work it is asked for
    /// meanwhile, which then does not wait for them. Every method sees them
    /// stored from the first that reads one of them on.
    fn upload_apart(&mut self, polys: &[&sparse::Polynomial<F, R>]) -> Vec<Slot> {
        self.upload(polys)
    }

    /// Gives each polynomial a new slot now, and returns with the slots the
    /// work that stores the polynomials, if the device leaves that to its
    /// caller: to be run once, when and where the caller likes, also on
    /// another thread while this device is used for other things. Every
    /// method sees the polynomials stored from the first that reads one of
    /// them on, and waits for the work to have run if it has not yet.
    ///
    /// The default stores them before it returns, and leaves no work.
    ///
    /// # Panics
    ///
    /// A method that reads one of the slots panics if the work was dropped
    /// without being run.
    fn upload_later<'a>(
        &mut self,
        polys: &[&'a sparse::Polynomial<F, R>],
    ) -> (Vec<Slot>, Option<Later<'a>>) {
        (self.upload_apart(polys), None)
    }

    /// A new slot whose coefficient of degree $k$ is $z^k$.
    fn powers(&mut self, z: F) -> Slot;

    /// For each job, a new slot holding the sum of `scalar * polynomial`
    /// over its terms.
    fn lincomb(&mut self, jobs: &[Vec<(F, Slot)>]) -> Vec<Slot>;

    /// For each `(a, s)`, a new slot whose coefficient of degree $k$ is
    /// `a[k] * powers[k] + s[k] + t[k]`: with `powers` from
    /// [`powers`](Self::powers), the dilation of `a` as
    /// [`sparse::Polynomial::dilate`] computes it, plus `s` and `t`.
    fn dilate_add(&mut self, jobs: &[(Slot, Slot)], powers: Slot, t: Slot) -> Vec<Slot>;

    /// [`sparse::Polynomial::revdot`] of each pair.
    fn revdot(&mut self, pairs: &[(Slot, Slot)]) -> Vec<F>;

    /// The sum over $k$ of `a[k] * b[k]` for each pair. With `b` from
    /// [`powers`](Self::powers) of a point, this is `a` evaluated there,
    /// as [`sparse::Polynomial::eval`] computes it.
    fn dot(&mut self, pairs: &[(Slot, Slot)]) -> Vec<F>;

    /// A new slot holding the sum over the jobs `(point, terms)` of the
    /// quotient of the job's combination, the sum of `scalar * polynomial`
    /// over its terms, by $X - \text{point}$, with the remainder dropped:
    /// the quotient's coefficient of degree $k$ is the sum over $j > k$ of
    /// the combination's coefficient of degree $j$ times
    /// $\text{point}^{j - k - 1}$.
    fn quotients(&mut self, jobs: &[(F, Vec<(F, Slot)>)]) -> Slot;

    /// Reads polynomials back.
    fn download(&mut self, slots: &[Slot]) -> Vec<sparse::Polynomial<F, R>>;

    /// Evaluates the wiring matrices of `registry` at `y`: for the circuit
    /// at each position of [`Registry::wiring_matrices`] that has a matrix,
    /// a new slot holding $s_i(X, y)$. Returns `None` if the device does
    /// not hold wiring matrices, as the default does not; the caller then
    /// restricts every circuit on the host.
    ///
    /// A device may return before the slots are filled, as long as every
    /// later method sees them filled: a caller with other work can ask for
    /// the evaluation ahead of the moment it needs it.
    fn wiring_y(&mut self, registry: &Registry<'_, F, R>, y: F) -> Option<Vec<Option<Slot>>> {
        let _ = (registry, y);
        None
    }

    /// As [`wiring_y`](Self::wiring_y) for the other variable: a new slot
    /// holding $s_i(x, Y)$ for each circuit with a matrix.
    fn wiring_x(&mut self, registry: &Registry<'_, F, R>, x: F) -> Option<Vec<Option<Slot>>> {
        let _ = (registry, x);
        None
    }
}

/// A statically dispatched implementation of Ragu's computational operations.
///
/// Every method has a correctness-first default. Implementations may override
/// individual methods, but must return exactly the same result as the default
/// implementation for the same inputs.
/// Canonical circuit and protocol data is constructed before it reaches these
/// methods; a backend only changes how the requested computation is performed.
/// Implementing this low-level trait does not make a downstream type selectable
/// by `ragu_pcd`; application execution is restricted to Ragu-owned backends.
///
/// Backends are currently selected by type and cannot carry per-application
/// state. If implementations need device handles or caches, Ragu can store the
/// selected backend as a value while retaining static dispatch.
pub trait Backend: Clone + Copy + Debug + Default + Send + Sync + 'static {
    /// Evaluates a sparse polynomial at `point`.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`sparse::Polynomial::eval`] exactly.
    fn sparse_eval<F: Field, R: Rank>(poly: &sparse::Polynomial<F, R>, point: F) -> F {
        poly.eval(point)
    }

    /// Computes the reverse inner product of two sparse polynomials.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`sparse::Polynomial::revdot`] exactly.
    fn sparse_revdot<F: Field, R: Rank>(
        lhs: &sparse::Polynomial<F, R>,
        rhs: &sparse::Polynomial<F, R>,
    ) -> F {
        lhs.revdot(rhs)
    }

    /// Commits to a sparse polynomial in projective form.
    ///
    /// The correctness-first implementation dispatches its MSM through
    /// [`Backend::msm`], so overriding MSM also accelerates polynomial
    /// commitments.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`sparse::Polynomial::commit`] exactly.
    fn sparse_commit<F: Field, C: Affine<Scalar = F>, R: Rank, G: FixedGenerators<C>>(
        poly: &sparse::Polynomial<F, R>,
        generators: &G,
    ) -> C::Projective {
        assert!(generators.g().len() >= R::num_coeffs());
        let bases = generators.g();

        Self::msm(
            poly.iter_stored_coeffs()
                .map(|(_, coefficient)| coefficient),
            poly.iter_stored_coeffs().map(|(index, _)| &bases[index]),
        )
    }

    /// Commits to independent sparse polynomials, returning results in input order.
    ///
    /// The default hands each polynomial's stored coefficients and matching
    /// generators to [`Self::msm_batch`], whose default performs each MSM
    /// separately and retains [`Self::msm`] overrides. It does not call
    /// [`Self::sparse_commit`], so overriding that method alone leaves batched
    /// commitments unchanged.
    ///
    /// # Correctness
    ///
    /// Each output must match [`sparse::Polynomial::commit`] exactly.
    fn sparse_commit_batch<C: Affine, R: Rank, G: FixedGenerators<C>, const N: usize>(
        polys: [&sparse::Polynomial<C::Scalar, R>; N],
        generators: &G,
    ) -> [C::Projective; N] {
        let bases = generators.g();
        assert!(bases.len() >= R::num_coeffs());
        Self::msm_batch(polys.map(|poly| {
            (
                poly.iter_stored_coeffs()
                    .map(|(_, coefficient)| coefficient),
                poly.iter_stored_coeffs().map(|(index, _)| &bases[index]),
            )
        }))
    }

    /// Commits to any number of independent sparse polynomials, returning
    /// results in input order.
    ///
    /// The default commits to each polynomial through
    /// [`Self::sparse_commit`], retaining its overrides. Backends may
    /// override this method to schedule the commitments together.
    ///
    /// # Correctness
    ///
    /// Each output must match [`sparse::Polynomial::commit`] exactly.
    fn sparse_commit_many<C: Affine, R: Rank, G: FixedGenerators<C>>(
        polys: &[&sparse::Polynomial<C::Scalar, R>],
        generators: &G,
    ) -> Vec<C::Projective> {
        polys
            .iter()
            .map(|poly| Self::sparse_commit(poly, generators))
            .collect()
    }

    /// Commits to the polynomials `device` holds in `slots` and reads them
    /// back, where the backend can do both without the polynomials leaving
    /// the device to be committed to. Returns `None` where it cannot, as the
    /// default does; the caller then downloads the slots and commits.
    ///
    /// # Correctness
    ///
    /// The polynomials must be what [`PolyDevice::download`] returns for
    /// `slots`, and the commitments must match
    /// [`sparse_commit_many`](Self::sparse_commit_many) on them exactly.
    #[allow(clippy::type_complexity)]
    fn device_commit<C: Affine, R: Rank, G: FixedGenerators<C>>(
        device: &mut dyn PolyDevice<C::Scalar, R>,
        slots: &[Slot],
        generators: &G,
    ) -> Option<(Vec<sparse::Polynomial<C::Scalar, R>>, Vec<C::Projective>)> {
        let _ = (device, slots, generators);
        None
    }

    /// Begins [`sparse_commit_many`](Self::sparse_commit_many) and returns
    /// without waiting for the commitments, where the backend computes them
    /// somewhere other than on the calling thread. Returns `None` where it
    /// does not, as the default does; the caller then calls
    /// `sparse_commit_many` when it wants them.
    ///
    /// # Correctness
    ///
    /// What [`StartedCommitments::finish`] returns must match
    /// `sparse_commit_many` on the same polynomials exactly.
    fn sparse_commit_many_start<C: Affine, R: Rank, G: FixedGenerators<C>>(
        polys: &[&sparse::Polynomial<C::Scalar, R>],
        generators: &G,
    ) -> Option<Box<dyn StartedCommitments<C::Projective>>> {
        let _ = (polys, generators);
        None
    }

    /// Commits to a sparse polynomial and normalizes the result to affine.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`sparse::Polynomial::commit_to_affine`] exactly.
    fn sparse_commit_to_affine<F: Field, C: Affine<Scalar = F>, R: Rank, G: FixedGenerators<C>>(
        poly: &sparse::Polynomial<F, R>,
        generators: &G,
    ) -> C {
        Self::sparse_commit(poly, generators).into()
    }

    /// Computes the registry restriction $m(W, x, y)$.
    ///
    /// Callers that also need the $W$-domain evaluations can reach for
    /// [`registry_wxy_over_domain`](Self::registry_wxy_over_domain) and
    /// [`registry_interpolate_xy`](Self::registry_interpolate_xy) directly,
    /// sharing a single per-circuit pass between the two representations.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`Registry::xy`] exactly.
    fn registry_xy<F: Field, R: Rank>(
        registry: &Registry<'_, F, R>,
        x: F,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        Self::registry_interpolate_xy(registry, Self::registry_wxy_over_domain(registry, x, y))
    }

    /// Evaluates the registry polynomial over its $W$-domain at $X = x$,
    /// $Y = y$.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`Registry::wxy_over_domain`] exactly.
    fn registry_wxy_over_domain<F: Field, R: Rank>(
        registry: &Registry<'_, F, R>,
        x: F,
        y: F,
    ) -> Vec<F> {
        registry.wxy_over_domain(x, y)
    }

    /// Interpolates $W$-domain evaluations into the monomial-basis polynomial
    /// $m(W, x, y)$.
    ///
    /// The default dispatches the inverse transform through [`Backend::ifft`].
    ///
    /// # Correctness
    ///
    /// Overrides must match [`Registry::interpolate_xy`] exactly.
    fn registry_interpolate_xy<F: Field, R: Rank>(
        registry: &Registry<'_, F, R>,
        evals: Vec<F>,
    ) -> sparse::Polynomial<F, R> {
        registry.interpolate_xy_with(evals, Self::ifft)
    }

    /// Computes the circuit restriction $s_i(X, y)$ selected by `circuit`.
    fn registry_circuit_y<F: Field, R: Rank>(
        registry: &Registry<'_, F, R>,
        circuit: CircuitIndex,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        registry.circuit_y(circuit, y)
    }

    /// Computes the registry restriction $m(w, x, Y)$.
    fn registry_at_x<F: Field, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        x: F,
    ) -> sparse::Polynomial<F, R> {
        registry.x(x)
    }

    /// Computes the registry restriction $m(w, X, y)$.
    fn registry_at_y<F: Field, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        registry.y(y)
    }

    /// Evaluates the registry polynomial at $(w, x, y)$.
    fn registry_wxy<F: Field, R: Rank>(registry: &Registry<'_, F, R>, w: F, x: F, y: F) -> F {
        registry.wxy(w, x, y)
    }

    /// Transforms natural-order coefficients into natural-order domain evaluations.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`ragu_core::fft`] exactly, including rejecting an
    /// input whose length differs from the domain size before mutating it.
    fn fft<F: Field>(domain: Domain<F>, values: &mut Vec<F>) {
        ragu_core::fft(domain, values);
    }

    /// Transforms natural-order domain evaluations into normalized coefficients.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`ragu_core::ifft`] exactly. The inverse includes
    /// division by the domain size and rejects an input of the wrong length
    /// before mutating it.
    fn ifft<F: Field>(domain: Domain<F>, values: &mut Vec<F>) {
        ragu_core::ifft(domain, values);
    }

    /// Computes the multiscalar multiplication
    /// $\langle \mathbf{a}, \mathbf{G} \rangle$.
    ///
    /// # Panics
    ///
    /// Panics if `coeffs` and `bases` differ in length. Pairing them up to
    /// the shorter one would silently drop terms from the sum.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`Affine::msm`] exactly, including the panic on
    /// operands of unequal length.
    fn msm<
        'a,
        C: Affine,
        A: IntoIterator<Item = &'a C::Scalar>,
        Bases: IntoIterator<Item = &'a C>,
    >(
        coeffs: A,
        bases: Bases,
    ) -> C::Projective
    where
        Bases::IntoIter: Clone + Sync,
    {
        ragu_core::msm(coeffs.into_iter().copied(), bases.into_iter().copied())
    }

    /// Computes independent MSMs, returning results in input order.
    ///
    /// The default calls [`Self::msm`] for each input, retaining MSM overrides.
    /// Backends may override this method to schedule the MSMs together.
    ///
    /// # Panics
    ///
    /// Panics if any input's operands differ in length, as [`Self::msm`]
    /// does.
    ///
    /// # Correctness
    ///
    /// Outputs must match separate calls to [`Self::msm`] exactly.
    fn msm_batch<
        'a,
        C: Affine,
        A: IntoIterator<Item = &'a C::Scalar>,
        Bases: IntoIterator<Item = &'a C>,
        const N: usize,
    >(
        inputs: [(A, Bases); N],
    ) -> [C::Projective; N]
    where
        Bases::IntoIter: Clone + Sync,
    {
        inputs.map(|(coeffs, bases)| Self::msm(coeffs, bases))
    }

    /// Opens a device that holds polynomials for the caller, if this backend
    /// has one free for this field and rank. The default has none, and the
    /// caller then computes on the host.
    fn poly_device<F: Field, R: Rank>() -> Option<Box<dyn PolyDevice<F, R>>> {
        None
    }

    /// Maps a finite set of independent inputs to results in input order.
    ///
    /// The default is an ordinary lazy iterator, with no job buffer. Backends
    /// may collect the inputs and evaluate them concurrently before returning.
    /// Consequently, `work` must be independent of execution order and must not
    /// have protocol side effects such as consuming transcript or RNG state.
    /// Callers must not rely on unevaluated work when consuming only a prefix.
    ///
    /// # Correctness
    ///
    /// Collecting all results must match `inputs.into_iter().map(work)` exactly,
    /// with one call per input and results in the original input order.
    fn map<I: IntoIterator, T: Send>(
        inputs: I,
        work: impl Fn(I::Item) -> T + Sync,
    ) -> impl Iterator<Item = T>
    where
        I::Item: Send,
    {
        inputs.into_iter().map(work)
    }

    /// Applies independent work to each item's original index and mutable slot.
    ///
    /// The default visits items serially. Backends may schedule them concurrently.
    /// The callback's result for each item must be independent of visitation order.
    ///
    /// # Correctness
    ///
    /// On success, each item must be visited exactly once with its original index,
    /// and the items must retain their original order. If the callback panics,
    /// some items may remain unvisited.
    fn for_each_mut<T: Send>(values: &mut [T], work: impl Fn(usize, &mut T) + Sync) {
        for (index, value) in values.iter_mut().enumerate() {
            work(index, value);
        }
    }
}

/// The backend used by default throughout Ragu.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReferenceBackend;

impl Backend for ReferenceBackend {}
