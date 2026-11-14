//! Common abstraction for orchestrating revdot claims.
//!
//! # Revdot claims
//!
//! A **revdot claim** asserts that two polynomials $a(X)$ and $b(X)$ satisfy
//! a reversed inner product on their coefficient vectors (see
//! [`sparse::Polynomial::revdot`]). In the proof system, each circuit stage
//! produces a claim of the form
//!
//! $$\operatorname{revdot}(a(X), b(X)) = k(Y),$$
//!
//! where $k(Y)$ is the public-input polynomial restricted at a verifier
//! challenge. Verifiers check these claims, and the folding machinery reduces
//! many such claims into a single claim plus a bounded set of error terms.
//!
//! This module provides helpers to build the $(a, b)$ pairs for each claim
//! and to aggregate them across proof components.

use alloc::{borrow::Cow, boxed::Box, vec::Vec};
use core::{borrow::Borrow, marker::PhantomData};

use ragu_backend::{Backend, PolyDevice, Slot};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryAt},
};
use ragu_primitives::vec::{FixedVec, Len};
use udon::field::Field;

use super::fold_revdot::{self, NumErrorTerms, Parameters};

/// Sum an iterator of polynomials, borrowing if only one element.
///
/// Returns `Cow::Borrowed` for a single polynomial, `Cow::Owned` for multiple.
/// Panics if the iterator is empty.
pub fn sum_polynomials<'rx, F: Field, R: Rank>(
    mut rxs: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>,
) -> Cow<'rx, sparse::Polynomial<F, R>> {
    let first = rxs.next().expect("must provide at least one rx polynomial");
    match rxs.next() {
        None => Cow::Borrowed(first),
        Some(second) => {
            let mut sum = first.clone();
            sum.add_assign(second);
            for rx in rxs {
                sum.add_assign(rx);
            }
            Cow::Owned(sum)
        }
    }
}

/// Trait for providing claim component values from sources.
///
/// This trait abstracts over what a "source" provides. For polynomial contexts
/// (verify, fuse), it provides polynomial references. For evaluation contexts
/// (`compute_v`), it provides single element evaluations (at $xz$).
///
/// Implementors provide access to rx values for all proofs they manage. The
/// `RxComponent` associated type defines which components can be requested.
pub trait Source {
    /// The type identifying which rx component to retrieve.
    type RxComponent: Copy;

    /// Opaque type for rx values.
    type Rx;

    /// Type for application circuit identifiers.
    type AppCircuitId;

    /// Get an iterator over rx values for all proofs for the given component.
    fn rx(&self, component: Self::RxComponent) -> impl Iterator<Item = Self::Rx>;

    /// Get an iterator over application circuit info for all proofs.
    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId>;
}

/// Processor that builds polynomial vectors for revdot claims.
///
/// Accumulates (a, b) polynomial pairs for each claim type, using
/// the registry polynomial to transform rx polynomials appropriately.
///
/// The type parameter `A` determines what is stored in the `a` vector:
/// - Verify path: `A = Cow<'rx, Polynomial>` (plain polynomial references)
/// - Fuse path: `A = TrackedPoly<'rx, FoldKey, F, R>` (polynomial +
///   commitment decomposition; see `fuse::claims`)
pub struct Builder<'m, 'rx, A, F: Field, R: Rank, B: Backend> {
    pub registry: &'m Registry<'m, F, R>,
    pub y: F,
    pub z: F,
    pub tz: sparse::Polynomial<F, R>,
    /// The accumulated `a` polynomials.
    pub a: Vec<A>,
    /// The accumulated `b` polynomials for revdot claims.
    pub b: Vec<Cow<'rx, sparse::Polynomial<F, R>>>,
    /// The claims whose `b` is still to be computed, for a builder made by
    /// [`Builder::deferred`]; `None` for one that computes each `b` as its
    /// claim is pushed.
    pending: Option<Vec<Pending>>,
    /// The claims' polynomials, when a device holds them. `a` and `b` then
    /// carry no coefficients on the host.
    pub device: Option<DeviceClaims<F, R>>,
    backend: PhantomData<B>,
}

/// Claims whose polynomials a device holds: claim `i` is `a[i]` and `b[i]`.
/// After [`fold_inner`](Self::fold_inner) the entries are the folded groups.
pub struct DeviceClaims<F: Field, R: Rank> {
    device: Box<dyn PolyDevice<F, R>>,
    a: Vec<Slot>,
    b: Vec<Slot>,
}

impl<F: Field, R: Rank> DeviceClaims<F, R> {
    /// The first-layer quotients, as
    /// [`fold_revdot::inner_error_terms_with_backend`] computes them.
    pub fn inner_error_terms<B: Backend, P: Parameters>(
        &mut self,
    ) -> FixedVec<FixedVec<F, NumErrorTerms<P::GroupSize>>, P::NumGroups> {
        let m = P::GroupSize::len();
        let pairs: Vec<_> = fold_revdot::product_pairs(self.a.len(), m)
            .map(|(i, j)| (self.a[i], self.b[j]))
            .collect();
        let mut products =
            crate::timing::span("dev.revdot", || self.device.revdot(&pairs)).into_iter();
        fold_revdot::inner_error_terms_from_products::<B, F, P>(self.a.len(), |_, len| {
            products.by_ref().take(len * len).collect()
        })
    }

    /// Replaces the claims by their `P::NumGroups` groups interpolated at
    /// `challenge`, as [`fold_revdot::fold_inner`] folds each side.
    pub fn fold_inner<P: Parameters>(&mut self, challenge: F) {
        let m = P::GroupSize::len();
        let groups = P::NumGroups::len();
        assert!(self.a.len() <= m * groups, "too many fold sources");
        let weights = fold_revdot::weights(challenge, m);
        // A group past the last claim is the zero polynomial: an empty sum.
        let side = |slots: &[Slot]| {
            let mut jobs: Vec<Vec<(F, Slot)>> = slots
                .chunks(m)
                .map(|chunk| weights.iter().copied().zip(chunk.iter().copied()).collect())
                .collect();
            jobs.resize(groups, Vec::new());
            jobs
        };
        let mut jobs = side(&self.a);
        jobs.extend(side(&self.b));
        let mut folded = self.device.lincomb(&jobs);
        self.b = folded.split_off(groups);
        self.a = folded;
    }

    /// The second-layer quotient of the folded groups, as
    /// [`fold_revdot::outer_error_terms_with_backend`] computes it.
    pub fn outer_error_terms<B: Backend, P: Parameters>(
        &mut self,
    ) -> FixedVec<F, NumErrorTerms<P::NumGroups>> {
        let groups = P::NumGroups::len();
        assert_eq!(self.a.len(), groups, "fold the claims first");
        let pairs: Vec<_> = fold_revdot::product_pairs(groups, groups)
            .map(|(i, j)| (self.a[i], self.b[j]))
            .collect();
        fold_revdot::outer_error_terms_from_products::<B, F, P>(self.device.revdot(&pairs))
    }

    /// Interpolates the folded groups at `challenge`, as
    /// [`fold_revdot::fold_outer`] folds each side, and returns the two
    /// accumulated polynomials with the device, which no longer holds
    /// claims.
    pub fn fold_outer<P: Parameters>(
        mut self,
        challenge: F,
    ) -> (
        sparse::Polynomial<F, R>,
        sparse::Polynomial<F, R>,
        Box<dyn PolyDevice<F, R>>,
    ) {
        let groups = P::NumGroups::len();
        assert_eq!(self.a.len(), groups, "fold the claims first");
        let weights = fold_revdot::weights(challenge, groups);
        let side = |slots: &[Slot]| -> Vec<(F, Slot)> {
            weights.iter().copied().zip(slots.iter().copied()).collect()
        };
        let folded = self.device.lincomb(&[side(&self.a), side(&self.b)]);
        let mut polys = self.device.download(&folded).into_iter();
        let a = polys.next().expect("two polynomials");
        let b = polys.next().expect("two polynomials");
        (a, b, self.device)
    }
}

/// A coefficient of a recorded combination, known before the challenge $z$.
#[derive(Clone, Copy)]
enum Coefficient {
    One,
    /// $z^k$.
    ZPower(usize),
}

/// How a recorded claim's `a` is formed from the uploaded polynomials.
enum Trace {
    /// One of them, as it is.
    Poly(usize),
    /// A combination of them.
    Sum(Vec<(Coefficient, usize)>),
}

/// How a recorded claim's `b` is formed.
enum Wiring {
    /// An uploaded polynomial, for a raw claim.
    Poly(usize),
    /// The dilated `a` plus the circuit's $s_y$ and $t(z)$.
    Circuit(CircuitIndex),
    /// The circuit's $s_y$ alone.
    Bonding(CircuitIndex),
}

/// Records claims as recipes over the polynomials they are built from, for
/// a device to carry out: the same claims, in the same order, as a
/// [`Builder`] accumulates on the host.
///
/// Which polynomials the claims read, and how they combine them, does not
/// depend on the challenges, so the claims can be recorded and their
/// polynomials uploaded before the challenges exist.
pub struct DeviceRecorder<'rx, F: Field, R: Rank> {
    /// The distinct polynomials the claims read, in first-use order.
    polys: Vec<&'rx sparse::Polynomial<F, R>>,
    /// Their slots, once [`upload`](Self::upload) has run.
    uploaded: Option<Vec<Slot>>,
    claims: Vec<(Trace, Wiring)>,
}

impl<F: Field, R: Rank> Default for DeviceRecorder<'_, F, R> {
    fn default() -> Self {
        Self {
            polys: Vec::new(),
            uploaded: None,
            claims: Vec::new(),
        }
    }
}

impl<'rx, F: Field, R: Rank> DeviceRecorder<'rx, F, R> {
    /// Has the device take slots for the polynomials the recorded claims
    /// read, and returns the work that stores them there, if the device
    /// leaves that to its caller ([`PolyDevice::upload_later`]). A recorder
    /// that has not uploaded does so in [`finish`](Self::finish).
    pub fn upload(
        &mut self,
        device: &mut dyn PolyDevice<F, R>,
    ) -> Option<ragu_backend::Later<'rx>> {
        let (slots, work) = device.upload_later(&self.polys);
        self.uploaded = Some(slots);
        work
    }

    /// Has [`upload`](Self::upload) upload `polys` as well, for the stages
    /// that read them from the device after the claims.
    pub fn also(&mut self, polys: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>) {
        for poly in polys {
            self.index(poly);
        }
    }

    /// The uploaded polynomials, each with its slot.
    pub fn held(&self) -> Vec<(&'rx sparse::Polynomial<F, R>, Slot)> {
        self.uploaded
            .iter()
            .flat_map(|slots| self.polys.iter().copied().zip(slots.iter().copied()))
            .collect()
    }

    /// The upload index of `poly`, which is uploaded once however many
    /// claims read it.
    fn index(&mut self, poly: &'rx sparse::Polynomial<F, R>) -> usize {
        match self
            .polys
            .iter()
            .position(|known| core::ptr::eq(*known, poly))
        {
            Some(index) => index,
            None => {
                self.polys.push(poly);
                self.polys.len() - 1
            }
        }
    }

    /// A claim with both sides given, as [`Builder`]'s raw claims.
    pub fn raw_claim(
        &mut self,
        a: &'rx sparse::Polynomial<F, R>,
        b: &'rx sparse::Polynomial<F, R>,
    ) {
        let (a, b) = (self.index(a), self.index(b));
        self.claims.push((Trace::Poly(a), Wiring::Poly(b)));
    }

    /// A claim on the sum of `rxs`, as [`Builder::circuit_impl`] on
    /// [`sum_polynomials`].
    ///
    /// # Panics
    ///
    /// Panics if `rxs` is empty.
    pub fn circuit_claim(
        &mut self,
        circuit_id: CircuitIndex,
        rxs: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>,
    ) {
        let terms: Vec<_> = rxs.map(|rx| (Coefficient::One, self.index(rx))).collect();
        let trace = match terms.as_slice() {
            [] => panic!("must provide at least one rx polynomial"),
            [(_, only)] => Trace::Poly(*only),
            _ => Trace::Sum(terms),
        };
        self.claims.push((trace, Wiring::Circuit(circuit_id)));
    }

    /// A claim on the Horner fold with $z$ of the groups' sums, as
    /// [`Builder::bonding_impl`] on [`Builder::fold_bonding_groups`]: of
    /// $n$ groups, group $i$ has coefficient $z^{n-1-i}$.
    pub fn bonding_claim(
        &mut self,
        circuit_id: CircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = &'rx sparse::Polynomial<F, R>>>,
    ) {
        let groups: Vec<Vec<usize>> = groups
            .map(|group| group.map(|rx| self.index(rx)).collect())
            .collect();
        let mut terms = Vec::new();
        for (power, group) in groups.iter().rev().enumerate() {
            terms.extend(group.iter().map(|poly| (Coefficient::ZPower(power), *poly)));
        }
        self.claims
            .push((Trace::Sum(terms), Wiring::Bonding(circuit_id)));
    }

    /// Has `device` form every claim's `a` and `b` at the challenges, from
    /// the polynomials the recorder uploaded there, and returns the claims
    /// with the restriction of `at` to `y`, [`RegistryAt::y`].
    ///
    /// A device that holds the registry's wiring matrices restricts the
    /// circuits itself; the host then computes only what the matrices do
    /// not cover. Otherwise the host restricts every circuit, once each.
    pub fn finish<B: Backend>(
        self,
        mut device: Box<dyn PolyDevice<F, R>>,
        registry: &Registry<'_, F, R>,
        at: &RegistryAt<'_, F, R>,
        y: F,
        z: F,
    ) -> (DeviceClaims<F, R>, sparse::Polynomial<F, R>) {
        let uploaded = match self.uploaded {
            Some(uploaded) => uploaded,
            None => crate::timing::span("dev.upload_children", || device.upload(&self.polys)),
        };
        // The powers of z the bonding folds use.
        let mut z_powers = alloc::vec![F::ONE];
        let mut coefficient = |coefficient: &Coefficient| match coefficient {
            Coefficient::One => F::ONE,
            Coefficient::ZPower(power) => {
                while z_powers.len() <= *power {
                    z_powers.push(z_powers[z_powers.len() - 1] * z);
                }
                z_powers[*power]
            }
        };

        let jobs: Vec<Vec<(F, Slot)>> = self
            .claims
            .iter()
            .filter_map(|(trace, _)| match trace {
                Trace::Sum(terms) => Some(
                    terms
                        .iter()
                        .map(|(coeff, poly)| (coefficient(coeff), uploaded[*poly]))
                        .collect(),
                ),
                Trace::Poly(_) => None,
            })
            .collect();
        let mut sums = crate::timing::span("dev.lincomb", || device.lincomb(&jobs)).into_iter();
        let a: Vec<Slot> = self
            .claims
            .iter()
            .map(|(trace, _)| match trace {
                Trace::Poly(poly) => uploaded[*poly],
                Trace::Sum(_) => sums.next().expect("one sum per combination"),
            })
            .collect();

        let mut circuits: Vec<CircuitIndex> = Vec::new();
        for (_, wiring) in &self.claims {
            if let Wiring::Circuit(circuit) | Wiring::Bonding(circuit) = wiring
                && !circuits.contains(circuit)
            {
                circuits.push(*circuit);
            }
        }

        // Each circuit's restriction, and the registry's, split into the
        // matrices the device evaluated and the rest, computed here.
        let matrices = crate::timing::span("dev.wiring", || device.wiring_y(registry, y));
        let elsewhere = |i: usize| {
            matrices
                .as_ref()
                .is_some_and(|slots| slots.get(i).is_some_and(Option::is_some))
        };
        let matrix = |i: usize| {
            matrices.as_ref().expect("a circuit held elsewhere")[i].expect("its matrix slot")
        };
        // How each claimed circuit's restriction is put together. A circuit
        // whose matrix the device evaluated needs only the registry's tag
        // term added. A masking polynomial evaluated here is its own notch
        // plus the term all of them share and the tag; those two terms are
        // computed once. Any other circuit is split by the registry, which
        // computes its rest here.
        enum Shape {
            Plain(usize),
            Mask(usize),
            Other,
        }
        let shapes: Vec<Shape> = circuits
            .iter()
            .map(|circuit| {
                match registry
                    .registered_circuit(*circuit)
                    .filter(|position| elsewhere(*position))
                {
                    Some(position) => Shape::Plain(position),
                    None => match registry.mask_circuit(*circuit) {
                        Some(position) => Shape::Mask(position),
                        None => Shape::Other,
                    },
                }
            })
            .collect();
        let tag = registry.tag_y(y).unwrap_or_default();
        let global = shapes
            .iter()
            .any(|shape| matches!(shape, Shape::Mask(_)))
            .then(|| registry.mask_global_y(y));
        let (own, (registry_held, registry_rest)) = crate::timing::span("dev.sy_all", || {
            let own: Vec<Option<(Vec<(usize, F)>, sparse::Polynomial<F, R>)>> = B::map(
                shapes.iter().zip(circuits.iter().copied()),
                |(shape, circuit)| {
                    crate::timing::span("claims.sy", || match shape {
                        Shape::Plain(_) => None,
                        Shape::Mask(position) => Some((Vec::new(), registry.own_y(*position, y))),
                        Shape::Other => Some(registry.circuit_y_parts(circuit, y, elsewhere)),
                    })
                },
            )
            .collect();
            (own, at.y_parts(y, elsewhere))
        });

        let tz = R::tz(z);
        let mut uploads: Vec<&sparse::Polynomial<F, R>> =
            own.iter().flatten().map(|(_, poly)| poly).collect();
        uploads.push(&tag);
        uploads.extend(&global);
        uploads.push(&registry_rest);
        uploads.push(&tz);
        let mut uploads = crate::timing::span("dev.upload_wiring", || device.upload(&uploads));
        let t = uploads.pop().expect("t(z) was uploaded");
        let registry_rest = (registry_rest, uploads.pop().expect("the registry's rest"));
        let global = global.map(|_| uploads.pop().expect("the masks' shared term"));
        let tag = uploads.pop().expect("the tag term");
        let mut own_slots = uploads.into_iter();

        // Every restriction is a sum of slots: its matrices with their
        // coefficients, and the terms above.
        let held = |held: &[(usize, F)]| -> Vec<(F, Slot)> {
            held.iter().map(|(i, coeff)| (*coeff, matrix(*i))).collect()
        };
        let mut jobs: Vec<Vec<(F, Slot)>> = shapes
            .iter()
            .zip(&own)
            .map(|(shape, own)| match shape {
                Shape::Plain(position) => alloc::vec![(F::ONE, matrix(*position)), (F::ONE, tag)],
                Shape::Mask(_) => alloc::vec![
                    (F::ONE, own_slots.next().expect("the mask's notch")),
                    (F::ONE, global.expect("the masks' shared term")),
                    (F::ONE, tag),
                ],
                Shape::Other => {
                    let (matrices, _) = own.as_ref().expect("a split circuit's parts");
                    let mut terms = held(matrices);
                    terms.push((F::ONE, own_slots.next().expect("the circuit's rest")));
                    terms
                }
            })
            .collect();
        if !registry_held.is_empty() {
            let mut terms = held(&registry_held);
            terms.push((F::ONE, registry_rest.1));
            jobs.push(terms);
        }
        let mut wiring = crate::timing::span("dev.lincomb", || device.lincomb(&jobs));
        let registry_y = match registry_held.is_empty() {
            true => registry_rest.0,
            false => {
                let slot = wiring.pop().expect("the registry's combination");
                crate::timing::span("dev.download", || device.download(&[slot]))
                    .pop()
                    .expect("one polynomial")
            }
        };
        let restriction = |circuit: &CircuitIndex| {
            wiring[circuits
                .iter()
                .position(|known| known == circuit)
                .expect("every claimed circuit was restricted")]
        };

        let powers = device.powers(z);
        let dilations: Vec<(Slot, Slot)> = self
            .claims
            .iter()
            .zip(&a)
            .filter_map(|((_, wiring), a)| match wiring {
                Wiring::Circuit(circuit) => Some((*a, restriction(circuit))),
                _ => None,
            })
            .collect();
        let mut dilated =
            crate::timing::span("dev.dilate", || device.dilate_add(&dilations, powers, t))
                .into_iter();
        let b: Vec<Slot> = self
            .claims
            .iter()
            .map(|(_, wiring)| match wiring {
                Wiring::Poly(poly) => uploaded[*poly],
                Wiring::Circuit(_) => dilated.next().expect("one dilation per circuit claim"),
                Wiring::Bonding(circuit) => restriction(circuit),
            })
            .collect();

        (DeviceClaims { device, a, b }, registry_y)
    }
}

/// A pushed claim whose `b` polynomial [`Builder::finish`] computes.
struct Pending {
    /// The claim's index in `a` and `b`.
    slot: usize,
    circuit_id: CircuitIndex,
    /// Whether `b` is the dilated `a` plus $s_y$ and $t(z)$, as for a
    /// circuit claim, or $s_y$ alone, as for a bonding claim.
    circuit: bool,
}

impl<'m, 'rx, A, F: Field, R: Rank, B: Backend> Builder<'m, 'rx, A, F, R, B>
where
    A: Borrow<sparse::Polynomial<F, R>>,
{
    /// Create a new claim builder.
    pub fn new(registry: &'m Registry<'m, F, R>, y: F, z: F) -> Self {
        Self {
            registry,
            y,
            z,
            tz: R::tz(z),
            a: Vec::new(),
            b: Vec::new(),
            pending: None,
            device: None,
            backend: PhantomData,
        }
    }

    /// Create a claim builder that leaves each circuit and bonding claim's
    /// `b` empty until [`finish`](Self::finish) computes them all, through
    /// [`Backend::map`]. The claims are the same as [`new`](Self::new)'s
    /// once `finish` has run, and `b` must not be read before.
    pub fn deferred(registry: &'m Registry<'m, F, R>, y: F, z: F) -> Self {
        Self {
            pending: Some(Vec::new()),
            ..Self::new(registry, y, z)
        }
    }

    /// Computes the `b` polynomial of every claim pushed since the builder
    /// was made or last finished. Does nothing for a builder that is not
    /// [`deferred`](Self::deferred).
    pub fn finish(&mut self) {
        let Some(pending) = self.pending.as_mut().map(core::mem::take) else {
            return;
        };
        let (registry, y, z, tz) = (self.registry, self.y, self.z, &self.tz);

        // A circuit's restriction to `y` is the same for every claim on it,
        // and the children each bring a claim on the same internal circuits,
        // so it is computed once per circuit.
        let mut circuits: Vec<CircuitIndex> = Vec::new();
        let slots: Vec<usize> = pending
            .iter()
            .map(|claim| {
                circuits
                    .iter()
                    .position(|circuit| *circuit == claim.circuit_id)
                    .unwrap_or_else(|| {
                        circuits.push(claim.circuit_id);
                        circuits.len() - 1
                    })
            })
            .collect();
        let restrictions: Vec<_> = B::map(circuits, |circuit_id| {
            crate::timing::span("claims.sy", || {
                B::registry_circuit_y(registry, circuit_id, y)
            })
        })
        .collect();

        // Borrow before scheduling so `A` need not be `Sync`.
        let jobs: Vec<_> = pending
            .into_iter()
            .zip(slots)
            .map(|(claim, circuit)| {
                let rx = claim.circuit.then(|| self.a[claim.slot].borrow());
                (claim.slot, &restrictions[circuit], rx)
            })
            .collect();
        let computed: Vec<_> = B::map(jobs, |(slot, sy, rx)| {
            let b = match rx {
                Some(rx) => crate::timing::span("claims.dilate_add", || {
                    let mut b = rx.clone();
                    b.dilate(z);
                    b.add_assign(sy);
                    b.add_assign(tz);
                    b
                }),
                None => sy.clone(),
            };
            (slot, b)
        })
        .collect();
        for (slot, b) in computed {
            self.b[slot] = Cow::Owned(b);
        }
    }

    /// Records a claim for [`finish`](Self::finish) if this builder is
    /// deferred, returning whether it did.
    fn defer(&mut self, circuit_id: CircuitIndex, circuit: bool) -> bool {
        let slot = self.b.len();
        match &mut self.pending {
            Some(pending) => {
                pending.push(Pending {
                    slot,
                    circuit_id,
                    circuit,
                });
                true
            }
            None => false,
        }
    }

    /// Push a circuit claim. Computes `b` from `a.borrow()` (the polynomial).
    pub fn circuit_impl(&mut self, circuit_id: CircuitIndex, a: A) {
        if self.defer(circuit_id, true) {
            self.a.push(a);
            self.b.push(Cow::Owned(sparse::Polynomial::new()));
            return;
        }
        let rx = a.borrow();
        let sy = B::registry_circuit_y(self.registry, circuit_id, self.y);
        let mut b = rx.clone();
        b.dilate(self.z);
        b.add_assign(&sy);
        b.add_assign(&self.tz);
        self.a.push(a);
        self.b.push(Cow::Owned(b));
    }

    /// Push a bonding claim. There is no dilation and no $t(z)$, so
    /// $b = s\_{y}$ and $k(y) = 0$.
    pub fn bonding_impl(&mut self, circuit_id: CircuitIndex, a: A) {
        if self.defer(circuit_id, false) {
            self.a.push(a);
            self.b.push(Cow::Owned(sparse::Polynomial::new()));
            return;
        }
        let sy = B::registry_circuit_y(self.registry, circuit_id, self.y);
        self.a.push(a);
        self.b.push(Cow::Owned(sy));
    }

    /// Horner-fold groups of polynomials. Each group is first summed, then
    /// the sums are Horner-folded with $z$.
    ///
    /// The fold gives group `i` coefficient $z^{n-1-i}$. Callers that track
    /// commitment decompositions must assign the same coefficients to the
    /// corresponding source keys.
    ///
    /// Folding is sound because the revdot identity for bonding polynomials is
    /// linear in the trace.
    pub fn fold_bonding_groups(
        &self,
        groups: impl Iterator<Item = impl Iterator<Item = &'rx sparse::Polynomial<F, R>>>,
    ) -> Cow<'rx, sparse::Polynomial<F, R>> {
        Cow::Owned(sparse::Polynomial::fold(
            groups.map(|g| sum_polynomials(g)),
            self.z,
        ))
    }
}
