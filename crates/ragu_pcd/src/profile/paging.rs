//! Experimental: the glue between a profile's [`Pages`] and the fuse.
//!
//! A profile that pages an internal circuit gets, after everything its
//! extension declares and the online batch adds: an extension circuit for
//! each page before the last, each loading one more extension stage, the
//! circuit's carry stage, and that stage's final mask over the pages. The
//! last page takes the circuit's own slot, with the circuit's instance. So
//! the pages' polynomials, commitments and claims are the extension's,
//! which the fuse already carries for any profile; what is left for the
//! fuse is to go through this module where it registers, claims and proves
//! its circuits:
//!
//! - registration ([`Registrar`]): a circuit whole, or its last page in
//!   its slot and the other pages, the carry stage's mask and the pages'
//!   mask in the extension's;
//! - claims: a page loads its circuit's stages beside the carry stage, the
//!   circuit's claim is its last page's, and one mask covers every page's
//!   own polynomial, the circuit's own among them, which is its last
//!   page's;
//! - proving ([`Prover`]): a trace per page, and the carry stage's values
//!   off them.
//!
//! A [`Cut`] says how many pages a circuit is cut into, each loading every
//! stage the circuit reserves, and how many values its carry stage holds.
//! Both are the profile's to state: each page is a polynomial of the proof,
//! which the circuits being paged fold and open with the rest, so a count
//! the pager chose where a circuit is registered would change the circuits
//! it had already cut. The census (`native_census` and `nested_census`,
//! with the `test-utils` feature) cuts each circuit with fewer pages until
//! it no longer cuts, and reports the fewest that do.
//!
//! Where the cuts fall is not stated. The pager places them where a
//! circuit is registered ([`Registrar`]), each time a registry is built,
//! and the pages it gives are checked against the circuit before any of
//! them is registered. The search has nothing random in it and gives the
//! same cuts on any number of threads, so the cuts are a function of the
//! circuit, of its [`Cut`], of the rank and of the pager's code. They are
//! searched for rather than pinned for three reasons:
//!
//! - a paged circuit changes with the application's header size, so a
//!   pinned cut would be a table with an entry for each size, not a
//!   constant;
//! - the check runs whether the cuts are pinned or searched for, and the
//!   check, not the search, is most of what paging adds to building a
//!   registry;
//! - what a pin would protect is the registered circuits, against a change
//!   to the pager that moves a cut. The fuse fixtures pin those for the
//!   aggregator, at the header size they prove at: such a change fails
//!   them, as a change to a circuit does.
//!
//! A change to the pager that moves a cut is therefore a change to the
//! registered circuits, and a proof made before it no longer verifies.
//!
//! A profile that pages nothing never reaches this module: the fuse calls
//! the profile's [`register_internal`](Profile::register_internal) and
//! [`prove_internal`](Profile::prove_internal), whose defaults register and
//! trace a circuit whole. A profile that pages takes the pager's versions
//! with [`paged_internal_circuits!`](crate::paged_internal_circuits), so
//! that only such a profile compiles its circuits for the pager's drivers.

use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use core::ops::Range;

use ragu_circuits::{
    Blind, CircuitExt, MaskObject,
    paging::{Pageable, Paged, Planned},
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryBuilder},
    staging::MultiStage,
};
use ragu_core::{Error, Result};
use ragu_primitives::vec::Len;
use rand::CryptoRng;
use udon::field::Field;

use super::{Cut, Extension, ExtensionRxs, Pages, Profile, Registration, Suffixed, online};
use crate::internal::{native, nested};

/// What the hooks' signatures name, for
/// [`paged_internal_circuits!`](crate::paged_internal_circuits).
#[doc(hidden)]
pub mod deps {
    pub use ragu_circuits::{
        paging::Pageable,
        polynomials::{Rank, sparse::Polynomial},
        registry::{CircuitIndex, Registry, RegistryBuilder},
        staging::MultiStage,
    };
    pub use ragu_core::Result;
    pub use rand::CryptoRng;
    pub use udon::field::Field;
}

/// The pager's versions of a profile's
/// [`register_internal`](crate::profile::Profile::register_internal) and
/// [`prove_internal`](crate::profile::Profile::prove_internal), for the
/// `impl` of a profile whose [`PAGES`](crate::profile::Profile::PAGES) cuts
/// a circuit.
#[macro_export]
macro_rules! paged_internal_circuits {
    () => {
        fn register_internal<'params, F, R, S>(
            pages: &mut $crate::profile::paging::Registrar<'params, F, R>,
            registry: $crate::profile::paging::deps::RegistryBuilder<'params, F, R>,
            which: $crate::profile::paging::Circuit,
            circuit: $crate::profile::paging::deps::MultiStage<F, R, S>,
        ) -> $crate::profile::paging::deps::Result<
            $crate::profile::paging::deps::RegistryBuilder<'params, F, R>,
        >
        where
            F: $crate::profile::paging::deps::Field,
            R: $crate::profile::paging::deps::Rank,
            S: $crate::profile::paging::deps::Pageable<F, R>,
            $crate::profile::paging::deps::MultiStage<F, R, S>: 'params,
        {
            pages.circuit(registry, which, circuit)
        }

        #[allow(clippy::too_many_arguments)]
        fn prove_internal<'source, F, R, S, RNG>(
            pages: &mut $crate::profile::paging::Prover<F, R>,
            which: $crate::profile::paging::Circuit,
            circuit: $crate::profile::paging::deps::MultiStage<F, R, S>,
            registry: &$crate::profile::paging::deps::Registry<'_, F, R>,
            own: $crate::profile::paging::deps::CircuitIndex,
            extension: impl Fn(u32) -> $crate::profile::paging::deps::CircuitIndex,
            witness: impl Fn() -> S::Witness<'source>,
            rng: &mut RNG,
        ) -> $crate::profile::paging::deps::Result<(
            $crate::profile::paging::deps::Polynomial<F, R>,
            S::Aux<'source>,
        )>
        where
            F: $crate::profile::paging::deps::Field,
            R: $crate::profile::paging::deps::Rank,
            S: $crate::profile::paging::deps::Pageable<F, R>,
            RNG: $crate::profile::paging::deps::CryptoRng,
        {
            pages.prove(which, circuit, registry, own, extension, witness, rng)
        }
    };
}

/// The values the carry stage of each of the fuse's internal circuits
/// holds under profile `P`: what the circuit's [`Cut`] states. Each is the
/// [`Pageable::Carry`] of its circuit, which sizes the carry stage every
/// page of the circuit loads.
pub mod carry {
    use core::marker::PhantomData;

    use ragu_primitives::vec::Len;

    use crate::profile::Profile;

    macro_rules! carries {
        ($($(#[$doc:meta])* $name:ident => $field:ident),+ $(,)?) => {$(
            $(#[$doc])*
            pub struct $name<P>(PhantomData<fn() -> P>);

            impl<P: Profile> Len for $name<P> {
                fn len() -> usize {
                    P::PAGES.$field.carry()
                }
            }
        )+};
    }

    carries! {
        /// The native `hashes_1` circuit's.
        Hashes1 => hashes_1,
        /// The native `hashes_2` circuit's.
        Hashes2 => hashes_2,
        /// The native `collapse` circuit's.
        Collapse => collapse,
        /// The native `compute_v` circuit's.
        ComputeV => compute_v,
        /// Each native `bind_challenges` circuit's.
        BindChallenges => bind_challenges,
        /// The native `bind_beta` circuit's.
        BindBeta => bind_beta,
        /// The native `bind_endoscalar` circuit's.
        BindEndoscalar => bind_endoscalar,
        /// Each step's of the native walk.
        EndoscalingStep => endoscaling_step,
        /// The nested `collapse` circuit's.
        NestedCollapse => nested_collapse,
        /// The nested `compute_v` circuit's.
        NestedComputeV => nested_compute_v,
        /// Each step's of the nested walk.
        NestedEndoscalingStep => nested_endoscaling_step,
    }
}

mod pageable {
    use ragu_circuits::{paging::Pageable, polynomials::Rank};
    use udon::curve::EndomorphismAffine as Affine;

    use super::carry;
    use crate::{
        internal::{native::circuits, nested, revdot},
        profile::{Profile, ProfiledCycle},
    };

    impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: revdot::Parameters>
        Pageable<C::CircuitField, R> for circuits::hashes_1::Circuit<'_, C, R, HEADER_SIZE, FP>
    {
        type Carry = carry::Hashes1<C::Profile>;
    }

    impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: revdot::Parameters>
        Pageable<C::CircuitField, R> for circuits::hashes_2::Circuit<'_, C, R, HEADER_SIZE, FP>
    {
        type Carry = carry::Hashes2<C::Profile>;
    }

    impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: revdot::Parameters>
        Pageable<C::CircuitField, R> for circuits::collapse::Circuit<C, R, HEADER_SIZE, FP>
    {
        type Carry = carry::Collapse<C::Profile>;
    }

    impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Pageable<C::CircuitField, R>
        for circuits::compute_v::Circuit<C, R, HEADER_SIZE>
    {
        type Carry = carry::ComputeV<C::Profile>;
    }

    impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, const K: usize>
        Pageable<C::CircuitField, R>
        for circuits::bind_challenges::Circuit<'_, C, R, HEADER_SIZE, K>
    {
        type Carry = carry::BindChallenges<C::Profile>;
    }

    impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Pageable<C::CircuitField, R>
        for circuits::bind_beta::Circuit<'_, C, R, HEADER_SIZE>
    {
        type Carry = carry::BindBeta<C::Profile>;
    }

    impl<C: ProfiledCycle, R: Rank> Pageable<C::CircuitField, R>
        for circuits::bind_endoscalar::Circuit<C, R>
    {
        type Carry = carry::BindEndoscalar<C::Profile>;
    }

    impl<C: ProfiledCycle, R: Rank> Pageable<C::CircuitField, R>
        for circuits::endoscaling_step::Circuit<C, R>
    {
        type Carry = carry::EndoscalingStep<C::Profile>;
    }

    impl<C: Affine, R: Rank, P: Profile> Pageable<C::Base, R>
        for nested::circuits::collapse::Circuit<C, R, P>
    {
        type Carry = carry::NestedCollapse<P>;
    }

    impl<C: Affine, R: Rank, P: Profile> Pageable<C::Base, R>
        for nested::circuits::compute_v::Circuit<C, R, P>
    {
        type Carry = carry::NestedComputeV<P>;
    }

    impl<C: Affine, R: Rank, P: Profile> Pageable<C::Base, R> for nested::EndoscalingStep<C, R, P> {
        type Carry = carry::NestedEndoscalingStep<P>;
    }
}

/// An internal circuit a profile can page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Circuit {
    /// The native `hashes_1` circuit.
    Hashes1,
    /// The native `hashes_2` circuit.
    Hashes2,
    /// The native `collapse` circuit.
    Collapse,
    /// The native `compute_v` circuit.
    ComputeV,
    /// A native `bind_challenges` circuit.
    BindChallenges(u32),
    /// The native `bind_beta` circuit.
    BindBeta,
    /// The native `bind_endoscalar` circuit.
    BindEndoscalar,
    /// The nested `collapse` circuit.
    NestedCollapse,
    /// The nested `compute_v` circuit.
    NestedComputeV,
    /// A step of the native walk.
    EndoscalingStep(u32),
    /// A step of the nested walk.
    NestedEndoscalingStep(u32),
}

impl Circuit {
    /// One side's circuits that profile `P` pages, each with its cut, in
    /// the order of their slots: the walk's steps after the others.
    fn paged<P: Profile>(nested: bool) -> Vec<(Self, Cut)> {
        let pages = &P::PAGES;
        let (circuits, step, steps): (Vec<Self>, fn(u32) -> Self, _) = if nested {
            (
                vec![Self::NestedCollapse, Self::NestedComputeV],
                Self::NestedEndoscalingStep,
                nested::NumSteps::<P>::len(),
            )
        } else {
            (
                [Self::Hashes1, Self::Hashes2, Self::Collapse, Self::ComputeV]
                    .into_iter()
                    .chain((0..native::NUM_BINDERS as u32).map(Self::BindChallenges))
                    .chain([Self::BindBeta, Self::BindEndoscalar])
                    .collect(),
                Self::EndoscalingStep,
                native::NumSteps::<P>::len(),
            )
        };
        let steps = if step(0).cut(pages).num_pages() > 1 {
            steps
        } else {
            0
        };
        circuits
            .into_iter()
            .chain((0..steps as u32).map(step))
            .map(|circuit| (circuit, circuit.cut(pages)))
            .filter(|&(_, cut)| cut.num_pages() > 1)
            .collect()
    }

    /// How `pages` cuts the circuit.
    const fn cut(self, pages: &Pages) -> Cut {
        match self {
            Self::Hashes1 => pages.hashes_1,
            Self::Hashes2 => pages.hashes_2,
            Self::Collapse => pages.collapse,
            Self::ComputeV => pages.compute_v,
            Self::BindChallenges(_) => pages.bind_challenges,
            Self::BindBeta => pages.bind_beta,
            Self::BindEndoscalar => pages.bind_endoscalar,
            Self::NestedCollapse => pages.nested_collapse,
            Self::NestedComputeV => pages.nested_compute_v,
            Self::EndoscalingStep(_) => pages.endoscaling_step,
            Self::NestedEndoscalingStep(_) => pages.nested_endoscaling_step,
        }
    }
}

/// The polynomials paging adds for a circuit cut by `cut`: one for each
/// page before the last, and the carry stage's.
pub(crate) const fn added(cut: Cut) -> usize {
    if cut.num_pages() > 1 {
        cut.num_pages()
    } else {
        0
    }
}

/// The polynomials paging adds to one side's extension, the walk's steps
/// aside: for each paged circuit, one for each page before the last and
/// the carry stage's. A paged step adds [`added`] to each of the walk's
/// steps, which the profile's [`Shape`](super::Shape) counts with them.
pub(crate) const fn rxs(pages: &Pages, nested: bool) -> usize {
    if nested {
        added(pages.nested_collapse) + added(pages.nested_compute_v)
    } else {
        added(pages.hashes_1)
            + added(pages.hashes_2)
            + added(pages.collapse)
            + added(pages.compute_v)
            + native::NUM_BINDERS * added(pages.bind_challenges)
            + added(pages.bind_beta)
            + added(pages.bind_endoscalar)
    }
}

/// Where a paged circuit's entries sit in its side's extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Slot {
    /// The circuit.
    pub circuit: Circuit,
    /// How its profile cuts it.
    pub cut: Cut,
    /// The extension circuits that are its pages before the last, in
    /// order.
    pub circuits: Range<u32>,
    /// The extension stage that is its carry stage.
    pub carry: u32,
    /// The extension mask over every page's own gates, which holds each
    /// page's polynomial off the stages and off the carry stage.
    pub mask: u32,
}

impl Slot {
    /// The last page.
    pub(crate) fn last(&self) -> usize {
        self.cut.num_pages() - 1
    }

    /// The page extension circuit `circuit` is, if one of this circuit's.
    pub(crate) fn page(&self, circuit: u32) -> Option<usize> {
        self.circuits
            .contains(&circuit)
            .then(|| (circuit - self.circuits.start) as usize)
    }

    /// Whether extension mask `mask` is the circuit's pages' mask, which
    /// covers its last page, whose polynomial is the circuit's own.
    pub(crate) fn masks_last(&self, mask: u32) -> bool {
        self.mask == mask
    }
}

/// One side's extension before paging's entries.
fn base<P: Profile>(nested: bool) -> Extension {
    if nested {
        online::stages::layout::<P, online::stages::Nested>()
    } else {
        online::stages::layout::<P, online::stages::Native>()
    }
}

/// Where each paged circuit's entries sit over `base`: the pages after its
/// circuits, the carry stages after its stages, and the pages' mask after
/// its final masks, each in the circuits' order.
fn slots_over<P: Profile>(base: &Extension, nested: bool) -> Vec<Slot> {
    let paged = Circuit::paged::<P>(nested);
    let mut circuit = base.circuits.len() as u32;
    let mut carry = base.stages as u32;
    let mut mask = (base.stages + paged.len() + base.final_masks.len()) as u32;
    paged
        .iter()
        .map(|&(which, cut)| {
            let circuits = circuit..circuit + cut.num_pages() as u32 - 1;
            circuit = circuits.end;
            let slot = Slot {
                circuit: which,
                cut,
                circuits,
                carry,
                mask,
            };
            carry += 1;
            mask += 1;
            slot
        })
        .collect()
}

/// Where each of one side's paged circuits' entries sit, in the circuits'
/// order; nothing for a profile that pages none.
pub(crate) fn slots<P: Profile>(nested: bool) -> Vec<Slot> {
    super::extended::<P>(nested).slots.clone()
}

/// Appends paging's entries to one side's extension. A circuit's pages'
/// mask is declared as a final mask over the extension circuits that are
/// its pages before the last; the last page's polynomial is the circuit's
/// own, which the claims add to the mask's.
pub(crate) fn extend<P: Profile>(extension: &mut Extension, nested: bool) -> Vec<Slot> {
    let slots = slots_over::<P>(extension, nested);
    for slot in &slots {
        extension
            .circuits
            .extend((0..slot.last()).map(|_| vec![slot.carry]));
        extension.stages += 1;
    }
    for slot in &slots {
        extension.final_masks.push(slot.circuits.clone().collect());
    }
    slots
}

fn refuse<T>(circuit: impl core::fmt::Debug, what: String) -> Result<T> {
    Err(Error::Initialization(
        format!("the profile's paging of {circuit:?} {what}").into(),
    ))
}

/// Cuts `circuit` into the pages `cut` declares, in polynomials of rank
/// `R`.
fn split<F: Field, R: Rank, S: Pageable<F, R>>(
    which: Circuit,
    circuit: MultiStage<F, R, S>,
    cut: Cut,
) -> Result<Paged<F, R, S>> {
    split_within(which, circuit, cut, R::blind_gate())
}

/// Cuts `circuit` into the pages `cut` declares, in polynomials of `limit`
/// gates. The carry stage's size is the circuit's own ([`Pageable`]),
/// which is its cut's in its profile.
fn split_within<F: Field, R: Rank, S: Pageable<F, R>>(
    which: impl core::fmt::Debug + Copy,
    circuit: impl Into<alloc::sync::Arc<MultiStage<F, R, S>>>,
    cut: Cut,
    limit: usize,
) -> Result<Paged<F, R, S>> {
    match Paged::cut(circuit, cut.num_pages(), limit) {
        Err(Error::GateBoundExceeded { limit }) => refuse(
            which,
            format!(
                "leaves its pages less room than the circuit takes, in polynomials of {limit} \
                 gates"
            ),
        ),
        paged => paged,
    }
}

type Register<'params, F, R> = Box<
    dyn FnOnce(RegistryBuilder<'params, F, R>) -> Result<RegistryBuilder<'params, F, R>> + 'params,
>;

/// What a paged circuit leaves to register after its last page.
struct Pending<'params, F: Field, R: Rank> {
    /// The pages before the last.
    pages: Vec<Option<Register<'params, F, R>>>,
    /// The carry stage's mask, with the stage's gates in the pages'
    /// polynomials.
    carry: (Option<MaskObject<R>>, Range<usize>),
    /// The mask of the pages' own polynomials, the carry stage's final
    /// mask, with the gate it leaves them from.
    mask: Option<(MaskObject<R>, usize)>,
}

/// An extension mask, as the registrar finds it.
pub(crate) enum Slotted<'params, F: Field, R: Rank> {
    /// One of paging's, registered.
    Paged(RegistryBuilder<'params, F, R>, Registration),
    /// The mask at this index of the extension before paging's entries,
    /// left to register.
    Other(RegistryBuilder<'params, F, R>, usize),
}

/// Registers one side's internal circuits, whole or in pages.
///
/// A paged circuit's last page is registered where the circuit would be;
/// its other pages and its masks are kept until the registry reaches the
/// extension slots they take, which come after every circuit.
pub struct Registrar<'params, F: Field, R: Rank> {
    slots: Vec<Slot>,
    /// The stages and final masks of the extension before paging's entries.
    base: (usize, usize),
    pending: Vec<Option<Pending<'params, F, R>>>,
    /// The pages each paged circuit was cut into, once it is registered.
    plans: Plans<F>,
}

/// The pages one side's paged circuits were cut into where they were
/// registered, by paged circuit: what a prover of the same application
/// pages them by, so that a proof cuts nothing again. A circuit it does
/// not hold is cut where it is proven.
#[derive(Clone, Debug)]
pub struct Plans<F: Field>(Vec<Option<Planned<F>>>);

impl<F: Field> Default for Plans<F> {
    fn default() -> Self {
        Plans(Vec::new())
    }
}

impl<'params, F: Field, R: Rank> Registrar<'params, F, R> {
    /// A registrar for one side of profile `P`.
    pub(crate) fn new<P: Profile>(nested: bool) -> Self {
        let base = base::<P>(nested);
        let slots = slots_over::<P>(&base, nested);
        Registrar {
            pending: slots.iter().map(|_| None).collect(),
            plans: Plans(slots.iter().map(|_| None).collect()),
            slots,
            base: (base.stages, base.final_masks.len()),
        }
    }

    /// The pages the circuits registered so far were cut into.
    pub(crate) fn plans(&self) -> Plans<F> {
        self.plans.clone()
    }

    /// Cuts `circuits` ahead of their registration, at once: a cut is
    /// kept for the process (with `std`), so each is found cut where
    /// [`circuit`](Self::circuit) registers it. It is for circuits that
    /// are many of a kind, as a walk's steps are, and does nothing for a
    /// circuit its profile does not page. A circuit that does not cut is
    /// refused where it is registered.
    pub(crate) fn warm<S>(&self, circuits: Vec<(Circuit, MultiStage<F, R, S>)>)
    where
        S: Pageable<F, R>,
        MultiStage<F, R, S>: Send,
    {
        use maybe_rayon::prelude::*;

        if !cfg!(feature = "std") {
            return;
        }
        let cuts: Vec<_> = circuits
            .into_iter()
            .filter_map(|(which, circuit)| {
                let cut = self.slots[self.position(which)?].cut;
                Some((which, circuit, cut))
            })
            .collect();
        cuts.into_par_iter().for_each(|(which, circuit, cut)| {
            let _ = split(which, circuit, cut);
        });
    }

    fn position(&self, which: Circuit) -> Option<usize> {
        self.slots.iter().position(|slot| slot.circuit == which)
    }

    /// Registers internal circuit `which`: whole, or its last page.
    ///
    /// # Errors
    ///
    /// Fails if the circuit does not cut into the pages its profile
    /// declares, or if a page cannot be registered.
    pub fn circuit<S>(
        &mut self,
        registry: RegistryBuilder<'params, F, R>,
        which: Circuit,
        circuit: MultiStage<F, R, S>,
    ) -> Result<RegistryBuilder<'params, F, R>>
    where
        S: Pageable<F, R>,
        MultiStage<F, R, S>: 'params,
    {
        let Some(position) = self.position(which) else {
            return registry.register_internal_circuit(circuit);
        };
        let slot = &self.slots[position];
        let paged = split(which, circuit, slot.cut)?;
        // The pages are held to the circuit they were cut from before any
        // is registered, so nothing that chose the cuts is trusted: not
        // the planner, and not a cut this process kept from before.
        paged.check()?;
        self.plans.0[position] = Some(paged.plan());
        let layout = paged.layout();
        let mask = Some((paged.page_mask()?, layout.carry.end));
        let pages = (0..slot.last())
            .map(|page| {
                let page = paged.page(page);
                let register: Register<'params, F, R> =
                    Box::new(move |registry| registry.register_internal_circuit(Suffixed(page)));
                Some(register)
            })
            .collect();
        let carry = (Some(paged.carry_mask()?), layout.carry.clone());
        self.pending[position] = Some(Pending { pages, carry, mask });
        registry.register_internal_circuit(paged.last())
    }

    /// Whether extension circuit `circuit` is a page.
    pub(crate) fn is_page(&self, circuit: u32) -> bool {
        self.slots.iter().any(|slot| slot.page(circuit).is_some())
    }

    fn pending(&mut self, position: usize) -> Result<&mut Pending<'params, F, R>> {
        let which = self.slots[position].circuit;
        match self.pending[position].as_mut() {
            Some(pending) => Ok(pending),
            None => refuse(
                which,
                "declares pages the profile does not register: it takes the pager's hooks with \
                 `paged_internal_circuits!`"
                    .into(),
            ),
        }
    }

    /// Registers extension circuit `circuit`, a page, over its carry stage.
    pub(crate) fn page(
        &mut self,
        registry: RegistryBuilder<'params, F, R>,
        circuit: u32,
    ) -> Result<(RegistryBuilder<'params, F, R>, Registration)> {
        let (position, page) = self
            .slots
            .iter()
            .enumerate()
            .find_map(|(position, slot)| Some((position, slot.page(circuit)?)))
            .expect("a page");
        let slot = self.slots[position].clone();
        let pending = self.pending(position)?;
        let Some(register) = pending.pages[page].take() else {
            return refuse(slot.circuit, "registers a page twice".into());
        };
        let carry = pending.carry.1.clone();
        Ok((register(registry)?, Registration::Staged(vec![carry])))
    }

    /// Registers extension mask `index` if it is one of paging's: a carry
    /// stage's stage mask, or its final mask, which holds each of the
    /// circuit's pages' own polynomials off the circuit's stages and the
    /// carry stage.
    ///
    /// # Errors
    ///
    /// Fails if the mask's circuit was not registered, or if the mask is
    /// registered twice.
    pub(crate) fn mask(
        &mut self,
        registry: RegistryBuilder<'params, F, R>,
        index: usize,
    ) -> Result<Slotted<'params, F, R>> {
        let (stages, final_masks) = self.base;
        let paged = self.slots.len();
        if index < stages {
            return Ok(Slotted::Other(registry, index));
        }
        if index < stages + paged {
            let position = self
                .slots
                .iter()
                .position(|slot| slot.carry as usize == index)
                .expect("the carry stage of one of the paged circuits");
            let which = self.slots[position].circuit;
            let (mask, carry) = &mut self.pending(position)?.carry;
            let Some(mask) = mask.take() else {
                return refuse(which, "registers its carry stage's mask twice".into());
            };
            let carry = carry.clone();
            return Ok(Slotted::Paged(
                registry.register_mask(mask),
                Registration::StageMask(carry),
            ));
        }
        if index < stages + paged + final_masks {
            return Ok(Slotted::Other(registry, index - paged));
        }

        let found = self
            .slots
            .iter()
            .position(|slot| slot.mask as usize == index);
        let Some(position) = found else {
            return Err(Error::Initialization(
                format!("the extension has no mask {index}").into(),
            ));
        };
        let which = self.slots[position].circuit;
        let Some((mask, from)) = self.pending(position)?.mask.take() else {
            return refuse(which, "registers a mask twice".into());
        };
        Ok(Slotted::Paged(
            registry.register_mask(mask),
            Registration::FinalMask(from),
        ))
    }
}

/// Traces one side's internal circuits, whole or in pages, and keeps the
/// polynomials the pages add to the extension.
pub struct Prover<F: Field, R: Rank> {
    slots: Vec<Slot>,
    /// The pages the circuits were cut into where they were registered.
    plans: Plans<F>,
    /// The pages' polynomials before each circuit's last, by paged circuit.
    pages: Vec<Option<Vec<sparse::Polynomial<F, R>>>>,
    /// The carry stage's polynomial, by paged circuit.
    carries: Vec<Option<sparse::Polynomial<F, R>>>,
}

impl<F: Field, R: Rank> Prover<F, R> {
    /// A prover for one side of profile `P`, which pages the circuits as
    /// `plans` holds them.
    pub(crate) fn new<P: Profile>(nested: bool, plans: &Plans<F>) -> Self {
        let slots = slots::<P>(nested);
        Prover {
            pages: slots.iter().map(|_| None).collect(),
            carries: slots.iter().map(|_| None).collect(),
            plans: plans.clone(),
            slots,
        }
    }

    /// Traces internal circuit `which` and assembles its polynomial: the
    /// circuit's own, at registry index `own`, or its last page's there and
    /// the other pages' at the indices `extension` gives their extension
    /// circuits. `witness` is asked for once, or once per page.
    ///
    /// # Errors
    ///
    /// Propagates any error from cutting, tracing or assembling.
    #[allow(clippy::too_many_arguments)]
    pub fn prove<'source, S, RNG>(
        &mut self,
        which: Circuit,
        circuit: MultiStage<F, R, S>,
        registry: &Registry<'_, F, R>,
        own: CircuitIndex,
        extension: impl Fn(u32) -> CircuitIndex,
        witness: impl Fn() -> S::Witness<'source>,
        rng: &mut RNG,
    ) -> Result<(sparse::Polynomial<F, R>, S::Aux<'source>)>
    where
        S: Pageable<F, R>,
        RNG: CryptoRng,
    {
        let Some(position) = self.slots.iter().position(|slot| slot.circuit == which) else {
            let (trace, aux) = circuit.trace(witness())?.into_parts();
            return Ok((registry.assemble(&trace, own, &mut *rng)?, aux));
        };
        let slot = &self.slots[position];
        let paged = match self.plans.0.get(position) {
            Some(Some(planned)) => Paged::planned(circuit, planned),
            _ => split(which, circuit, slot.cut)?,
        };

        // One walk of the circuit gives every page before the last the
        // values of its gates, and the carry stage its values; the last
        // page walks it once more, for the public output.
        let captured = paged.capture(witness())?;
        let mut pages = Vec::with_capacity(slot.circuits.len());
        for (page, circuit) in slot.circuits.clone().enumerate() {
            let trace = paged.page(page).trace(&captured.pages[page])?.into_output();
            pages.push(registry.assemble(&trace, extension(circuit), &mut *rng)?);
        }
        let (last, aux) = paged.last().trace(witness())?.into_parts();
        let last = registry.assemble(&last, own, &mut *rng)?;
        let carry = paged.carry_rx(Blind::random(&mut *rng), &captured.carry)?;
        self.carries[position] = Some(carry);
        self.pages[position] = Some(pages);
        Ok((last, aux))
    }

    /// Appends the pages' and the carry stages' polynomials to the
    /// extension's, in the order of their slots.
    ///
    /// # Errors
    ///
    /// Fails if a paged circuit was not proven.
    pub(crate) fn finish(self, rxs: &mut ExtensionRxs<F, R>) -> Result<()> {
        for ((slot, pages), carry) in self.slots.iter().zip(self.pages).zip(self.carries) {
            let (Some(pages), Some(carry)) = (pages, carry) else {
                return refuse(slot.circuit, "was not proven".into());
            };
            rxs.circuits.extend(pages);
            rxs.stages.push(carry);
        }
        Ok(())
    }
}

/// How one of the fuse's internal circuits sizes up, and how its profile
/// cuts it.
#[cfg(feature = "test-utils")]
#[derive(Clone, Debug)]
pub struct Sizing {
    /// The circuit's name.
    pub name: &'static str,
    /// Its gates, the SYSTEM gate and its stages' included.
    pub gates: usize,
    /// Its constraints.
    pub constraints: usize,
    /// The gates of the stages it reserves, in the order it reserves them.
    pub stages: Vec<Range<usize>>,
    /// The gates of its own, past its stages.
    pub own: usize,
    /// How it is cut.
    pub cut: Cut,
    /// The layout of its pages and how it spreads over them, checked
    /// against the circuit: the error if it does not cut or the pages'
    /// constraints are not its own.
    pub pages: core::result::Result<
        (
            ragu_circuits::paging::Layout,
            ragu_circuits::paging::PagingReport,
        ),
        String,
    >,
    /// A digest of its pages as a registry holds them
    /// ([`Paged::digest`]), where it cuts: what tells one cut of the
    /// circuit from another.
    pub digest: Option<[u8; 32]>,
    /// For a circuit that does not cut: how it would spread over the same
    /// pages in polynomials of [`SLACK`] more gates, if it then cuts, which
    /// tells what its pages are short of.
    pub unbounded: Option<ragu_circuits::paging::PagingReport>,
    /// Where the census was asked for them, the fewest pages the circuit
    /// cuts in; nothing if it does not cut in [`RAISES`] more than its
    /// cut's. They are the fewest for the profile as it is: a profile that
    /// takes them has fewer polynomials, which its circuits then cut with
    /// too, and may then cut in fewer still.
    pub fewest: Option<usize>,
}

/// How many more pages a census tries for a circuit that does not cut,
/// where it is asked for the fewest.
#[cfg(feature = "test-utils")]
pub const RAISES: usize = 16;

/// The fewest pages `circuit` cuts in: raised from `cut`'s until it cuts,
/// then lowered for as long as it still does, to one at the least.
#[cfg(feature = "test-utils")]
fn fewest<F: Field, R: Rank, S: Pageable<F, R>>(
    name: &'static str,
    circuit: &alloc::sync::Arc<MultiStage<F, R, S>>,
    cut: Cut,
) -> Option<usize> {
    let cuts = |pages: usize| {
        split_within(name, circuit.clone(), Cut::pages(pages), R::blind_gate()).is_ok()
    };
    let mut pages = cut.num_pages();
    let mut raises = 0;
    while !cuts(pages) {
        if raises == RAISES {
            return None;
        }
        raises += 1;
        pages += 1;
    }
    while pages > 1 && cuts(pages - 1) {
        pages -= 1;
    }
    Some(pages)
}

/// The gates past a polynomial's that a census gives the pages of a circuit
/// that does not cut, to tell what they are short of.
#[cfg(feature = "test-utils")]
pub const SLACK: usize = 600;

#[cfg(feature = "test-utils")]
fn sized<F: Field, R: Rank, S: Pageable<F, R>>(
    name: &'static str,
    cut: Cut,
    (cuts, solve): (&[(&'static str, Cut)], bool),
    circuit: MultiStage<F, R, S>,
) -> Result<Sizing> {
    let circuit = alloc::sync::Arc::new(circuit);
    let cut = cuts
        .iter()
        .find(|(of, _)| *of == name)
        .map_or(cut, |&(_, cut)| cut);
    let (gates, constraints) = ragu_circuits::paging::size(&*circuit)?;
    let stages = ragu_circuits::paging::Stages::of::<F, R, S>();
    let mut digest = None;
    let pages = split_within(name, circuit.clone(), cut, R::blind_gate())
        .and_then(|paged| {
            paged.check()?;
            digest = Some(paged.digest()?);
            Ok((paged.layout().clone(), paged.report().clone()))
        })
        .map_err(|error| format!("{error:?}"));
    let fewest = solve.then(|| fewest(name, &circuit, cut)).flatten();
    let unbounded = match pages {
        Ok(_) => None,
        Err(_) => split_within(name, circuit, cut, R::blind_gate() + SLACK)
            .ok()
            .map(|paged| paged.report().clone()),
    };
    Ok(Sizing {
        name,
        gates,
        constraints,
        own: gates.saturating_sub(stages.own_start()),
        stages: stages.spans,
        cut,
        pages,
        digest,
        unbounded,
        fewest,
    })
}

/// Sizes the native internal circuits of cycle `C`'s profile at rank `R`
/// and cuts each as the profile does, or as `cuts` says for the circuits it
/// names, and with `fewest` finds the fewest pages each cuts in
/// ([`Sizing::fewest`]). The circuits are only walked, so a profile need
/// not fit the rank.
///
/// # Errors
///
/// Propagates any error from walking a circuit.
#[cfg(feature = "test-utils")]
pub fn native_census<C: super::ProfiledCycle, R: Rank, const HEADER_SIZE: usize>(
    params: &C::Params,
    num_application_steps: usize,
    cuts: &[(&'static str, Cut)],
    fewest: bool,
) -> Result<Vec<Sizing>> {
    let cuts = (cuts, fewest);
    use native::circuits;

    let pages = C::Profile::PAGES;

    type Revdot<C> = native::RevdotParameters<<C as super::ProfiledCycle>::Profile>;
    let log2_circuits = native::total_circuit_counts::<C::Profile>(num_application_steps).1;
    let mut census = vec![
        sized(
            "native.hashes_1",
            pages.hashes_1,
            cuts,
            circuits::hashes_1::Circuit::<C, R, HEADER_SIZE, Revdot<C>>::new(params, log2_circuits),
        )?,
        sized(
            "native.hashes_2",
            pages.hashes_2,
            cuts,
            circuits::hashes_2::Circuit::<C, R, HEADER_SIZE, Revdot<C>>::new(params),
        )?,
        sized(
            "native.collapse",
            pages.collapse,
            cuts,
            circuits::collapse::Circuit::<C, R, HEADER_SIZE, Revdot<C>>::new(),
        )?,
        sized(
            "native.compute_v",
            pages.compute_v,
            cuts,
            circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new(),
        )?,
    ];
    // The binding circuits read different stages: each is sized.
    const BINDERS: [&str; native::NUM_BINDERS] = [
        "native.bind_challenges_0",
        "native.bind_challenges_1",
        "native.bind_challenges_2",
        "native.bind_challenges_3",
    ];
    for (k, name) in BINDERS.into_iter().enumerate() {
        census.push(crate::with_binder!(
            k,
            C,
            R,
            HEADER_SIZE,
            params,
            |circuit| sized(name, pages.bind_challenges, cuts, circuit)?
        ));
    }
    census.push(sized(
        "native.bind_beta",
        pages.bind_beta,
        cuts,
        circuits::bind_beta::Circuit::<C, R, HEADER_SIZE>::new(params),
    )?);
    census.push(sized(
        "native.bind_endoscalar",
        pages.bind_endoscalar,
        cuts,
        circuits::bind_endoscalar::Circuit::<C, R>::new(),
    )?);
    census.push(sized(
        "native.endoscaling_step",
        pages.endoscaling_step,
        cuts,
        circuits::endoscaling_step::Circuit::<C, R>::new(0),
    )?);
    Ok(census)
}

/// Sizes the nested internal circuits of cycle `C`'s profile at rank `R`,
/// as [`native_census`] does the native ones.
///
/// # Errors
///
/// Propagates any error from walking a circuit.
#[cfg(feature = "test-utils")]
pub fn nested_census<C: super::ProfiledCycle, R: Rank>(
    cuts: &[(&'static str, Cut)],
    fewest: bool,
) -> Result<Vec<Sizing>> {
    let cuts = (cuts, fewest);
    use crate::internal::nested;

    let pages = C::Profile::PAGES;
    Ok(vec![
        sized(
            "nested.collapse",
            pages.nested_collapse,
            cuts,
            MultiStage::new(nested::circuits::collapse::Circuit::<
                C::HostCurve,
                R,
                C::Profile,
            >::new()),
        )?,
        sized(
            "nested.compute_v",
            pages.nested_compute_v,
            cuts,
            MultiStage::new(nested::circuits::compute_v::Circuit::<
                C::HostCurve,
                R,
                C::Profile,
            >::new()),
        )?,
        sized(
            "nested.endoscaling_step",
            pages.nested_endoscaling_step,
            cuts,
            MultiStage::new(nested::EndoscalingStep::<C::HostCurve, R, C::Profile>::new(
                0,
            )),
        )?,
    ])
}

/// Sizes and checks every native walk step in index order. The ordinary
/// census represents the walk with its first step; this catches changes to
/// the last step's gate or carry layout as well.
///
/// # Errors
///
/// Propagates any error from walking a step. A cut failure is stored in
/// [`Sizing::pages`] so the caller can report all failed steps together.
#[cfg(feature = "test-utils")]
pub fn native_walk_census<C: super::ProfiledCycle, R: Rank>() -> Result<Vec<Sizing>> {
    let cut = C::Profile::PAGES.endoscaling_step;
    (0..native::NumSteps::<C::Profile>::len())
        .map(|step| {
            sized(
                "native.endoscaling_step",
                cut,
                (&[], false),
                native::circuits::endoscaling_step::Circuit::<C, R>::new(step),
            )
        })
        .collect()
}

/// Nested counterpart of [`native_walk_census`].
///
/// # Errors
///
/// As in [`native_walk_census`].
#[cfg(feature = "test-utils")]
pub fn nested_walk_census<C: super::ProfiledCycle, R: Rank>() -> Result<Vec<Sizing>> {
    let cut = C::Profile::PAGES.nested_endoscaling_step;
    (0..nested::NumSteps::<C::Profile>::len())
        .map(|step| {
            sized(
                "nested.endoscaling_step",
                cut,
                (&[], false),
                MultiStage::new(nested::EndoscalingStep::<C::HostCurve, R, C::Profile>::new(
                    step,
                )),
            )
        })
        .collect()
}

#[cfg(all(test, feature = "unstable-fuzzing"))]
#[path = "../../tests/profile_paging.rs"]
mod tests;
