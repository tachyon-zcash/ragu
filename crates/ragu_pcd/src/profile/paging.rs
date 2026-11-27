//! The glue between a profile's [`PageCounts`] and the fuse.
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
//! A [`PageCount`] says how many pages an unpaged circuit is cut into, each
//! loading every stage the circuit reserves, and how many values its carry
//! stage holds. Both are the profile's to state: each page is a polynomial
//! of the proof, which the circuits being paged fold and open with the
//! rest, so a count the pager chose where a circuit is registered would
//! change the circuits it had already cut. The numbers come from a census
//! pass (`native_census` and `nested_census`, with the `test-utils`
//! feature), which is run offline when a circuit or the pager changes: it
//! cuts each circuit with fewer pages until it no longer cuts, and reports
//! the fewest that do and the values they carry.
//!
//! Where the cuts fall is not stated. Registration-time paging places
//! them: the pager runs where a circuit is registered ([`Registrar`]),
//! each time a registry is built, and the pages it gives are checked
//! against the unpaged circuit before any of them is registered. The
//! search has nothing random in it and gives the same cuts on any number
//! of threads, so the cuts are a function of the circuit, of its
//! [`PageCount`], of the rank and of the pager's code. They are searched
//! for rather than pinned for three reasons:
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
//! A profile that pages nothing goes through this module too: the
//! [`Registrar`] registers its circuits whole and the [`Prover`] traces
//! them whole.
//!
//! A profile may also prove a circuit of its own extension in pages
//! ([`ExtensionPages`]), as the aggregator does each side of its
//! decompression. Nothing is appended for it: the profile's [`Extension`]
//! declares the pages, the circuit's stages and its carry stage among its
//! own entries, each page loading every stage and then the carry stage, so
//! the claims and the masks are the extension's as it declares them. The
//! [`Registrar`] takes the checked pages once for a registry build and
//! registers each at its extension circuit, and the profile's prover
//! traces them by the pages the build kept ([`Plans`]).

use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use core::ops::Range;

use ragu_circuits::{
    Blind, CircuitExt, MaskObject,
    paging::{Carry, Checked, Pageable, Pages, Planned},
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryBuilder},
    staging::{MultiStage, Stage},
};
use ragu_core::{Error, Result};
use ragu_primitives::vec::Len;
use rand::CryptoRng;
use udon::field::Field;

use super::{Extension, ExtensionRxs, PageCount, PageCounts, Profile, Registration, online};
use crate::internal::{native, nested};

/// One of the fuse's internal circuits: which one it is, and what its
/// profile pins for it, as constants of the circuit's type.
///
/// Whether a circuit is paged is then known where the circuit is compiled:
/// a profile that does not page a circuit compiles nothing of the pager
/// for it. And a circuit says which circuit it is, so no caller states it
/// beside the circuit.
pub trait Pinned {
    /// What the circuit's profile pins for it.
    const COUNT: PageCount;

    /// Whether the profile cuts the circuit into more than one page.
    const PAGED: bool = Self::COUNT.num_pages() > 1;

    /// Which of the fuse's internal circuits this one is.
    fn which(&self) -> Circuit;
}

mod pinned {
    use core::marker::PhantomData;

    use ragu_circuits::{paging::Pageable, polynomials::Rank};
    use ragu_primitives::vec::Len;
    use udon::curve::EndomorphismAffine as Affine;

    use super::{Circuit, Pinned};
    use crate::{
        internal::{native::circuits, nested, revdot},
        profile::{PageCount, Profile, ProfiledCycle},
    };

    /// Each internal circuit: its field, its profile, the count the
    /// profile pins for it, which circuit it is, and a name for the length
    /// of its carry stage. The length cannot be a type over the circuit's
    /// own, since a circuit may borrow and a length may not.
    macro_rules! pinned {
        ($(
            impl[$($generics:tt)*] $circuit:ty, over $field:ty, in $profile:ty:
                $count:ident as $carry:ident, |$this:ident| $which:expr;
        )+) => {$(
            /// The values the circuit's carry stage holds under profile
            /// `P`: what its [`PageCount`] states.
            pub struct $carry<P>(PhantomData<fn() -> P>);

            impl<P: Profile> Len for $carry<P> {
                fn len() -> usize {
                    P::PAGE_COUNTS.$count.carry()
                }
            }

            impl<$($generics)*> Pageable<$field, R> for $circuit {
                type Carry = $carry<$profile>;
            }

            impl<$($generics)*> Pinned for $circuit {
                const COUNT: PageCount = <$profile as Profile>::PAGE_COUNTS.$count;

                fn which(&self) -> Circuit {
                    let $this = self;
                    $which
                }
            }
        )+};
    }

    /// A step's or a binder's index, which is small.
    fn index(index: usize) -> u32 {
        u32::try_from(index).expect("an internal circuit's index fits a u32")
    }

    pinned! {
        impl[C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: revdot::Parameters]
            circuits::hashes_1::Circuit<'_, C, R, HEADER_SIZE, FP>,
            over C::CircuitField, in C::Profile: hashes_1 as Hashes1, |_this| Circuit::Hashes1;
        impl[C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: revdot::Parameters]
            circuits::hashes_2::Circuit<'_, C, R, HEADER_SIZE, FP>,
            over C::CircuitField, in C::Profile: hashes_2 as Hashes2, |_this| Circuit::Hashes2;
        impl[C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: revdot::Parameters]
            circuits::collapse::Circuit<C, R, HEADER_SIZE, FP>,
            over C::CircuitField, in C::Profile: collapse as Collapse, |_this| Circuit::Collapse;
        impl[C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize]
            circuits::compute_v::Circuit<C, R, HEADER_SIZE>,
            over C::CircuitField, in C::Profile: compute_v as ComputeV, |_this| Circuit::ComputeV;
        impl[C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, const K: usize]
            circuits::bind_challenges::Circuit<'_, C, R, HEADER_SIZE, K>,
            over C::CircuitField, in C::Profile: bind_challenges as BindChallenges,
            |_this| Circuit::BindChallenges(index(K));
        impl[C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize]
            circuits::bind_beta::Circuit<'_, C, R, HEADER_SIZE>,
            over C::CircuitField, in C::Profile: bind_beta as BindBeta, |_this| Circuit::BindBeta;
        impl[C: ProfiledCycle, R: Rank]
            circuits::bind_endoscalar::Circuit<C, R>,
            over C::CircuitField, in C::Profile: bind_endoscalar as BindEndoscalar,
            |_this| Circuit::BindEndoscalar;
        impl[C: ProfiledCycle, R: Rank]
            circuits::endoscaling_step::Circuit<C, R>,
            over C::CircuitField, in C::Profile: endoscaling_step as EndoscalingStep,
            |this| Circuit::EndoscalingStep(index(this.step()));
        impl[C: Affine, R: Rank, P: Profile]
            nested::circuits::collapse::Circuit<C, R, P>,
            over C::Base, in P: nested_collapse as NestedCollapse, |_this| Circuit::NestedCollapse;
        impl[C: Affine, R: Rank, P: Profile]
            nested::circuits::compute_v::Circuit<C, R, P>,
            over C::Base, in P: nested_compute_v as NestedComputeV, |_this| Circuit::NestedComputeV;
        impl[C: Affine, R: Rank, P: Profile]
            nested::EndoscalingStep<C, R, P>,
            over C::Base, in P: nested_endoscaling_step as NestedEndoscalingStep,
            |this| Circuit::NestedEndoscalingStep(index(this.step()));
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
    fn paged<P: Profile>(nested: bool) -> Vec<(Self, PageCount)> {
        let pages = &P::PAGE_COUNTS;
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
        let steps = if step(0).count(pages).num_pages() > 1 {
            steps
        } else {
            0
        };
        circuits
            .into_iter()
            .chain((0..steps as u32).map(step))
            .map(|circuit| (circuit, circuit.count(pages)))
            .filter(|&(_, count)| count.num_pages() > 1)
            .collect()
    }

    /// The registry index of the circuit's own slot in profile `P`.
    fn own<P: Profile>(self) -> CircuitIndex {
        use native::InternalCircuitIndex as Native;
        use nested::InternalCircuitIndex as Nested;
        match self {
            Self::Hashes1 => Native::Hashes1Circuit.circuit_index::<P>(),
            Self::Hashes2 => Native::Hashes2Circuit.circuit_index::<P>(),
            Self::Collapse => Native::CollapseCircuit.circuit_index::<P>(),
            Self::ComputeV => Native::ComputeVCircuit.circuit_index::<P>(),
            Self::BindChallenges(k) => Native::BindChallengesCircuit(k).circuit_index::<P>(),
            Self::BindBeta => Native::BindBetaCircuit.circuit_index::<P>(),
            Self::BindEndoscalar => Native::BindEndoscalarCircuit.circuit_index::<P>(),
            Self::EndoscalingStep(step) => Native::EndoscalingStep(step).circuit_index::<P>(),
            Self::NestedCollapse => Nested::Collapse.circuit_index::<P>(),
            Self::NestedComputeV => Nested::ComputeV.circuit_index::<P>(),
            Self::NestedEndoscalingStep(step) => Nested::EndoscalingStep(step).circuit_index::<P>(),
        }
    }

    /// How `pages` cuts the circuit.
    const fn count(self, pages: &PageCounts) -> PageCount {
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
pub(crate) const fn added(count: PageCount) -> usize {
    if count.num_pages() > 1 {
        count.num_pages()
    } else {
        0
    }
}

/// The polynomials paging adds to one side's extension, the walk's steps
/// aside: for each paged circuit, one for each page before the last and
/// the carry stage's. A paged step adds [`added`] to each of the walk's
/// steps, which the profile's [`Shape`](super::Shape) counts with them.
pub(crate) const fn rxs(pages: &PageCounts, nested: bool) -> usize {
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
pub(crate) struct Placement {
    /// The circuit.
    pub circuit: Circuit,
    /// What its profile pins for it.
    pub count: PageCount,
    /// The extension circuits that are its pages before the last, in
    /// order.
    pub circuits: Range<u32>,
    /// The extension stage that is its carry stage.
    pub carry: u32,
    /// The extension mask over every page's own gates, which holds each
    /// page's polynomial off the stages and off the carry stage.
    pub mask: u32,
}

impl Placement {
    /// The last page.
    pub(crate) fn last(&self) -> usize {
        self.count.num_pages() - 1
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
fn placements_over<P: Profile>(base: &Extension, nested: bool) -> Vec<Placement> {
    let paged = Circuit::paged::<P>(nested);
    let mut circuit = base.circuits.len() as u32;
    let mut carry = base.stages as u32;
    let mut mask = (base.stages + paged.len() + base.final_masks.len()) as u32;
    paged
        .iter()
        .map(|&(which, count)| {
            let circuits = circuit..circuit + count.num_pages() as u32 - 1;
            circuit = circuits.end;
            let placement = Placement {
                circuit: which,
                count,
                circuits,
                carry,
                mask,
            };
            carry += 1;
            mask += 1;
            placement
        })
        .collect()
}

/// Where each of one side's paged circuits' entries sit, in the circuits'
/// order; nothing for a profile that pages none.
pub(crate) fn placements<P: Profile>(nested: bool) -> Vec<Placement> {
    super::extended::<P>(nested).placements.clone()
}

/// Appends paging's entries to one side's extension. A circuit's pages'
/// mask is declared as a final mask over the extension circuits that are
/// its pages before the last; the last page's polynomial is the circuit's
/// own, which the claims add to the mask's.
pub(crate) fn extend<P: Profile>(extension: &mut Extension, nested: bool) -> Vec<Placement> {
    let placements = placements_over::<P>(extension, nested);
    for placement in &placements {
        extension
            .circuits
            .extend((0..placement.last()).map(|_| vec![placement.carry]));
        extension.stages += 1;
    }
    for placement in &placements {
        extension
            .final_masks
            .push(placement.circuits.clone().collect());
    }
    placements
}

fn refuse<T>(circuit: impl core::fmt::Debug, what: String) -> Result<T> {
    Err(Error::Initialization(
        format!("the profile's paging of {circuit:?} {what}").into(),
    ))
}

/// Refuses a circuit whose pages do not have the room, by name.
fn room<T>(which: impl core::fmt::Debug + Copy, cut: Result<T>) -> Result<T> {
    match cut {
        Err(Error::GateBoundExceeded { limit }) => refuse(
            which,
            format!(
                "leaves its pages less room than the circuit takes, in polynomials of {limit} \
                 gates"
            ),
        ),
        cut => cut,
    }
}

/// Cuts `circuit` into `pages` pages, in polynomials of rank `R`. The carry
/// stage's size is the circuit's own ([`Pageable`]), which is its count's
/// in its profile.
fn split<F: Field, R: Rank, S: Pageable<F, R>>(
    which: impl core::fmt::Debug + Copy,
    circuit: impl Into<alloc::sync::Arc<MultiStage<F, R, S>>>,
    pages: usize,
) -> Result<Pages<F, R, S>> {
    room(which, Pages::cut(circuit, pages))
}

/// As [`split`], in polynomials of `limit` gates.
#[cfg(feature = "test-utils")]
fn split_within<F: Field, R: Rank, S: Pageable<F, R>>(
    which: impl core::fmt::Debug + Copy,
    circuit: impl Into<alloc::sync::Arc<MultiStage<F, R, S>>>,
    pages: usize,
    limit: usize,
) -> Result<Pages<F, R, S>> {
    room(which, Pages::cut_within(circuit, pages, limit))
}

/// Cuts `circuits`, which their profile pages, at once
/// ([`Registrar::warm`]). A circuit that does not cut is left out.
fn warm<F: Field, R: Rank, S>(circuits: Vec<MultiStage<F, R, S>>) -> Vec<(Circuit, Planned<F>)>
where
    S: Pageable<F, R> + Pinned,
    MultiStage<F, R, S>: Send,
{
    use maybe_rayon::prelude::*;

    circuits
        .into_par_iter()
        .filter_map(|circuit| {
            let which = circuit.inner().which();
            let paged = split(which, circuit, S::COUNT.num_pages()).ok()?;
            Some((which, paged.plan()))
        })
        .collect()
}

/// Refuses pages that are not what the circuit's profile pins: as many,
/// over a carry stage of the size pinned.
///
/// The registry has a slot for each page the profile declares, and
/// registers and proves that many. How many pages a plan has is the
/// pager's to say, and whatever kept the plan, so it is held to the pin
/// here: with a page more, the pages would check, and one of them would
/// not be registered.
fn held_to_pin<F: Field, R: Rank, S: Pageable<F, R> + Pinned>(
    which: Circuit,
    paged: &Pages<F, R, S>,
) -> Result<()> {
    let (pages, carry) = (paged.num_pages(), paged.stages().carry);
    if pages != S::COUNT.num_pages() || carry != S::COUNT.carry() {
        return refuse(
            which,
            format!(
                "is in {pages} pages over a carry stage of {carry} values, where its profile \
                 pins {} and {}",
                S::COUNT.num_pages(),
                S::COUNT.carry()
            ),
        );
    }
    Ok(())
}

/// Where paged circuit `which`, of type `S`, is among `placements`, held
/// to the count its type pins.
fn placed<S: Pinned>(placements: &[Placement], which: Circuit) -> Result<usize> {
    match placements
        .iter()
        .position(|placement| placement.circuit == which)
    {
        Some(position) if placements[position].count == S::COUNT => Ok(position),
        _ => refuse(
            which,
            "is not the circuit its profile pins the pages of".into(),
        ),
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
    placements: Vec<Placement>,
    /// The stages and final masks of the extension before paging's entries.
    base: (usize, usize),
    pending: Vec<Option<Pending<'params, F, R>>>,
    /// The pages of the circuits cut ahead of their registration
    /// ([`warm`](Self::warm)), until each is registered.
    warmed: Vec<Option<Planned<F>>>,
    /// The pages each paged circuit was cut into, once it is registered.
    plans: Plans<F>,
    /// The profile's extension circuits in pages, each page until it is
    /// registered.
    extension: Vec<ExtensionPages<'params, F, R>>,
}

/// The pages one side's paged circuits were cut into where they were
/// registered: what a prover of the same application pages them by, so
/// that a proof cuts nothing again. A circuit it does not hold is cut
/// where it is proven.
#[derive(Clone, Debug)]
pub struct Plans<F: Field> {
    /// The fuse's circuits', by paged circuit.
    fuse: Vec<Option<Planned<F>>>,
    /// The pages of the extension's paged circuits, in the order the
    /// profile gave them ([`Profile::native_extension_pages`]).
    extension: Vec<Planned<F>>,
}

impl<F: Field> Default for Plans<F> {
    fn default() -> Self {
        Plans {
            fuse: Vec::new(),
            extension: Vec::new(),
        }
    }
}

impl<F: Field> Plans<F> {
    /// The pages of the extension's paged circuits, in the order the
    /// profile gave them.
    pub(crate) fn extension(&self) -> &[Planned<F>] {
        &self.extension
    }
}

/// One of a profile's extension circuits in pages, for one registry build:
/// cut, held to the unpaged circuit, and each page left to register at the
/// extension circuit its profile declares for it.
///
/// It is made of [`Checked`] pages alone, so a registry takes no page of an
/// extension circuit that the check did not hold to the circuit, and it is
/// held to the count its profile pins where it is made. The registry build
/// then registers each page once and refuses to finish with a page left
/// (`Registrar::finish`), so every page's claim is one of the proof's.
///
/// The profile's [`Extension`] declares the rest, as it does for any
/// circuit of its own: each page a circuit that loads the unpaged
/// circuit's stages and then its carry stage, and the carry stage's final
/// mask over the pages. The registration is checked against that
/// declaration as any staged circuit's is
/// (`Extension::check_registered`).
pub struct ExtensionPages<'params, F: Field, R: Rank> {
    /// The extension circuits that are the pages, in order.
    circuits: Range<u32>,
    /// The pages left to register.
    pages: Vec<Option<Register<'params, F, R>>>,
    /// The gates of each stage a page loads, the carry stage's last.
    stages: Vec<Range<usize>>,
    planned: Planned<F>,
}

impl<'params, F: Field, R: Rank> ExtensionPages<'params, F, R> {
    /// The pages of `checked`, at the extension circuits from `first` on,
    /// the last page's last.
    ///
    /// # Errors
    ///
    /// Fails if the pages are not as many as `count` pins, or if their
    /// carry stage is not of the size it pins.
    pub fn new<S>(first: u32, count: PageCount, checked: &Checked<F, R, S>) -> Result<Self>
    where
        S: Pageable<F, R>,
        MultiStage<F, R, S>: 'params,
    {
        let paged = checked.pages();
        let (pages, carry) = (paged.num_pages(), paged.stages().carry);
        if pages != count.num_pages() || carry != count.carry() {
            return refuse(
                format_args!("extension circuit {first}"),
                format!(
                    "is in {pages} pages over a carry stage of {carry} values, where its profile \
                     pins {} and {}",
                    count.num_pages(),
                    count.carry()
                ),
            );
        }
        let last = pages - 1;
        let registers = (0..pages)
            .map(|page| {
                // A page before the last ends its output with a zero of
                // its own; the last carries the circuit's output, which
                // takes the zero every extension circuit's ends with.
                let register: Register<'params, F, R> = if page < last {
                    let page = checked.page(page);
                    Box::new(move |registry| registry.register_internal_circuit(page))
                } else {
                    let page = checked.last();
                    Box::new(move |registry| {
                        registry.register_internal_circuit(super::Suffixed(page))
                    })
                };
                Some(register)
            })
            .collect();
        Ok(ExtensionPages {
            circuits: first..first + pages as u32,
            pages: registers,
            stages: <Carry<F, R, S> as Stage<F, R>>::gate_ranges(),
            planned: paged.plan(),
        })
    }

    /// The page extension circuit `circuit` is, if one of these.
    fn page(&self, circuit: u32) -> Option<usize> {
        self.circuits
            .contains(&circuit)
            .then(|| (circuit - self.circuits.start) as usize)
    }
}

impl<'params, F: Field, R: Rank> Registrar<'params, F, R> {
    /// A registrar for one side of profile `P`.
    pub(crate) fn new<P: Profile>(nested: bool) -> Self {
        let base = base::<P>(nested);
        let placements = placements_over::<P>(&base, nested);
        Registrar {
            pending: placements.iter().map(|_| None).collect(),
            warmed: placements.iter().map(|_| None).collect(),
            plans: Plans {
                fuse: placements.iter().map(|_| None).collect(),
                extension: Vec::new(),
            },
            placements,
            base: (base.stages, base.final_masks.len()),
            extension: Vec::new(),
        }
    }

    /// Takes the profile's extension circuits in pages
    /// ([`Profile::native_extension_pages`]), to register each page at its
    /// extension circuit ([`page`](Self::page)).
    ///
    /// # Errors
    ///
    /// Fails if two of them take one extension circuit.
    pub(crate) fn declare(&mut self, extension: Vec<ExtensionPages<'params, F, R>>) -> Result<()> {
        for (index, pages) in extension.iter().enumerate() {
            let overlaps = |other: &ExtensionPages<'params, F, R>| {
                pages.circuits.start < other.circuits.end
                    && other.circuits.start < pages.circuits.end
            };
            if extension[..index].iter().any(overlaps) {
                return refuse(
                    format_args!("extension circuit {}", pages.circuits.start),
                    "takes an extension circuit another paged circuit takes".into(),
                );
            }
        }
        self.plans.extension = extension
            .iter()
            .map(|pages| pages.planned.clone())
            .collect();
        self.extension = extension;
        Ok(())
    }

    /// The pages every paged circuit was cut into, once every circuit is
    /// registered.
    ///
    /// # Errors
    ///
    /// Fails if a page of an extension circuit was not registered: its
    /// profile's extension declares fewer circuits than the pages take.
    pub(crate) fn finish(self) -> Result<Plans<F>> {
        for pages in &self.extension {
            if let Some(page) = pages.pages.iter().position(Option::is_some) {
                return refuse(
                    format_args!("extension circuit {}", pages.circuits.start),
                    format!("leaves its page {page} unregistered"),
                );
            }
        }
        Ok(self.plans)
    }

    /// Cuts `circuits` ahead of their registration, at once, and keeps
    /// their pages for [`circuit`](Self::circuit) to register. It is for
    /// circuits that are many of a kind, as a walk's steps are, and does
    /// nothing for a circuit its profile does not page. A circuit that
    /// does not cut is refused where it is registered.
    pub(crate) fn warm<S>(&mut self, circuits: Vec<MultiStage<F, R, S>>)
    where
        S: Pageable<F, R> + Pinned,
        MultiStage<F, R, S>: Send,
    {
        if const { S::PAGED } {
            for (which, planned) in warm::<F, R, S>(circuits) {
                if let Ok(position) = placed::<S>(&self.placements, which) {
                    self.warmed[position] = Some(planned);
                }
            }
        }
    }

    /// Registers internal circuit `circuit`: whole, or its last page.
    /// Whether it is paged is a constant of its type ([`Pinned`]), so the
    /// paged branch is compiled only for a circuit its profile pages.
    ///
    /// # Errors
    ///
    /// Fails if the circuit does not cut into the pages its profile
    /// declares, or if a page cannot be registered.
    pub fn circuit<S>(
        &mut self,
        registry: RegistryBuilder<'params, F, R>,
        circuit: MultiStage<F, R, S>,
    ) -> Result<RegistryBuilder<'params, F, R>>
    where
        S: Pageable<F, R> + Pinned,
        MultiStage<F, R, S>: 'params,
    {
        if const { S::PAGED } {
            self.paged(registry, circuit)
        } else {
            registry.register_internal_circuit(circuit)
        }
    }

    /// Registers a paged circuit: its last page, and keeps the others.
    fn paged<S>(
        &mut self,
        registry: RegistryBuilder<'params, F, R>,
        circuit: MultiStage<F, R, S>,
    ) -> Result<RegistryBuilder<'params, F, R>>
    where
        S: Pageable<F, R> + Pinned,
        MultiStage<F, R, S>: 'params,
    {
        let which = circuit.inner().which();
        let position = placed::<S>(&self.placements, which)?;
        let placement = &self.placements[position];
        let paged = match self.warmed[position].take() {
            Some(planned) => Pages::planned(circuit, &planned),
            None => split(which, circuit, S::COUNT.num_pages())?,
        };
        // The pages are held to the profile's pin and to the circuit they
        // were cut from before any is registered, so nothing that chose
        // the cuts is trusted: only checked pages hand out a circuit to
        // register.
        held_to_pin(which, &paged)?;
        let checked = paged.check()?;
        let paged = checked.pages();
        self.plans.fuse[position] = Some(paged.plan());
        let layout = paged.layout();
        let mask = Some((paged.page_mask()?, layout.carry.end));
        let pages = (0..placement.last())
            .map(|page| {
                let page = checked.page(page);
                let register: Register<'params, F, R> =
                    Box::new(move |registry| registry.register_internal_circuit(page));
                Some(register)
            })
            .collect();
        let carry = (Some(paged.carry_mask()?), layout.carry.clone());
        self.pending[position] = Some(Pending { pages, carry, mask });
        registry.register_internal_circuit(checked.last())
    }

    /// Whether extension circuit `circuit` is a page: of one of the fuse's
    /// circuits, or of one of the profile's extension circuits.
    pub(crate) fn is_page(&self, circuit: u32) -> bool {
        self.placements
            .iter()
            .any(|placement| placement.page(circuit).is_some())
            || self
                .extension
                .iter()
                .any(|pages| pages.page(circuit).is_some())
    }

    fn pending(&mut self, position: usize) -> Result<&mut Pending<'params, F, R>> {
        let which = self.placements[position].circuit;
        match self.pending[position].as_mut() {
            Some(pending) => Ok(pending),
            None => refuse(which, "has a page registered before the circuit is".into()),
        }
    }

    /// Registers extension circuit `circuit`, a page: one of the fuse's
    /// circuits', over its carry stage, or one of the profile's extension
    /// circuits', over the stages its circuit loads and its carry stage.
    pub(crate) fn page(
        &mut self,
        registry: RegistryBuilder<'params, F, R>,
        circuit: u32,
    ) -> Result<(RegistryBuilder<'params, F, R>, Registration)> {
        let declared = self
            .extension
            .iter_mut()
            .find_map(|pages| Some((pages.page(circuit)?, pages)));
        if let Some((page, pages)) = declared {
            let Some(register) = pages.pages[page].take() else {
                return refuse(
                    format_args!("extension circuit {circuit}"),
                    "registers a page twice".into(),
                );
            };
            return Ok((
                register(registry)?,
                Registration::Staged(pages.stages.clone()),
            ));
        }
        let (position, page) = self
            .placements
            .iter()
            .enumerate()
            .find_map(|(position, placement)| Some((position, placement.page(circuit)?)))
            .expect("a page");
        let placement = self.placements[position].clone();
        let pending = self.pending(position)?;
        let Some(register) = pending.pages[page].take() else {
            return refuse(placement.circuit, "registers a page twice".into());
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
        let paged = self.placements.len();
        if index < stages {
            return Ok(Slotted::Other(registry, index));
        }
        if index < stages + paged {
            let position = self
                .placements
                .iter()
                .position(|placement| placement.carry as usize == index)
                .expect("the carry stage of one of the paged circuits");
            let which = self.placements[position].circuit;
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
            .placements
            .iter()
            .position(|placement| placement.mask as usize == index);
        let Some(position) = found else {
            return Err(Error::Initialization(
                format!("the extension has no mask {index}").into(),
            ));
        };
        let which = self.placements[position].circuit;
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
    placements: Vec<Placement>,
    /// The pages the circuits were cut into where they were registered.
    plans: Plans<F>,
    /// The pages' polynomials before each circuit's last, by paged circuit.
    pages: Vec<Option<Vec<sparse::Polynomial<F, R>>>>,
    /// The carry stage's polynomial, by paged circuit.
    carries: Vec<Option<sparse::Polynomial<F, R>>>,
    /// The registry index of an internal circuit's own slot, and of an
    /// extension circuit, on the prover's side of its profile.
    own: fn(Circuit) -> CircuitIndex,
    extension: fn(u32) -> CircuitIndex,
}

impl<F: Field, R: Rank> Prover<F, R> {
    /// A prover for one side of profile `P`, which pages the circuits as
    /// `plans` holds them.
    pub(crate) fn new<P: Profile>(nested: bool, plans: &Plans<F>) -> Self {
        let placements = placements::<P>(nested);
        Prover {
            pages: placements.iter().map(|_| None).collect(),
            carries: placements.iter().map(|_| None).collect(),
            plans: plans.clone(),
            placements,
            own: Circuit::own::<P>,
            extension: if nested {
                |circuit| {
                    nested::InternalCircuitIndex::ExtensionCircuit(circuit).circuit_index::<P>()
                }
            } else {
                |circuit| {
                    native::InternalCircuitIndex::ExtensionCircuit(circuit).circuit_index::<P>()
                }
            },
        }
    }

    /// Traces internal circuit `circuit` and assembles its polynomial: the
    /// circuit's own, or its last page's in its place and the other pages'
    /// at their extension circuits. `witness` is asked for once, or twice
    /// for a circuit in pages. As in [`Registrar::circuit`], the paged
    /// branch is compiled only for a circuit its profile pages.
    ///
    /// # Errors
    ///
    /// Propagates any error from cutting, tracing or assembling.
    pub fn prove<'source, S, RNG>(
        &mut self,
        circuit: MultiStage<F, R, S>,
        registry: &Registry<'_, F, R>,
        witness: impl Fn() -> S::Witness<'source>,
        rng: &mut RNG,
    ) -> Result<(sparse::Polynomial<F, R>, S::Aux<'source>)>
    where
        S: Pageable<F, R> + Pinned,
        RNG: CryptoRng,
    {
        if const { S::PAGED } {
            self.paged(circuit, registry, witness, rng)
        } else {
            let own = (self.own)(circuit.inner().which());
            let (trace, aux) = circuit.trace(witness())?.into_parts();
            Ok((registry.assemble(&trace, own, rng)?, aux))
        }
    }

    /// Traces a paged circuit: each page, and the carry stage's values.
    fn paged<'source, S, RNG>(
        &mut self,
        circuit: MultiStage<F, R, S>,
        registry: &Registry<'_, F, R>,
        witness: impl Fn() -> S::Witness<'source>,
        rng: &mut RNG,
    ) -> Result<(sparse::Polynomial<F, R>, S::Aux<'source>)>
    where
        S: Pageable<F, R> + Pinned,
        RNG: CryptoRng,
    {
        let which = circuit.inner().which();
        let (own, extension) = ((self.own)(which), self.extension);
        let position = placed::<S>(&self.placements, which)?;
        let placement = &self.placements[position];
        let paged = match self.plans.fuse.get(position) {
            Some(Some(planned)) => Pages::planned(circuit, planned),
            _ => split(which, circuit, S::COUNT.num_pages())?,
        };
        held_to_pin(which, &paged)?;

        // One walk of the circuit gives every page before the last the
        // values of its gates, and the carry stage its values; the last
        // page walks it once more, for the public output.
        let captured = paged.capture(witness())?;
        let mut pages = Vec::with_capacity(placement.circuits.len());
        for (page, circuit) in placement.circuits.clone().enumerate() {
            let trace = paged.trace_page(page, &captured.pages[page])?;
            pages.push(registry.assemble(&trace, extension(circuit), &mut *rng)?);
        }
        let (last, aux) = paged.trace_last(witness())?.into_parts();
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
        for ((placement, pages), carry) in self.placements.iter().zip(self.pages).zip(self.carries)
        {
            let (Some(pages), Some(carry)) = (pages, carry) else {
                return refuse(placement.circuit, "was not proven".into());
            };
            rxs.circuits.extend(pages);
            rxs.stages.push(carry);
        }
        Ok(())
    }
}

/// How one of the fuse's internal circuits sizes up, and what its profile
/// pins for it.
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
    /// What its profile pins for it.
    pub count: PageCount,
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
    /// ([`Pages::digest`]), where it cuts: what tells one cut of the
    /// circuit from another.
    pub digest: Option<[u8; 32]>,
    /// For a circuit that does not cut: how it would spread over the same
    /// pages in polynomials of [`SLACK`] more gates, if it then cuts, which
    /// tells what its pages are short of.
    pub unbounded: Option<ragu_circuits::paging::PagingReport>,
    /// Where the census was asked for them, the fewest pages the circuit
    /// cuts in; nothing if it does not cut in [`RAISES`] more than its
    /// count's. They are the fewest for the profile as it is: a profile that
    /// takes them has fewer polynomials, which its circuits then cut with
    /// too, and may then cut in fewer still.
    pub fewest: Option<usize>,
}

/// How many more pages a census tries for a circuit that does not cut,
/// where it is asked for the fewest.
#[cfg(feature = "test-utils")]
pub const RAISES: usize = 16;

/// `circuit` in `pages` pages as a registry takes them: cut, held to the
/// circuit, and each page with a wiring polynomial at rank `R`, which is
/// where a page that writes more gates or enforces more constraints than
/// the rank has is refused. A cut alone budgets a page's own gates. Gives
/// the pages and their digest.
#[cfg(feature = "test-utils")]
fn accepted<F: Field, R: Rank, S: Pageable<F, R>>(
    name: &'static str,
    circuit: alloc::sync::Arc<MultiStage<F, R, S>>,
    pages: usize,
) -> Result<(ragu_circuits::paging::Checked<F, R, S>, [u8; 32])> {
    let checked = split(name, circuit, pages)?.check()?;
    let digest = checked.pages().digest()?;
    Ok((checked, digest))
}

/// The fewest pages a registry takes `circuit` in ([`accepted`]): raised
/// from `count`'s until it does, then lowered for as long as it still
/// does, to one at the least.
#[cfg(feature = "test-utils")]
fn fewest<F: Field, R: Rank, S: Pageable<F, R>>(
    name: &'static str,
    circuit: &alloc::sync::Arc<MultiStage<F, R, S>>,
    count: PageCount,
) -> Option<usize> {
    let cuts = |pages: usize| accepted(name, circuit.clone(), pages).is_ok();
    let mut pages = count.num_pages();
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

/// Sizes `circuit`, an unpaged circuit named `name`, and cuts it as `count`
/// pins, or as `counts` says if they name it; with `solve` finds the
/// fewest pages it cuts in ([`Sizing::fewest`]).
#[cfg(feature = "test-utils")]
pub(crate) fn sized<F: Field, R: Rank, S: Pageable<F, R>>(
    name: &'static str,
    count: PageCount,
    (counts, solve): (&[(&'static str, PageCount)], bool),
    circuit: MultiStage<F, R, S>,
) -> Result<Sizing> {
    let circuit = alloc::sync::Arc::new(circuit);
    let count = counts
        .iter()
        .find(|(of, _)| *of == name)
        .map_or(count, |&(_, count)| count);
    let (gates, constraints) = ragu_circuits::paging::size(&*circuit)?;
    let stages = ragu_circuits::paging::Stages::of::<F, R, S>();
    let mut digest = None;
    let pages = accepted(name, circuit.clone(), count.num_pages())
        .map(|(checked, pages)| {
            digest = Some(pages);
            let paged = checked.pages();
            (paged.layout().clone(), paged.report().clone())
        })
        .map_err(|error| format!("{error:?}"));
    let fewest = solve.then(|| fewest(name, &circuit, count)).flatten();
    let unbounded = match pages {
        Ok(_) => None,
        Err(_) => split_within(name, circuit, count.num_pages(), R::blind_gate() + SLACK)
            .ok()
            .map(|paged| paged.report().clone()),
    };
    Ok(Sizing {
        name,
        gates,
        constraints,
        own: gates.saturating_sub(stages.own_start()),
        stages: stages.spans,
        count,
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
    counts: &[(&'static str, PageCount)],
    fewest: bool,
) -> Result<Vec<Sizing>> {
    let counts = (counts, fewest);
    use native::circuits;

    let pages = C::Profile::PAGE_COUNTS;

    type Revdot<C> = native::RevdotParameters<<C as super::ProfiledCycle>::Profile>;
    let log2_circuits = native::total_circuit_counts::<C::Profile>(num_application_steps).1;
    let mut census = vec![
        sized(
            "native.hashes_1",
            pages.hashes_1,
            counts,
            circuits::hashes_1::Circuit::<C, R, HEADER_SIZE, Revdot<C>>::new(params, log2_circuits),
        )?,
        sized(
            "native.hashes_2",
            pages.hashes_2,
            counts,
            circuits::hashes_2::Circuit::<C, R, HEADER_SIZE, Revdot<C>>::new(params),
        )?,
        sized(
            "native.collapse",
            pages.collapse,
            counts,
            circuits::collapse::Circuit::<C, R, HEADER_SIZE, Revdot<C>>::new(),
        )?,
        sized(
            "native.compute_v",
            pages.compute_v,
            counts,
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
            |circuit| sized(name, pages.bind_challenges, counts, circuit)?
        ));
    }
    census.push(sized(
        "native.bind_beta",
        pages.bind_beta,
        counts,
        circuits::bind_beta::Circuit::<C, R, HEADER_SIZE>::new(params),
    )?);
    census.push(sized(
        "native.bind_endoscalar",
        pages.bind_endoscalar,
        counts,
        circuits::bind_endoscalar::Circuit::<C, R>::new(),
    )?);
    census.push(sized(
        "native.endoscaling_step",
        pages.endoscaling_step,
        counts,
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
    counts: &[(&'static str, PageCount)],
    fewest: bool,
) -> Result<Vec<Sizing>> {
    let counts = (counts, fewest);
    use crate::internal::nested;

    let pages = C::Profile::PAGE_COUNTS;
    Ok(vec![
        sized(
            "nested.collapse",
            pages.nested_collapse,
            counts,
            MultiStage::new(nested::circuits::collapse::Circuit::<
                C::HostCurve,
                R,
                C::Profile,
            >::new()),
        )?,
        sized(
            "nested.compute_v",
            pages.nested_compute_v,
            counts,
            MultiStage::new(nested::circuits::compute_v::Circuit::<
                C::HostCurve,
                R,
                C::Profile,
            >::new()),
        )?,
        sized(
            "nested.endoscaling_step",
            pages.nested_endoscaling_step,
            counts,
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
    let count = C::Profile::PAGE_COUNTS.endoscaling_step;
    (0..native::NumSteps::<C::Profile>::len())
        .map(|step| {
            sized(
                "native.endoscaling_step",
                count,
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
    let count = C::Profile::PAGE_COUNTS.nested_endoscaling_step;
    (0..nested::NumSteps::<C::Profile>::len())
        .map(|step| {
            sized(
                "nested.endoscaling_step",
                count,
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
