//! Experimental: the glue between a profile's [`Pages`] and the fuse.
//!
//! A profile that pages an internal circuit gets, after everything its
//! extension declares and the online batch adds: an extension circuit for
//! each page before the last, each loading one more extension stage, the
//! circuit's carry stage, and a mask over the gates of each page's own. The
//! last page takes the circuit's own slot, with the circuit's instance. So
//! the pages' polynomials, commitments and claims are the extension's,
//! which the fuse already carries for any profile; what is left for the
//! fuse is to go through this module where it registers, claims and proves
//! its circuits:
//!
//! - registration ([`Registrar`]): a circuit whole, or its last page in
//!   its slot and the other pages, the carry stage's mask and the pages'
//!   masks in the extension's;
//! - claims: a page loads the stages of its circuit that its profile says
//!   it does beside the carry stage, the circuit's claim is its last
//!   page's, and a mask covers the polynomials of the pages it is for, the
//!   circuit's own among them, which is its last page's;
//! - proving ([`Prover`]): a trace per page, and the carry stage's values
//!   off them and off the stages some page does not load.
//!
//! A profile may tell a page to hold no gates of its circuit's own
//! ([`Cut::idle`]): it loads stages the other pages do not and holds the
//! carry stage to what they read of them.
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
    paging::{Paged, Stages},
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryBuilder},
    staging::{MultiStage, MultiStageCircuit},
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
        polynomials::{Rank, sparse::Polynomial},
        registry::{CircuitIndex, Registry, RegistryBuilder},
        staging::{MultiStage, MultiStageCircuit},
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
            S: $crate::profile::paging::deps::MultiStageCircuit<F, R>,
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
            stages: &[&$crate::profile::paging::deps::Polynomial<F, R>],
            witness: impl Fn() -> S::Witness<'source>,
            rng: &mut RNG,
        ) -> $crate::profile::paging::deps::Result<(
            $crate::profile::paging::deps::Polynomial<F, R>,
            S::Aux<'source>,
        )>
        where
            F: $crate::profile::paging::deps::Field,
            R: $crate::profile::paging::deps::Rank,
            S: $crate::profile::paging::deps::MultiStageCircuit<F, R>,
            RNG: $crate::profile::paging::deps::CryptoRng,
        {
            pages.prove(
                which, circuit, registry, own, extension, stages, witness, rng,
            )
        }
    };
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
        let steps = if step(0).cut(pages).pages > 1 {
            steps
        } else {
            0
        };
        circuits
            .into_iter()
            .chain((0..steps as u32).map(step))
            .map(|circuit| (circuit, circuit.cut(pages)))
            .filter(|&(_, cut)| cut.pages > 1)
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

    /// Whether the circuit's claims can tell the stages each page loads:
    /// the nested circuits' and those of the native circuits over the
    /// points stages, whose claims list the stages they reserve.
    const fn tells_loads(self) -> bool {
        matches!(
            self,
            Self::NestedCollapse
                | Self::NestedComputeV
                | Self::BindEndoscalar
                | Self::EndoscalingStep(_)
                | Self::NestedEndoscalingStep(_)
        )
    }

    /// Whether the circuit's own polynomial stays under the final mask of
    /// its last stage when it is paged, so that its last page keeps clear
    /// of that stage. A paged step's is under its pages' mask alone.
    pub(crate) const fn sealed(self) -> bool {
        !matches!(
            self,
            Self::EndoscalingStep(_) | Self::NestedEndoscalingStep(_)
        )
    }
}

/// The polynomials paging adds for a circuit cut by `cut`: one for each
/// page before the last, and the carry stage's.
pub(crate) const fn added(cut: Cut) -> usize {
    if cut.pages > 1 { cut.pages } else { 0 }
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
    /// The extension masks that are the masks of its pages' own
    /// polynomials, each with the pages it is for.
    pub masks: Vec<(u32, Vec<usize>)>,
}

impl Slot {
    /// The entries of `chain`, the stages the circuit reserves in order,
    /// that page `page` loads.
    pub(crate) fn loads<T: Copy>(&self, page: usize, chain: &[T]) -> Vec<T> {
        match self.cut.loads.get(page) {
            Some(loads) => loads.iter().map(|&stage| chain[stage as usize]).collect(),
            None => chain.to_vec(),
        }
    }

    /// The last page.
    pub(crate) fn last(&self) -> usize {
        self.cut.pages - 1
    }

    /// The page extension circuit `circuit` is, if one of this circuit's.
    pub(crate) fn page(&self, circuit: u32) -> Option<usize> {
        self.circuits
            .contains(&circuit)
            .then(|| (circuit - self.circuits.start) as usize)
    }

    /// Whether extension mask `mask` is one for the last page, whose
    /// polynomial is the circuit's own.
    pub(crate) fn masks_last(&self, mask: u32) -> bool {
        self.masks
            .iter()
            .any(|(of, pages)| *of == mask && pages.contains(&self.last()))
    }
}

/// The pages that share a mask over their own gates: those that load the
/// same stages, whose own gates then start at the same gate. Under its
/// last stage's final mask, the last page's start past that stage whatever
/// it loads, so it has a mask to itself when the loads are told.
fn groups(cut: Cut, sealed: bool) -> Vec<Vec<usize>> {
    let apart = usize::from(sealed && !cut.loads.is_empty());
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for page in 0..cut.pages - apart {
        match groups
            .iter_mut()
            .find(|group| cut.loads.get(group[0]) == cut.loads.get(page))
        {
            Some(group) => group.push(page),
            None => groups.push(vec![page]),
        }
    }
    if apart == 1 {
        groups.push(vec![cut.pages - 1]);
    }
    groups
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
/// circuits, the carry stages after its stages, and the pages' masks after
/// its final masks, each in the circuits' order.
fn slots_over<P: Profile>(base: &Extension, nested: bool) -> Vec<Slot> {
    let paged = Circuit::paged::<P>(nested);
    let mut circuit = base.circuits.len() as u32;
    let mut mask = (base.stages + paged.len() + base.final_masks.len()) as u32;
    paged
        .iter()
        .enumerate()
        .map(|(position, &(which, cut))| {
            let circuits = circuit..circuit + cut.pages as u32 - 1;
            circuit = circuits.end;
            let masks: Vec<(u32, Vec<usize>)> = groups(cut, which.sealed())
                .into_iter()
                .zip(mask..)
                .map(|(pages, mask)| (mask, pages))
                .collect();
            mask += masks.len() as u32;
            Slot {
                circuit: which,
                cut,
                circuits,
                carry: (base.stages + position) as u32,
                masks,
            }
        })
        .collect()
}

/// Where each of one side's paged circuits' entries sit, in the circuits'
/// order; nothing for a profile that pages none.
pub(crate) fn slots<P: Profile>(nested: bool) -> Vec<Slot> {
    slots_over::<P>(&base::<P>(nested), nested)
}

/// Appends paging's entries to one side's extension. A mask is declared as
/// a final mask over the extension circuits that are the pages it is for,
/// which is none for one that is for the last page alone: it covers no
/// polynomial of the extension's. A profile's own declaration may not name
/// a final mask over no circuit ([`Extension::is_consistent`]); these
/// entries are added past that check.
pub(crate) fn extend<P: Profile>(extension: &mut Extension, nested: bool) {
    let slots = slots_over::<P>(extension, nested);
    for slot in &slots {
        extension
            .circuits
            .extend(slot.circuits.clone().map(|_| vec![slot.carry]));
    }
    extension.stages += slots.len();
    for slot in &slots {
        for (_, pages) in &slot.masks {
            extension.final_masks.push(
                pages
                    .iter()
                    .filter(|&&page| page < slot.last())
                    .map(|&page| slot.circuits.start + page as u32)
                    .collect(),
            );
        }
    }
}

fn refuse<T>(circuit: impl core::fmt::Debug, what: String) -> Result<T> {
    Err(Error::Initialization(
        format!("the profile's paging of {circuit:?} {what}").into(),
    ))
}

/// Cuts `circuit` into the pages `cut` declares, in polynomials of rank
/// `R`.
fn split<F: Field, R: Rank, S: MultiStageCircuit<F, R>>(
    which: Circuit,
    circuit: MultiStage<F, R, S>,
    cut: Cut,
) -> Result<Paged<F, MultiStage<F, R, S>>> {
    split_within(
        which,
        (which.tells_loads(), which.sealed()),
        circuit,
        cut,
        R::blind_gate(),
    )
}

/// Cuts `circuit` into the pages `cut` declares, in polynomials of `limit`
/// gates.
fn split_within<F: Field, R: Rank, S: MultiStageCircuit<F, R>>(
    which: impl core::fmt::Debug + Copy,
    (tells_loads, sealed): (bool, bool),
    circuit: impl Into<alloc::sync::Arc<MultiStage<F, R, S>>>,
    cut: Cut,
    limit: usize,
) -> Result<Paged<F, MultiStage<F, R, S>>> {
    let mut stages =
        Stages::of::<F, R, S>().idling(cut.idle.iter().map(|&page| page as usize).collect());
    if !sealed {
        stages = stages.unsealed();
    }
    let stages = if cut.loads.is_empty() {
        stages.pages(cut.pages)
    } else if cut.loads.len() != cut.pages {
        return refuse(
            which,
            format!(
                "declares {} pages and the stages {} of them load",
                cut.pages,
                cut.loads.len()
            ),
        );
    } else if !tells_loads {
        return refuse(
            which,
            "declares the stages its pages load, which only a nested circuit's can".into(),
        );
    } else {
        stages.loading(
            cut.loads
                .iter()
                .map(|loads| loads.iter().map(|&stage| stage as usize).collect())
                .collect(),
        )
    };
    match Paged::cut(circuit, &stages, limit) {
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
    carry_mask: Option<MaskObject<R>>,
    /// The masks of the pages' own polynomials, each with the gates it
    /// leaves them, in the order of the slot's.
    masks: Vec<Option<(MaskObject<R>, Range<usize>)>>,
    /// The carry stage's gates in every page's polynomial.
    carry: Range<usize>,
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
}

impl<'params, F: Field, R: Rank> Registrar<'params, F, R> {
    /// A registrar for one side of profile `P`.
    pub(crate) fn new<P: Profile>(nested: bool) -> Self {
        let base = base::<P>(nested);
        let slots = slots_over::<P>(&base, nested);
        Registrar {
            pending: slots.iter().map(|_| None).collect(),
            slots,
            base: (base.stages, base.final_masks.len()),
        }
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
        S: MultiStageCircuit<F, R>,
        MultiStage<F, R, S>: 'params,
    {
        let Some(position) = self.position(which) else {
            return registry.register_internal_circuit(circuit);
        };
        let slot = &self.slots[position];
        let paged = split(which, circuit, slot.cut)?;
        let layout = paged.layout();
        let mut masks = Vec::with_capacity(slot.masks.len());
        for (_, pages) in &slot.masks {
            let window = layout.window(pages[0]);
            if pages.iter().any(|&page| layout.window(page) != window) {
                return refuse(which, "gives pages under one mask other gates".into());
            }
            masks.push(Some((paged.own_mask::<R>(pages[0])?, window)));
        }
        let pages = (0..slot.last())
            .map(|page| {
                let page = paged.page(page);
                let register: Register<'params, F, R> =
                    Box::new(move |registry| registry.register_internal_circuit(Suffixed(page)));
                Some(register)
            })
            .collect();
        self.pending[position] = Some(Pending {
            pages,
            carry_mask: Some(paged.carry_mask::<R>()?),
            masks,
            carry: layout.carry.clone(),
        });
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
        let which = self.slots[position].circuit;
        let pending = self.pending(position)?;
        let Some(register) = pending.pages[page].take() else {
            return refuse(which, "registers a page twice".into());
        };
        Ok((
            register(registry)?,
            Registration::Staged(vec![pending.carry.clone()]),
        ))
    }

    /// Registers extension mask `index` if it is one of paging's: a carry
    /// stage's mask, or the mask of some pages' own polynomials, which
    /// holds each off the stages its page loads and the carry stage.
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
            let position = index - stages;
            let which = self.slots[position].circuit;
            let pending = self.pending(position)?;
            let Some(mask) = pending.carry_mask.take() else {
                return refuse(which, "registers its carry stage's mask twice".into());
            };
            let carry = pending.carry.clone();
            return Ok(Slotted::Paged(
                registry.register_mask(mask),
                Registration::StageMask(carry),
            ));
        }
        if index < stages + paged + final_masks {
            return Ok(Slotted::Other(registry, index - paged));
        }

        let found = self.slots.iter().enumerate().find_map(|(position, slot)| {
            let group = slot
                .masks
                .iter()
                .position(|(mask, _)| *mask as usize == index)?;
            Some((position, group, slot.circuit))
        });
        let Some((position, group, which)) = found else {
            return Err(Error::Initialization(
                format!("the extension has no mask {index}").into(),
            ));
        };
        let Some((mask, window)) = self.pending(position)?.masks[group].take() else {
            return refuse(which, "registers a mask twice".into());
        };
        Ok(Slotted::Paged(
            registry.register_mask(mask),
            Registration::Window(window),
        ))
    }
}

/// Traces one side's internal circuits, whole or in pages, and keeps the
/// polynomials the pages add to the extension.
pub struct Prover<F: Field, R: Rank> {
    slots: Vec<Slot>,
    /// The pages' polynomials before each circuit's last, by paged circuit.
    pages: Vec<Option<Vec<sparse::Polynomial<F, R>>>>,
    /// The carry stages' polynomials, by paged circuit.
    carries: Vec<Option<sparse::Polynomial<F, R>>>,
}

impl<F: Field, R: Rank> Prover<F, R> {
    /// A prover for one side of profile `P`.
    pub(crate) fn new<P: Profile>(nested: bool) -> Self {
        let slots = slots::<P>(nested);
        Prover {
            pages: slots.iter().map(|_| None).collect(),
            carries: slots.iter().map(|_| None).collect(),
            slots,
        }
    }

    /// Traces internal circuit `which` and assembles its polynomial: the
    /// circuit's own, at registry index `own`, or its last page's there and
    /// the other pages' at the indices `extension` gives their extension
    /// circuits. `witness` is asked for once, or once per page. `stages`
    /// are the polynomials of the stages the circuit reserves, in order:
    /// those of the stages that some page does not load, at least.
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
        stages: &[&sparse::Polynomial<F, R>],
        witness: impl Fn() -> S::Witness<'source>,
        rng: &mut RNG,
    ) -> Result<(sparse::Polynomial<F, R>, S::Aux<'source>)>
    where
        S: MultiStageCircuit<F, R>,
        RNG: CryptoRng,
    {
        let Some(position) = self.slots.iter().position(|slot| slot.circuit == which) else {
            let (trace, aux) = circuit.trace(witness())?.into_parts();
            return Ok((registry.assemble(&trace, own, &mut *rng)?, aux));
        };
        let slot = &self.slots[position];
        let paged = split(which, circuit, slot.cut)?;

        let mut traces = Vec::with_capacity(paged.num_pages());
        let mut pages = Vec::with_capacity(slot.circuits.len());
        for (page, circuit) in slot.circuits.clone().enumerate() {
            let trace = paged.page(page).trace(witness())?.into_output();
            pages.push(registry.assemble(&trace, extension(circuit), &mut *rng)?);
            traces.push(Some(trace));
        }
        let (last, aux) = paged.last().trace(witness())?.into_parts();
        let last_rx = registry.assemble(&last, own, &mut *rng)?;
        traces.push(Some(last));
        let last = last_rx;
        self.carries[position] =
            Some(paged.carry_rx::<R>(Blind::random(&mut *rng), &traces, stages)?);
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
    /// For a circuit that does not cut: how it would spread over the same
    /// pages if they had all the room it takes, which tells what each
    /// would have to hold.
    pub unbounded: Option<ragu_circuits::paging::PagingReport>,
}

#[cfg(feature = "test-utils")]
fn sized<F: Field, R: Rank, S: MultiStageCircuit<F, R>>(
    name: &'static str,
    cut: Cut,
    cuts: &[(&'static str, Cut)],
    circuit: MultiStage<F, R, S>,
) -> Result<Sizing> {
    // A step's place is under its pages' mask alone.
    let sealed = !name.ends_with("endoscaling_step");
    let circuit = alloc::sync::Arc::new(circuit);
    let cut = cuts
        .iter()
        .find(|(of, _)| *of == name)
        .map_or(cut, |&(_, cut)| cut);
    let (gates, constraints) = ragu_circuits::paging::size(&*circuit)?;
    let stages = Stages::of::<F, R, S>();
    let pages = split_within(name, (true, sealed), circuit.clone(), cut, R::blind_gate())
        .and_then(|paged| {
            paged.check()?;
            Ok((paged.layout().clone(), paged.report().clone()))
        })
        .map_err(|error| format!("{error:?}"));
    let unbounded = match pages {
        Ok(_) => None,
        Err(_) => split_within(name, (true, sealed), circuit, cut, 1 << 24)
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
        unbounded,
    })
}

/// Sizes the native internal circuits of cycle `C`'s profile at rank `R`
/// and cuts each as the profile does, or as `cuts` says for the circuits it
/// names. The circuits are only walked, so a profile need not fit the
/// rank.
///
/// # Errors
///
/// Propagates any error from walking a circuit.
#[cfg(feature = "test-utils")]
pub fn native_census<C: super::ProfiledCycle, R: Rank, const HEADER_SIZE: usize>(
    params: &C::Params,
    num_application_steps: usize,
    cuts: &[(&'static str, Cut)],
) -> Result<Vec<Sizing>> {
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
    census.push(crate::with_binder!(
        0,
        C,
        R,
        HEADER_SIZE,
        params,
        |circuit| sized(
            "native.bind_challenges_0",
            pages.bind_challenges,
            cuts,
            circuit
        )?
    ));
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
) -> Result<Vec<Sizing>> {
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
