//! What a paged circuit registers and proves: the pages, as multi-stage
//! circuits over the circuit's stages and its carry stage that replay what
//! a plan compiled for them.
//!
//! With the carry stage, the stages and the layout in the parent module,
//! the recorder and the check, this is what a page's soundness rests on.
//! It reads a plan and takes nothing else of how the plan was chosen.

use alloc::{format, sync::Arc, vec, vec::Vec};
use core::marker::PhantomData;

use ragu_core::{
    Coeff, Result,
    convert::WireMap,
    drivers::{Driver, DriverTypes, DriverValue, LinearExpression},
    gadgets::{Bound, Gadget},
    maybe::{Always, Maybe, MaybeKind},
};
use udon::field::Field;

use super::{
    Captured, Carry, DERIVED, Layout, ONE, Pageable, Paged, PagingReport, Plan, Planned, Program,
    Stages, diverged,
};
use crate::{
    Blind, Circuit, MaskObject, WithAux, floor_planner, into_wiring_object,
    polynomials::{Rank, sparse},
    staging::{MultiStage, MultiStageCircuit, StageBuilder, StageExt},
};

impl<F: Field> Program<F> {
    /// Allocates the page's own gates on `dr`, with `values`, makes its
    /// combinations and enforces its constraints. `reserved` are the wires
    /// of the stages' and the carry stage's gates, two a gate, which the
    /// page's stage builder reserved. Gives the wires of the public
    /// output, which only the last page has.
    fn replay<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        reserved: &[D::Wire],
        values: &DriverValue<D, &[[F; 4]]>,
    ) -> Result<Vec<D::Wire>> {
        // The page's own gates start past the reserved ones.
        let first = reserved.len() / 2 + 1;
        // A reserved gate has its $a$ and $d$ wires, which hold a stage's
        // values, and no other: a program that names another is not one a
        // plan of a circuit over stages compiles.
        let named = |wire: u32| wire & DERIVED == 0 && (1..first as u32).contains(&(wire / 4));
        let lists = self
            .sums
            .iter()
            .chain(&self.constraints)
            .chain(&self.outputs);
        if lists
            .flatten()
            .any(|&(wire, _)| named(wire) && matches!(wire % 4, 1 | 2))
        {
            return Err(diverged("a page names a wire a stage does not hold"));
        }
        let mut gates: Vec<[D::Wire; 4]> = Vec::with_capacity(self.own);
        for gate in 0..self.own {
            let value = |kind: usize| {
                values
                    .snag()
                    .get(gate)
                    .map(|values| Coeff::Arbitrary(values[kind]))
                    .ok_or_else(|| diverged("a page was given too few of its gates' values"))
            };
            let (a, b, c, extra) = dr.gate(|| Ok((value(0)?, value(1)?, value(2)?)))?;
            let d = dr.assign_extra(extra, || value(3))?;
            gates.push([a, b, c, d]);
        }
        fn combine<W: Clone, F: Field, L: LinearExpression<W, F>>(
            lc: L,
            terms: &[(u32, Coeff<F>)],
            one: &W,
            (reserved, gates): (&[W], &[[W; 4]]),
            sums: &[W],
        ) -> L {
            let first = reserved.len() / 2 + 1;
            terms.iter().fold(lc, |lc, &(wire, coeff)| {
                let wire = if wire & DERIVED != 0 {
                    &sums[(wire ^ DERIVED) as usize]
                } else {
                    match (wire / 4) as usize {
                        0 => one,
                        gate if gate < first => {
                            &reserved[2 * (gate - 1) + usize::from(wire % 4 == 3)]
                        }
                        gate => &gates[gate - first][(wire % 4) as usize],
                    }
                };
                lc.add_term(wire, coeff)
            })
        }
        // TODO(#503): a routine the circuit calls is replayed here as part
        // of the page's flat run, so it has no segment a memo can key on.
        // The check holds its gates to this page, together and in order
        // (`Recording::split_routine`); what is left is for the page to
        // call it as a routine on `dr`.
        let one = D::ONE;
        let wires = (reserved, &gates[..]);
        let mut sums: Vec<D::Wire> = Vec::with_capacity(self.sums.len());
        for terms in &self.sums {
            let sum = dr.add(|lc| combine(lc, terms, &one, wires, &sums));
            sums.push(sum);
        }
        for terms in &self.constraints {
            dr.enforce_zero(|lc| combine(lc, terms, &one, wires, &sums))?;
        }
        Ok(self
            .outputs
            .iter()
            .map(|terms| dr.add(|lc| combine(lc, terms, &one, wires, &sums)))
            .collect())
    }
}

/// The driver that walks a circuit for what a replay of its pages cannot
/// give: the public output, over wires named as the planning driver names
/// them, and with a witness the value of every gate. It emits nothing, and
/// counts what the circuit does.
struct Shadow<F, K> {
    /// The gates allocated, the SYSTEM gate included.
    gates: usize,
    /// The linear combinations made.
    sums: usize,
    /// The constraints enforced.
    constraints: usize,
    /// The $a$, $b$, $c$ and $d$ values of each gate, the SYSTEM gate
    /// first, where the walk has a witness.
    values: Vec<[F; 4]>,
    _kind: PhantomData<K>,
}

impl<F: Field, K: MaybeKind> Shadow<F, K> {
    fn new() -> Self {
        // The SYSTEM gate is the driver's.
        Shadow {
            gates: 1,
            sums: 0,
            constraints: 0,
            values: vec![[F::ZERO; 4]],
            _kind: PhantomData,
        }
    }

    /// Whether the circuit emitted what its plan saw.
    fn follows(&self, plan: &Plan<F>, sums: usize) -> Result<()> {
        if self.gates != plan.num_gates || self.constraints != plan.homes.len() || self.sums != sums
        {
            return Err(diverged(&format!(
                "the walk saw {} gates, {} constraints and {} combinations where the plan has \
                 {}, {} and {}",
                self.gates,
                self.constraints,
                self.sums,
                plan.num_gates,
                plan.homes.len(),
                sums,
            )));
        }
        Ok(())
    }
}

impl<F: Field, K: MaybeKind> DriverTypes for Shadow<F, K> {
    type ImplField = F;
    type ImplWire = u32;
    type MaybeKind = K;
    type LCadd = ();
    type LCenforce = ();
    type Extra = u32;

    fn gate(
        &mut self,
        values: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(u32, u32, u32, u32)> {
        let gate = u32::try_from(self.gates).expect("gate indices fit a wire");
        self.gates += 1;
        K::maybe_try_just(|| {
            let (a, b, c) = values()?;
            self.values.push([a.value(), b.value(), c.value(), F::ZERO]);
            Ok(())
        })?;
        Ok((4 * gate, 4 * gate + 1, 4 * gate + 2, 4 * gate + 3))
    }

    fn assign_extra(&mut self, extra: u32, value: impl Fn() -> Result<Coeff<F>>) -> Result<u32> {
        K::maybe_try_just(|| {
            let value = value()?.value();
            self.values
                .get_mut((extra / 4) as usize)
                .ok_or_else(|| diverged("a gate allocated without its values"))?[3] = value;
            Ok(())
        })?;
        Ok(extra)
    }
}

impl<'dr, F: Field, K: MaybeKind> Driver<'dr> for Shadow<F, K> {
    type F = F;
    type Wire = u32;
    const ONE: u32 = ONE;

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> u32 {
        self.sums += 1;
        DERIVED | (self.sums - 1) as u32
    }

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        self.constraints += 1;
        Ok(())
    }
}

/// Gives each wire of the public output, in traversal order, the wire the
/// last page made for it.
struct Resolver<F, K, D: DriverTypes> {
    wires: alloc::vec::IntoIter<D::ImplWire>,
    _marker: PhantomData<(F, K)>,
}

impl<F: Field, K: MaybeKind, D: DriverTypes<ImplField = F>> WireMap<F> for Resolver<F, K, D> {
    type Src = Shadow<F, K>;
    type Dst = D;

    fn convert_wire(&mut self, _: &u32) -> Result<D::ImplWire> {
        self.wires
            .next()
            .ok_or_else(|| diverged("an output wire past the plan's last"))
    }
}

impl<F: Field> Planned<F> {
    /// The layout of the pages' polynomials.
    pub fn layout(&self) -> &Layout {
        &self.plan.layout
    }

    /// What the circuit was cut over.
    pub fn stages(&self) -> &Stages {
        &self.plan.stages
    }
}

impl<F: Field, R: Rank, S: Pageable<F, R>> Paged<F, R, S> {
    /// The pages the circuit was cut into, apart from it.
    pub fn plan(&self) -> Planned<F> {
        Planned {
            plan: self.plan.clone(),
            report: self.report.clone(),
        }
    }

    /// `circuit` in the pages `planned` holds, which a cut of the same
    /// circuit gave: the one registered, where a proof is of a registered
    /// circuit. The circuit is not walked. A circuit that allocates or
    /// enforces other counts than the one that was cut fails when its
    /// pages are traced; one that differs only in what it enforces gives
    /// pages that are not the registered circuit's, as any other change
    /// to a registered circuit does.
    pub fn planned(circuit: impl Into<Arc<MultiStage<F, R, S>>>, planned: &Planned<F>) -> Self {
        Paged {
            circuit: circuit.into(),
            plan: planned.plan.clone(),
            report: planned.report.clone(),
            stages: Stages::of::<F, R, S>().pages(planned.plan.pages()),
        }
    }

    /// Checks the pages' complete constraints against the circuit's own,
    /// including the equations defining every carry slot. Each page gate
    /// is mapped to its original gate, a carry slot or an otherwise unused
    /// wire; the resulting linear forms must match exactly after the carry
    /// definitions are accounted for.
    ///
    /// # Errors
    ///
    /// Fails if the plan is laid over other stages than the circuit's, a
    /// walk fails, a gate is missing or repeated, a carry slot lacks its
    /// definition, or the constraints differ.
    pub fn check(&self) -> Result<()> {
        super::check::check(self)
    }

    /// The layout of the pages' polynomials.
    pub fn layout(&self) -> &Layout {
        &self.plan.layout
    }

    /// What the circuit was cut over.
    pub fn stages(&self) -> &Stages {
        &self.plan.stages
    }

    /// A digest of what a registry holds of the circuit in pages: each
    /// page's wiring polynomial, as a registry hashes it into its tag,
    /// with the gates the pages' mask leaves them, and the carry stage's
    /// gates. It changes with where a cut falls, with the order the gates
    /// are placed in and with what a page enforces, and with nothing else
    /// of how the pages were chosen.
    ///
    /// # Errors
    ///
    /// Fails if a page does not fit rank `R`.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let layout = &self.plan.layout;
        let pages = self.plan.pages();
        let mut state = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ragu_paged_pages")
            .to_state();
        let gates = |state: &mut blake2b_simd::State, gates: &core::ops::Range<usize>| {
            state.update(&(gates.start as u64).to_le_bytes());
            state.update(&(gates.end as u64).to_le_bytes());
        };
        state.update(&(pages as u64).to_le_bytes());
        gates(&mut state, &layout.carry);
        gates(&mut state, &layout.window());
        for page in 0..pages {
            let object = if page + 1 < pages {
                into_wiring_object::<F, _, R>(self.page(page))?
            } else {
                into_wiring_object::<F, _, R>(self.last())?
            };
            let plan = floor_planner::floor_plan(object.segment_records());
            object.monomials(&plan).hash_into(&mut state);
        }
        let mut digest = [0; 32];
        digest.copy_from_slice(state.finalize().as_bytes());
        Ok(digest)
    }

    /// The pages the circuit takes, the last included.
    pub fn num_pages(&self) -> usize {
        self.plan.pages()
    }

    /// How the circuit spreads over its pages.
    pub fn report(&self) -> &PagingReport {
        &self.report
    }

    /// Page `index`, which is not the last.
    ///
    /// # Panics
    ///
    /// Panics if `index` is the last page or past it.
    pub fn page(&self, index: usize) -> MultiStage<F, R, Page<F, R, S>> {
        assert!(
            index + 1 < self.plan.pages(),
            "the last page is `last`'s, with the public output"
        );
        MultiStage::new(Page {
            plan: self.plan.clone(),
            index,
            _marker: PhantomData,
        })
    }

    /// The last page, which carries the circuit's public output.
    pub fn last(&self) -> MultiStage<F, R, LastPage<F, R, S>> {
        MultiStage::new(LastPage {
            circuit: self.circuit.clone(),
            plan: self.plan.clone(),
        })
    }

    /// What one walk of the circuit with `witness` gives its pages: the
    /// values of the gates each page before the last holds, which is that
    /// page's witness, and the carry stage's values. Tracing the pages
    /// then walks the circuit once rather than once for each.
    ///
    /// # Errors
    ///
    /// Propagates any error from the circuit's witness, and fails if the
    /// circuit emits other counts than the walk it was cut from.
    pub fn capture(&self, witness: S::Witness<'_>) -> Result<Captured<F>> {
        let mut dr = Shadow::<F, Always<()>>::new();
        self.circuit
            .witness(&mut dr, Always::maybe_just(|| witness))?;
        let plan = &*self.plan;
        dr.follows(plan, plan.sums)?;
        let value = |wire: u32| dr.values[(wire / 4) as usize][(wire % 4) as usize];
        Ok(Captured {
            pages: plan.held[..plan.pages() - 1]
                .iter()
                .map(|held| held.iter().map(|&gate| dr.values[gate as usize]).collect())
                .collect(),
            carry: plan
                .slots
                .iter()
                .map(|slot| {
                    slot.iter()
                        .fold(F::ZERO, |sum, &(wire, coeff)| sum + coeff * value(wire))
                })
                .collect(),
        })
    }

    /// The carry stage's polynomial for `values` ([`Captured::carry`]).
    ///
    /// # Errors
    ///
    /// Fails if the carry stage does not fit rank `R`, or if `values` are
    /// more than it holds.
    pub fn carry_rx(
        &self,
        blind: impl Into<Blind<F>>,
        values: &[F],
    ) -> Result<sparse::Polynomial<F, R>> {
        <Carry<F, R, S> as StageExt<F, R>>::rx(blind, values)
    }

    /// The carry stage's stage mask, which holds its polynomial to its
    /// gates.
    ///
    /// # Errors
    ///
    /// Fails if the carry stage does not fit rank `R`.
    pub fn carry_mask(&self) -> Result<MaskObject<R>> {
        <Carry<F, R, S> as StageExt<F, R>>::stage_mask()
    }

    /// The carry stage's final mask, which holds a page's own polynomial
    /// off the stages and the carry stage: the final mask of every page,
    /// each a multi-stage circuit whose last stage the carry stage is.
    ///
    /// # Errors
    ///
    /// Fails if the carry stage does not fit rank `R`.
    pub fn page_mask(&self) -> Result<MaskObject<R>> {
        <Carry<F, R, S> as StageExt<F, R>>::final_mask()
    }
}

/// A page of a [`Paged`] circuit other than the last: a multi-stage circuit
/// over the circuit's stages and its carry stage, with no public output,
/// which allocates and enforces what the plan compiled for it. Its witness
/// is the values of the gates it holds, in the order of its polynomial
/// ([`Paged::capture`]).
pub struct Page<F: Field, R, S> {
    plan: Arc<Plan<F>>,
    index: usize,
    _marker: PhantomData<fn() -> (R, S)>,
}

impl<F: Field, R: Rank, S: Pageable<F, R>> MultiStageCircuit<F, R> for Page<F, R, S> {
    type Last = Carry<F, R, S>;
    type Instance<'source> = ();
    type Witness<'source> = &'source [[F; 4]];
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (reserved, builder) = builder.reserve_through::<Self::Last>()?;
        let dr = builder.finish();
        self.plan.programs[self.index].replay(dr, &reserved, &witness)?;
        Ok(WithAux::new((), D::unit()))
    }
}

/// The last page of a [`Paged`] circuit, with the circuit's public output:
/// a multi-stage circuit over the circuit's stages and its carry stage, as
/// the other pages are.
pub struct LastPage<F: Field, R: Rank, S: MultiStageCircuit<F, R>> {
    circuit: Arc<MultiStage<F, R, S>>,
    plan: Arc<Plan<F>>,
}

impl<F: Field, R: Rank, S: Pageable<F, R>> MultiStageCircuit<F, R> for LastPage<F, R, S> {
    type Last = Carry<F, R, S>;
    type Instance<'source> = S::Instance<'source>;
    type Witness<'source> = S::Witness<'source>;
    type Output = S::Output;
    type Aux<'source> = S::Aux<'source>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        self.circuit.instance(dr, instance)
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        // The circuit's own walk gives the public output and, with a
        // witness, the values of the page's gates; the page allocates and
        // enforces what the plan compiled for it, as the others do.
        //
        // TODO: the walk is for the output gadget's type alone. A page
        // whose output is the elements the circuit writes needs none.
        let plan = &*self.plan;
        let last = plan.pages() - 1;
        let mut shadow = Shadow::<F, D::MaybeKind>::new();
        let (output, aux) = self.circuit.witness(&mut shadow, witness)?.into_parts();
        shadow.follows(plan, plan.sums)?;
        let values = D::just(|| {
            plan.held[last]
                .iter()
                .map(|&gate| shadow.values[gate as usize])
                .collect::<Vec<_>>()
        });
        let (reserved, builder) = builder.reserve_through::<Self::Last>()?;
        let dr = builder.finish();
        let wires = plan.programs[last].replay(
            dr,
            &reserved,
            &values.as_ref().map(|values| &values[..]),
        )?;
        let output = output.map(&mut Resolver::<F, D::MaybeKind, D> {
            wires: wires.into_iter(),
            _marker: PhantomData,
        })?;
        Ok(WithAux::new(output, aux))
    }
}
