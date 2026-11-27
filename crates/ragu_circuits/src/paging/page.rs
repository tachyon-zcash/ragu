//! What a paged circuit registers and proves: the pages, as circuits that
//! replay what a plan compiled for them, and the polynomial and mask of
//! their carry stage.
//!
//! With the stages and the layout in the parent module, the recorder and
//! the check, this is what a page's soundness rests on. It reads a plan
//! and takes nothing else of how the plan was chosen.

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
    DERIVED, Layout, ONE, Paged, PagingReport, Plan, Planned, Program, Stages, diverged, refuse,
};
use crate::{
    Blind, Circuit, MaskObject, WithAux, floor_planner, into_wiring_object,
    polynomials::{Rank, sparse},
    staging,
    trace::Trace,
};

impl<F: Field> Program<F> {
    /// Allocates the page's gates on `dr`, its own with `values` and the
    /// rest without, makes its combinations and enforces its constraints.
    /// Gives the wires of the public output, which only the last page
    /// has.
    fn replay<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        values: &DriverValue<D, &[[F; 4]]>,
    ) -> Result<Vec<D::Wire>> {
        // The gates past the SYSTEM gate: those of the stages the page
        // loads and of the carry stage, which it gives no value, and its
        // own between them.
        let mut gates: Vec<[D::Wire; 4]> = Vec::with_capacity(self.gates);
        for gate in 1..=self.gates {
            let held = self.own.contains(&gate);
            let value = |kind: usize| {
                if !held {
                    return Ok(Coeff::Zero);
                }
                values
                    .snag()
                    .get(gate - self.own.start)
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
            gates: &[[W; 4]],
            sums: &[W],
        ) -> L {
            terms.iter().fold(lc, |lc, &(wire, coeff)| {
                let wire = if wire & DERIVED != 0 {
                    &sums[(wire ^ DERIVED) as usize]
                } else {
                    match (wire / 4) as usize {
                        0 => one,
                        gate => &gates[gate - 1][(wire % 4) as usize],
                    }
                };
                lc.add_term(wire, coeff)
            })
        }
        // TODO(#503): a routine the circuit calls is replayed here as part
        // of the page's flat run, so its segment is not one a memo can
        // key on. Its gates are all on this page, together and in order;
        // what is left is for the page to call the routine on `dr`, in a
        // segment the floor planner places among the page's gates.
        let one = D::ONE;
        let mut sums: Vec<D::Wire> = Vec::with_capacity(self.sums.len());
        for terms in &self.sums {
            let sum = dr.add(|lc| combine(lc, terms, &one, &gates, &sums));
            sums.push(sum);
        }
        for terms in &self.constraints {
            dr.enforce_zero(|lc| combine(lc, terms, &one, &gates, &sums))?;
        }
        Ok(self
            .outputs
            .iter()
            .map(|terms| dr.add(|lc| combine(lc, terms, &one, &gates, &sums)))
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

    /// The circuit's stages, as its pages load them.
    pub fn stages(&self) -> &Stages {
        &self.plan.stages
    }
}

impl<F: Field, C: Circuit<F>> Paged<F, C> {
    /// The pages the circuit was cut into, apart from it.
    pub fn plan(&self) -> Planned<F> {
        Planned {
            plan: self.plan.clone(),
            report: self.report.clone(),
            stages: self.stages.clone(),
        }
    }

    /// `circuit` in the pages `planned` holds, which a cut of the same
    /// circuit gave: the one registered, where a proof is of a registered
    /// circuit. The circuit is not walked. A circuit that allocates or
    /// enforces other counts than the one that was cut fails when its
    /// pages are traced; one that differs only in what it enforces gives
    /// pages that are not the registered circuit's, as any other change
    /// to a registered circuit does.
    pub fn planned(circuit: impl Into<Arc<C>>, planned: &Planned<F>) -> Self {
        Paged {
            circuit: circuit.into(),
            plan: planned.plan.clone(),
            report: planned.report.clone(),
            stages: planned.stages.clone(),
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
    /// Fails if the plan is laid over other stages than the circuit was
    /// cut over, a walk fails, a gate is missing or repeated, a carry slot
    /// lacks its definition, or the constraints differ.
    pub fn check(&self) -> Result<()> {
        super::check::check(self)
    }

    /// The layout of the pages' polynomials.
    pub fn layout(&self) -> &Layout {
        &self.plan.layout
    }

    /// The circuit's stages, as its pages load them.
    pub fn stages(&self) -> &Stages {
        &self.plan.stages
    }

    /// A digest of what a registry holds of the circuit in pages: each
    /// page's wiring polynomial, as a registry hashes it into its tag,
    /// with the gates the page's mask leaves it, and the carry stage's
    /// gates. It changes with where a cut falls, with the order the gates
    /// are placed in and with what a page enforces, and with nothing else
    /// of how the pages were chosen.
    ///
    /// # Errors
    ///
    /// Fails if a page does not fit rank `R`.
    pub fn digest<R: Rank>(&self) -> Result<[u8; 32]> {
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
        for page in 0..pages {
            gates(&mut state, &layout.window());
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
    pub fn page(&self, index: usize) -> Page<F> {
        assert!(
            index + 1 < self.plan.pages(),
            "the last page is `last`'s, with the public output"
        );
        Page {
            plan: self.plan.clone(),
            index,
        }
    }

    /// The values of the gates each page before the last holds, in the
    /// order of its polynomial, off one walk of the circuit with
    /// `witness`: what [`Page`] takes as its witness, so that tracing the
    /// pages walks the circuit once rather than once for each.
    ///
    /// # Errors
    ///
    /// Propagates any error from the circuit's witness.
    pub fn capture(&self, witness: C::Witness<'_>) -> Result<Vec<Vec<[F; 4]>>> {
        let mut dr = Shadow::<F, Always<()>>::new();
        self.circuit
            .witness(&mut dr, Always::maybe_just(|| witness))?;
        let plan = &*self.plan;
        dr.follows(plan, plan.sums)?;
        Ok(plan.held[..plan.pages() - 1]
            .iter()
            .map(|held| held.iter().map(|&gate| dr.values[gate as usize]).collect())
            .collect())
    }

    /// The last page, which carries the circuit's public output.
    pub fn last(&self) -> LastPage<F, C> {
        LastPage {
            circuit: self.circuit.clone(),
            plan: self.plan.clone(),
        }
    }

    /// The carry stage's values, read off the pages' traces, in page order.
    /// A circuit without gates of its own carries nothing and gives no
    /// trace.
    ///
    /// # Errors
    ///
    /// Fails if a slot combines the wires of a page without a trace.
    ///
    /// # Panics
    ///
    /// Panics if `traces` are not this circuit's pages' traces.
    pub fn carry_values(&self, traces: &[Option<Trace<F>>]) -> Result<Vec<F>> {
        assert!(
            traces.is_empty() || traces.len() == self.plan.pages(),
            "a trace for each page"
        );
        let plan = &*self.plan;
        let slots = &plan.slots;
        let mut values = Vec::with_capacity(slots.len());
        for combination in slots {
            let mut sum = F::ZERO;
            for &(wire, coeff) in combination {
                let (gate, kind) = ((wire / 4) as usize, wire % 4);
                let (page, local) = plan.place(gate).expect("a slot combines a page's wires");
                let Some(trace) = traces.get(page).and_then(Option::as_ref) else {
                    return refuse(format!(
                        "the carry stage holds values of page {page}, whose trace it was not \
                         given"
                    ));
                };
                assert_eq!(trace.segments.len(), 1, "a page's trace is one segment");
                let segment = &trace.segments[0];
                let value = match kind {
                    0 => segment.a[local],
                    1 => segment.b[local],
                    2 => segment.c[local],
                    _ => segment.d[local],
                };
                sum += coeff * value;
            }
            values.push(sum);
        }
        Ok(values)
    }

    /// The carry stage's polynomial for the pages' traces (see
    /// [`carry_values`](Self::carry_values)).
    ///
    /// # Errors
    ///
    /// Fails if the carry stage does not fit rank `R`, or as
    /// [`carry_values`](Self::carry_values) does.
    pub fn carry_rx<R: Rank>(
        &self,
        blind: impl Into<Blind<F>>,
        traces: &[Option<Trace<F>>],
    ) -> Result<sparse::Polynomial<F, R>> {
        let carry = &self.plan.layout.carry;
        staging::stage_rx(
            blind,
            carry.start,
            2 * carry.len(),
            &self.carry_values(traces)?,
        )
    }

    /// The well-formedness mask of the carry stage's polynomial.
    ///
    /// # Errors
    ///
    /// Fails if the carry stage does not fit rank `R`.
    pub fn carry_mask<R: Rank>(&self) -> Result<MaskObject<R>> {
        let carry = &self.plan.layout.carry;
        staging::stage_mask(carry.start, carry.len())
    }

    /// The well-formedness mask of a page's own polynomial, which is zero
    /// off the page's own gates: on the gates before them, where the
    /// stages are, and on the carry stage's. The mask is the same for
    /// every page: it is over the whole window ([`Layout::window`]), which
    /// a page need not fill.
    ///
    /// # Errors
    ///
    /// Fails if the pages' gates do not fit rank `R`.
    pub fn own_mask<R: Rank>(&self) -> Result<MaskObject<R>> {
        let window = self.plan.layout.window();
        staging::stage_mask(window.start, window.len())
    }
}

/// A page of a [`Paged`] circuit other than the last: a circuit with no
/// public output, which allocates and enforces what the plan compiled for
/// it. Its witness is the values of the gates it holds, in the order of
/// its polynomial ([`Paged::capture`]).
pub struct Page<F: Field> {
    plan: Arc<Plan<F>>,
    index: usize,
}

impl<F: Field> Circuit<F> for Page<F> {
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

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        self.plan.programs[self.index].replay(dr, &witness)?;
        Ok(WithAux::new((), D::unit()))
    }
}

/// The last page of a [`Paged`] circuit, with the circuit's public output.
pub struct LastPage<F: Field, C> {
    circuit: Arc<C>,
    plan: Arc<Plan<F>>,
}

impl<F: Field, C: Circuit<F>> Circuit<F> for LastPage<F, C> {
    type Instance<'source> = C::Instance<'source>;
    type Witness<'source> = C::Witness<'source>;
    type Output = C::Output;
    type Aux<'source> = C::Aux<'source>;

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

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        // The circuit's own walk gives the public output and, with a
        // witness, the values of the page's gates; the page allocates and
        // enforces what the plan compiled for it, as the others do.
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
        let wires = plan.programs[last].replay(dr, &values.as_ref().map(|values| &values[..]))?;
        let output = output.map(&mut Resolver::<F, D::MaybeKind, D> {
            wires: wires.into_iter(),
            _marker: PhantomData,
        })?;
        Ok(WithAux::new(output, aux))
    }
}
