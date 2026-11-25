//! The circuits that run an opening program in chunks.
//!
//! [`compute_v`](super::compute_v) recomputes the batch evaluation $v$ in
//! one circuit, a step per polynomial of the children's proofs. A profile
//! whose proofs carry more polynomials than that circuit can take
//! ([`Chunking`](crate::profile::Chunking)) runs the same steps as a
//! program ([`open`](super::super::open)), and chunk $j$ of these circuits
//! runs its share of it, in order: from the program's state after chunk
//! $j - 1$ (all zero for the first chunk) to the state it enforces the
//! [`carry`](super::super::stages::open) stage to hold after chunk $j$.
//! `compute_v` takes $v$ from the state after the last chunk.
//!
//! ## What a chunk reads
//!
//! - The step's challenges, from the unified instance.
//! - The effective $\beta$, $t(xz)$ and the second layer's interpolation
//!   weights, from the carry stage, where `compute_v` holds each to the
//!   value it computes; and the online helper's sums, likewise.
//! - The evaluations its steps take, from its own polynomial of the
//!   [`band`](super::super::stages::open) stage: copies of the `query` and
//!   `eval` stages' values, which the chunk's
//!   [`open_loading`](super::open_loading) bonding holds to those stages.
//! - The children's instances and the step's online openings, from the
//!   preamble, for the openings at their points.
//!
//! ## Staging
//!
//! The circuit ends on the band stage, after the preamble and the carry
//! stage. It reserves the binding stage, the root of the native stage
//! tree, and reads none of it.
//!
//! ## Instance
//!
//! The unified instance, of which the chunk covers no slot.

use alloc::{collections::BTreeMap, sync::Arc};
use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt as _, allocator::Standard};

use super::super::{
    open::{self, Input, Point, Schedule, Shared, State, Values},
    stages::{
        open::{BandStage, Carry, CarryStage},
        points::BindingStage,
        preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::{internal::Side, profile::ProfiledCycle};

/// A chunk of an opening program run in chunks.
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize> {
    chunk: usize,
    schedule: Arc<Schedule>,
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Circuit<C, R, HEADER_SIZE> {
    /// Creates chunk `chunk` of the program `schedule` shares.
    ///
    /// # Panics
    ///
    /// Panics if the schedule has no such chunk.
    pub fn new(chunk: usize, schedule: Arc<Schedule>) -> MultiStage<C::CircuitField, R, Self> {
        assert!(chunk < schedule.chunks(), "no such opening chunk");
        MultiStage::new(Circuit {
            chunk,
            schedule,
            _marker: PhantomData,
        })
    }
}

/// Witness for a chunk.
pub struct Witness<'a, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> {
    /// The unified instance containing challenges and accumulated coverage.
    pub unified: unified::Instance<C>,
    /// Witness for the preamble stage.
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// The carry stage's values.
    pub carry: &'a [C::CircuitField],
    /// The values of the chunk's band.
    pub band: &'a [C::CircuitField],
}

/// A chunk's values: its band's copies, the preamble, and the points the
/// step's challenges give.
pub(crate) struct Stored<'a, 'dr, D: Driver<'dr>, C: ProfiledCycle<CircuitField = D::F>, const H: usize>
{
    pub band: &'a [Element<'dr, D>],
    pub slots: BTreeMap<Input, usize>,
    pub preamble: &'a native_preamble::Output<'dr, D, C, H>,
    pub w: &'a Element<'dr, D>,
    pub x: &'a Element<'dr, D>,
    pub y: &'a Element<'dr, D>,
    pub xz: &'a Element<'dr, D>,
}

/// The value of `point`, off the preamble and the step's challenges.
pub(crate) fn point<'dr, D: Driver<'dr>, C: ProfiledCycle<CircuitField = D::F>, const H: usize>(
    dr: &mut D,
    preamble: &native_preamble::Output<'dr, D, C, H>,
    [w, x, y, xz]: [&Element<'dr, D>; 4],
    point: Point,
) -> Element<'dr, D> {
    let child = |side| match side {
        Side::Left => &preamble.left,
        Side::Right => &preamble.right,
    };
    match point {
        Point::ChildU(side) => child(side).unified.u.clone(),
        Point::ChildY(side) => child(side).unified.y.clone(),
        Point::ChildX(side) => child(side).unified.x.clone(),
        Point::W => w.clone(),
        Point::X => x.clone(),
        Point::Y => y.clone(),
        Point::Xz => xz.clone(),
        Point::CircuitId => preamble.own.circuit_id.clone(),
        Point::Internal(id) => {
            Element::constant(dr, id.circuit_index::<C::Profile>().omega_j())
        }
        Point::Online(slot) => preamble.own.online[slot].x.clone(),
    }
}

impl<'dr, D: Driver<'dr>, C: ProfiledCycle<CircuitField = D::F>, const H: usize> Values<'dr, D>
    for Stored<'_, 'dr, D, C, H>
{
    fn input(&self, input: Input) -> Element<'dr, D> {
        let slot = self
            .slots
            .get(&input)
            .expect("a chunk's band holds every input of its steps");
        self.band[*slot].clone()
    }

    fn child_v(&self, side: Side) -> Element<'dr, D> {
        match side {
            Side::Left => self.preamble.left.unified.v.clone(),
            Side::Right => self.preamble.right.unified.v.clone(),
        }
    }

    fn online_y(&self, slot: usize) -> Element<'dr, D> {
        self.preamble.own.online[slot].y.clone()
    }

    fn point(&self, dr: &mut D, at: Point) -> Result<Element<'dr, D>> {
        Ok(point(dr, self.preamble, [self.w, self.x, self.y, self.xz], at))
    }
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> MultiStageCircuit<C::CircuitField, R>
    for Circuit<C, R, HEADER_SIZE>
{
    type Last = BandStage<C, R, HEADER_SIZE>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let builder = builder.skip_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (carry, builder) = builder.add_stage::<CarryStage<C, R, HEADER_SIZE>>()?;
        let (band, builder) = builder.add_stage::<BandStage<C, R, HEADER_SIZE>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let carry = carry.unenforced(dr, witness.as_ref().map(|w| w.carry))?;
        let band = band.unenforced(dr, witness.as_ref().map(|w| w.band))?;
        let carry = Carry::<_, C::Profile>::new(&carry[..]);

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));
        let w = unified_output.w.read(dr, allocator)?;
        let y = unified_output.y.read(dr, allocator)?;
        let z = unified_output.z.read(dr, allocator)?;
        let mu = unified_output.mu.read(dr, allocator)?;
        let x = unified_output.x.read(dr, allocator)?;
        let alpha = unified_output.alpha.read(dr, allocator)?;
        let u = unified_output.u.read(dr, allocator)?;
        let xz = x.mul(dr, &z)?;

        let shared = Shared {
            alpha: &alpha,
            u: &u,
            z: &z,
            mu: &mu,
            beta: carry.beta(),
            txz: carry.txz(),
            outer: carry.outer(),
            online_fold: carry.online_fold(),
        };
        let values = Stored {
            band: &band[..],
            slots: self.schedule.slots(self.chunk),
            preamble: &preamble,
            w: &w,
            x: &x,
            y: &y,
            xz: &xz,
        };

        // From the state the chunk before left, or the program's start, to
        // the state the next chunk takes up.
        let start = match self.chunk.checked_sub(1) {
            Some(before) => carry.after(before),
            None => State::filled(Element::zero(dr)),
        };
        let end = open::run::<_, C::Profile, _>(
            dr,
            self.schedule.window(self.chunk),
            start,
            &shared,
            &values,
        )?;
        let staged = carry.after(self.chunk);
        for (computed, staged) in end.values().into_iter().zip(staged.values()) {
            computed.enforce_equal(dr, staged)?;
        }

        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}
