//! Query stage for fuse operations.
//!
//! Witnesses the claimed polynomial evaluations needed for the `compute_v`
//! circuit to verify the $f(u)$ quotient polynomial. Each child proof's `rx`
//! polynomials are evaluated at $xz$:
//!
//! - $r\_i(xz)$ — used to recompute both $A(xz)$ (undilated) and $B(x)$ (since
//!   $b\_i(x) = r\_i(xz) + s\_y + t\_z$).
//!
//! Because $A$ has no $Z$-dilation, checking it at $xz$ instead of $x$ lets
//! both $A$ and $B$ share the same $\{r\_i(xz)\}$ evaluations, eliminating the
//! need for separate $r\_i(x)$ queries.
//!
//! Additionally witnesses the $a$/$b$ polynomial evaluations and registry
//! transition evaluations needed for mesh consistency checks.

use core::marker::PhantomData;

use ragu_arithmetic::{Cycle, ff::PrimeField};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging,
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind, WireEqualizer},
    maybe::Maybe,
};
use ragu_primitives::{Element, allocator::Allocator};

use crate::{
    Proof,
    internal::native::{
        InternalCircuitIndex, InternalCircuitValues, RxComponent, RxIndex, RxValues,
    },
};

/// Witness for a child proof's polynomial evaluations.
pub struct ChildEvaluationsWitness<F> {
    /// Rx polynomial evaluations at $xz$.
    pub rx: RxValues<F>,

    /// $A$ polynomial evaluation at $xz$.
    pub a_poly_at_xz: F,

    /// $B$ polynomial evaluation at $x$.
    pub b_poly_at_x: F,

    /// Child's `registry_xy` polynomial evaluated at current step's $w$.
    pub child_registry_xy_at_current_w: F,

    /// Current `registry_xy` polynomial evaluated at child's `circuit_id`.
    pub current_registry_xy_at_child_circuit_id: F,

    /// Current `registry_wy` polynomial evaluated at child's $x$.
    pub current_registry_wy_at_child_x: F,
}

impl<F: PrimeField> ChildEvaluationsWitness<F> {
    /// Creates a child evaluations witness from a proof evaluated at the given points.
    pub fn from_proof<C: Cycle<CircuitField = F>, R: Rank>(
        proof: &Proof<C, R>,
        w: F,
        x: F,
        xz: F,
        registry_xy: &sparse::Polynomial<F, R>,
        registry_wy: &sparse::Polynomial<F, R>,
    ) -> Self {
        ChildEvaluationsWitness {
            rx: RxValues::from_fn(|id| proof[id].eval(xz)),
            a_poly_at_xz: proof[RxComponent::AbA].eval(xz),
            b_poly_at_x: proof[RxComponent::AbB].eval(x),
            child_registry_xy_at_current_w: proof.native_registry_xy_poly().eval(w),
            current_registry_xy_at_child_circuit_id: registry_xy.eval(proof.circuit_id().omega_j()),
            current_registry_wy_at_child_x: registry_wy.eval(proof.x()),
        }
    }
}

/// Witness data for the query stage.
pub struct Witness<C: Cycle> {
    /// Pre-computed registry_xy evaluations at each internal circuit's omega^j.
    pub fixed_registry: InternalCircuitValues<C::CircuitField>,
    /// m(w, x, y) - verifies registry_xy/registry_wy consistency at current coordinates.
    pub registry_wxy: C::CircuitField,
    /// Left child proof polynomial evaluations.
    pub left: ChildEvaluationsWitness<C::CircuitField>,
    /// Right child proof polynomial evaluations.
    pub right: ChildEvaluationsWitness<C::CircuitField>,
}

/// Allocate [`InternalCircuitValues`] of [`Element`]s from pre-computed witness
/// values.
pub fn alloc_fixed_registry<'dr, D: Driver<'dr>, A: Allocator<'dr, D>>(
    dr: &mut D,
    allocator: &mut A,
    witness: DriverValue<D, &InternalCircuitValues<D::F>>,
) -> Result<InternalCircuitValues<Element<'dr, D>>> {
    InternalCircuitValues::try_from_fn(|id| {
        Element::alloc(dr, allocator, witness.as_ref().map(|w| *w.get(id)))
    })
}

impl<'dr, D: Driver<'dr>> Gadget<'dr, D> for InternalCircuitValues<Element<'dr, D>> {
    type Kind = InternalCircuitValues<Element<'static, PhantomData<D::F>>>;
}

// SAFETY: `Element` is `Send` when `D::Wire: Send`, and `InternalCircuitValues`
// is a plain product of `Element`s, so the same implication holds.
unsafe impl<F: ragu_arithmetic::ff::Field> ragu_core::gadgets::GadgetKind<F>
    for InternalCircuitValues<Element<'static, PhantomData<F>>>
{
    type Rebind<'dr, D: Driver<'dr, F = F>> = InternalCircuitValues<Element<'dr, D>>;

    fn map_gadget<
        'src,
        'dst,
        WM: ragu_core::convert::WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
    >(
        this: &InternalCircuitValues<Element<'src, WM::Src>>,
        wm: &mut WM,
    ) -> Result<InternalCircuitValues<Element<'dst, WM::Dst>>> {
        InternalCircuitValues::try_from_fn(|id| this.get(id).map(wm))
    }

    fn enforce_conservative_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        eq: &mut WireEqualizer<'_, 'dr, D1>,
        a: &InternalCircuitValues<Element<'dr, D2>>,
        b: &InternalCircuitValues<Element<'dr, D2>>,
    ) -> Result<()> {
        for &id in &InternalCircuitIndex::ALL {
            eq.enforce_conservative_equal_gadget(a.get(id), b.get(id))?;
        }
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>> Gadget<'dr, D> for RxValues<Element<'dr, D>> {
    type Kind = RxValues<Element<'static, PhantomData<D::F>>>;
}

// SAFETY: `Element` is `Send` when `D::Wire: Send`, and `RxValues`
// is a plain product of `Element`s, so the same implication holds.
unsafe impl<F: ragu_arithmetic::ff::Field> ragu_core::gadgets::GadgetKind<F>
    for RxValues<Element<'static, PhantomData<F>>>
{
    type Rebind<'dr, D: Driver<'dr, F = F>> = RxValues<Element<'dr, D>>;

    fn map_gadget<
        'src,
        'dst,
        WM: ragu_core::convert::WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
    >(
        this: &RxValues<Element<'src, WM::Src>>,
        wm: &mut WM,
    ) -> Result<RxValues<Element<'dst, WM::Dst>>> {
        RxValues::try_from_fn(|id| this.get(id).map(wm))
    }

    fn enforce_conservative_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        eq: &mut WireEqualizer<'_, 'dr, D1>,
        a: &RxValues<Element<'dr, D2>>,
        b: &RxValues<Element<'dr, D2>>,
    ) -> Result<()> {
        for &id in &RxIndex::ALL {
            eq.enforce_conservative_equal_gadget(a.get(id), b.get(id))?;
        }
        Ok(())
    }
}

impl<F: ragu_arithmetic::ff::Field> ragu_primitives::io::Write<F>
    for RxValues<Element<'static, PhantomData<F>>>
{
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: ragu_primitives::io::Buffer<'dr, D>>(
        this: &Bound<'dr, D, Self>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        for &id in &RxIndex::ALL {
            buf.write(dr, this.get(id))?;
        }
        Ok(())
    }
}

/// Gadget for a child proof's polynomial evaluations.
#[derive(Gadget)]
pub struct ChildEvaluations<'dr, D: Driver<'dr>> {
    /// Rx polynomial evaluations at $xz$.
    #[ragu(gadget)]
    pub rx: RxValues<Element<'dr, D>>,

    /// $A$ polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub a_poly_at_xz: Element<'dr, D>,

    /// $B$ polynomial evaluation at $x$.
    #[ragu(gadget)]
    pub b_poly_at_x: Element<'dr, D>,

    /// Child's `registry_xy` polynomial evaluated at current step's $w$.
    #[ragu(gadget)]
    pub child_registry_xy_at_current_w: Element<'dr, D>,

    /// Current `registry_xy` polynomial evaluated at child's `circuit_id`.
    #[ragu(gadget)]
    pub current_registry_xy_at_child_circuit_id: Element<'dr, D>,

    /// Current `registry_wy` polynomial evaluated at child's $x$.
    #[ragu(gadget)]
    pub current_registry_wy_at_child_x: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> ChildEvaluations<'dr, D> {
    /// Allocate child evaluations from pre-computed witness values.
    pub fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, &ChildEvaluationsWitness<D::F>>,
    ) -> Result<Self> {
        let rx = RxValues::try_from_fn(|id| {
            Element::alloc(dr, allocator, witness.as_ref().map(|w| *w.rx.get(id)))
        })?;
        Ok(ChildEvaluations {
            rx,
            a_poly_at_xz: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.a_poly_at_xz))?,
            b_poly_at_x: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.b_poly_at_x))?,
            child_registry_xy_at_current_w: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|w| w.child_registry_xy_at_current_w),
            )?,
            current_registry_xy_at_child_circuit_id: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|w| w.current_registry_xy_at_child_circuit_id),
            )?,
            current_registry_wy_at_child_x: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|w| w.current_registry_wy_at_child_x),
            )?,
        })
    }
}

/// Prover-internal output gadget for the query stage.
///
/// This is stage communication data, not part of the circuit's public instance.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>> {
    /// Fixed registry evaluations at each internal circuit's omega^j.
    #[ragu(gadget)]
    pub fixed_registry: InternalCircuitValues<Element<'dr, D>>,
    /// m(w, x, y) - verifies registry_xy/registry_wy consistency at current coordinates.
    #[ragu(gadget)]
    pub registry_wxy: Element<'dr, D>,
    /// Left child proof polynomial evaluations.
    #[ragu(gadget)]
    pub left: ChildEvaluations<'dr, D>,
    /// Right child proof polynomial evaluations.
    #[ragu(gadget)]
    pub right: ChildEvaluations<'dr, D>,
}

/// The query stage of the fuse witness.
#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE>
{
    type Parent = super::preamble::Stage<C, R, HEADER_SIZE>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _>];

    fn values() -> usize {
        // InternalCircuitIndex::NUM + registry_wxy (1) + 2 * ChildEvaluations (16 each)
        InternalCircuitIndex::NUM + 1 + 2 * 16
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let allocator = &mut ();
        let fixed_registry =
            alloc_fixed_registry(dr, allocator, witness.as_ref().map(|w| &w.fixed_registry))?;
        let registry_wxy = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.registry_wxy))?;
        let left = ChildEvaluations::alloc(dr, allocator, witness.as_ref().map(|w| &w.left))?;
        let right = ChildEvaluations::alloc(dr, allocator, witness.as_ref().map(|w| &w.right))?;
        Ok(Output {
            fixed_registry,
            registry_wxy,
            left,
            right,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::Pasta;

    use super::*;
    use crate::internal::tests::{HEADER_SIZE, R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<Pasta, R, { HEADER_SIZE }>::default());
    }
}
