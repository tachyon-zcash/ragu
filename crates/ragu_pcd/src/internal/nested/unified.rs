//! The unified instance of the nested internal circuits.
//!
//! The nested circuits that verify a fuse step share one public instance,
//! serialized into their $k(Y)$ in [`Write`] order:
//!
//! - the nested accumulator value $c_n$ and batch evaluation $v_n$;
//! - the lifts of this step's $x$, $y$ and $u$, which a parent needs to open
//!   this step's polynomials at;
//! - the host-curve commitments the parent endoscales and that live in this
//!   step's bridge stages: `preamble`, `inner_error`, `outer_error`, `query`,
//!   `eval`, $a$, $b$, `registry_xy` and $P$, then the five native points
//!   stages holding the walk's inputs, the native stages besides those whose
//!   contents must be fixed before a challenge is squeezed (see
//!   [`native::stages::points`](crate::internal::native::stages::points)),
//!   the native challenges stage, then the commitments of the polynomials the step witnessed, which the
//!   parent accumulates.
//!
//! A parent witnesses all of these in its `preamble` bridge stage. Its
//! [`collapse`](super::circuits::collapse) circuit computes the expected
//! $k(y_n)$ from those copies and checks their use in the nested fold,
//! binding them to this step's exported values outside the base case.
//! Each slot is the responsibility of exactly one circuit: the
//! [`export`](super::circuits::export) circuit pins $x$, $y$, $u$ and the
//! commitments to the stages that hold them, the
//! [`collapse`](super::circuits::collapse) circuit checks $c_n$ and the
//! [`compute_v`](super::circuits::compute_v) circuit computes $v_n$. The
//! [`OutputBuilder`] tracks that [`Coverage`] the way the native instance's
//! builder does, and the prover asserts it complete once every circuit is
//! traced.
//!
//! There is no suffix zero here: the nested registry holds internal circuits
//! only, so nothing needs telling apart from an application circuit.

use alloc::vec::Vec;
use core::marker::PhantomData;
use ragu_circuits::horner::Horner;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, Kind},
    maybe::Maybe,
};

use ragu_primitives::{
    Element, GadgetExt, Point,
    allocator::Allocator,
    io::Write,
    vec::{FixedVec, Len},
};
use udon::curve::EndomorphismAffine as Affine;

use crate::internal::native::unified::Slot;

/// The host-curve commitments the instance exports from the step's stages,
/// in [`Write`] order; the witnessed polynomials' follow them.
pub const NUM_STAGE_EXPORTS: usize = 15;

/// The host-curve commitments the instance of an application witnessing
/// `polys` polynomials per step exports, in [`Write`] order.
pub const fn num_exported(polys: usize) -> usize {
    NUM_STAGE_EXPORTS + polys
}

/// Length type for the exported commitments, for a poly count `L`.
pub struct ExportedLen<L: Len>(PhantomData<L>);

impl<L: Len> Len for ExportedLen<L> {
    fn len() -> usize {
        num_exported(L::len())
    }
}

/// The gadget kind of the nested internal circuits' output.
#[allow(type_alias_bounds)]
pub type OutputKind<C: Affine, L> = Kind![C::Base; Output<'_, _, C, L>];

/// Native (non-gadget) representation of the nested unified instance.
///
/// Also carries the [`Coverage`] accumulated by the circuits it has been
/// threaded through, so that the prover can check every slot is constrained
/// by exactly one of them.
#[derive(Clone)]
pub struct Instance<C: Affine> {
    pub c: C::Base,
    pub v: C::Base,
    pub x: C::Base,
    pub y: C::Base,
    pub u: C::Base,
    /// The step's stage exports, then its witnessed polynomials'
    /// commitments: [`num_exported`] of them.
    pub exported: Vec<C>,
    /// Accumulated coverage from prior circuits.
    pub coverage: Coverage,
}

impl<C: Affine> Instance<C> {
    /// Asserts that every slot has been covered by some circuit.
    ///
    /// # Panics
    ///
    /// Panics if any slot has not been covered.
    pub fn assert_complete(self) {
        self.coverage.assert_complete();
    }
}

/// Which slots of the instance have been constrained by a circuit, one flag
/// per slot; the exported commitments count as one slot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    c: bool,
    v: bool,
    x: bool,
    y: bool,
    u: bool,
    exported: bool,
}

impl Coverage {
    /// Marks a coverage flag, panicking on double-cover.
    fn cover(flag: &mut bool, name: &str) {
        assert!(!*flag, "slot `{name}` covered by multiple circuits");
        *flag = true;
    }

    /// Asserts that every slot has been covered.
    fn assert_complete(self) {
        self.for_each_slot(0, |name, covered, _| {
            assert!(covered, "slot `{name}` not covered by any circuit");
        });
    }

    /// Walks the slots in the output's $k(Y)$ order, handing `f` each slot's
    /// name, whether a circuit has covered it, and the number of $k(Y)$
    /// wires it writes: one per element, two per exported point, of which
    /// there are `num_exported`.
    pub fn for_each_slot(&self, num_exported: usize, mut f: impl FnMut(&'static str, bool, usize)) {
        f("c", self.c, 1);
        f("v", self.v, 1);
        f("x", self.x, 1);
        f("y", self.y, 1);
        f("u", self.u, 1);
        f("exported", self.exported, 2 * num_exported);
    }
}

/// The shared public instance of the nested internal circuits, for a poly
/// count `L`.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, L: Len> {
    #[ragu(gadget)]
    pub c: Element<'dr, D>,
    #[ragu(gadget)]
    pub v: Element<'dr, D>,
    #[ragu(gadget)]
    pub x: Element<'dr, D>,
    #[ragu(gadget)]
    pub y: Element<'dr, D>,
    #[ragu(gadget)]
    pub u: Element<'dr, D>,
    #[ragu(gadget)]
    pub exported: FixedVec<Point<'dr, D, C>, ExportedLen<L>>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, L: Len> Output<'dr, D, C, L> {
    /// Allocates the instance's wires from its native values.
    pub fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        instance: DriverValue<D, &Instance<C>>,
    ) -> Result<Self> {
        Ok(Output {
            c: Element::alloc(dr, allocator, instance.as_ref().map(|i| i.c))?,
            v: Element::alloc(dr, allocator, instance.as_ref().map(|i| i.v))?,
            x: Element::alloc(dr, allocator, instance.as_ref().map(|i| i.x))?,
            y: Element::alloc(dr, allocator, instance.as_ref().map(|i| i.y))?,
            u: Element::alloc(dr, allocator, instance.as_ref().map(|i| i.u))?,
            exported: alloc_exported(dr, instance.as_ref().map(|i| &i.exported[..]))?,
        })
    }

    /// Evaluates this instance's $k(Y)$ at `y`: the Horner evaluation of its
    /// wires in [`Write`] order with the trailing constant $1$.
    pub fn ky(&self, dr: &mut D, y: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        let mut horner = Horner::new(y);
        self.write(dr, &mut horner)?;
        horner.finish_ky(dr)
    }
}

/// Allocates the exported commitments' wires.
fn alloc_exported<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, L: Len>(
    dr: &mut D,
    exported: DriverValue<D, &[C]>,
) -> Result<FixedVec<Point<'dr, D, C>, ExportedLen<L>>> {
    D::try_just(|| {
        if exported.as_ref().take().len() == ExportedLen::<L>::len() {
            Ok(())
        } else {
            Err(ragu_core::Error::MalformedEncoding(
                "nested instance does not export the configured commitments".into(),
            ))
        }
    })?;
    FixedVec::try_from_fn(|i| Point::alloc(dr, exported.as_ref().map(|e| e[i])))
}

/// Builder for constructing an [`Output`] gadget slot by slot.
///
/// Each field is a [`Slot`] a circuit can read without taking responsibility
/// for it, receive and constrain, or compute and provide; whatever is left
/// is allocated by [`finish`](Self::finish), which also folds the circuit's
/// coverage into the [`Instance`] it returns.
pub struct OutputBuilder<'dr, D: Driver<'dr>, A, C: Affine<Base = D::F>, L: Len> {
    pub c: Slot<'dr, D, A, Element<'dr, D>, C::Base>,
    pub v: Slot<'dr, D, A, Element<'dr, D>, C::Base>,
    pub x: Slot<'dr, D, A, Element<'dr, D>, C::Base>,
    pub y: Slot<'dr, D, A, Element<'dr, D>, C::Base>,
    pub u: Slot<'dr, D, A, Element<'dr, D>, C::Base>,
    pub exported: Slot<'dr, D, A, FixedVec<Point<'dr, D, C>, ExportedLen<L>>, Vec<C>>,
    instance: DriverValue<D, Instance<C>>,
}

impl<'dr, D: Driver<'dr>, A: Allocator<'dr, D>, C: Affine<Base = D::F>, L: Len>
    OutputBuilder<'dr, D, A, C, L>
{
    /// Creates a builder over `instance`, which carries the values and the
    /// coverage accumulated so far.
    pub fn new(instance: DriverValue<D, Instance<C>>) -> Self {
        fn element<'dr, D: Driver<'dr>, A: Allocator<'dr, D>>(
            dr: &mut D,
            allocator: &mut A,
            value: DriverValue<D, D::F>,
        ) -> Result<Element<'dr, D>> {
            Element::alloc(dr, allocator, value)
        }
        fn exported<'dr, D: Driver<'dr>, A, C: Affine<Base = D::F>, L: Len>(
            dr: &mut D,
            _: &mut A,
            value: DriverValue<D, Vec<C>>,
        ) -> Result<FixedVec<Point<'dr, D, C>, ExportedLen<L>>> {
            alloc_exported(dr, value.as_ref().map(|v| &v[..]))
        }
        OutputBuilder {
            c: Slot::new(instance.as_ref().map(|i| i.c), element),
            v: Slot::new(instance.as_ref().map(|i| i.v), element),
            x: Slot::new(instance.as_ref().map(|i| i.x), element),
            y: Slot::new(instance.as_ref().map(|i| i.y), element),
            u: Slot::new(instance.as_ref().map(|i| i.u), element),
            exported: Slot::new(instance.as_ref().map(|i| i.exported.clone()), exported),
            instance,
        }
    }

    /// Finishes the output, allocating every slot the circuit left alone,
    /// and returns it with the [`Instance`] carrying this circuit's coverage.
    pub fn finish(
        self,
        dr: &mut D,
        allocator: &mut A,
    ) -> Result<(Output<'dr, D, C, L>, DriverValue<D, Instance<C>>)> {
        let c = self.c.take(dr, allocator)?;
        let v = self.v.take(dr, allocator)?;
        let x = self.x.take(dr, allocator)?;
        let y = self.y.take(dr, allocator)?;
        let u = self.u.take(dr, allocator)?;
        let exported = self.exported.take(dr, allocator)?;
        let output = Output {
            c: c.0,
            v: v.0,
            x: x.0,
            y: y.0,
            u: u.0,
            exported: exported.0,
        };
        let instance = self.instance.map(move |mut inst| {
            for (covered, flag, name) in [
                (c.1, &mut inst.coverage.c, "c"),
                (v.1, &mut inst.coverage.v, "v"),
                (x.1, &mut inst.coverage.x, "x"),
                (y.1, &mut inst.coverage.y, "y"),
                (u.1, &mut inst.coverage.u, "u"),
                (exported.1, &mut inst.coverage.exported, "exported"),
            ] {
                if covered {
                    Coverage::cover(flag, name);
                }
            }
            inst
        });
        Ok((output, instance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_assert_complete_passes_when_all_set() {
        Coverage {
            c: true,
            v: true,
            x: true,
            y: true,
            u: true,
            exported: true,
        }
        .assert_complete();
    }

    #[test]
    #[should_panic(expected = "not covered by any circuit")]
    fn coverage_assert_complete_catches_missing() {
        Coverage {
            c: true,
            ..Coverage::default()
        }
        .assert_complete();
    }

    #[test]
    #[should_panic(expected = "covered by multiple circuits")]
    fn coverage_catches_overlap() {
        let mut cov = Coverage::default();
        Coverage::cover(&mut cov.v, "v");
        Coverage::cover(&mut cov.v, "v");
    }
}
