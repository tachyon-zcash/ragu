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
//!   `eval`, $a$, $b$, `registry_xy` and $P$.
//!
//! A parent witnesses all of these in its `preamble` bridge stage and folds
//! this step's circuit claims with the $k(y_n)$ it computes from them, which
//! is what binds the copies it holds to the values this step's circuits
//! enforced. The [`export`](super::circuits::export) circuit is the one that
//! pins the instance to the stages.

use ragu_arithmetic::CurveAffine;
use ragu_circuits::horner::Horner;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt, Point,
    allocator::Allocator,
    io::Write,
    vec::{ConstLen, FixedVec},
};

/// The host-curve commitments the instance exports, in [`Write`] order.
pub const NUM_EXPORTED: usize = 9;

/// Length type for the exported commitments.
pub type ExportedLen = ConstLen<NUM_EXPORTED>;

/// Native (non-gadget) representation of the nested unified instance.
#[derive(Clone, Copy)]
pub struct Instance<C: CurveAffine> {
    pub c: C::Base,
    pub v: C::Base,
    pub x: C::Base,
    pub y: C::Base,
    pub u: C::Base,
    pub exported: [C; NUM_EXPORTED],
}

/// The shared public instance of the nested internal circuits.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
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
    pub exported: FixedVec<Point<'dr, D, C>, ExportedLen>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Output<'dr, D, C> {
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
            exported: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, instance.as_ref().map(|inst| inst.exported[i]))
            })?,
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
