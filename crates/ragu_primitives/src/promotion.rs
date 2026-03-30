//! Strips away the witness data from a gadget while preserving its wire
//! structure.

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    convert::{CloneWires, WireMap},
    drivers::{Driver, DriverTypes, DriverValue},
    gadgets::{Bound, Gadget, GadgetKind},
    maybe::Empty,
};

use core::ops::Deref;

/// Trait for gadgets that support promotion from a [`Demoted`] state.
///
/// Demoted gadgets can be promoted back to their original form using
/// [`Demoted::promote`] as long as the gadget implements this trait.
pub trait Promotion<F: Field>: GadgetKind<F> {
    /// The type of witness data needed to promote a demoted gadget.
    type Value: Send;

    /// Promote a demoted gadget with new witness data.
    fn promote<'dr, D: Driver<'dr, F = F>>(
        demoted: &Demoted<'dr, D, Bound<'dr, D, Self>>,
        witness: DriverValue<D, Self::Value>,
    ) -> Bound<'dr, D, Self>;
}

/// A driver that mimics another driver but strips away witness data.
///
/// Bounded by [`DriverTypes`] rather than [`Driver<'dr>`](Driver) so the
/// struct itself carries no lifetime parameter. The full [`Driver<'dr>`](Driver)
/// bound is introduced at the impl level where the lifetime is needed.
#[doc(hidden)]
pub struct DemotedDriver<D: DriverTypes> {
    _marker: core::marker::PhantomData<D>,
}

impl<D: DriverTypes> DriverTypes for DemotedDriver<D> {
    type MaybeKind = Empty;
    type LCadd = ();
    type LCenforce = ();
    type ImplField = D::ImplField;
    type ImplWire = D::ImplWire;

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(
            Coeff<Self::ImplField>,
            Coeff<Self::ImplField>,
            Coeff<Self::ImplField>,
            Coeff<Self::ImplField>,
        )>,
    ) -> Result<(
        Self::ImplWire,
        Self::ImplWire,
        Self::ImplWire,
        Self::ImplWire,
    )> {
        unreachable!("DemotedDriver cannot be constructed")
    }
}

impl<'dr, D: Driver<'dr>> Driver<'dr> for DemotedDriver<D> {
    const ONE: D::Wire = D::ONE;
    type F = D::F;
    type Wire = D::Wire;

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        unreachable!("DemotedDriver cannot be constructed")
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        unreachable!("DemotedDriver cannot be constructed")
    }

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        unreachable!("DemotedDriver cannot be constructed")
    }
}

/// Simple redirect of wire conversion to the underlying wire map.
struct Demoter<'a, WM> {
    inner: &'a mut WM,
}

impl<F: Field, WM: WireMap<F>> WireMap<F> for Demoter<'_, WM> {
    type Src = DemotedDriver<WM::Src>;
    type Dst = DemotedDriver<WM::Dst>;

    fn convert_wire(
        &mut self,
        wire: &<WM::Src as DriverTypes>::ImplWire,
    ) -> Result<<WM::Dst as DriverTypes>::ImplWire> {
        self.inner.convert_wire(wire)
    }
}

/// A gadget that strips witness data from another gadget.
///
/// All gadgets can be demoted using
/// [`GadgetExt::demote`](crate::GadgetExt::demote), producing a [`Demoted`]
/// version of the original gadget that has its witness data stripped away. They
/// can be recovered (promoted) from their demoted state; gadgets must opt into
/// supporting this by implementing the [`Promotion`] trait so that users can
/// then use the [`Demoted::promote`] method. Optionally, gadgets can offer
/// their own custom promotion strategies.
///
/// # Consistency
///
/// `Demoted` intentionally does not implement `Consistent`. A demoted gadget
/// has no witness data, so it cannot meaningfully enforce consistency. Promote
/// the gadget first, then call `enforce_consistent` on the result.
pub struct Demoted<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> {
    gadget: Bound<'dr, DemotedDriver<D>, G::Kind>,
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Deref for Demoted<'dr, D, G> {
    type Target = Bound<'dr, DemotedDriver<D>, G::Kind>;

    fn deref(&self) -> &Self::Target {
        &self.gadget
    }
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Demoted<'dr, D, G> {
    /// Strips a gadget of its witness data and returns a demoted version of it.
    pub fn new(gadget: &G) -> Result<Self> {
        Ok(Demoted {
            gadget: CloneWires::<_, DemotedDriver<D>>::remap(gadget)?,
        })
    }

    /// Promote this demoted gadget with new witness data.
    pub fn promote(&self, witness: DriverValue<D, <G::Kind as Promotion<D::F>>::Value>) -> G
    where
        G::Kind: Promotion<D::F>,
    {
        <G::Kind as Promotion<D::F>>::promote(self, witness)
    }
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Clone for Demoted<'dr, D, G> {
    fn clone(&self) -> Self {
        Demoted {
            gadget: self.gadget.clone(),
        }
    }
}

/// A [`GadgetKind`] for the [`Demoted`] gadget.
#[doc(hidden)]
pub struct DemotedKind<F: Field, G: GadgetKind<F>> {
    _marker: core::marker::PhantomData<(G, F)>,
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Gadget<'dr, D> for Demoted<'dr, D, G> {
    type Kind = DemotedKind<D::F, G::Kind>;
}

unsafe impl<F: Field, G: GadgetKind<F>> GadgetKind<F> for DemotedKind<F, G> {
    type Rebind<'dr, D: Driver<'dr, F = F>> = Demoted<'dr, D, Bound<'dr, D, G>>;

    fn map_gadget<'src, 'dst, WM: WireMap<F>>(
        this: &Bound<'src, WM::Src, Self>,
        wm: &mut WM,
    ) -> Result<Bound<'dst, WM::Dst, Self>>
    where
        WM::Src: Driver<'src, F = F>,
        WM::Dst: Driver<'dst, F = F>,
    {
        Ok(Demoted {
            gadget: G::map_gadget(&this.gadget, &mut Demoter { inner: wm })?,
        })
    }

    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Bound<'dr, D2, Self>,
        b: &Bound<'dr, D2, Self>,
    ) -> Result<()> {
        G::enforce_equal_gadget(dr, &a.gadget, &b.gadget)
    }
}
