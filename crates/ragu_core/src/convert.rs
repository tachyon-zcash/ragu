//! Conversions that translate gadgets from one [`Driver`] context to another.
//!
//! Gadgets are polymorphic over drivers, and translating a gadget from one
//! driver context to another while preserving its structure and semantics is a
//! fundamental operation. Any code that operates across multiple driver
//! contexts will need this: [routines](crate::routines) translate their inputs
//! onto [`Wireless`] [`Emulator`]s for prediction, wire-counting passes discard
//! wire values entirely, and driver implementations may need to inject or
//! rewrite wires during circuit analysis.
//!
//! [`WireMap`] provides a uniform mechanism for these conversions: an
//! implementor fixes a source and destination driver via associated types, then
//! converts wires one at a time.
//!
//! ### Public API
//!
//! - [`WireMap`], the core conversion trait.
//! - [`CloneWires`], a [`WireMap`] that clones wires unchanged.
//! - [`StripWires`], a [`WireMap`] that discards wire values for use with
//!   wireless emulators.
//!
//! See also the [book] for a user-oriented introduction to conversion.
//!
//! [book]: https://tachyon.z.cash/ragu/guide/gadgets/conversion.html

use core::marker::PhantomData;
use ff::Field;

use crate::{
    Result,
    drivers::{
        Driver, DriverTypes,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, Gadget},
};

/// Conversion context that maps wires from one driver to another.
///
/// Each implementor fixes a specific source and destination driver via
/// associated types. When the same conversion logic applies to multiple
/// source/destination pairs, use a wrapper struct parameterized by those
/// types. See [`StripWires`] for an example.
///
/// `Src` and `Dst` are bounded by [`DriverTypes`] (not [`Driver<'dr>`](Driver))
/// so the trait itself carries no lifetime parameter. The full [`Driver`]
/// bound is instead introduced on individual methods like [`Gadget::map`]
/// and [`GadgetKind::map_gadget`](crate::gadgets::GadgetKind::map_gadget),
/// where source and destination lifetimes are constrained via `where`
/// clauses.
pub trait WireMap<F: Field> {
    /// The source driver whose wires are being converted.
    ///
    /// Must implement [`Driver<'dr>`](Driver) at every call site that
    /// passes this `WireMap` to [`Gadget::map`].
    type Src: DriverTypes<ImplField = F>;

    /// The destination driver whose wires are produced.
    ///
    /// Must implement [`Driver<'dr>`](Driver) at every call site that
    /// passes this `WireMap` to [`Gadget::map`].
    type Dst: DriverTypes<ImplField = F>;

    /// Converts a wire from the source driver to the destination driver.
    fn convert_wire(
        &mut self,
        wire: &<Self::Src as DriverTypes>::ImplWire,
    ) -> Result<<Self::Dst as DriverTypes>::ImplWire>;

    /// Maps a gadget from [`Src`](Self::Src) to [`Dst`](Self::Dst) using a
    /// fresh default instance of this wire map.
    ///
    /// The source driver is inferred from the gadget; the destination can be
    /// inferred from the return context or spelled out explicitly:
    ///
    /// ```ignore
    /// let output: Bound<'_, Dst, _> = MyWireMap::remap(&gadget)?;
    /// let output = MyWireMap::<_, Dst>::remap(&gadget)?;
    /// ```
    fn remap<'src, 'dst, G: Gadget<'src, Self::Src>>(
        gadget: &G,
    ) -> Result<Bound<'dst, Self::Dst, G::Kind>>
    where
        Self: Default,
        Self::Src: Driver<'src, F = F>,
        Self::Dst: Driver<'dst, F = F>,
    {
        gadget.map(&mut Self::default())
    }
}

/// A [`WireMap`] that passes wires through unchanged by cloning them.
///
/// The source and destination must share the same wire type, so conversion
/// calls [`.clone()`](Clone::clone) on each wire. This is useful when
/// rebinding a gadget to a new lifetime without changing its wire
/// representation.
pub struct CloneWires<Src: DriverTypes, Dst: DriverTypes>(PhantomData<(Src, Dst)>);

impl<Src: DriverTypes, Dst: DriverTypes> Default for CloneWires<Src, Dst> {
    fn default() -> Self {
        CloneWires(PhantomData)
    }
}

impl<F: Field, Src, Dst> WireMap<F> for CloneWires<Src, Dst>
where
    Src: DriverTypes<ImplField = F>,
    Dst: DriverTypes<ImplField = F, ImplWire = Src::ImplWire>,
{
    type Src = Src;
    type Dst = Dst;

    fn convert_wire(
        &mut self,
        wire: &<Src as DriverTypes>::ImplWire,
    ) -> Result<<Dst as DriverTypes>::ImplWire> {
        Ok(wire.clone())
    }
}

/// A [`WireMap`] that maps any driver's wires to `()`, discarding wire
/// values for use with `Emulator<Wireless<D::MaybeKind, D::ImplField>>`.
///
/// This conversion is used to pass a gadget from a concrete driver into
/// [`Routine::predict`], which operates on a [`Wireless`] emulator. The
/// wrapper struct is parameterized by the source driver so that each source
/// type gets its own blanket [`WireMap`] impl.
///
/// [`Routine::predict`]: crate::routines::Routine::predict
pub struct StripWires<D: DriverTypes>(PhantomData<D>);

impl<D: DriverTypes> Default for StripWires<D> {
    fn default() -> Self {
        StripWires(PhantomData)
    }
}

impl<F: Field, D: DriverTypes<ImplField = F>> WireMap<F> for StripWires<D> {
    type Src = D;
    type Dst = Emulator<Wireless<D::MaybeKind, F>>;

    fn convert_wire(&mut self, _: &D::ImplWire) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use ragu_arithmetic::Coeff;
    use ragu_pasta::Fp;

    use crate::{
        Result,
        convert::WireMap,
        drivers::{
            Driver,
            emulator::{Emulator, Wired, Wireless},
        },
        gadgets::{Bound, Gadget, GadgetKind},
        maybe::Always,
    };

    type F = Fp;
    type Emu = Emulator<Wireless<Always<()>, F>>;

    struct TwoWires<'dr, D: Driver<'dr>> {
        a: D::Wire,
        b: D::Wire,
        _marker: core::marker::PhantomData<&'dr ()>,
    }

    impl<'dr, D: Driver<'dr>> Clone for TwoWires<'dr, D> {
        fn clone(&self) -> Self {
            TwoWires {
                a: self.a.clone(),
                b: self.b.clone(),
                _marker: core::marker::PhantomData,
            }
        }
    }

    struct TwoWiresKind;

    /// # Safety
    /// `D::Wire: Send` implies `TwoWires<'dr, D>: Send` since the struct
    /// only contains wires and `PhantomData`.
    unsafe impl<FieldType: Field> GadgetKind<FieldType> for TwoWiresKind {
        type Rebind<'dr, D: Driver<'dr, F = FieldType>> = TwoWires<'dr, D>;

        fn map_gadget<
            'src,
            'dst,
            WM: WireMap<FieldType, Src: Driver<'src, F = FieldType>, Dst: Driver<'dst, F = FieldType>>,
        >(
            this: &Bound<'src, WM::Src, Self>,
            wm: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            Ok(TwoWires {
                a: wm.convert_wire(&this.a)?,
                b: wm.convert_wire(&this.b)?,
                _marker: core::marker::PhantomData,
            })
        }

        fn enforce_equal_gadget<
            'dr,
            D1: Driver<'dr, F = FieldType>,
            D2: Driver<'dr, F = FieldType, Wire = <D1 as Driver<'dr>>::Wire>,
        >(
            dr: &mut D1,
            a: &Bound<'dr, D2, Self>,
            b: &Bound<'dr, D2, Self>,
        ) -> Result<()> {
            dr.enforce_equal(&a.a, &b.a)?;
            dr.enforce_equal(&a.b, &b.b)?;
            Ok(())
        }
    }

    impl<'dr, D: Driver<'dr>> Gadget<'dr, D> for TwoWires<'dr, D> {
        type Kind = TwoWiresKind;
    }

    struct OneWire<'dr, D: Driver<'dr>> {
        w: D::Wire,
        _marker: core::marker::PhantomData<&'dr ()>,
    }

    impl<'dr, D: Driver<'dr>> Clone for OneWire<'dr, D> {
        fn clone(&self) -> Self {
            OneWire {
                w: self.w.clone(),
                _marker: core::marker::PhantomData,
            }
        }
    }

    struct OneWireKind;

    /// # Safety
    /// `D::Wire: Send` implies `OneWire<'dr, D>: Send` since the struct
    /// only contains a wire and `PhantomData`.
    unsafe impl<FieldType: Field> GadgetKind<FieldType> for OneWireKind {
        type Rebind<'dr, D: Driver<'dr, F = FieldType>> = OneWire<'dr, D>;

        fn map_gadget<'dr, 'dr2, WM: WireMap<FieldType>>(
            this: &Bound<'dr, WM::Src, Self>,
            ndr: &mut WM,
        ) -> Result<Bound<'dr2, WM::Dst, Self>>
        where
            WM::Src: Driver<'dr, F = FieldType>,
            WM::Dst: Driver<'dr2, F = FieldType>,
        {
            Ok(OneWire {
                w: ndr.convert_wire(&this.w)?,
                _marker: core::marker::PhantomData,
            })
        }

        fn enforce_equal_gadget<
            'dr,
            D1: Driver<'dr, F = FieldType>,
            D2: Driver<'dr, F = FieldType, Wire = <D1 as Driver<'dr>>::Wire>,
        >(
            dr: &mut D1,
            a: &Bound<'dr, D2, Self>,
            b: &Bound<'dr, D2, Self>,
        ) -> Result<()> {
            dr.enforce_equal(&a.w, &b.w)?;
            Ok(())
        }
    }

    impl<'dr, D: Driver<'dr>> Gadget<'dr, D> for OneWire<'dr, D> {
        type Kind = OneWireKind;
    }

    #[test]
    fn stateful_wiremap_produces_different_results_on_repeated_use() -> Result<()> {
        struct IncrementingMap {
            counter: u64,
        }

        impl WireMap<F> for IncrementingMap {
            type Src = Emulator<Wired<F>>;
            type Dst = Emulator<Wired<F>>;

            fn convert_wire(&mut self, _wire: &F) -> Result<F> {
                self.counter += 1;
                Ok(F::from(self.counter))
            }
        }

        let mut dr = Emulator::<Wired<F>>::extractor();
        let a = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(100))))?;
        let b = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(200))))?;
        let gadget = TwoWires {
            a,
            b,
            _marker: core::marker::PhantomData,
        };

        let mut map = IncrementingMap { counter: 0 };

        let mapped1: TwoWires<'_, Emulator<Wired<F>>> = gadget.map(&mut map)?;
        assert_eq!(mapped1.a, F::from(1));
        assert_eq!(mapped1.b, F::from(2));

        let mapped2: TwoWires<'_, Emulator<Wired<F>>> = gadget.map(&mut map)?;
        assert_eq!(mapped2.a, F::from(3));
        assert_eq!(mapped2.b, F::from(4));

        assert_eq!(map.counter, 4);
        Ok(())
    }

    #[test]
    fn wiremap_partial_failure_leaves_dirty_state() -> Result<()> {
        struct FailOnEven {
            call_count: usize,
        }

        impl WireMap<F> for FailOnEven {
            type Src = Emu;
            type Dst = core::marker::PhantomData<F>;

            fn convert_wire(&mut self, _: &()) -> Result<()> {
                self.call_count += 1;
                if self.call_count.is_multiple_of(2) {
                    Err(crate::Error::InvalidWitness("even call".into()))
                } else {
                    Ok(())
                }
            }
        }

        let gadget: TwoWires<'_, Emu> = TwoWires {
            a: (),
            b: (),
            _marker: core::marker::PhantomData,
        };

        let mut map = FailOnEven { call_count: 0 };

        let result = gadget.map(&mut map);
        assert!(result.is_err());
        assert_eq!(map.call_count, 2);

        let one_wire: OneWire<'_, Emu> = OneWire {
            w: (),
            _marker: core::marker::PhantomData,
        };
        let result2 = one_wire.map(&mut map);
        assert!(result2.is_ok());
        assert_eq!(map.call_count, 3);

        let result3 = gadget.map(&mut map);
        assert!(result3.is_err());
        assert_eq!(map.call_count, 4);

        Ok(())
    }
}
