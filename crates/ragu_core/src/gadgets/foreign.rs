//! Implementations of gadgets for foreign types.

use ff::Field;

use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

use crate::{
    Result,
    convert::WireMap,
    drivers::Driver,
    gadgets::{Bound, Gadget, GadgetKind},
};

mod unit_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>> Gadget<'dr, D> for () {
        type Kind = ();
    }

    /// Safety: `Rebind<'dr, D> = ()`, which is unconditionally `Send`
    /// regardless of `D::Wire`.
    unsafe impl<F: Field> GadgetKind<F> for () {
        type Rebind<'dr, D: Driver<'dr, F = F>> = ();

        fn map_gadget<
            'src,
            'dst,
            WM: WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
        >(
            _: &Bound<'src, WM::Src, Self>,
            _: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            Ok(())
        }

        fn enforce_equal_gadget<
            'dr,
            D1: Driver<'dr, F = F>,
            D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
        >(
            _: &mut D1,
            _: &Bound<'dr, D2, Self>,
            _: &Bound<'dr, D2, Self>,
        ) -> Result<()> {
            Ok(())
        }
    }
}

mod array_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>, const N: usize> Gadget<'dr, D> for [G; N] {
        type Kind = [PhantomData<G::Kind>; N];
    }

    /// Safety: `G: GadgetKind<F>` implies that `Bound<'dr, D, G>` is `Send`
    /// when `D::Wire` is `Send`, by the safety contract of `GadgetKind`. Because
    /// `[Bound<'dr, D, G>; N]` only contains `Bound<'dr, D, G>`, it is also
    /// `Send` when `D::Wire` is `Send`.
    unsafe impl<F: Field, G: GadgetKind<F>, const N: usize> GadgetKind<F> for [PhantomData<G>; N] {
        type Rebind<'dr, D: Driver<'dr, F = F>> = [Bound<'dr, D, G>; N];

        fn map_gadget<
            'src,
            'dst,
            WM: WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
        >(
            this: &Bound<'src, WM::Src, Self>,
            wm: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            // TODO(ebfull): perhaps replace with core::array::try_from_fn when
            // stable (see https://github.com/rust-lang/rust/issues/89379)
            let mut result = Vec::with_capacity(N);
            for item in this.iter() {
                result.push(G::map_gadget(item, wm)?);
            }
            Ok(result
                .try_into()
                .unwrap_or_else(|_| unreachable!("Vec had exactly N elements")))
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
            for (a, b) in a.iter().zip(b.iter()) {
                G::enforce_equal_gadget(dr, a, b)?;
            }
            Ok(())
        }
    }
}

mod pair_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G1: Gadget<'dr, D>, G2: Gadget<'dr, D>> Gadget<'dr, D> for (G1, G2) {
        type Kind = (PhantomData<G1::Kind>, PhantomData<G2::Kind>);
    }

    /// Safety: `G1: GadgetKind<F>` and `G2: GadgetKind<F>` imply that both
    /// `Bound<'dr, D, G1>` and `Bound<'dr, D, G2>` are `Send` when `D::Wire`
    /// is `Send`, by the safety contract of `GadgetKind`. Because the tuple
    /// only contains these two types, it is also `Send` when `D::Wire` is `Send`.
    unsafe impl<F: Field, G1: GadgetKind<F>, G2: GadgetKind<F>> GadgetKind<F>
        for (PhantomData<G1>, PhantomData<G2>)
    {
        type Rebind<'dr, D: Driver<'dr, F = F>> = (Bound<'dr, D, G1>, Bound<'dr, D, G2>);

        fn map_gadget<
            'src,
            'dst,
            WM: WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
        >(
            this: &Bound<'src, WM::Src, Self>,
            wm: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            Ok((G1::map_gadget(&this.0, wm)?, G2::map_gadget(&this.1, wm)?))
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
            G1::enforce_equal_gadget(dr, &a.0, &b.0)?;
            G2::enforce_equal_gadget(dr, &a.1, &b.1)?;
            Ok(())
        }
    }
}

mod box_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Gadget<'dr, D> for Box<G> {
        type Kind = PhantomData<Box<G::Kind>>;
    }

    /// Safety: `G: GadgetKind<F>` implies that `Bound<'dr, D, G>` is `Send`
    /// when `D::Wire` is `Send`, by the safety contract of `GadgetKind`. Because
    /// `Box<Bound<'dr, D, G>>` is `Send` when its contents are `Send`, it is
    /// also `Send` when `D::Wire` is `Send`.
    unsafe impl<F: Field, G: GadgetKind<F>> GadgetKind<F> for PhantomData<Box<G>> {
        type Rebind<'dr, D: Driver<'dr, F = F>> = Box<Bound<'dr, D, G>>;

        fn map_gadget<
            'src,
            'dst,
            WM: WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
        >(
            this: &Bound<'src, WM::Src, Self>,
            wm: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            Ok(Box::new(G::map_gadget(this, wm)?))
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
            G::enforce_equal_gadget(dr, a, b)
        }
    }
}
