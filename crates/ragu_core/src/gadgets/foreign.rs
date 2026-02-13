//! Implementations of gadgets for foreign types.

use ff::Field;

use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

use crate::{
    Result,
    drivers::{Driver, FromDriver},
    gadgets::{Consistent, Gadget, GadgetKind},
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

        fn map_gadget<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
            _: &Self::Rebind<'dr, D>,
            _: &mut ND,
        ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>> {
            Ok(())
        }

        fn enforce_equal_gadget<
            'dr,
            D1: Driver<'dr, F = F>,
            D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
        >(
            _: &mut D1,
            _: &Self::Rebind<'dr, D2>,
            _: &Self::Rebind<'dr, D2>,
        ) -> Result<()> {
            Ok(())
        }
    }

    impl<'dr, D: Driver<'dr>> Consistent<'dr, D> for () {
        fn enforce_consistent(&self, _: &mut D) -> Result<()> {
            Ok(())
        }
    }
}

mod array_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>, const N: usize> Gadget<'dr, D> for [G; N] {
        type Kind = [PhantomData<G::Kind>; N];
    }

    /// Safety: `G: GadgetKind<F>` implies that `G::Rebind<'dr, D>` is `Send`
    /// when `D::Wire` is `Send`, by the safety contract of `GadgetKind`. Because
    /// `[G::Rebind<'dr, D>; N]` only contains `G::Rebind<'dr, D>`, it is also
    /// `Send` when `D::Wire` is `Send`.
    unsafe impl<F: Field, G: GadgetKind<F>, const N: usize> GadgetKind<F> for [PhantomData<G>; N] {
        type Rebind<'dr, D: Driver<'dr, F = F>> = [G::Rebind<'dr, D>; N];

        fn map_gadget<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
            this: &Self::Rebind<'dr, D>,
            ndr: &mut ND,
        ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>> {
            // TODO(ebfull): perhaps replace with core::array::try_from_fn when
            // stable (see https://github.com/rust-lang/rust/issues/89379)
            let mut result = Vec::with_capacity(N);
            for item in this.iter() {
                result.push(G::map_gadget(item, ndr)?);
            }
            match result.try_into() {
                Ok(arr) => Ok(arr),
                Err(_) => unreachable!(),
            }
        }

        fn enforce_equal_gadget<
            'dr,
            D1: Driver<'dr, F = F>,
            D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
        >(
            dr: &mut D1,
            a: &Self::Rebind<'dr, D2>,
            b: &Self::Rebind<'dr, D2>,
        ) -> Result<()> {
            for (a, b) in a.iter().zip(b.iter()) {
                G::enforce_equal_gadget(dr, a, b)?;
            }
            Ok(())
        }
    }

    impl<'dr, D: Driver<'dr>, G: Consistent<'dr, D>, const N: usize> Consistent<'dr, D> for [G; N] {
        fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
            for item in self.iter() {
                item.enforce_consistent(dr)?;
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
    /// `G1::Rebind<'dr, D>` and `G2::Rebind<'dr, D>` are `Send` when `D::Wire`
    /// is `Send`, by the safety contract of `GadgetKind`. Because the tuple
    /// only contains these two types, it is also `Send` when `D::Wire` is `Send`.
    unsafe impl<F: Field, G1: GadgetKind<F>, G2: GadgetKind<F>> GadgetKind<F>
        for (PhantomData<G1>, PhantomData<G2>)
    {
        type Rebind<'dr, D: Driver<'dr, F = F>> = (G1::Rebind<'dr, D>, G2::Rebind<'dr, D>);

        fn map_gadget<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
            this: &Self::Rebind<'dr, D>,
            ndr: &mut ND,
        ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>> {
            Ok((G1::map_gadget(&this.0, ndr)?, G2::map_gadget(&this.1, ndr)?))
        }

        fn enforce_equal_gadget<
            'dr,
            D1: Driver<'dr, F = F>,
            D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
        >(
            dr: &mut D1,
            a: &Self::Rebind<'dr, D2>,
            b: &Self::Rebind<'dr, D2>,
        ) -> Result<()> {
            G1::enforce_equal_gadget(dr, &a.0, &b.0)?;
            G2::enforce_equal_gadget(dr, &a.1, &b.1)?;
            Ok(())
        }
    }

    impl<'dr, D: Driver<'dr>, G1: Consistent<'dr, D>, G2: Consistent<'dr, D>> Consistent<'dr, D>
        for (G1, G2)
    {
        fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
            self.0.enforce_consistent(dr)?;
            self.1.enforce_consistent(dr)?;
            Ok(())
        }
    }
}

mod box_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Gadget<'dr, D> for Box<G> {
        type Kind = PhantomData<Box<G::Kind>>;
    }

    /// Safety: `G: GadgetKind<F>` implies that `G::Rebind<'dr, D>` is `Send`
    /// when `D::Wire` is `Send`, by the safety contract of `GadgetKind`. Because
    /// `Box<G::Rebind<'dr, D>>` is `Send` when its contents are `Send`, it is
    /// also `Send` when `D::Wire` is `Send`.
    unsafe impl<F: Field, G: GadgetKind<F>> GadgetKind<F> for PhantomData<Box<G>> {
        type Rebind<'dr, D: Driver<'dr, F = F>> = Box<G::Rebind<'dr, D>>;

        fn map_gadget<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
            this: &Self::Rebind<'dr, D>,
            ndr: &mut ND,
        ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>> {
            Ok(Box::new(G::map_gadget(this, ndr)?))
        }

        fn enforce_equal_gadget<
            'dr,
            D1: Driver<'dr, F = F>,
            D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
        >(
            dr: &mut D1,
            a: &Self::Rebind<'dr, D2>,
            b: &Self::Rebind<'dr, D2>,
        ) -> Result<()> {
            G::enforce_equal_gadget(dr, a, b)
        }
    }

    impl<'dr, D: Driver<'dr>, G: Consistent<'dr, D>> Consistent<'dr, D> for Box<G> {
        fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
            (**self).enforce_consistent(dr)
        }
    }
}
