//! Implementations of gadgets for foreign types.

use ff::Field;

use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

use crate::{
    Result,
    drivers::{Driver, FromDriver},
    gadgets::{ConstraintFreeKind, Gadget, GadgetKind},
};

mod unit_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>> Gadget<'dr, D> for () {
        type Kind = ();
    }

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

    // Unit type has no wires and no constraints.
    impl ConstraintFreeKind for () {}
}

mod array_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>, const N: usize> Gadget<'dr, D> for [G; N] {
        type Kind = [PhantomData<G::Kind>; N];
    }

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

    // Arrays are constraint-free if their element type is constraint-free.
    impl<G: ConstraintFreeKind, const N: usize> ConstraintFreeKind for [PhantomData<G>; N] {}
}

mod pair_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G1: Gadget<'dr, D>, G2: Gadget<'dr, D>> Gadget<'dr, D> for (G1, G2) {
        type Kind = (PhantomData<G1::Kind>, PhantomData<G2::Kind>);
    }

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

    // Tuples are constraint-free if both elements are constraint-free.
    impl<G1: ConstraintFreeKind, G2: ConstraintFreeKind> ConstraintFreeKind
        for (PhantomData<G1>, PhantomData<G2>)
    {
    }
}

mod box_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Gadget<'dr, D> for Box<G> {
        type Kind = PhantomData<Box<G::Kind>>;
    }

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

    // Box is constraint-free if its inner type is constraint-free.
    impl<G: ConstraintFreeKind> ConstraintFreeKind for PhantomData<Box<G>> {}
}
