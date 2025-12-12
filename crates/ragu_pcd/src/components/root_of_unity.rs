//! Gadget for asserting that an element is a root of unity.

use core::ops::Deref;

use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, FromDriver},
    gadgets::{Gadget, GadgetKind},
};
use ragu_primitives::Element;

/// A wrapper around an [`Element`] that should be constrained to be a $2^k$ root of unity.
///
/// The `k` value is stored in the gadget and used when [`Self::enforce`] is called.
pub struct RootOfUnity<'dr, D: Driver<'dr>> {
    element: Element<'dr, D>,
    k: u32,
}

impl<'dr, D: Driver<'dr>> Clone for RootOfUnity<'dr, D> {
    fn clone(&self) -> Self {
        RootOfUnity {
            element: self.element.clone(),
            k: self.k,
        }
    }
}

impl<'dr, D: Driver<'dr>> RootOfUnity<'dr, D> {
    /// Wrap an element without adding constraints.
    ///
    /// Use [`Self::enforce`] to add the root-of-unity constraint later.
    pub fn unchecked(element: Element<'dr, D>, k: u32) -> Self {
        RootOfUnity { element, k }
    }

    /// Enforce that the element is a $2^k$ root of unity.
    ///
    /// This costs `k` multiplication constraints plus one linear constraint.
    pub fn enforce(&self, dr: &mut D) -> Result<()> {
        let mut value = self.element.clone();
        for _ in 0..self.k {
            value = value.square(dr)?;
        }
        let one = Element::one();
        let diff = value.sub(dr, &one);
        diff.enforce_zero(dr)?;
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>> Deref for RootOfUnity<'dr, D> {
    type Target = Element<'dr, D>;

    fn deref(&self) -> &Self::Target {
        &self.element
    }
}

/// The [`GadgetKind`] for [`RootOfUnity`].
pub struct RootOfUnityKind<F: Field>(core::marker::PhantomData<F>);

unsafe impl<F: Field> GadgetKind<F> for RootOfUnityKind<F> {
    type Rebind<'dr, D: Driver<'dr, F = F>> = RootOfUnity<'dr, D>;

    fn map_gadget<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
        this: &Self::Rebind<'dr, D>,
        ndr: &mut ND,
    ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>> {
        Ok(RootOfUnity {
            element: this.element.map(ndr)?,
            k: this.k,
        })
    }

    fn enforce_equal_gadget<'dr, D2: Driver<'dr, F = F, Wire = D::Wire>, D: Driver<'dr, F = F>>(
        dr: &mut D2,
        a: &Self::Rebind<'dr, D>,
        b: &Self::Rebind<'dr, D>,
    ) -> Result<()> {
        a.element.enforce_equal(dr, &b.element)?;
        debug_assert_eq!(a.k, b.k, "RootOfUnity k values must match");

        Ok(())
    }
}

impl<'dr, D: Driver<'dr>> Gadget<'dr, D> for RootOfUnity<'dr, D> {
    type Kind = RootOfUnityKind<D::F>;

    fn num_wires(&self) -> usize {
        self.element.num_wires()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use ff::Field;
    use ragu_pasta::{Fp, fp};
    use ragu_primitives::Simulator;

    // (omega, k, should_pass)
    fn test_cases() -> Vec<(Fp, u32, bool)> {
        // 2^32 primitive roots of unity
        let root_of_unity1 =
            fp!(0x2bce74deac30ebda362120830561f81aea322bf2b7bb7584bdad6fabd87ea32f);
        let root_of_unity2 =
            fp!(0x16d296aa2b2fb60c7f2cf0bd729140e59875893be132b539a16988b46a2131f1);
        let root_of_unity3 =
            fp!(0x0e16194e05e127fc65f98157c0a42b1c050cd2c5dd8b481c9d9e9fd0a13ee1c9);

        vec![
            // 1 is a 2^0 root of unity (1^1 = 1)
            (Fp::ONE, 0, true),
            // 1 is also a 2^k root of unity for any k (1^(2^k) = 1)
            (Fp::ONE, 1, true),
            (Fp::ONE, 2, true),
            (Fp::ONE, 3, true),
            (Fp::ONE, 8, true),
            (Fp::ONE, 30, true),
            (Fp::ONE, 31, true),
            (Fp::ONE, 32, true),
            (Fp::ONE, 1000, true),
            // -1 is a 2^k root of unity where k >= 1
            (-Fp::ONE, 0, false),
            (-Fp::ONE, 1, true),
            (-Fp::ONE, 2, true),
            (-Fp::ONE, 32, true),
            // 0 is not a root of unity for any k
            (Fp::ZERO, 0, false),
            (Fp::ZERO, 1, false),
            (Fp::ZERO, 8, false),
            (Fp::ZERO, 32, false),
            // 2 is not a root of unity
            (Fp::from(2), 0, false),
            (Fp::from(2), 1, false),
            (Fp::from(2), 8, false),
            // Arbitrary value is (likely) not a root of unity
            (Fp::from(0xdeadbeef), 4, false),
            // Examples of 2^32 roots of unity
            (root_of_unity1, 32, true),
            (root_of_unity1, 31, false),
            (root_of_unity1, 1, false),
            (root_of_unity2, 32, true),
            (root_of_unity2, 31, false),
            (root_of_unity2, 1, false),
            (root_of_unity3, 32, true),
            (root_of_unity3, 31, false),
            (root_of_unity3, 1, false),
        ]
    }

    #[test]
    fn test_root_of_unity() -> Result<()> {
        for (i, (omega, k, should_pass)) in test_cases().into_iter().enumerate() {
            let result = Simulator::simulate(omega, |dr, witness| {
                let omega = Element::alloc(dr, witness)?;
                let root = RootOfUnity::unchecked(omega, k);
                root.enforce(dr)?;
                Ok(())
            });

            assert_eq!(
                result.is_ok(),
                should_pass,
                "test case {i} failed: omega={omega:?}, k={k}, expected should_pass={should_pass}",
            );
        }

        Ok(())
    }
}
