//! Gadget for asserting that an element is a root of unity.

use core::ops::Deref;

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
};
use ragu_primitives::{
    Element,
    raw::{Raw, Stable},
};

/// Wrapper type for log2 of domain size that implements `Stable<u32>`.
///
/// This type asserts that within a given circuit synthesis context, all instances
/// will dereference to the same value, satisfying the fungibility requirement.
#[derive(Copy, Clone)]
pub struct Log2DomainSize(pub u32);

impl Deref for Log2DomainSize {
    type Target = u32;
    fn deref(&self) -> &u32 {
        &self.0
    }
}

impl Stable<u32> for Log2DomainSize {}

/// A gadget representing a validated root of unity in the evaluation domain.
#[derive(Gadget)]
pub struct RootOfUnity<'dr, #[ragu(driver)] D: Driver<'dr>, S: Stable<u32>> {
    #[ragu(gadget)]
    element: Element<'dr, D>,
    #[ragu(gadget)]
    log2: Raw<'dr, D, u32, S>,
}

impl<'dr, D: Driver<'dr>, S: Stable<u32>> RootOfUnity<'dr, D, S> {
    pub fn alloc(dr: &mut D, omega: DriverValue<D, D::F>, log2_circuits: S) -> Result<Self> {
        let element = Element::alloc(dr, omega)?;

        let mut value = element.clone();
        for _ in 0..*log2_circuits {
            value = value.square(dr)?;
        }
        let one = Element::one();
        let diff = value.sub(dr, &one);
        diff.enforce_zero(dr)?;

        Ok(RootOfUnity {
            element,
            log2: Raw::new(log2_circuits),
        })
    }
}

impl<'dr, D: Driver<'dr>, S: Stable<u32>> Deref for RootOfUnity<'dr, D, S> {
    type Target = Element<'dr, D>;

    fn deref(&self) -> &Self::Target {
        &self.element
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use ff::Field;
    use ragu_pasta::{Fp, fp};
    use ragu_primitives::Simulator;

    /// Test wrapper for k that implements Stable<u32>.
    #[derive(Copy, Clone)]
    struct TestK(u32);

    impl Deref for TestK {
        type Target = u32;
        fn deref(&self) -> &u32 {
            &self.0
        }
    }

    impl Stable<u32> for TestK {}

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
    fn test_enforce_root_of_unity() -> Result<()> {
        for (i, (omega, k, should_pass)) in test_cases().into_iter().enumerate() {
            let result = Simulator::simulate(omega, |dr, witness| {
                RootOfUnity::alloc(dr, witness, TestK(k))?;
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
