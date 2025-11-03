//! # `ragu_pasta`
//!
//! This crate provides [`Pasta`], an implementation of the [`Cycle`] trait,
//! which stores the public parameters and constants used in Ragu for the fields
//! and curves associated with the [Pasta curve
//! cycle](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/).
//!
//! ## Parameter Initialization
//!
//! Runtime initialization can be done through [`Pasta::default`]. This can be
//! time consuming, which is obnoxious for tests and other purposes.
//!
//! Alternatively, the crate feature `baked` can be enabled to generate the
//! parameters at compile time and store them as a static in memory.
//! [`Pasta::baked`] can then be used to obtain a `&'static Pasta` with
//! substantially lower computational cost for initialization, at the expense of
//! a larger binary size.

#![no_std]
#![allow(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1_favicon32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1_rustdoc128.png")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

use arithmetic::{Cycle, FixedGenerators};

pub use common::{PallasGenerators, Pasta, VestaGenerators};
pub use pasta_curves::{Ep, EpAffine, Eq, EqAffine, Fp, Fq};

#[macro_use]
mod macros;

mod common {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/pasta_common.rs"));
}

mod poseidon_fp;
mod poseidon_fq;

pub use poseidon_fp::PoseidonFp;
pub use poseidon_fq::PoseidonFq;

impl Cycle for Pasta {
    type CircuitField = pasta_curves::Fp;
    type ScalarField = pasta_curves::Fq;
    type NestedCurve = pasta_curves::EpAffine;
    type HostCurve = pasta_curves::EqAffine;

    type HostGenerators = VestaGenerators;
    type NestedGenerators = PallasGenerators;

    fn host_generators(&self) -> &Self::HostGenerators {
        &self.vesta
    }

    fn nested_generators(&self) -> &Self::NestedGenerators {
        &self.pallas
    }

    type CircuitPoseidon = poseidon_fp::PoseidonFp;
    type ScalarPoseidon = poseidon_fq::PoseidonFq;

    fn circuit_poseidon(&self) -> &Self::CircuitPoseidon {
        &poseidon_fp::PoseidonFp
    }
    fn scalar_poseidon(&self) -> &Self::ScalarPoseidon {
        &poseidon_fq::PoseidonFq
    }
}

impl FixedGenerators<pasta_curves::EpAffine> for PallasGenerators {
    fn g(&self) -> &[pasta_curves::EpAffine] {
        &self.g
    }

    fn h(&self) -> &pasta_curves::EpAffine {
        &self.h
    }
}

impl FixedGenerators<pasta_curves::EqAffine> for VestaGenerators {
    fn g(&self) -> &[pasta_curves::EqAffine] {
        &self.g
    }

    fn h(&self) -> &pasta_curves::EqAffine {
        &self.h
    }
}

#[cfg(feature = "baked")]
mod baked {
    use alloc::vec::Vec;
    use ff::PrimeField;
    use lazy_static::lazy_static;
    use pasta_curves::arithmetic::CurveAffine;

    use super::{PallasGenerators, Pasta, VestaGenerators};

    const RAW_PARAMETERS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pasta_parameters.bin"));

    fn get_point<C: CurveAffine>(source: &mut &[u8]) -> C {
        let mut x_repr = <C::Base as PrimeField>::Repr::default();
        let mut y_repr = <C::Base as PrimeField>::Repr::default();
        x_repr.as_mut().copy_from_slice(&source[0..32]);
        y_repr.as_mut().copy_from_slice(&source[32..64]);
        *source = &source[64..];

        let x = C::Base::from_repr(x_repr).unwrap();
        let y = C::Base::from_repr(y_repr).unwrap();

        C::from_xy(x, y).unwrap()
    }

    fn get_points_for_curve<C: CurveAffine>(source: &mut &[u8], n: usize) -> (Vec<C>, C) {
        let mut g = Vec::with_capacity(n);
        for _ in 0..n {
            g.push(get_point(source));
        }
        let h = get_point(source);

        (g, h)
    }

    lazy_static! {
        static ref PASTA_PARAMETERS: Pasta = {
            let mut params = RAW_PARAMETERS;

            let (ep_g, ep_h) = get_points_for_curve(&mut params, 1 << crate::common::DEFAULT_EP_K);
            let (eq_g, eq_h) = get_points_for_curve(&mut params, 1 << crate::common::DEFAULT_EQ_K);

            assert_eq!(params.len(), 0);

            Pasta {
                pallas: PallasGenerators { g: ep_g, h: ep_h },
                vesta: VestaGenerators { g: eq_g, h: eq_h },
            }
        };
    }

    impl Pasta {
        /// Returns a static reference to the baked-in parameters for the Pasta cycle.
        pub fn baked() -> &'static Self {
            &PASTA_PARAMETERS
        }
    }

    #[test]
    fn test_baked_params() {
        use arithmetic::{Cycle, FixedGenerators};

        let pasta = Pasta::baked();

        assert_eq!(
            pasta.nested_generators().g().len(),
            1 << crate::common::DEFAULT_EP_K
        );
        assert_eq!(
            pasta.host_generators().g().len(),
            1 << crate::common::DEFAULT_EQ_K
        );

        let regenerated = Pasta::default();

        assert_eq!(
            pasta.nested_generators().g(),
            regenerated.nested_generators().g()
        );
        assert_eq!(
            pasta.host_generators().g(),
            regenerated.host_generators().g()
        );
        assert_eq!(
            pasta.nested_generators().h(),
            regenerated.nested_generators().h()
        );
        assert_eq!(
            pasta.host_generators().h(),
            regenerated.host_generators().h()
        );
    }
}
