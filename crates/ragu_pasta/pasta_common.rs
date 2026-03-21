use ragu_arithmetic::CurveExt;
use group::{Curve, prime::PrimeCurveAffine};
use pasta_curves::{
    EpAffine,
    EqAffine,
    Ep,
    Eq
};

use alloc::{vec, vec::Vec};

const DOMAIN_PREFIX: &str = "Ragu-Parameters";

pub const DEFAULT_EP_K: usize = 13;
pub const DEFAULT_EQ_K: usize = 13;

/// Runtime parameters for the Pasta curve cycle, holding generator points
/// for the Pallas and Vesta curves.
pub struct PastaParams {
    pub(crate) pallas: PallasGenerators,
    pub(crate) vesta: VestaGenerators,
}

/// Fixed generators for the Pallas curve.
pub struct PallasGenerators {
    pub(crate) g: Vec<EpAffine>,
    pub(crate) h: EpAffine,
}

/// Fixed generators for the Vesta curve.
pub struct VestaGenerators {
    pub(crate) g: Vec<EqAffine>,
    pub(crate) h: EqAffine,
}

fn params_for_curve<C: CurveExt>(n: usize) -> (Vec<C::AffineExt>, C::AffineExt) {
    let g_projective = {
        let hasher = C::hash_to_curve(DOMAIN_PREFIX);
        let mut g = Vec::with_capacity(n);
        for i in 0..(n as u32) {
            let mut message = [0u8; 5];
            message[1..5].copy_from_slice(&i.to_le_bytes());
            g.push(hasher(&message));
        }
        g
    };
    let mut g = vec![C::AffineExt::identity(); n];
    Curve::batch_normalize(&g_projective[..], &mut g);

    let h: C::AffineExt = C::hash_to_curve(DOMAIN_PREFIX)(&[1]).into();

    (g, h)
}

impl PastaParams {
    /// Generate Pasta parameters at runtime via hash-to-curve.
    pub(crate) fn generate() -> Self {
        let (ep_g, ep_h) = params_for_curve::<Ep>(1usize << DEFAULT_EP_K);
        let (eq_g, eq_h) = params_for_curve::<Eq>(1usize << DEFAULT_EQ_K);

        PastaParams {
            pallas: PallasGenerators {
                g: ep_g,
                h: ep_h,
            },
            vesta: VestaGenerators {
                g: eq_g,
                h: eq_h,
            }
        }
    }
}
