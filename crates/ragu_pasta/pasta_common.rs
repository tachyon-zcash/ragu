use ragu_arithmetic::CurveExt;
use ragu_arithmetic::group::Curve;
use ragu_arithmetic::pasta_curves::{
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
    pub(crate) u: EpAffine,
}

/// Fixed generators for the Vesta curve.
pub struct VestaGenerators {
    pub(crate) g: Vec<EqAffine>,
    pub(crate) h: EqAffine,
    pub(crate) u: EqAffine,
}

fn params_for_curve<C: CurveExt>(n: usize) -> (Vec<C::AffineExt>, C::AffineExt, C::AffineExt) {
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
    // Placeholder values; every slot is overwritten by `batch_normalize` below.
    let mut g = vec![C::AffineExt::default(); n];
    Curve::batch_normalize(&g_projective[..], &mut g);

    // The one-byte messages cannot collide with the five-byte messages the
    // vector generators hash.
    let h: C::AffineExt = C::hash_to_curve(DOMAIN_PREFIX)(&[1]).into();
    let u: C::AffineExt = C::hash_to_curve(DOMAIN_PREFIX)(&[2]).into();

    (g, h, u)
}

impl PastaParams {
    /// Generate Pasta parameters at runtime via hash-to-curve.
    pub(crate) fn generate() -> Self {
        let (ep_g, ep_h, ep_u) = params_for_curve::<Ep>(1usize << DEFAULT_EP_K);
        let (eq_g, eq_h, eq_u) = params_for_curve::<Eq>(1usize << DEFAULT_EQ_K);

        PastaParams {
            pallas: PallasGenerators {
                g: ep_g,
                h: ep_h,
                u: ep_u,
            },
            vesta: VestaGenerators {
                g: eq_g,
                h: eq_h,
                u: eq_u,
            }
        }
    }
}
