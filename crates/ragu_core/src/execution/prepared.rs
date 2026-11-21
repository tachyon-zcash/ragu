//! Immutable Pasta bases with cached endomorphism coordinates.

use alloc::vec::Vec;
use core::any::Any;

use udon::{
    curve::{
        Affine, AffineAdapter, Pallas, PastaCurve, PreparedAffinePoint, ProjectiveAdapter, Vesta,
    },
    field::FieldAdapter,
};

use super::{
    executor::{self, PoolExecutor},
    msm::{MsmBuffers, MsmWorkspace, execute_prepared},
};

#[derive(Clone, Debug)]
enum PastaBases {
    Pallas(Vec<PreparedAffinePoint<Pallas>>),
    Vesta(Vec<PreparedAffinePoint<Vesta>>),
}

/// Immutable bases prepared for repeated Pasta MSMs.
///
/// Preparation caches each base's endomorphism coordinates. Scalars are
/// supplied afresh for every multiplication; this does not cache an MSM result.
/// The original bases remain available to reference backends.
#[derive(Clone, Debug)]
pub struct PreparedMsm<C: Affine> {
    bases: Vec<C>,
    pasta: PastaBases,
}

impl<C: Affine> PreparedMsm<C> {
    /// Prepares nonidentity Pasta bases, or returns `None` for another curve
    /// or a basis containing the identity. Those inputs use the ordinary MSM.
    pub fn new(bases: &[C]) -> Option<Self> {
        let bases = bases.to_vec();
        let pasta = prepare::<Pallas>(&bases)
            .map(PastaBases::Pallas)
            .or_else(|| prepare::<Vesta>(&bases).map(PastaBases::Vesta))?;
        Some(Self { bases, pasta })
    }

    /// The original bases, in their original order.
    pub fn bases(&self) -> &[C] {
        &self.bases
    }

    /// Multiplies fresh scalars by the prepared bases through Ragu's worker pool.
    ///
    /// # Panics
    ///
    /// Panics before execution unless there is exactly one scalar per base.
    pub fn evaluate(&self, scalars: Vec<C::Scalar>) -> C::Projective {
        self.evaluate_with_workspace(scalars, &mut MsmWorkspace::default())
    }

    /// Multiplies fresh scalars, retaining the workspace for later checks.
    ///
    /// The workspace may be reused across input lengths and Pasta curves.
    ///
    /// # Panics
    ///
    /// Panics before execution unless there is exactly one scalar per base.
    pub fn evaluate_with_workspace(
        &self,
        scalars: Vec<C::Scalar>,
        workspace: &mut MsmWorkspace,
    ) -> C::Projective {
        assert_eq!(
            scalars.len(),
            self.bases.len(),
            "msm operands must have equal length"
        );
        match &self.pasta {
            PastaBases::Pallas(bases) => {
                evaluate::<C, Pallas>(&scalars, bases, &mut workspace.pallas)
            }
            PastaBases::Vesta(bases) => evaluate::<C, Vesta>(&scalars, bases, &mut workspace.vesta),
        }
    }
}

fn prepare<P: PastaCurve>(bases: &dyn Any) -> Option<Vec<PreparedAffinePoint<P>>> {
    let bases = bases.downcast_ref::<Vec<AffineAdapter<P>>>()?;
    AffineAdapter::as_slice(bases)
        .iter()
        .map(|base| base.as_affine().map(PreparedAffinePoint::from_affine))
        .collect()
}

fn evaluate<C: Affine, P: PastaCurve>(
    scalars: &dyn Any,
    bases: &[PreparedAffinePoint<P>],
    buffers: &mut MsmBuffers<P>,
) -> C::Projective {
    let scalars = scalars
        .downcast_ref::<Vec<FieldAdapter<P::Scalar>>>()
        .expect("the prepared curve's scalar type");
    let result = ProjectiveAdapter::new(execute_prepared(
        FieldAdapter::as_slice(scalars),
        bases,
        executor::options(),
        &PoolExecutor,
        buffers,
    ));
    *(&result as &dyn Any)
        .downcast_ref::<C::Projective>()
        .expect("the prepared curve's projective type")
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use rand::{Rng, SeedableRng, rngs::StdRng};
    use udon::field::Field;

    use super::*;

    fn check<P: PastaCurve>(mut workspace: Option<&mut MsmWorkspace>) {
        let mut rng = StdRng::seed_from_u64(701);
        let generator = AffineAdapter::<P>::generator();
        let points: Vec<_> = (1..=17)
            .map(|i| AffineAdapter::from(generator.to_projective() * FieldAdapter::from(i)))
            .collect();
        for n in [8193, 1, 0, 128, 8192, 31, 2049, 129, 32768, 32769, 257, 0] {
            let bases: Vec<_> = (0..n).map(|i| points[i % points.len()]).collect();
            let prepared = PreparedMsm::new(&bases).unwrap();
            assert_eq!(prepared.bases(), bases);
            for row in 0..3 {
                let scalars: Vec<FieldAdapter<P::Scalar>> = (0..n)
                    .map(|i| match row {
                        0 => FieldAdapter::ZERO,
                        1 if i % 3 == 0 => -FieldAdapter::ONE,
                        1 => FieldAdapter::from(i as u64),
                        _ => FieldAdapter::random(|bytes| rng.fill_bytes(bytes)),
                    })
                    .collect();
                let expected = AffineAdapter::<P>::msm(&scalars, &bases);
                let result = match workspace.as_deref_mut() {
                    Some(workspace) => prepared.evaluate_with_workspace(scalars, workspace),
                    None => prepared.evaluate(scalars),
                };
                assert_eq!(result, expected);
            }
        }
        assert!(PreparedMsm::new(&[AffineAdapter::<P>::identity()]).is_none());
        assert!(PreparedMsm::new(&[generator, AffineAdapter::<P>::identity()]).is_none());
    }

    #[test]
    fn prepared_bases_match_ordinary_msms_on_both_curves() {
        check::<Pallas>(None);
        check::<Vesta>(None);
    }

    #[test]
    fn prepared_workspace_can_be_reused_across_sizes_scalars_and_curves() {
        let mut workspace = MsmWorkspace::default();
        check::<Pallas>(Some(&mut workspace));
        check::<Vesta>(Some(&mut workspace));
        check::<Pallas>(Some(&mut workspace));
    }

    #[test]
    #[should_panic(expected = "msm operands must have equal length")]
    fn prepared_bases_reject_short_scalar_rows() {
        let prepared = PreparedMsm::new(&[AffineAdapter::<Pallas>::generator()]).unwrap();
        prepared.evaluate(vec![]);
    }
}
