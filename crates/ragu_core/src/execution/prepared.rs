//! Immutable Pasta bases with reusable generator tables.

#[cfg(feature = "large-msm-tables")]
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;

use udon::{
    curve::{
        Affine, AffineAdapter, Pallas, PastaCurve, PreparedAffinePoint, ProjectiveAdapter, Vesta,
    },
    field::FieldAdapter,
    msm::Bases,
};
#[cfg(feature = "large-msm-tables")]
use udon::{
    curve::{AffinePoint, ProjectivePoint},
    exec::TaskBudget,
    field::PastaField,
    msm::{AlphaCodebook, AlphaCoefficient, AlphaDescription, AlphaTable},
};

use super::{
    executor::{self, PoolExecutor},
    msm::{MsmBuffers, MsmWorkspace, execute_prepared},
};

#[derive(Clone, Debug)]
enum PastaBases {
    Pallas(PreparedBases<Pallas>),
    Vesta(PreparedBases<Vesta>),
}

#[derive(Clone, Debug)]
enum PreparedBases<P: PastaCurve> {
    Coordinates(Vec<PreparedAffinePoint<P>>),
    #[cfg(feature = "large-msm-tables")]
    Alpha(AlphaBank<P>),
}

/// Private, immutable output of Udon's table and codebook preparation. Binding
/// these buffers only checks dimensions, so they must never be populated from
/// untrusted serialized data or mixed between different descriptions/bases.
#[derive(Clone, Debug)]
#[cfg(feature = "large-msm-tables")]
struct AlphaBank<P: PastaCurve> {
    description: AlphaDescription,
    codes: Vec<u32>,
    coefficients: Vec<AlphaCoefficient>,
    entries: Vec<PreparedAffinePoint<P>>,
}

#[cfg(feature = "large-msm-tables")]
impl<P: PastaCurve> AlphaBank<P> {
    fn new(bases: &[PreparedAffinePoint<P>]) -> Option<Self> {
        // Sixty-four layers with cached endomorphisms trade retained memory
        // and one-time preparation for less online bucket work. Bound each
        // point bank to 192 MiB (rank 15 with 96-byte entries): larger
        // inputs still use cached endomorphism coordinates. Check amortization
        // for a serial budget so the same bank is useful in either core mode.
        let description = AlphaDescription::new(7).expect("supported alpha width");
        let required = description
            .requirements::<P, PreparedAffinePoint<P>>(bases.len())
            .ok()?;
        if !description.amortized(bases.len(), TaskBudget::SERIAL)
            || required.table_entries > (192 * 1024 * 1024) / size_of::<PreparedAffinePoint<P>>()
        {
            return None;
        }
        let mut codes = vec![0; description.codes()];
        let mut coefficients = vec![AlphaCoefficient::ZERO; description.layers()];
        let mut codebook_scratch = vec![0; description.codebook_scratch()];
        let codebook = AlphaCodebook::prepare(
            description,
            &mut codes,
            &mut coefficients,
            &mut codebook_scratch,
        );
        let mut entries =
            vec![PreparedAffinePoint::from_affine(&AffinePoint::GENERATOR); required.table_entries];
        let mut projective = vec![ProjectivePoint::IDENTITY; required.projective_scratch];
        let mut field = vec![PastaField::ZERO; required.field_scratch];
        AlphaTable::prepare(
            codebook,
            bases,
            &mut entries,
            &mut projective,
            &mut field,
            executor::options().task_budget(),
            &PoolExecutor,
        );
        Some(Self {
            description,
            codes,
            coefficients,
            entries,
        })
    }

    fn table(&self) -> AlphaTable<'_, P, PreparedAffinePoint<P>> {
        let codebook = AlphaCodebook::bind(self.description, &self.codes, &self.coefficients);
        AlphaTable::bind(codebook, &self.entries)
    }
}

impl<P: PastaCurve> PreparedBases<P> {
    fn bases(&self) -> Bases<'_, P> {
        match self {
            Self::Coordinates(bases) => Bases::Prepared(bases),
            #[cfg(feature = "large-msm-tables")]
            Self::Alpha(bank) => Bases::AlphaPrepared(bank.table()),
        }
    }
}

/// Immutable bases prepared for repeated Pasta MSMs.
///
/// Preparation caches each base's endomorphism coordinates. With the opt-in
/// `large-msm-tables` feature, it instead caches a 64-layer alpha table when
/// it fits within 192 MiB and meets Udon's serial amortization heuristic. These
/// are variable-time MSM tables for public verifier arithmetic, prepared once
/// and reused with fresh scalars. Large tables add startup work and retain
/// about 403 MB for two rank-15 banks, excluding the original bases and scratch.
/// The original bases remain available to reference backends. Neither scalar
/// rows nor MSM results are retained here.
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

fn prepare<P: PastaCurve>(bases: &dyn Any) -> Option<PreparedBases<P>> {
    let bases = bases.downcast_ref::<Vec<AffineAdapter<P>>>()?;
    let bases: Vec<_> = AffineAdapter::as_slice(bases)
        .iter()
        .map(|base| base.as_affine().map(PreparedAffinePoint::from_affine))
        .collect::<Option<_>>()?;
    #[cfg(feature = "large-msm-tables")]
    if let Some(bank) = AlphaBank::new(&bases) {
        return Some(PreparedBases::Alpha(bank));
    }
    Some(PreparedBases::Coordinates(bases))
}

fn evaluate<C: Affine, P: PastaCurve>(
    scalars: &dyn Any,
    bases: &PreparedBases<P>,
    buffers: &mut MsmBuffers<P>,
) -> C::Projective {
    let scalars = scalars
        .downcast_ref::<Vec<FieldAdapter<P::Scalar>>>()
        .expect("the prepared curve's scalar type");
    let result = ProjectiveAdapter::new(execute_prepared(
        FieldAdapter::as_slice(scalars),
        bases.bases(),
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
            #[cfg(feature = "large-msm-tables")]
            if matches!(n, 8192 | 32768 | 32769) {
                let uses_alpha = matches!(
                    &prepared.pasta,
                    PastaBases::Pallas(PreparedBases::Alpha(_))
                        | PastaBases::Vesta(PreparedBases::Alpha(_))
                );
                assert_eq!(
                    uses_alpha,
                    n <= 32768,
                    "production ranks and the storage cap"
                );
            }
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
