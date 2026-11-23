//! Immutable Pasta bases prepared for repeated MSMs.

use alloc::{vec, vec::Vec};
use core::{any::Any, fmt};

use udon::{
    curve::{
        Affine, AffineAdapter, AffinePoint, Pallas, PastaCurve, Point, PreparedAffinePoint,
        ProjectivePoint, Vesta,
    },
    field::{FieldAdapter, PastaField},
    msm::{AlphaCodebook, AlphaCoefficient, AlphaDescription, AlphaTable, Bases},
};

use super::{
    executor::{self, PoolExecutor},
    msm::{MsmBuffers, MsmWorkspace, execute_indexed, execute_prepared, projective},
};

/// The table's window width, in bits of each half of a scalar.
///
/// Udon offers five, six and seven. Each bit doubles the table and shortens
/// the walk over a scalar: five stores 16 multiples of every base and takes 26
/// windows, where six would store 32 and take 22. Measured on Ragu's
/// commitments, six was no faster at rank 13 and at most about 5% faster at
/// rank 15, for twice the memory.
const WIDTH: u8 = 5;

const DESCRIPTION: AlphaDescription = match AlphaDescription::new(WIDTH) {
    Ok(description) => description,
    Err(_) => panic!("Udon supports this width"),
};

/// One curve's prepared bases. Udon's [`Bases`] views borrow them for each
/// MSM.
#[derive(Clone)]
enum Storage<P: PastaCurve> {
    /// Each base with its cached endomorphism coordinates.
    Points(Vec<PreparedAffinePoint<P>>),
    /// A table of each base's small multiples, in Udon's layer-major layout.
    Table {
        codes: Vec<u32>,
        coefficients: Vec<AlphaCoefficient>,
        entries: Vec<PreparedAffinePoint<P>>,
    },
}

impl<P: PastaCurve> Storage<P> {
    /// Prepares `bases` as a table when `table` is set, or returns `None` if
    /// a base is the identity.
    fn prepare(bases: &[Point<P>], table: bool) -> Option<Self> {
        let bases: Vec<AffinePoint<P>> = bases
            .iter()
            .map(|base| base.as_affine().copied())
            .collect::<Option<_>>()?;
        if !table {
            return Some(Self::Points(
                bases.iter().map(PreparedAffinePoint::from_affine).collect(),
            ));
        }

        let mut codes = vec![0; DESCRIPTION.codes()];
        let mut coefficients = vec![AlphaCoefficient::ZERO; DESCRIPTION.layers()];
        let mut scratch = vec![0; DESCRIPTION.codebook_scratch()];
        let codebook =
            AlphaCodebook::prepare(DESCRIPTION, &mut codes, &mut coefficients, &mut scratch);

        let required = DESCRIPTION
            .requirements::<P, PreparedAffinePoint<P>>(bases.len())
            .expect("the table's size fits");
        let mut entries =
            vec![PreparedAffinePoint::from_affine(&AffinePoint::GENERATOR); required.table_entries];
        let mut projective = vec![ProjectivePoint::IDENTITY; required.projective_scratch];
        let mut field = vec![PastaField::ZERO; required.field_scratch];
        AlphaTable::prepare(
            codebook,
            &bases,
            &mut entries,
            &mut projective,
            &mut field,
            executor::options().task_budget(),
            &PoolExecutor,
        );

        Some(Self::Table {
            codes,
            coefficients,
            entries,
        })
    }

    fn bases(&self) -> Bases<'_, P> {
        match self {
            Self::Points(points) => Bases::Prepared(points),
            Self::Table {
                codes,
                coefficients,
                entries,
            } => Bases::AlphaPrepared(AlphaTable::bind(
                AlphaCodebook::bind(DESCRIPTION, codes, coefficients),
                entries,
            )),
        }
    }
}

#[derive(Clone)]
enum PastaStorage {
    Pallas(Storage<Pallas>),
    Vesta(Storage<Vesta>),
}

/// Immutable bases prepared for repeated Pasta MSMs.
///
/// [`new`](Self::new) caches each base's endomorphism coordinates.
/// [`with_table`](Self::with_table) also stores small multiples of every
/// base, so that each window of a scalar selects a stored multiple rather
/// than forming it, which takes fewer point additions. Scalars are supplied
/// afresh for every multiplication; this does not cache an MSM result. The
/// original bases remain available to reference backends.
#[derive(Clone)]
pub struct PreparedMsm<C: Affine> {
    bases: Vec<C>,
    pasta: PastaStorage,
}

impl<C: Affine> fmt::Debug for PreparedMsm<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let table = matches!(
            self.pasta,
            PastaStorage::Pallas(Storage::Table { .. })
                | PastaStorage::Vesta(Storage::Table { .. })
        );
        f.debug_struct("PreparedMsm")
            .field("len", &self.bases.len())
            .field("table", &table)
            .finish_non_exhaustive()
    }
}

impl<C: Affine> PreparedMsm<C> {
    /// Prepares nonidentity Pasta bases, or returns `None` for another curve
    /// or a basis containing the identity. Those inputs use the ordinary MSM.
    pub fn new(bases: &[C]) -> Option<Self> {
        Self::prepare(bases, false)
    }

    /// Prepares nonidentity Pasta bases with a table of their small
    /// multiples, through Ragu's worker pool. Returns `None` as
    /// [`new`](Self::new) does.
    ///
    /// Preparation costs a few dozen point operations per base, and the table
    /// holds 16 points of 96 bytes for each: about 12.6 MB for 8192 bases. It
    /// is worth preparing for bases that many MSMs share, such as a
    /// commitment scheme's generators.
    pub fn with_table(bases: &[C]) -> Option<Self> {
        Self::prepare(bases, true)
    }

    fn prepare(bases: &[C], table: bool) -> Option<Self> {
        let bases = bases.to_vec();
        let pasta = prepare::<Pallas>(&bases, table)
            .map(PastaStorage::Pallas)
            .or_else(|| prepare::<Vesta>(&bases, table).map(PastaStorage::Vesta))?;
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
            PastaStorage::Pallas(storage) => {
                evaluate::<C, Pallas>(&scalars, storage.bases(), &mut workspace.pallas)
            }
            PastaStorage::Vesta(storage) => {
                evaluate::<C, Vesta>(&scalars, storage.bases(), &mut workspace.vesta)
            }
        }
    }

    /// Evaluates independent scalar rows over indexed subsets of the same
    /// bases, returning their results in input order.
    ///
    /// Each row is a list of scalars and, for each, the position of its base
    /// in the slice the bases were prepared from. Positions may repeat, and
    /// repeated positions contribute separately. The rows share one Udon
    /// batch plan and the current worker pool's task budget, as
    /// [`msm_many`](crate::msm_many)'s inputs do.
    ///
    /// # Panics
    ///
    /// Panics before executing any MSM if a row's lengths differ or a
    /// position is outside the prepared bases.
    pub fn evaluate_many_indexed(
        &self,
        rows: Vec<(Vec<C::Scalar>, Vec<u32>)>,
    ) -> Vec<C::Projective> {
        match &self.pasta {
            PastaStorage::Pallas(storage) => execute_indexed::<C, Pallas>(storage.bases(), &rows),
            PastaStorage::Vesta(storage) => execute_indexed::<C, Vesta>(storage.bases(), &rows),
        }
    }
}

fn prepare<P: PastaCurve>(bases: &dyn Any, table: bool) -> Option<Storage<P>> {
    let bases = bases.downcast_ref::<Vec<AffineAdapter<P>>>()?;
    Storage::prepare(AffineAdapter::as_slice(bases), table)
}

fn evaluate<C: Affine, P: PastaCurve>(
    scalars: &dyn Any,
    bases: Bases<'_, P>,
    buffers: &mut MsmBuffers<P>,
) -> C::Projective {
    let scalars = scalars
        .downcast_ref::<Vec<FieldAdapter<P::Scalar>>>()
        .expect("the prepared curve's scalar type");
    projective::<C, P>(execute_prepared(
        FieldAdapter::as_slice(scalars),
        bases,
        executor::options(),
        &PoolExecutor,
        buffers,
    ))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
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

    fn check_table<P: PastaCurve>() {
        let mut rng = StdRng::seed_from_u64(613);
        let generator = AffineAdapter::<P>::generator();
        let bases: Vec<_> = (0..300_u64)
            .map(|i| AffineAdapter::from(generator.to_projective() * FieldAdapter::from(i + 1)))
            .collect();
        let table = PreparedMsm::with_table(&bases).unwrap();
        assert_eq!(table.bases(), bases);

        // Dense, sparse, repeated, special-valued and empty rows in one plan.
        let rows: Vec<(Vec<FieldAdapter<P::Scalar>>, Vec<u32>)> = [300, 1, 0, 37, 300, 64]
            .into_iter()
            .enumerate()
            .map(|(row, n)| {
                let positions: Vec<u32> = (0..n)
                    .map(|i| match row {
                        // The whole table, in order.
                        0 => i as u32,
                        // Scattered positions, some of them repeated.
                        3 => rng.random_range(0..40),
                        _ => rng.random_range(0..bases.len() as u32),
                    })
                    .collect();
                let scalars = (0..n)
                    .map(|i| match (row, i % 4) {
                        (4, 0) => FieldAdapter::ZERO,
                        (4, 1) => FieldAdapter::ONE,
                        (4, 2) => -FieldAdapter::ONE,
                        _ => FieldAdapter::random(|bytes| rng.fill_bytes(bytes)),
                    })
                    .collect();
                (scalars, positions)
            })
            .collect();

        let expected: Vec<_> = rows
            .iter()
            .map(|(scalars, positions)| {
                let selected: Vec<_> = positions.iter().map(|&i| bases[i as usize]).collect();
                AffineAdapter::<P>::msm(scalars, &selected)
            })
            .collect();
        let prepared = PreparedMsm::new(&bases).unwrap();
        assert_eq!(prepared.evaluate_many_indexed(rows.clone()), expected);
        assert_eq!(table.evaluate_many_indexed(rows.clone()), expected);
        assert_eq!(table.evaluate_many_indexed(rows), expected);
        assert!(table.evaluate_many_indexed(Vec::new()).is_empty());

        let empty = PreparedMsm::<AffineAdapter<P>>::with_table(&[]).unwrap();
        assert!(empty.bases().is_empty());
        assert_eq!(
            empty.evaluate_many_indexed(vec![(vec![], vec![])]),
            [AffineAdapter::<P>::identity().to_projective()]
        );

        assert!(PreparedMsm::with_table(&[generator, AffineAdapter::<P>::identity()]).is_none());
    }

    #[test]
    fn table_msms_match_ordinary_msms_on_both_curves() {
        check_table::<Pallas>();
        check_table::<Vesta>();
    }

    #[test]
    #[should_panic(expected = "msm operands must have equal length")]
    fn table_rejects_rows_of_unequal_length() {
        let table = PreparedMsm::with_table(&[AffineAdapter::<Pallas>::generator()]).unwrap();
        table.evaluate_many_indexed(vec![(vec![FieldAdapter::ONE], vec![])]);
    }

    #[test]
    #[should_panic(expected = "every position lies within the base bank")]
    fn table_rejects_positions_outside_it() {
        let table = PreparedMsm::with_table(&[AffineAdapter::<Pallas>::generator()]).unwrap();
        table.evaluate_many_indexed(vec![(vec![FieldAdapter::ONE], vec![1])]);
    }
}
