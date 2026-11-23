//! Fixed Pasta bases with a retained table of their multiples.

use alloc::{vec, vec::Vec};
use core::{any::Any, fmt, marker::PhantomData};

use udon::{
    curve::{
        Affine, AffineAdapter, AffinePoint, Pallas, PastaCurve, Point, PreparedAffinePoint,
        ProjectivePoint, Vesta,
    },
    field::PastaField,
    msm::{AlphaCodebook, AlphaCoefficient, AlphaDescription, AlphaTable, Bases},
};

use super::{
    executor::{self, PoolExecutor},
    msm::execute_indexed,
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

/// The storage behind one curve's table. Udon's views borrow it for each MSM.
struct Layers<P: PastaCurve> {
    codes: Vec<u32>,
    coefficients: Vec<AlphaCoefficient>,
    entries: Vec<PreparedAffinePoint<P>>,
}

impl<P: PastaCurve> Layers<P> {
    /// Prepares the table, or returns `None` if a base is the identity.
    fn prepare(bases: &[Point<P>]) -> Option<Self> {
        let bases: Vec<AffinePoint<P>> = bases
            .iter()
            .map(|base| base.as_affine().copied())
            .collect::<Option<_>>()?;

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

        Some(Self {
            codes,
            coefficients,
            entries,
        })
    }

    fn bases(&self) -> Bases<'_, P> {
        Bases::AlphaPrepared(AlphaTable::bind(
            AlphaCodebook::bind(DESCRIPTION, &self.codes, &self.coefficients),
            &self.entries,
        ))
    }
}

enum PastaLayers {
    Pallas(Layers<Pallas>),
    Vesta(Layers<Vesta>),
}

/// A table of small multiples of fixed Pasta bases, for repeated MSMs over
/// subsets of them.
///
/// An MSM over raw bases forms every multiple it needs afresh. With the
/// table, each window of a scalar selects a stored multiple instead, which
/// takes fewer point additions. Preparation costs a few dozen point
/// operations per base, and the table holds 16 points of 96 bytes for each:
/// about 12.6 MB for 8192 bases. It is worth preparing for bases that many MSMs
/// share, such as a commitment scheme's generators.
pub struct BaseTable<C: Affine> {
    len: usize,
    layers: PastaLayers,
    _curve: PhantomData<C>,
}

impl<C: Affine> fmt::Debug for BaseTable<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BaseTable")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl<C: Affine> BaseTable<C> {
    /// Prepares a table of nonidentity Pasta bases through Ragu's worker
    /// pool, or returns `None` for another curve or a basis containing the
    /// identity.
    pub fn new(bases: &[C]) -> Option<Self> {
        let bases = bases.to_vec();
        let layers = prepare::<Pallas>(&bases)
            .map(PastaLayers::Pallas)
            .or_else(|| prepare::<Vesta>(&bases).map(PastaLayers::Vesta))?;
        Some(Self {
            len: bases.len(),
            layers,
            _curve: PhantomData,
        })
    }

    /// The number of bases in the table.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the table holds no bases.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Computes independent MSMs over the table's bases, returning their
    /// results in input order.
    ///
    /// Each row is a list of scalars and, for each, the position of its base
    /// in the slice the table was prepared from. Positions may repeat. The
    /// rows share one Udon batch plan and the current worker pool's task
    /// budget, as [`msm_many`](crate::msm_many)'s inputs do.
    ///
    /// # Panics
    ///
    /// Panics if a row's scalars and positions differ in length or a
    /// position lies outside the table. Every row is checked before any MSM
    /// runs.
    pub fn msm_many(&self, rows: Vec<(Vec<C::Scalar>, Vec<u32>)>) -> Vec<C::Projective> {
        match &self.layers {
            PastaLayers::Pallas(layers) => execute_indexed::<C, Pallas>(layers.bases(), &rows),
            PastaLayers::Vesta(layers) => execute_indexed::<C, Vesta>(layers.bases(), &rows),
        }
    }
}

fn prepare<P: PastaCurve>(bases: &dyn Any) -> Option<Layers<P>> {
    let bases = bases.downcast_ref::<Vec<AffineAdapter<P>>>()?;
    Layers::prepare(AffineAdapter::as_slice(bases))
}

#[cfg(test)]
mod tests {
    use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
    use udon::field::{Field, FieldAdapter};

    use super::*;

    fn check<P: PastaCurve>() {
        let mut rng = StdRng::seed_from_u64(613);
        let generator = AffineAdapter::<P>::generator();
        let bases: Vec<_> = (0..300_u64)
            .map(|i| AffineAdapter::from(generator.to_projective() * FieldAdapter::from(i + 1)))
            .collect();
        let table = BaseTable::new(&bases).unwrap();
        assert_eq!(table.len(), bases.len());
        assert!(!table.is_empty());

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
        let prepared = crate::PreparedMsm::new(&bases).unwrap();
        assert_eq!(prepared.evaluate_many_indexed(rows.clone()), expected);
        assert_eq!(table.msm_many(rows.clone()), expected);
        // The retained scratch serves a second run.
        assert_eq!(table.msm_many(rows), expected);
        assert!(table.msm_many(Vec::new()).is_empty());

        let empty = BaseTable::<AffineAdapter<P>>::new(&[]).unwrap();
        assert!(empty.is_empty());
        assert_eq!(
            empty.msm_many(vec![(vec![], vec![])]),
            [AffineAdapter::<P>::identity().to_projective()]
        );

        assert!(BaseTable::new(&[generator, AffineAdapter::<P>::identity()]).is_none());
    }

    #[test]
    fn table_msms_match_ordinary_msms_on_both_curves() {
        check::<Pallas>();
        check::<Vesta>();
    }

    #[test]
    #[should_panic(expected = "msm operands must have equal length")]
    fn table_rejects_rows_of_unequal_length() {
        let table = BaseTable::new(&[AffineAdapter::<Pallas>::generator()]).unwrap();
        table.msm_many(vec![(vec![FieldAdapter::ONE], vec![])]);
    }

    #[test]
    #[should_panic(expected = "every position lies within the base bank")]
    fn table_rejects_positions_outside_it() {
        let table = BaseTable::new(&[AffineAdapter::<Pallas>::generator()]).unwrap();
        table.msm_many(vec![(vec![FieldAdapter::ONE], vec![1])]);
    }
}
