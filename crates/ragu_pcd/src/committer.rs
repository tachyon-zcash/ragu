//! What the prover commits to polynomials with on one curve.

use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use ragu_backend::Backend;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{BaseTable, FixedGenerators, PreparedMsm};
use udon::curve::Affine;

/// One curve's commitment generators, with the backend's table of them when
/// the application prepared one (see
/// [`ApplicationBuilder::with_commitment_tables`]).
///
/// Every commitment goes through the backend `B`, and is the one
/// [`Backend::sparse_commit`] defines whether or not there is a table.
///
/// [`ApplicationBuilder::with_commitment_tables`]: crate::ApplicationBuilder::with_commitment_tables
pub(crate) struct Committer<'a, C: Affine, G, B> {
    generators: &'a G,
    table: Option<BaseTable<C>>,
    prepared: Option<Arc<PreparedMsm<C>>>,
    _backend: PhantomData<B>,
}

impl<'a, C: Affine, G: FixedGenerators<C>, B: Backend> Committer<'a, C, G, B> {
    /// Shares the verifier's prepared bases when available. A committer with
    /// a table uses its stored multiples for every commitment.
    pub(crate) fn new<R: Rank>(
        generators: &'a G,
        with_table: bool,
        verifier_bases: Option<&Arc<PreparedMsm<C>>>,
    ) -> Self {
        let table = with_table
            .then(|| B::prepare_commitments(&generators.g()[..R::num_coeffs()]))
            .flatten();
        let prepared = if table.is_none() {
            verifier_bases
                .cloned()
                .or_else(|| B::prepare_msm(&generators.g()[..R::num_coeffs()]).map(Arc::new))
        } else {
            None
        };
        Self {
            generators,
            table,
            prepared,
            _backend: PhantomData,
        }
    }

    /// Commits to a polynomial.
    pub(crate) fn commit<R: Rank>(&self, poly: &sparse::Polynomial<C::Scalar, R>) -> C {
        match &self.table {
            Some(table) => self.commit_tabled(poly, table).into(),
            None => B::sparse_commit_to_affine(poly, self.generators),
        }
    }

    /// Commits to a polynomial, leaving the commitment projective.
    pub(crate) fn commit_projective<R: Rank>(
        &self,
        poly: &sparse::Polynomial<C::Scalar, R>,
    ) -> C::Projective {
        match &self.table {
            Some(table) => self.commit_tabled(poly, table),
            None => B::sparse_commit(poly, self.generators),
        }
    }

    fn commit_tabled<R: Rank>(
        &self,
        poly: &sparse::Polynomial<C::Scalar, R>,
        table: &BaseTable<C>,
    ) -> C::Projective {
        B::sparse_commit_tabled(&[poly], self.generators, table)
            .pop()
            .expect("one commitment per polynomial")
    }

    /// Commits to independent polynomials together, in input order, leaving
    /// the commitments projective.
    pub(crate) fn commit_batch<R: Rank, const N: usize>(
        &self,
        polys: [&sparse::Polynomial<C::Scalar, R>; N],
    ) -> [C::Projective; N] {
        match &self.table {
            Some(table) => {
                let mut commitments =
                    B::sparse_commit_tabled(&polys, self.generators, table).into_iter();
                core::array::from_fn(|_| commitments.next().expect("one commitment per polynomial"))
            }
            None => B::sparse_commit_batch(polys, self.generators),
        }
    }

    /// Commits to a slice of polynomials together, in input order.
    pub(crate) fn commit_many<R: Rank>(
        &self,
        polys: &[sparse::Polynomial<C::Scalar, R>],
    ) -> Vec<C> {
        match (&self.table, &self.prepared) {
            (Some(table), _) => {
                let polys: Vec<_> = polys.iter().collect();
                let projective = B::sparse_commit_tabled(&polys, self.generators, table);
                let mut affine = alloc::vec![C::identity(); projective.len()];
                C::batch_to_affine(&projective, &mut affine);
                affine
            }
            (None, Some(prepared)) => {
                B::sparse_commit_many_prepared_to_affine(polys, self.generators, prepared)
            }
            (None, None) => B::sparse_commit_many_to_affine(polys, self.generators),
        }
    }
}
