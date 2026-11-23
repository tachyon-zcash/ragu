//! What the prover commits to polynomials with on one curve.

use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use ragu_backend::Backend;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{FixedGenerators, PreparedMsm};
use udon::curve::Affine;

/// One curve's commitment generators, with the backend's prepared bank of
/// them when it has one: a table of their multiples when the application
/// prepared one (see [`ApplicationBuilder::with_commitment_tables`]), or
/// else the bases the verifier prepared for its IPA checks.
///
/// Every commitment goes through the backend `B`, and is the one
/// [`Backend::sparse_commit`] defines whether or not there is a bank.
///
/// [`ApplicationBuilder::with_commitment_tables`]: crate::ApplicationBuilder::with_commitment_tables
pub(crate) struct Committer<'a, C: Affine, G, B> {
    generators: &'a G,
    prepared: Option<Arc<PreparedMsm<C>>>,
    _backend: PhantomData<B>,
}

impl<'a, C: Affine, G: FixedGenerators<C>, B: Backend> Committer<'a, C, G, B> {
    /// Prepares the backend's table when `with_table` is set and the backend
    /// offers one. Otherwise shares the verifier's prepared bases when
    /// available, or prepares bases of its own.
    pub(crate) fn new<R: Rank>(
        generators: &'a G,
        with_table: bool,
        verifier_bases: Option<&Arc<PreparedMsm<C>>>,
    ) -> Self {
        let bases = &generators.g()[..R::num_coeffs()];
        let prepared = with_table
            .then(|| B::prepare_commitments(bases))
            .flatten()
            .map(Arc::new)
            .or_else(|| verifier_bases.cloned())
            .or_else(|| B::prepare_msm(bases).map(Arc::new));
        Self {
            generators,
            prepared,
            _backend: PhantomData,
        }
    }

    /// Commits to a polynomial.
    pub(crate) fn commit<R: Rank>(&self, poly: &sparse::Polynomial<C::Scalar, R>) -> C {
        match &self.prepared {
            Some(prepared) => self.commit_prepared(poly, prepared).into(),
            None => B::sparse_commit_to_affine(poly, self.generators),
        }
    }

    /// Commits to a polynomial, leaving the commitment projective.
    pub(crate) fn commit_projective<R: Rank>(
        &self,
        poly: &sparse::Polynomial<C::Scalar, R>,
    ) -> C::Projective {
        match &self.prepared {
            Some(prepared) => self.commit_prepared(poly, prepared),
            None => B::sparse_commit(poly, self.generators),
        }
    }

    fn commit_prepared<R: Rank>(
        &self,
        poly: &sparse::Polynomial<C::Scalar, R>,
        prepared: &PreparedMsm<C>,
    ) -> C::Projective {
        B::sparse_commit_prepared(&[poly], self.generators, prepared)
            .pop()
            .expect("one commitment per polynomial")
    }

    /// Commits to independent polynomials together, in input order, leaving
    /// the commitments projective.
    pub(crate) fn commit_batch<R: Rank, const N: usize>(
        &self,
        polys: [&sparse::Polynomial<C::Scalar, R>; N],
    ) -> [C::Projective; N] {
        match &self.prepared {
            Some(prepared) => {
                let mut commitments =
                    B::sparse_commit_prepared(&polys, self.generators, prepared).into_iter();
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
        match &self.prepared {
            Some(prepared) => {
                let polys: Vec<_> = polys.iter().collect();
                let projective = B::sparse_commit_prepared(&polys, self.generators, prepared);
                let mut affine = alloc::vec![C::identity(); projective.len()];
                C::batch_to_affine(&projective, &mut affine);
                affine
            }
            None => B::sparse_commit_many_to_affine(polys, self.generators),
        }
    }
}
