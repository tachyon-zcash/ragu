use std::marker::PhantomData;

use crate::accumulator::{CompressedAccumulator, UncompressedAccumulator};
use arithmetic::CurveAffine;
use ragu_circuits::{mesh::Mesh, polynomials::Rank};
use ragu_core::Error;

// TODO: https://github.com/ebfull/ragu/issues/16.
pub struct AccumulationProver<C, R>
where
    C: CurveAffine,
    R: Rank,
{
    pub(crate) _curve_cycle: PhantomData<C>,
    _rank: PhantomData<R>,
}

impl<C: CurveAffine, R: Rank> AccumulationProver<C, R> {
    pub fn new() -> Self {
        Self {
            _curve_cycle: PhantomData,
            _rank: PhantomData,
        }
    }

    /// Calling the actual in-circuit accumulation (recursive circuits)
    pub fn accumulate(
        &mut self,
        _acc1: UncompressedAccumulator<C, R>,
        _acc2: UncompressedAccumulator<C, R>,
        _circuit_tag: &str,
        _mesh: &Mesh<C::Scalar, R>,
        _application_witness: &[C::Scalar],
    ) -> Result<UncompressedAccumulator<C, R>, Error> {
        todo!()
    }

    /// Compress to succinct accmulator form.
    pub fn compress(
        &self,
        _proof: UncompressedAccumulator<C, R>,
    ) -> Result<CompressedAccumulator<C>, Error> {
        todo!()
    }

    /// Uncompress to expanded accumulator form.
    pub fn uncompress(
        &self,
        _proof: CompressedAccumulator<C>,
    ) -> Result<UncompressedAccumulator<C, R>, Error> {
        todo!()
    }
}

impl<C: CurveAffine, R: Rank> Default for AccumulationProver<C, R> {
    fn default() -> Self {
        Self::new()
    }
}
