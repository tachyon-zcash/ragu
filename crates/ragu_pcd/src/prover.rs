use std::marker::PhantomData;

use arithmetic::CurveAffine;
use ragu_circuits::polynomials::Rank;
use ragu_core::Error;

use crate::accumulator::{Accumulator, CompressedAccumulator, UncompressedAccumulator};

/// Curve-specific prover that invokes recursive circuits.
///
/// This is a lower layer that actually calls into the recursive circuits
/// to perform accumulation. It operates on a single curve and doesn't know
/// about curve cycling - that's handled by `CurveCycleEngine`.
pub struct AccumulationProver<C, R>
where
    C: CurveAffine,
    R: Rank,
{
    pub(crate) _curve_cycle: PhantomData<C>,
    _rank: PhantomData<R>,
}

/// TODO: Determine which the mesh construction fits in.
impl<C: CurveAffine, R: Rank> AccumulationProver<C, R> {
    pub fn new() -> Self {
        Self {
            _curve_cycle: PhantomData,
            _rank: PhantomData,
        }
    }

    /// Execute one accumulation step on this curve. Calls into
    /// the recursive circuits.
    pub fn step(
        &mut self,
        _prev_acc: Accumulator<C, R>,
        _circuit_tag: &str,
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
