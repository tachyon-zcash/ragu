//! Low-Level: Curve-specific logic.
//!
//! `AccumulationProver`` encapsulates all the prover logic (rule validation,
//! circuit synthesis, recursive circuit invocation) for a specific curve.

use arithmetic::CurveAffine;
use ragu_circuits::{Circuit, mesh::Mesh, polynomials::Rank};
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
    mesh: Mesh<'static, C::Scalar, R>,
}

/// TODO: Determine which the mesh construction fits in.
impl<C: CurveAffine, R: Rank> AccumulationProver<C, R> {
    /// Create a new accumulation prover with a mesh supporting up to 2^log2_circuits circuits.
    pub fn new(log2_circuits: u32) -> Self {
        Self {
            mesh: Mesh::new(log2_circuits),
        }
    }

    /// Register a circuit into this prover's mesh.
    pub fn register_circuit<Circ>(&mut self, circuit: Circ) -> Result<(), Error>
    where
        Circ: Circuit<C::Scalar> + Send + 'static,
    {
        self.mesh.add_bare_circuit(circuit)?;
        Ok(())
    }

    /// Execute one accumulation step on this curve.
    pub fn step(
        &mut self,
        _prev_acc: Accumulator<C, R>,
        _witnesses: Option<&[Vec<C::Scalar>]>,
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
        Self::new(4)
    }
}
