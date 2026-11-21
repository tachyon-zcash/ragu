//! Rerandomization: a fresh proof of the same header and data.

use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use rand::CryptoRng;

use crate::{
    Application, Pcd, SelectableBackend, header::Header, profile::ProfiledCycle,
    step::internal::rerandomize::Rerandomize,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Returns the cached valid `Pcd<()>` used as the neutral right child of
    /// rerandomization.
    ///
    /// The proof is lazily created by folding the bootstrap proof with itself
    /// through the unit instantiation of the rerandomization step. Subsequent
    /// calls reuse the same proof.
    fn seeded_trivial_pcd<RNG: CryptoRng>(&self, rng: &mut RNG) -> Result<Pcd<C, R, ()>> {
        let proof = match self.seeded_trivial.get() {
            Some(proof) => proof,
            None => {
                let (pcd, ()) = self.fuse(
                    rng,
                    Rerandomize::new(),
                    (),
                    self.bootstrap_pcd(),
                    self.bootstrap_pcd(),
                )?;
                self.seeded_trivial.get_or_init(|| pcd.into_parts().0)
            }
        };
        Ok(proof.clone().carry(()))
    }

    /// Rerandomize proof-carrying data.
    ///
    /// This will internally fold the [`Pcd`] with a cached seeded `Pcd<()>`
    /// using an internal rerandomization step, producing a
    /// fresh proof that is valid for the same [`Header`] and carries the same
    /// data. `Application::verify_uncompressed` produces the same result on
    /// the provided `pcd` as it would on the output of this method.
    ///
    /// The intent is that the output be unlinkable to the input. Today that is
    /// not achieved at all: the output embeds the input's commitments and stage
    /// polynomials in the clear (as its left-child data), and its folded
    /// accumulator is a deterministic function of the input proof, cached
    /// seeded proof, and public challenges. Achieving witness-hiding of the
    /// accumulator needs a fold-level randomizer; unlinkability of an
    /// uncompressed proof additionally needs the child data hidden (compression,
    /// or a second randomized pass). Both are future work, tracked separately.
    pub fn rerandomize<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: Pcd<C, R, H>,
        rng: &mut RNG,
    ) -> Result<Pcd<C, R, H>> {
        let seeded_trivial = self.seeded_trivial_pcd(rng)?;

        // The Rerandomize step's witness() returns the left input's data as
        // output data, preserving it through rerandomization. Its right child
        // is the valid, cached seeded unit proof.
        self.fuse(rng, Rerandomize::new(), (), pcd, seeded_trivial)
            .map(|(pcd, ())| pcd)
    }
}
