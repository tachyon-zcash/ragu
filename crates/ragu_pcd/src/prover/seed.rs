//! Seeding: the leaves of a PCD tree.

use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use rand::CryptoRng;

use crate::{Application, Pcd, SelectableBackend, profile::ProfiledCycle, step::Step};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Seed a new computation by running a [`Step`] declaring `()` for both of
    /// its inputs.
    ///
    /// This is the entry point for creating leaf nodes in a PCD tree. The step
    /// is fused against the bootstrap proof that
    /// [`ApplicationBuilder::finalize`](crate::ApplicationBuilder::finalize) built or installed as both children, so
    /// this is an ordinary fuse whose child claims are enforced, not a base
    /// case.
    pub fn seed<'source, RNG: CryptoRng, S: Step<C, Left = (), Right = ()>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        self.fuse(
            rng,
            step,
            witness,
            self.bootstrap_pcd(),
            self.bootstrap_pcd(),
        )
    }
}
