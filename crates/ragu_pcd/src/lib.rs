//! # `ragu_pcd`

#![cfg_attr(not(test), no_std)]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
// #![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1_favicon32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1_rustdoc128.png")]

extern crate alloc;

use arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    mesh::{self, Mesh, MeshBuilder},
    polynomials::Rank,
};
use ragu_core::{Error, Result};
use rand::Rng;

use alloc::collections::BTreeMap;
use core::{any::TypeId, marker::PhantomData};

pub use header::Header;
pub use proof::{Pcd, Proof};
pub use step::Step;
use step::{Adapter, rerandomize::Rerandomize};

mod header;
mod proof;
pub mod step;

/// Builder for a proof-carrying data application.
///
/// ## Generic Parameters
///
/// * The [`R: Rank`](Rank) parameter defines the size of the polynomials used
///   in the construction.
/// * The [`C: Cycle`](Cycle) parameter defines the cycle of elliptic curves
///   used.
/// * The `HEADER_SIZE` parameter defines the _size_ of the headers in terms of
///   the number of elements in the public inputs reserved for each header,
///   including its discriminant (prefix).
pub struct ApplicationBuilder<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    circuit_mesh: MeshBuilder<'params, C::CircuitField, R>,
    next_step_index: usize,
    header_map: BTreeMap<header::Prefix, TypeId>,
    _marker: PhantomData<C>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Default
    for ApplicationBuilder<'_, C, R, HEADER_SIZE>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>
    ApplicationBuilder<'params, C, R, HEADER_SIZE>
{
    /// Create a new [`ApplicationBuilder`] for proof-carrying data.
    pub fn new() -> Self {
        let tmp = ApplicationBuilder {
            circuit_mesh: MeshBuilder::new(),
            next_step_index: 0,
            header_map: BTreeMap::new(),
            _marker: PhantomData,
        };
        let tmp = tmp
            .register(step::rerandomize::Rerandomize::<()>::new())
            .expect("internal step");

        tmp
    }

    /// Register a new application-defined [`Step`] in this context. The
    /// provided [`Step`]'s [`INDEX`](Step::INDEX) should be the next sequential
    /// index that has not been inserted yet.
    pub fn register<S: Step<C> + 'params>(mut self, step: S) -> Result<Self> {
        if S::INDEX.map() != self.next_step_index {
            return Err(Error::Initialization(
                "steps must be registered in sequential order".into(),
            ));
        }

        match self
            .header_map
            .get(&<S::Output as Header<C::CircuitField>>::PREFIX)
        {
            Some(ty) => {
                if *ty != TypeId::of::<S::Output>() {
                    return Err(Error::Initialization(
                        "two different Header implementations using the same prefix".into(),
                    ));
                }
            }
            None => {
                self.header_map.insert(
                    <S::Output as Header<C::CircuitField>>::PREFIX,
                    TypeId::of::<S::Output>(),
                );
            }
        }

        self.circuit_mesh = self
            .circuit_mesh
            .register_circuit(Adapter::<C, S, R, HEADER_SIZE>::new(step))?;
        self.next_step_index += 1;

        Ok(self)
    }

    /// Finalize the mesh and seed the base accumulator.
    pub fn finalize(self, params: &'params C) -> Result<Application<'params, C, R, HEADER_SIZE>> {
        // TODO: JIT-register all recursion circuits to the Vesta mesh before finalization.

        // TODO: Before registering the recursion circuits,
        // precompute the domain size, then register the recursion circuits
        // and pass them the domain size accrordingly.
        //
        // let total_circuits = num_application_circuits (variable) + num_recursion_circuits (fixed).
        // let domain_log2_size = compute_domain_log2_size(total_circuits);
        //
        // After, register recursion circuits, passing them the domain size.
        // Then inside the recursion circuits, each circuit needs to validate
        // the omega is in the expected domain.
        //
        // We should also add an assertion to check the expected circuit counts.

        let circuit_mesh = self.circuit_mesh.finalize(params.circuit_poseidon())?;

        Ok(Application {
            _marker: PhantomData,
            circuit_mesh,
            host_generators: params.host_generators(),
        })
    }
}

/// The recursion context that is used to create and verify proof-carrying data.
pub struct Application<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R, [(); HEADER_SIZE])>,
    circuit_mesh: Mesh<'params, C::CircuitField, R>,
    host_generators: &'params C::HostGenerators,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Creates a trivial proof for the empty [`Header`] implementation `()`.
    /// This may or may not be identical to any previously constructed (trivial)
    /// proof, and so is not guaranteed to be freshly randomized.
    pub fn trivial(&self) -> Proof<C, R> {
        // TODO: should we store the trivial proof and cache it?
        Proof::trivial(&self.circuit_mesh, self.host_generators)
    }

    /// Creates a random trivial proof for the empty [`Header`] implementation
    /// `()`. This takes more time to generate because it cannot be cached
    /// within the [`Application`].
    fn random<'source>(&self) -> Pcd<'source, C, R, ()> {
        Proof::random(&self.circuit_mesh, self.host_generators).carry(())
    }

    /// Merge two PCD into one using a provided [`Step`].
    ///
    /// ## Parameters
    ///
    /// * `rng`: a random number generator used to sample randomness during
    ///   proof generation. The fact that this method takes a random number
    ///   generator is not an indication that the resulting proof-carrying data
    ///   is zero-knowledge; that must be ensured by performing
    ///   [`Application::rerandomize`] at a later point.
    /// * `step`: the [`Step`] instance that has been registered in this
    ///   [`Application`].
    /// * `witness`: the witness data for the [`Step`]
    /// * `left`: the left PCD to merge in this step; must correspond to the
    ///   [`Step::Left`] header.
    /// * `right`: the right PCD to merge in this step; must correspond to the
    ///   [`Step::Right`] header.
    fn merge<'source, RNG: Rng, S: Step<C>>(
        &self,
        _rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(Proof<C, R>, S::Aux<'source>)> {
        let circuit_id = mesh::omega_j(S::INDEX.map() as u32);

        let circuit = Adapter::<C, S, R, HEADER_SIZE>::new(step);
        let (_rx, aux) = circuit.rx::<R>((left.data, right.data, witness))?;

        // TODO: Implement real accumulator folding. Currently just passing through
        // the left proof without combining it with the right proof.
        Ok((
            Proof {
                _marker: PhantomData,
                circuit_id,
                witness: left.proof.witness,
                instance: left.proof.instance,
                endoscalars: left.proof.endoscalars,
                deferreds: left.proof.deferreds,
            },
            aux,
        ))
    }

    /// Rerandomize proof-carrying data.
    ///
    /// This will internally fold the [`Pcd`] with a random proof instance using
    /// an internal rerandomization step, such that the resulting proof is valid
    /// for the same [`Header`] but reveals nothing else about the original
    /// proof. As a result, [`Application::verify`] should produce the same
    /// result on the provided `pcd` as it would the output of this method.
    pub fn rerandomize<'source, RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        pcd: Pcd<'source, C, R, H>,
        rng: &mut RNG,
    ) -> Result<Pcd<'source, C, R, H>> {
        let random_proof = self.random();
        let data = pcd.data.clone();
        let rerandomized_proof = self.merge(rng, Rerandomize::new(), (), pcd, random_proof)?;

        Ok(rerandomized_proof.0.carry(data))
    }

    /// Verifies some [`Pcd`] for the provided [`Header`].
    pub fn verify<RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        _pcd: &Pcd<'_, C, R, H>,
        mut _rng: RNG,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arithmetic::Cycle;
    use ragu_circuits::polynomials::R;
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
    };
    use ragu_pasta::Pasta;
    use step::{Encoded, Encoder, Index};

    struct ExampleStep;

    impl Step<Pasta> for ExampleStep {
        const INDEX: Index = Index::new(0);

        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = ();
        type Right = ();
        type Output = ();

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = <Pasta as Cycle>::CircuitField>, const HEADER_SIZE: usize>(
            &self,
            dr: &mut D,
            _witness: DriverValue<D, Self::Witness<'source>>,
            left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
            right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HEADER_SIZE>,
                Encoded<'dr, D, Self::Right, HEADER_SIZE>,
                Encoded<'dr, D, Self::Output, HEADER_SIZE>,
            ),
            DriverValue<D, Self::Aux<'source>>,
        )> {
            let left_encoded = left.encode(dr)?;
            let right_encoded = right.encode(dr)?;
            let output_encoded = Encoder {
                witness: D::just(|| ())
            }.encode(dr)?;

            Ok((
                (left_encoded, right_encoded, output_encoded),
                D::just(|| ()),
            ))
        }
    }

    #[test]
    fn test_trivial_proof_creation() -> Result<()> {
        let params = Pasta::default();
        type TestRank = R<10>;
        const HEADER_SIZE: usize = 8;

        let builder = ApplicationBuilder::<Pasta, TestRank, HEADER_SIZE>::new();
        let builder = builder.register(ExampleStep)?;
        let app = builder.finalize(&params)?;

        let _proof1 = app.trivial();
        let _proof2 = app.trivial();

        Ok(())
    }

    #[test]
    fn test_pcd_creation() -> Result<()> {
        let params = Pasta::default();
        type TestRank = R<10>;
        const HEADER_SIZE: usize = 8;

        let builder = ApplicationBuilder::<Pasta, TestRank, HEADER_SIZE>::new();
        let builder = builder.register(ExampleStep)?;
        let app = builder.finalize(&params)?;

        let proof = app.trivial();
        let _pcd = proof.carry::<()>(());

        Ok(())
    }

    #[test]
    fn test_multiple_steps() -> Result<()> {
        let params = Pasta::default();
        type TestRank = R<10>;
        const HEADER_SIZE: usize = 8;

        struct SecondStep;
        impl Step<Pasta> for SecondStep {
            const INDEX: Index = Index::new(1);
            type Witness<'source> = ();
            type Aux<'source> = ();
            type Left = ();
            type Right = ();
            type Output = ();

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = <Pasta as Cycle>::CircuitField>, const HEADER_SIZE: usize>(
                &self,
                dr: &mut D,
                _witness: DriverValue<D, Self::Witness<'source>>,
                left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
                right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
            ) -> Result<(
                (
                    Encoded<'dr, D, Self::Left, HEADER_SIZE>,
                    Encoded<'dr, D, Self::Right, HEADER_SIZE>,
                    Encoded<'dr, D, Self::Output, HEADER_SIZE>,
                ),
                DriverValue<D, Self::Aux<'source>>,
            )> {
                let left_encoded = left.encode(dr)?;
                let right_encoded = right.encode(dr)?;
                let output_encoded = Encoder { witness: D::just(|| ()) }.encode(dr)?;
                Ok(((left_encoded, right_encoded, output_encoded), D::just(|| ()),))
            }
        }

        let builder = ApplicationBuilder::<Pasta, TestRank, HEADER_SIZE>::new();
        let builder = builder.register(ExampleStep)?;
        let builder = builder.register(SecondStep)?;
        let _app = builder.finalize(&params)?;

        Ok(())
    }
}