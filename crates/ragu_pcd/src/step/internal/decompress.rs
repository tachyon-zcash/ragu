//! Internal step that decompresses a compressed proof: the one step whose
//! output header is a compressed proof's statement.
//!
//! A profile whose native extension verifies a compressed proof carries
//! those circuits in every proof, so every fuse runs them over some
//! compressed proof. This step is the one whose own output header is the
//! decompressed proof's: it declares the unit header for both inputs, so
//! it is proved against the bootstrap proof as a seed is, and takes the
//! header data of the proof it decompresses as its witness, encoding it
//! uniformly so that one circuit serves every header type, as
//! [`Rerandomize`] does; `test_decompress_consistency` pins that. Its
//! inputs are constants, so it cannot take the base case, and
//! [`Encoded::new_uniform`] holds its witnessed output suffix away from
//! [`Dummy`].
//!
//! The step's circuit constrains nothing about the header it outputs; the
//! binding is the claims'. The native extension's statement circuit exposes
//! the output header the extension verified as its public output, and its
//! claim's $k(y)$, computed by the verifier of this proof from this proof's
//! circuit id and output header ([`statement_ky`]), is that header's when
//! the circuit id is this step's and the unit header's for any other step.
//! A proof of this step whose output header is not the decompressed
//! statement's therefore has a false claim, as a proof with relabelled
//! application headers does.
//!
//! Only a profile whose native extension declares a statement circuit
//! registers this step ([`num_internal_steps`]); for any other, its
//! witnessed header would bind to nothing.
//!
//! [`Rerandomize`]: super::rerandomize::Rerandomize
//! [`Encoded::new_uniform`]: crate::step::Encoded::new_uniform
//! [`Dummy`]: crate::header::Dummy
//! [`statement_ky`]: crate::internal::native::stages::preamble::ProofInputs::statement_ky
//! [`num_internal_steps`]: crate::step::num_internal_steps

use core::marker::PhantomData;

use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::allocator::Standard;

use super::super::{Encoded, Index, Step};
use crate::Header;
pub(crate) use crate::step::InternalStepIndex::Decompress as INTERNAL_ID;

pub(crate) struct Decompress<H> {
    _marker: PhantomData<H>,
}

impl<H> Decompress<H> {
    pub fn new() -> Self {
        Decompress {
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, H: Header<C::CircuitField>> Step<C> for Decompress<H> {
    const INDEX: Index = Index::internal(INTERNAL_ID);

    /// The header data of the decompressed proof.
    type Witness<'source> = H::Data;
    type Aux<'source> = ();

    type Left = ();
    type Right = ();
    type Output = H;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        // Uniform, so that every header type decompresses through the one
        // registered circuit; the suffix is a witness wire constrained away
        // from `Dummy` (see `Encoded::new_uniform`).
        let output = Encoded::new_uniform(dr, allocator, witness.clone())?;
        Ok(((left, right, output), witness, D::unit()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One registered circuit serves every header type: the step's circuit
    /// is the same for any `H`, so `finalize` registering `Decompress<()>`
    /// covers every decompressed header, and it stays wiring-identical to a
    /// frozen twin with constant unit inputs and a uniform output.
    #[test]
    fn test_decompress_consistency() {
        use ragu_circuits::polynomials;
        use ragu_core::{
            Result,
            drivers::{Driver, DriverValue},
            gadgets::{Bound, Kind},
            maybe::Maybe,
            pasta::{Fp, Pasta},
        };
        use ragu_primitives::{Element, allocator::Allocator};
        use ragu_testing::registry::TestRegistryBuilder;

        use crate::header::{Header, Suffix};

        const HEADER_SIZE: usize = 4;
        type R = polynomials::TestRank;

        struct Single;
        impl Header<Fp> for Single {
            const SUFFIX: Suffix = Suffix::new(0);
            type Data = Fp;
            type Output = Kind![Fp; Element<'_, _>];
            fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
                dr: &mut D,
                allocator: &mut A,
                witness: DriverValue<D, Self::Data>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Element::alloc(dr, allocator, witness)
            }
        }

        struct Pair;
        impl Header<Fp> for Pair {
            const SUFFIX: Suffix = Suffix::new(1);
            type Data = (Fp, Fp);
            type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
            fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
                dr: &mut D,
                allocator: &mut A,
                witness: DriverValue<D, Self::Data>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                let (a, b) = witness.cast();
                let a = Element::alloc(dr, allocator, a)?;
                let b = Element::alloc(dr, allocator, b)?;
                Ok((a, b))
            }
        }

        let circuit_single =
            super::super::adapter::Adapter::<Pasta, Decompress<Single>, R, HEADER_SIZE>::new(
                Decompress::new(),
            );
        let circuit_pair =
            super::super::adapter::Adapter::<Pasta, Decompress<Pair>, R, HEADER_SIZE>::new(
                Decompress::new(),
            );
        // `Decompress<()>` is the instantiation `finalize` registers.
        let circuit_unit =
            super::super::adapter::Adapter::<Pasta, Decompress<()>, R, HEADER_SIZE>::new(
                Decompress::new(),
            );

        // A frozen twin of `Decompress`, written from primitives: the
        // standard unit encoding for both inputs and one uniform wire set for
        // the output, which holds the witness.
        struct Twin;
        impl Step<Pasta> for Twin {
            const INDEX: Index = Index::internal(INTERNAL_ID);
            type Witness<'source> = ();
            type Aux<'source> = ();
            type Left = ();
            type Right = ();
            type Output = ();
            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, ()>,
                left: DriverValue<D, ()>,
                right: DriverValue<D, ()>,
            ) -> Result<(
                (
                    Encoded<'dr, D, (), HS>,
                    Encoded<'dr, D, (), HS>,
                    Encoded<'dr, D, (), HS>,
                ),
                DriverValue<D, ()>,
                DriverValue<D, ()>,
            )> {
                let allocator = &mut ragu_primitives::allocator::Standard::new();
                let left = Encoded::<'dr, D, (), HS>::new(dr, allocator, left)?;
                let right = Encoded::<'dr, D, (), HS>::new(dr, allocator, right)?;
                let output =
                    Encoded::<'dr, D, (), HS>::new_uniform(dr, allocator, witness.clone())?;
                Ok(((left, right, output), witness, D::unit()))
            }
        }
        let circuit_twin = super::super::adapter::Adapter::<Pasta, Twin, R, HEADER_SIZE>::new(Twin);

        let mut builder: TestRegistryBuilder<'_, _, R> = TestRegistryBuilder::new();
        let single_h = builder.register_circuit(circuit_single).unwrap();
        let pair_h = builder.register_circuit(circuit_pair).unwrap();
        let unit_h = builder.register_circuit(circuit_unit).unwrap();
        let twin_h = builder.register_circuit(circuit_twin).unwrap();
        let registry = builder.finalize().unwrap();

        let x = Fp::from(5u64);
        let y = Fp::from(17u64);
        assert_eq!(registry.xy(single_h, x, y), registry.xy(pair_h, x, y));
        assert_eq!(registry.xy(single_h, x, y), registry.xy(unit_h, x, y));
        assert_eq!(
            registry.xy(unit_h, x, y),
            registry.xy(twin_h, x, y),
            "Decompress must use standard unit inputs and a uniform output"
        );
    }
}
