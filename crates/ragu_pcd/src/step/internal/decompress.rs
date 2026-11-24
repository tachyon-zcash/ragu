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
//! [`Dummy`] and from zero.
//!
//! The native statement claim binds the output header and the transcript
//! digest to the wallet proof that the chunks verify. The bootstrap's
//! first slot is opened at the staged digest to expose it to that claim.
//! The nested binding claim holds each output commitment to the wallet
//! proof's corresponding commitment. The IPA helper lives in the profile's
//! native online batch (see the decompression module's *The step binding*).
//!
//! At setup the aggregator registers the wallet's exact header type for
//! each accepted output. Suffixes of unregistered polynomial-bearing
//! outputs are excluded in the decompression circuit. The statement claim
//! binds the checked suffix to the wallet proof.
//!
//! Only a profile whose native extension declares a statement circuit
//! registers this step ([`num_internal_steps`]); for any other, its
//! witnessed header would bind to nothing. `tests/decompression/statement.rs`
//! proves the step under a stand-in statement circuit and checks the
//! binding both ways.
//!
//! [`Rerandomize`]: super::rerandomize::Rerandomize
//! [`Encoded::new_uniform`]: crate::step::Encoded::new_uniform
//! [`Dummy`]: crate::header::Dummy
//! [`num_internal_steps`]: crate::step::num_internal_steps

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::allocator::Standard;

use super::super::{Encoded, HeaderInput, Index, Oracles, Prepared, Step};
pub(crate) use crate::step::InternalStepIndex::Decompress as INTERNAL_ID;
use crate::{
    Header,
    header::{NUM_ONLINE_FP_POLYS, Suffix},
};

/// The left input slot the step opens at the transcript digest it staged:
/// the first. The opening's point is public, which is how the staged
/// digest reaches the statement claim; its value is the bootstrap proof's
/// padding there and is read by nothing.
pub(crate) const DIGEST_SLOT: usize = 0;

pub(crate) struct Decompress<H> {
    excluded_suffixes: Vec<Suffix>,
    carry_polynomials: bool,
    _marker: PhantomData<H>,
}

impl<H> Decompress<H> {
    #[cfg(test)]
    pub fn new(carry_polynomials: bool) -> Self {
        Self::with_excluded_suffixes(&[], carry_polynomials)
    }

    pub(crate) fn with_excluded_suffixes(
        excluded_suffixes: &[Suffix],
        carry_polynomials: bool,
    ) -> Self {
        Decompress {
            excluded_suffixes: excluded_suffixes.to_vec(),
            carry_polynomials,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, H: Header<C::CircuitField>> Step<C> for Decompress<H> {
    const INDEX: Index = Index::internal(INTERNAL_ID);

    /// The output header data and polynomials, and the final squeeze of
    /// the wallet proof's compression transcript.
    type Witness<'source> = (
        H::Data,
        [Vec<C::CircuitField>; NUM_ONLINE_FP_POLYS],
        C::CircuitField,
    );
    type Aux<'source> = ();

    type Left = ();
    type Right = ();
    type Output = H;

    /// The transcript digest.
    const NUM_STAGED: usize = 1;

    /// Supply the two output polynomials and stage the transcript digest.
    fn prepare<'source>(
        &self,
        witness: &Self::Witness<'source>,
        _: HeaderInput<'_, C::CircuitField, ()>,
        _: HeaderInput<'_, C::CircuitField, ()>,
    ) -> Result<Prepared<C::CircuitField, H>> {
        Ok(Prepared::from_polynomials(witness.1.clone()).stage([witness.2]))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, C, Self>,
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
        // Every header type uses the same registered circuit.
        // `Encoded::new_uniform_excluding` constrains the suffix wire away
        // from `Dummy`, zero, and each suffix excluded at finalization.
        let (data, _, _) = witness.cast();
        let output =
            Encoded::new_uniform_excluding(dr, allocator, data.clone(), &self.excluded_suffixes)?;
        // The staged digest, made public as the point of an opening: the
        // left input's first slot, the bootstrap proof's padding, opened
        // there and its value left unread. The native extension's chunks
        // hold the digest to their transcript's last squeeze, through the
        // statement circuit's claim, so the round challenges they squeeze
        // were fixed when the stage was committed, before the challenge.
        let digest = oracles.staged()[0].clone();
        oracles.left_at(DIGEST_SLOT).open(dr, &digest)?;
        // The extension binds these output commitments to the wallet's
        // verified ones. The ordinary PCS batch handles their openings.
        if self.carry_polynomials {
            let zeta = oracles.zeta().clone();
            for slot in 0..NUM_ONLINE_FP_POLYS {
                oracles.output_at(slot).open(dr, &zeta)?;
            }
        }
        Ok(((left, right, output), data, D::unit()))
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

        use crate::header::{Header, NUM_ONLINE_FP_POLYS, Padding, Suffix};

        const HEADER_SIZE: usize = 4;
        type R = polynomials::TestRank;

        struct Single;
        impl Header<Fp> for Single {
            const SUFFIX: Suffix = Suffix::new(0);
            type OnlinePolyCommit = (Padding, Padding);
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
            type OnlinePolyCommit = (Padding, Padding);
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
                Decompress::new(true),
            );
        let circuit_pair =
            super::super::adapter::Adapter::<Pasta, Decompress<Pair>, R, HEADER_SIZE>::new(
                Decompress::new(true),
            );
        // `Decompress<()>` is the instantiation `finalize` registers.
        let circuit_unit =
            super::super::adapter::Adapter::<Pasta, Decompress<()>, R, HEADER_SIZE>::new(
                Decompress::new(true),
            );

        // A frozen twin of `Decompress`, written from primitives: the
        // standard unit encoding for both inputs, one uniform wire set for
        // the output, which holds the witness, the left input's first slot
        // opened at the staged value and both output slots opened at the
        // challenge.
        struct Twin;
        impl Step<Pasta> for Twin {
            const INDEX: Index = Index::internal(INTERNAL_ID);
            type Witness<'source> = ();
            type Aux<'source> = ();
            type Left = ();
            type Right = ();
            type Output = ();
            const NUM_STAGED: usize = 1;
            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
                &self,
                dr: &mut D,
                oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
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
                // The left input's first slot opened at the staged value.
                let staged = oracles.staged()[0].clone();
                oracles.left_at(0).open(dr, &staged)?;
                let zeta = oracles.zeta().clone();
                for i in 0..NUM_ONLINE_FP_POLYS {
                    oracles.output_at(i).open(dr, &zeta)?;
                }
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
            "Decompress must use standard unit inputs, a uniform output, one staged point and two opened output slots"
        );
    }
}
