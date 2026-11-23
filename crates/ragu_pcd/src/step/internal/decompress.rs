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
//! The step's circuit constrains nothing about the header data it outputs;
//! the binding is the claims'. The statement carries no polynomials, so the
//! resulting proof carries none of the compressed proof's: a proof whose
//! slots carry meaningful polynomials does not survive decompression. The
//! last output slot is padding: the step does not open it, so the adapter
//! opens it at $\zeta$ and holds it to the constant one. The first holds
//! the challenge polynomial $s(X)$ of the host curve's IPA of the
//! compressed proof, which the step commits before $\zeta$ and opens at
//! $\zeta$ without constraining the value: the extension's chunks hold the
//! value to $s$ at $\zeta$ over the round challenges they squeeze, and
//! their IPA's $G'$ to the slot's commitment, through the step binding the
//! statement claim carries (see the decompression module's *The step
//! binding*). That check is sound only if the round challenges were
//! fixed before $\zeta$ as the polynomial was, so the step also stages
//! the digest of the compressed proof's transcript, its last squeeze,
//! taken after every round message of both curves' IPAs, and opens its
//! left input's first slot, the bootstrap proof's padding, at the staged
//! wire: the opening's point makes the digest public and its value is
//! read by nothing. The chunks hold the digest to the last squeeze of the
//! transcript they run, through the same claim, so the round challenges
//! were fixed when the stage was committed. A prover who commits another
//! polynomial in the slot, or stages another digest, has a false claim.
//! The digest and the slot's commitment are functions of the compressed
//! proof, and both can be read from this step's proof. The native
//! extension's statement circuit exposes the output header the extension
//! verified as its public output, and its claim's $k(y)$, computed by the
//! verifier of this proof from this proof's circuit id, output header and
//! the two openings above, which the proof's `hashes_1` exports for it
//! ([`statement_ky`]), is that header's when the circuit id is this step's
//! and the unit header's for any other step. A proof of this step whose
//! output header is not the decompressed statement's therefore has a false
//! claim, as a proof with relabelled application headers does.
//!
//! The statement circuit exposes the compressed proof's padded output header,
//! including its suffix. At setup, the aggregator registers the wallet's
//! exact header type for each padding-only output. The decompression step
//! constrains its output suffix to differ from every wallet output suffix
//! that names an application polynomial. A wallet can use those headers in
//! earlier steps and finish with a padding-only header for decompression.
//! The application fixes the excluded suffixes when registering this
//! circuit. The statement claim binds the checked suffix to the wallet
//! proof, and a consuming fuse or the terminal verifier checks that claim.
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
//! [`statement_ky`]: crate::internal::native::stages::preamble::ProofInputs::statement_ky
//! [`num_internal_steps`]: crate::step::num_internal_steps

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::allocator::Standard;
use udon::field::Field;

use super::super::{Encoded, HeaderInput, Index, Oracles, Prepared, Step};
pub(crate) use crate::step::InternalStepIndex::Decompress as INTERNAL_ID;
use crate::{Header, header::Suffix, ipa::challenge_polynomial};

/// The output slot that holds the host IPA's $s(X)$: the first, which the
/// nested extension's binding circuit holds the IPA's $G'$ to.
pub(crate) const S_SLOT: usize = 0;

/// The left input slot the step opens at the transcript digest it staged:
/// the first. The opening's point is public, which is how the staged
/// digest reaches the statement claim; its value is the bootstrap proof's
/// padding there and is read by nothing.
pub(crate) const DIGEST_SLOT: usize = 0;

pub(crate) struct Decompress<H> {
    excluded_suffixes: Vec<Suffix>,
    _marker: PhantomData<H>,
}

impl<H> Decompress<H> {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_excluded_suffixes(&[])
    }

    pub(crate) fn with_excluded_suffixes(excluded_suffixes: &[Suffix]) -> Self {
        Decompress {
            excluded_suffixes: excluded_suffixes.to_vec(),
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, H: Header<C::CircuitField>> Step<C> for Decompress<H> {
    const INDEX: Index = Index::internal(INTERNAL_ID);

    /// The header data of the decompressed proof, the round challenges of
    /// the host curve's IPA of its compressed proof, in transcript order,
    /// and the digest of that proof's compression transcript: its last
    /// squeeze, taken after every round message of both curves' IPAs.
    type Witness<'source> = (H::Data, Vec<C::CircuitField>, C::CircuitField);
    type Aux<'source> = ();

    type Left = ();
    type Right = ();
    type Output = H;

    /// The transcript digest.
    const NUM_STAGED: usize = 1;

    /// The first output slot holds the host IPA's challenge polynomial
    /// $s(X)$, whose commitment is that IPA's $G'$; the last holds
    /// padding. The transcript digest is staged, so that it is committed
    /// with $s(X)$ before the step's challenge.
    fn prepare<'source>(
        &self,
        witness: &Self::Witness<'source>,
        _: HeaderInput<'_, C::CircuitField, ()>,
        _: HeaderInput<'_, C::CircuitField, ()>,
    ) -> Result<Prepared<C::CircuitField, H>> {
        let s = challenge_polynomial(&witness.1);
        Ok(Prepared::from_polynomials(core::array::from_fn(|slot| {
            if slot == S_SLOT {
                s.clone()
            } else {
                alloc::vec![C::CircuitField::ONE]
            }
        }))
        .stage([witness.2]))
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
        // Uniform, so that every header type decompresses through the one
        // registered circuit; the suffix is a witness wire constrained away
        // from `Dummy` and from zero (see `Encoded::new_uniform`).
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
        // The slot holding s(X) is opened at the step's challenge and its
        // value left unconstrained here: the native extension's chunks
        // hold it to s at that point, through the statement circuit's
        // claim, over the round challenges they squeeze. The other slot is
        // not opened, so the adapter holds it to the constant one.
        let zeta = oracles.zeta().clone();
        oracles.output_at(S_SLOT).open(dr, &zeta)?;
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
        use ragu_primitives::{Element, GadgetExt, allocator::Allocator};
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
        // standard unit encoding for both inputs, one uniform wire set for
        // the output, which holds the witness, the left input's first slot
        // opened at the one staged value and the first output slot opened
        // at the challenge.
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
                // The first output slot opened at the challenge and left
                // unconstrained, the last held to one as padding.
                let zeta = oracles.zeta().clone();
                oracles.output_at(0).open(dr, &zeta)?;
                for i in 1..NUM_ONLINE_FP_POLYS {
                    let value = oracles.output_at(i).open(dr, &zeta)?;
                    value.enforce_equal(dr, &Element::one())?;
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
            "Decompress must use standard unit inputs, a uniform output, one staged point and one opened output slot"
        );
    }
}
