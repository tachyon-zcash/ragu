//! The aggregator profile: the fuse plus the chunk circuits that verify a
//! wallet's compressed proof, declared as its extension. Public only under
//! the `unstable-aggregator` feature, through [`profile`](crate::profile).

use alloc::collections::BTreeMap;
use core::any::TypeId;

use ragu_circuits::{
    polynomials::{AggregatorRank, Rank, WalletRank},
    registry::Registry,
};
use ragu_core::{Error, Result};
use rand::CryptoRng;

use super::{
    extension::{self, Counts},
    prover::{Decompressed, Decompression},
};
use crate::{
    SelectableBackend,
    compress::runs::num_runs,
    header::{NUM_INTERNAL_SUFFIXES, Suffix},
    ipa::IpaCycle,
    profile::{
        AGGREGATOR_NAME, BondingSlot, BuiltIn, CircuitSlot, Extension, ExtensionRxs, Profile,
        ProfiledCycle, Registered, Standard,
    },
};

/// The aggregator profile: the fuse plus the circuits that verify a
/// [`Standard`] compressed proof in circuit, for wallet proofs over
/// [`Pasta`](ragu_core::pasta::Pasta) at the wallet rank with `HEADER_SIZE`-element headers.
///
/// The circuits are the decompression module's chunk circuits, laid out as
/// its extension, which an aggregator proves at [`AggregatorRank`]: each
/// polynomial a profile adds is one more commitment the fuse's hashing
/// circuits absorb, one more evaluation its compute-v circuit takes, two
/// more claims its collapse circuits fold and a longer walk whose every
/// step loads the longer points stage, and at the wallet rank two
/// polynomials per side already push a nested endoscaling step past the
/// budget. At four times the budget the fuse carries the extension, and
/// the hooks refuse any other rank.
///
/// A profile's declaration is a constant, so the circuit counts are
/// pinned per header size ([`native_circuits`](Self::native_circuits))
/// rather than computed from the schedule, and the hooks check the pins
/// against the schedule they register. A header size without a pin does
/// not compile; pin it from the counts the schedule's tests report. Only
/// 4-element headers are pinned outside the crate's tests, so
/// `Aggregator<4>` is the one aggregator that compiles.
///
/// Every proof of the profile carries the chunk circuits' polynomials, so
/// every fuse runs the chunks over a compressed proof, a step that
/// decompresses nothing included (see the decompression module's *What
/// remains*). The application
/// holds a [`Decompression`] of the wallet application it aggregates, taken
/// at [`finalize_with`](crate::ApplicationBuilder::finalize_with), whose
/// canonical compressed proof every fuse decompresses, except the
/// decompression step: it decompresses the wallet proof it is given
/// ([`decompress`](crate::Application::decompress)) and outputs that
/// proof's header. The extension's statement circuit exposes the header
/// the chunks verified, and its claim's $k(y)$ holds a proof of the
/// decompression step to it; each side's binding circuit exposes the other
/// side's stage commitments it absorbed or recomputed, and its claim's
/// $k(y)$ holds the two sides to one compressed proof.
///
/// The aggregator and its wallet application share one parameters
/// instance: [`finalize_with`](crate::ApplicationBuilder::finalize_with)
/// compares the two by reference, not by their generators, so finalize
/// both over one table, such as the one `baked_aggregator()` returns.
///
/// # Soundness
///
/// The profile is not yet sound against a dishonest prover. The chunk
/// circuits take the wallet registry's evaluations from the prover
/// unchecked, and the IPA's final generator $G'$ as a free witness point,
/// so a dishonest prover can have the aggregator accept a compressed proof
/// the wallet application's verifier rejects. Both close through the
/// polynomial-query hooks
/// [#821](https://github.com/tachyon-zcash/ragu/pull/821) proposes; until
/// then an aggregator proof attests a decompression an honest prover ran,
/// and the profile is public only under the `unstable-aggregator` feature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aggregator<const HEADER_SIZE: usize>;

impl<const HEADER_SIZE: usize> Aggregator<HEADER_SIZE> {
    /// The native chunk circuits of the decompression for
    /// `header_size`-element headers, and how many of them run transcript
    /// chunks, first among them, and digits chunks, last. The
    /// compression's transcript absorbs the three headers, so the
    /// transcript ones grow with the header size.
    ///
    /// # Panics
    ///
    /// Panics, in constant evaluation, for a header size without a pin,
    /// so that an aggregator over an unpinned header size does not compile.
    /// The internal tests' header size is pinned in the tests alone.
    pub const fn native_circuits(header_size: usize) -> Counts {
        match header_size {
            4 => Counts {
                circuits: 31,
                transcript: 4,
                digits: 1,
            },
            #[cfg(test)]
            103 => Counts {
                circuits: 34,
                transcript: 7,
                digits: 1,
            },
            _ => panic!("the aggregator profile pins no circuit counts for this header size"),
        }
    }

    /// The nested chunk circuits of the decompression, the same for every
    /// header size: none run transcript chunks, and the digits chunks come
    /// last.
    pub const NESTED_CIRCUITS: Counts = Counts {
        circuits: 18,
        transcript: 0,
        digits: 1,
    };

    /// The endoscalings a step of either walk performs: what fits a step at
    /// the aggregator rank beside the stages it reserves, which cuts the
    /// walks and with them the proof's polynomials by more than the ratio
    /// to the wallet rank's four, since the sides size each other.
    pub const ENDOSCALINGS_PER_STEP: usize = 14;

    /// Checks that the hooks register at the aggregator rank for the
    /// profile's header size. The hooks are generic over the rank and the
    /// header size the application declares, which [`Profile`] cannot tie
    /// to the profile's own, so the check runs when the hooks do.
    fn accepts<R: Rank>(header_size: usize) -> Result<()> {
        if R::RANK != AggregatorRank::RANK {
            return Err(Error::Initialization(
                "the aggregator profile proves at the aggregator rank".into(),
            ));
        }
        if header_size != HEADER_SIZE {
            return Err(Error::Initialization(
                "the aggregator profile's header size is not the application's".into(),
            ));
        }
        Ok(())
    }
}

impl<const HEADER_SIZE: usize> Profile for Aggregator<HEADER_SIZE> {
    const NAME: &'static str = AGGREGATOR_NAME;
    const BUILT_IN: Option<BuiltIn> = Some(BuiltIn(TypeId::of::<Self>));
    // The chunk circuits, the statement and binding circuits and the
    // stages on the native side; the chunk circuits, the binding circuit
    // and the stages on the nested side.
    const NATIVE_EXTENSION: usize =
        Self::native_circuits(HEADER_SIZE).circuits + 2 + extension::NATIVE_STAGES;
    const NESTED_EXTENSION: usize =
        Self::NESTED_CIRCUITS.circuits + 1 + extension::nested_stages(num_runs::<WalletRank>());

    const NATIVE_ENDOSCALINGS_PER_STEP: usize = Self::ENDOSCALINGS_PER_STEP;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = Self::ENDOSCALINGS_PER_STEP;

    type Context<'params, Base, R, B>
        = Decompression<'params, Base, R, HEADER_SIZE, B>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    /// The chunk circuits are registered over the parameters the
    /// application finalizes over, and their traces built over the wallet
    /// application's, so the two must be the same parameters. A
    /// decompressed statement is the wallet's output header, which this
    /// application reads through the header type it registers at the
    /// statement's suffix: it must be the wallet's own type, so that the
    /// two assign the statement the same encoding and meaning, field order
    /// and padding included. The unit header is the crate's.
    fn check_context<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        params: &Base::Params,
        headers: &BTreeMap<Suffix, TypeId>,
    ) -> Result<()>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        if !core::ptr::eq(params, context.wallet().params) {
            return Err(Error::Initialization(
                "the aggregator finalizes over other parameters than its wallet application: the chunk circuits registered over the aggregator's must match the traces built over the wallet's"
                    .into(),
            ));
        }
        for (suffix, wallet) in context.wallet().output_headers() {
            if suffix.get() < u64::from(NUM_INTERNAL_SUFFIXES) {
                continue;
            }
            match headers.get(suffix) {
                Some(ours) if ours == wallet => {}
                Some(_) => {
                    return Err(Error::Initialization(
                        alloc::format!(
                            "the aggregator registers another header type at suffix {} than the wallet application outputs there: a decompressed statement is read with the wallet's own header type",
                            suffix.get()
                        )
                        .into(),
                    ));
                }
                None => {
                    return Err(Error::Initialization(
                        alloc::format!(
                            "the aggregator registers no header at suffix {}, which the wallet application outputs: a decompressed statement is read with the wallet's own header type, registered there",
                            suffix.get()
                        )
                        .into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn native_extension() -> Extension {
        extension::native_layout(Self::native_circuits(HEADER_SIZE), num_runs::<WalletRank>())
    }

    fn nested_extension() -> Extension {
        extension::nested_layout(Self::NESTED_CIRCUITS, num_runs::<WalletRank>())
    }

    fn register_native_circuit<'params, Base, R: Rank, const H: usize>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::CircuitField, R>,
        params: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(H)?;
        extension::register_native_circuit::<Base, WalletRank, R, H>(
            circuit,
            Self::native_circuits(HEADER_SIZE),
            slot,
            params,
        )
    }

    fn register_native_bonding<'params, Base, R: Rank, const H: usize>(
        bonding: usize,
        slot: BondingSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(H)?;
        extension::register_native_bonding::<Base, WalletRank, R, H>(bonding, slot)
    }

    fn register_nested_circuit<'params, Base, R: Rank>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::ScalarField, R>,
        params: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(HEADER_SIZE)?;
        extension::register_nested_circuit::<Base, WalletRank, R, HEADER_SIZE>(
            circuit,
            Self::NESTED_CIRCUITS,
            slot,
            params,
        )
    }

    fn register_nested_bonding<'params, Base, R: Rank>(
        bonding: usize,
        slot: BondingSlot<'params, Base::ScalarField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(HEADER_SIZE)?;
        extension::register_nested_bonding::<Base, WalletRank, R, HEADER_SIZE>(bonding, slot)
    }

    fn native_extension_rxs<'params, Base, R, const H: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        registry: &Registry<'params, Base::CircuitField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        Self::accepts::<R>(H)?;
        context.native_rxs::<Self>(source, registry, rng)
    }

    fn nested_extension_rxs<'params, Base, R, const H: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        registry: &Registry<'params, Base::ScalarField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        Self::accepts::<R>(H)?;
        context.nested_rxs::<Self>(source, registry, rng)
    }
}
