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
    online,
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
        online::{
            Layout,
            circuit::Witness,
            mesh::Mesh,
            source::SourceRegistry,
            stages::{Native, Nested},
        },
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
/// The decompression step's public statement is the wallet's output header.
/// The compressed proof's fields are witnesses for the chunk circuits. The
/// consumer binds each run commitment the transcript absorbs to the stage
/// holding the values the chunks check. Honest proofs use the same run
/// commitments as native verification. The mask allows nonzero values in
/// unused slots, which can change the challenges for the same proof fields.
///
/// A soundness argument for the wallet statement must cover the circuit's
/// transcript and the prover's adaptive queries, including repeated trials
/// with different unused coefficients. A bound across the verifier's rounds
/// remains open (see the decompression module's *What binds the two sides*).
///
/// The wallet registry's evaluations are claimed values of the profile's
/// online batches, which the step's fuse opens on restrictions its source
/// meshes hold to the wallet registries the [`Decompression`] carries. The
/// proof's own circuit is held to the wallet registry's domain. Both IPAs'
/// final generators are bound: the host curve's through the polynomial
/// the decompression step commits in its first output slot, the nested
/// curve's through the step's online Fq polynomial, each over round
/// challenges the transcript digest that step stages fixes before its
/// challenge. The decompression module's *Registry evaluations* and *The
/// step binding* give the arguments. The construction has not been
/// audited, and the profile is public only under the
/// `unstable-aggregator` feature.
///
/// # Privacy
///
/// Compressing the result of [`decompress`](crate::Application::decompress)
/// publishes its run stage commitments. The first two commit to the wallet
/// proof's instance commitments and scalars with a zero alpha. They stay the
/// same across independent compressions of the same underlying wallet
/// proof, so observers can link the published decompression proofs.
///
/// An ordinary fuse uses the canonical wallet bootstrap proof for its own
/// extension stages. If the parent is compressed, it publishes the run
/// commitments for that bootstrap proof. Compression is non-hiding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aggregator<const HEADER_SIZE: usize>;

impl<const HEADER_SIZE: usize> Aggregator<HEADER_SIZE> {
    /// The native chunk circuits of the decompression for
    /// `header_size`-element headers, and how many of them run transcript
    /// chunks, first among them, and digits chunks, last. The
    /// compression's transcript absorbs the output header, so the
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
                circuits: 32,
                transcript: 4,
                digits: 1,
            },
            #[cfg(test)]
            195 => Counts {
                circuits: 34,
                transcript: 6,
                digits: 1,
            },
            _ => panic!("the aggregator profile pins no circuit counts for this header size"),
        }
    }

    /// The nested chunk circuits of the decompression, the same for every
    /// header size: none run transcript chunks, and the digits chunks come
    /// last.
    pub const NESTED_CIRCUITS: Counts = Counts {
        circuits: 19,
        transcript: 0,
        digits: 1,
    };

    /// The endoscalings a step of either walk performs: what fits a step at
    /// the aggregator rank beside the stages it reserves, which cuts the
    /// walks and with them the proof's polynomials by more than the ratio
    /// to the wallet rank's four, since the sides size each other.
    pub const ENDOSCALINGS_PER_STEP: usize = 17;

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

    // One online Fq polynomial per step: the nested IPA's s(X).
    const ONLINE_FQ_POLYS: usize = 1;

    // The wallet registry's evaluations the chunks read, as openings of
    // its restrictions, which the meshes hold to the registry.
    const NATIVE_ONLINE: Layout = online::NATIVE;
    const NESTED_ONLINE: Layout = online::NESTED;
    const NATIVE_MESH: Option<Mesh> = Some(online::MESH);
    const NESTED_MESH: Option<Mesh> = Some(online::MESH);
    // The proof's own circuit is one of the wallet registry's: its domain
    // point, at which the claims' restriction is opened, is held to that
    // registry's domain, as the native verifier holds the circuit id.
    const NATIVE_DOMAIN_INPUTS: &'static [usize] = &[online::input::CIRCUIT];
    // Every circuit of either extension loads its field's online stages
    // first: the chunks, which read them, and the statement and binding
    // circuits, which share the chunks' stages after them.
    const NATIVE_ONLINE_CONSUMERS: &'static [u32] =
        online::consumers(Self::native_circuits(HEADER_SIZE).circuits + 2);
    const NESTED_ONLINE_CONSUMERS: &'static [u32] =
        online::consumers(Self::NESTED_CIRCUITS.circuits + 1);

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
    /// and padding included. The unit header is the crate's. A decompressed
    /// proof's slots hold the host IPA's $s(X)$ and padding, not the
    /// polynomials the wallet's proof carried, so every header the wallet's
    /// steps output must leave its slots to padding, which no step can
    /// open: a step of this application could otherwise open one as the
    /// polynomial its header names.
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
        for (suffix, &(wallet, carries_polynomial)) in context.wallet().output_headers() {
            if suffix.get() < u64::from(NUM_INTERNAL_SUFFIXES) {
                continue;
            }
            if carries_polynomial {
                return Err(Error::Initialization(
                    alloc::format!(
                        "the wallet application outputs a header at suffix {} whose proofs carry an online polynomial: a decompressed proof's slots hold the host IPA's challenge polynomial and padding, so a header a decompressed statement can carry must leave its slots to padding",
                        suffix.get()
                    )
                    .into(),
                ));
            }
            match headers.get(suffix) {
                Some(ours) if *ours == wallet => {}
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

    /// The wallet application's registries, which the context holds: the
    /// meshes certify the evaluations the chunks read as theirs.
    fn source_registries<'a, 'params: 'a, Base, R, B>(
        context: &'a Self::Context<'params, Base, R, B>,
    ) -> (
        Option<SourceRegistry<'a, Base::CircuitField>>,
        Option<SourceRegistry<'a, Base::ScalarField>>,
    )
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        let wallet = context.wallet();
        (
            Some(SourceRegistry::new::<WalletRank, B>(
                wallet.native_registry(),
            )),
            Some(SourceRegistry::new::<WalletRank, B>(
                wallet.nested_registry(),
            )),
        )
    }

    fn native_online_inputs<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
    ) -> Result<alloc::vec::Vec<Base::CircuitField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        Ok(context.native_online_inputs(source))
    }

    fn nested_online_inputs<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
    ) -> Result<alloc::vec::Vec<Base::ScalarField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        Ok(context.nested_online_inputs(source))
    }

    fn native_extension() -> Extension {
        extension::native_layout(Self::native_circuits(HEADER_SIZE), num_runs::<WalletRank>())
    }

    fn online_fq_polynomials<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
    ) -> Result<alloc::vec::Vec<ragu_circuits::polynomials::sparse::Polynomial<Base::ScalarField, R>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        Ok(context.online_fq_polynomials(source))
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
        online_openings: &[[Base::CircuitField; 2]; 3 * crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::CircuitField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let _ = (context, source, online_openings, registry, rng);
        Err(Error::Initialization(NO_ONLINE_STAGES.into()))
    }

    fn native_extension_rxs_with_online<'params, Base, R, const H: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        online_openings: &[[Base::CircuitField; 2]; 3 * crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::CircuitField, R>,
        online: Option<&Witness<'_, Base::CircuitField, Self, Native>>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        Self::accepts::<R>(H)?;
        let online = online.ok_or_else(|| Error::Initialization(NO_ONLINE_STAGES.into()))?;
        context.native_rxs::<Self>(
            source,
            online_openings,
            registry,
            online::stages(online),
            rng,
        )
    }

    fn nested_extension_rxs<'params, Base, R, const H: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        output_commitments: &[Base::HostCurve; crate::header::NUM_ONLINE_FP_POLYS],
        online_fq_openings: &[Base::ScalarField],
        registry: &Registry<'params, Base::ScalarField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let _ = (
            context,
            source,
            output_commitments,
            online_fq_openings,
            registry,
            rng,
        );
        Err(Error::Initialization(NO_ONLINE_STAGES.into()))
    }

    fn nested_extension_rxs_with_online<'params, Base, R, const H: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        output_commitments: &[Base::HostCurve; crate::header::NUM_ONLINE_FP_POLYS],
        online_fq_openings: &[Base::ScalarField],
        registry: &Registry<'params, Base::ScalarField, R>,
        online: Option<&Witness<'_, Base::ScalarField, Self, Nested>>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        Self::accepts::<R>(H)?;
        let online = online.ok_or_else(|| Error::Initialization(NO_ONLINE_STAGES.into()))?;
        context.nested_rxs::<Self>(
            source,
            output_commitments,
            online_fq_openings,
            registry,
            online::stages(online),
            rng,
        )
    }
}

/// The chunk circuits load the online stages the step's fuse committed, so
/// their traces are built with them.
const NO_ONLINE_STAGES: &str =
    "the aggregator's chunk circuits are traced over the step's online stages";
