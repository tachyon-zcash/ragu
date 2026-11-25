//! The aggregator profile: the fuse plus the chunk circuits that verify a
//! wallet's compressed proof, declared as its extension, with the layout
//! the profile declares to carry them and the hooks that register them.
//! The public types are re-exported through [`profile`](crate::profile).
//!
//! On the native side the extension is the circuit-field side's chunk
//! circuits, one per group of chunks of its schedule, over its six stages:
//! the instance, messages, lifts and work stages every chunk loads, the
//! transcript stage the transcript chunks load after them, and the digits
//! stage the digits chunks load after the work stage instead. Three final
//! masks bind the chunks by their last stage. After the chunks come the
//! statement circuit, which loads the instance stage alone and exposes the
//! output header the chunks verified, then the step binding, as its public
//! output, under a fourth final mask (see
//! [`StatementCircuit`](super::circuits::StatementCircuit)), and the binding
//! circuit, which loads the instance, messages, lifts and work stages and
//! exposes the commitments of the scalar-field side's run stages the
//! transcript absorbed, the side's recomputations of that side's lifts and
//! digits stages and the nested IPA's $G'$, under the work stage's final
//! mask (see [`BindingCircuit`](super::circuits::BindingCircuit)). On the
//! nested side it is the scalar-field side's chunks over its stages, one
//! per run of the compression's transcript, then the trailing, lifts, work
//! and digits stages (see [`Front`]), the digits chunks last, under two
//! final masks, and its binding circuit, which exposes its recomputation
//! of the circuit-field side's digits stage, the commitment of the first
//! output slot of the step that proves the chunks, and the point and value
//! at which that step opened its online Fq polynomial; that side's
//! transcript stage is empty and stays out.
//!
//! Every circuit of either side loads the aggregator's two online stages
//! of the side's field, which the fuse commits, before the extension's
//! (see [`OnlineInputStage`](super::stages::OnlineInputStage)).
//!
//! The chunk circuits verify a standard-profile compressed proof at rank
//! `K` as circuits at the profile's rank `R`, so the hooks take the base
//! cycle the profile extends and build the circuits over it. A profile's
//! declaration is a constant, so [`Aggregator`] declares the layout from
//! pinned circuit counts ([`native_layout`] and [`nested_layout`]) rather
//! than from the schedule, and the hooks check the pins against the
//! schedule they register.

use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{any::TypeId, iter::repeat_n};

use ragu_circuits::{
    polynomials::{AggregatorRank, Rank, WalletRank},
    registry::Registry,
};
use ragu_core::{Error, Result};
use rand::CryptoRng;

use super::{
    circuits::{self, last},
    online,
    program::Last,
    prover::{Decompressed, Decompression},
    side::{Native, Nested, Side},
    stages::{
        DigitsStage, Front, InstanceStage, LiftsStage, Runs, TranscriptStage, WorkStage, num_runs,
    },
};
use crate::{
    SelectableBackend,
    header::{NUM_INTERNAL_SUFFIXES, Suffix},
    ipa::IpaCycle,
    profile::{
        AGGREGATOR_NAME, Binding, BuiltIn, CircuitSlot, Extension, ExtensionRxs, MaskSlot, Profile,
        ProfiledCycle, Registered, Standard,
        online::{Layout, SourceRegistry, circuit::Witness, mesh::Mesh, stages as online_stages},
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
/// Applications can choose a header size from 1 through 195 field
/// elements. Decompression uses the same width on both sides, so
/// the wallet application must also fit at [`WalletRank`].
/// The profile declares its circuit counts at compile time and checks
/// them against the schedule when registering the circuits.
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
/// The decompression step's public statement includes the wallet's output
/// header and both online polynomial commitments.
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
/// the decompression step commits in its native online batch, the nested
/// curve's through the step's online Fq polynomial, each over round
/// challenges the transcript digest that step stages fixes before its
/// challenge. The decompression module's *Registry evaluations* and *The
/// step binding* give the arguments. The construction is unaudited.
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
    /// A header size outside 1 through 195 panics. This fails at compile
    /// time when evaluating the profile's associated constants.
    pub const fn native_circuits(header_size: usize) -> Counts {
        // The rank-15 schedule packs the same 27 work circuits and one
        // digits circuit across this range. Only the number of transcript
        // circuits changes. Registration checks these counts against the
        // actual schedule for the chosen width.
        let transcript = match header_size {
            1..=57 => 4,
            58..=153 => 5,
            154..=195 => 6,
            _ => panic!("the aggregator header size must be between 1 and 195"),
        };
        Counts {
            circuits: 27 + transcript + 1,
            transcript,
            digits: 1,
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
    const NATIVE_EXTENSION: usize = Self::native_circuits(HEADER_SIZE).circuits + 2 + NATIVE_STAGES;
    const NESTED_EXTENSION: usize =
        Self::NESTED_CIRCUITS.circuits + 1 + nested_stages(num_runs::<WalletRank>());

    // One online Fq polynomial per step: the nested IPA's s(X).
    const ONLINE_FQ_POLYS: usize = 1;
    const DECOMPRESS_ONLINE_POLYNOMIALS: bool = true;

    // The wallet registry's evaluations the chunks read, as openings of
    // its restrictions, which the meshes hold to the registry.
    const NATIVE_ONLINE: Layout = online::NATIVE;
    const NESTED_ONLINE: Layout = online::NESTED;
    const NATIVE_MESH: Option<Mesh> = Some(online::NATIVE_MESH);
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
    /// statement's suffix. The aggregator must register the wallet's own
    /// header type at every suffix the wallet's steps output, whether or
    /// not the header carries online polynomials.
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
        for (suffix, &wallet) in context.wallet().output_headers() {
            if suffix.get() < u64::from(NUM_INTERNAL_SUFFIXES) {
                continue;
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

    fn native_online_polynomials<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        phase: crate::profile::online::Phase,
        _: &[Base::CircuitField],
        _: crate::profile::online::PreparationChallenges<Base::CircuitField>,
    ) -> Result<
        alloc::vec::Vec<ragu_circuits::polynomials::sparse::Polynomial<Base::CircuitField, R>>,
    >
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        Ok(if phase == crate::profile::online::Phase::BeforeY {
            alloc::vec![context.host_ipa_polynomial(source)]
        } else {
            alloc::vec::Vec::new()
        })
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
        native_layout(Self::native_circuits(HEADER_SIZE), num_runs::<WalletRank>())
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
        nested_layout(Self::NESTED_CIRCUITS, num_runs::<WalletRank>())
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
        register_native_circuit::<Base, WalletRank, R, H>(
            circuit,
            Self::native_circuits(HEADER_SIZE),
            slot,
            params,
        )
    }

    fn register_native_mask<'params, Base, R: Rank, const H: usize>(
        mask: usize,
        slot: MaskSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(H)?;
        register_native_mask::<Base, WalletRank, R, H>(mask, slot)
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
        register_nested_circuit::<Base, WalletRank, R, HEADER_SIZE>(
            circuit,
            Self::NESTED_CIRCUITS,
            slot,
            params,
        )
    }

    fn register_nested_mask<'params, Base, R: Rank>(
        mask: usize,
        slot: MaskSlot<'params, Base::ScalarField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(HEADER_SIZE)?;
        register_nested_mask::<Base, WalletRank, R, HEADER_SIZE>(mask, slot)
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
        online: Option<&Witness<'_, Base::CircuitField, Self, online_stages::Native>>,
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
        online: Option<&Witness<'_, Base::ScalarField, Self, online_stages::Nested>>,
        native_online_commitments: &[Base::HostCurve],
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
            *output_commitments,
            native_online_commitments[online::HOST_IPA],
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

/// A side's stage indices among its extension's stages: its front's
/// first, `front` of them, then the lifts and work stages, and after the
/// work stage the transcript stage, on the side with one, and the digits
/// stage. The final masks follow the stages: the work stage's, the
/// transcript stage's on the side with one, the digits stage's, and on
/// that side the instance stage's, the statement circuit's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Indices {
    /// The front stages.
    pub front: usize,
    /// Whether the side has a transcript stage.
    pub with_transcript: bool,
}

impl Indices {
    /// The native side's: the instance and messages stages in front, a
    /// transcript stage after the work stage.
    pub(crate) const fn native() -> Self {
        Indices {
            front: 2,
            with_transcript: true,
        }
    }

    /// The nested side's for a proof of `runs` runs: a stage per run and
    /// the trailing stage in front, no transcript stage.
    pub(crate) const fn nested(runs: usize) -> Self {
        Indices {
            front: runs + 1,
            with_transcript: false,
        }
    }

    pub(crate) const fn lifts(self) -> u32 {
        self.front as u32
    }

    pub(crate) const fn work(self) -> u32 {
        self.front as u32 + 1
    }

    /// The transcript stage's index, on the side with one.
    pub(crate) const fn transcript(self) -> u32 {
        self.front as u32 + 2
    }

    pub(crate) const fn digits(self) -> u32 {
        self.front as u32 + 2 + self.with_transcript as u32
    }

    /// The stages.
    pub(crate) const fn stages(self) -> usize {
        self.front + 3 + self.with_transcript as usize
    }

    /// The stages every chunk circuit loads: the front, lifts and work
    /// stages.
    fn common(self) -> Vec<u32> {
        (0..=self.work()).collect()
    }
}

/// The native extension's stages: the instance, messages, lifts, work,
/// transcript and digits stages.
pub(crate) const NATIVE_STAGES: usize = Indices::native().stages();

/// The nested extension's stages for a proof of `runs` runs: a stage per
/// run, the trailing, lifts, work and digits stages.
pub(crate) const fn nested_stages(runs: usize) -> usize {
    Indices::nested(runs).stages()
}

/// A side's chunk circuit counts: its chunk circuits and, among them, how
/// many run transcript chunks, first, and how many digits chunks, last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    /// The chunk circuits.
    pub circuits: usize,
    /// How many of them, first, run transcript chunks.
    pub transcript: usize,
    /// How many of them, last, run digits chunks.
    pub digits: usize,
}

impl Counts {
    /// The chunk circuits that load no stage past the work stage.
    const fn work(self) -> usize {
        self.circuits - self.transcript - self.digits
    }
}

/// The native layout of the chunk circuits `counts` describes, for proofs
/// of `runs` runs, as the schedule orders them, and the statement and
/// binding circuits after them: every chunk circuit loads the instance,
/// messages, lifts and work stages, a transcript one the transcript stage
/// after them and a digits one the digits stage, the statement circuit
/// the instance stage alone and the binding circuit the first four. A
/// final mask binds each kind by its last stage: the work stage's, the
/// transcript stage's, the digits stage's, then the instance stage's. The
/// binding circuit exposes the nested extension's run stages, which the
/// transcript absorbed, its recomputations of that extension's lifts and
/// digits stages, and the nested IPA's $G'$, which the proof's consumer
/// holds to the step's online Fq commitment, in that order.
///
/// # Panics
///
/// Panics if the transcript and digits counts exceed the chunk circuits.
pub(crate) fn native_layout(counts: Counts, runs: usize) -> Extension {
    assert!(
        counts.transcript + counts.digits <= counts.circuits,
        "the transcript and digits circuits are among the chunk circuits"
    );
    let indices = Indices::native();
    let nested = Indices::nested(runs);
    let statement = counts.circuits as u32;
    let binding = statement + 1;
    let mut circuits = Vec::with_capacity(counts.circuits + 2);
    circuits.extend(repeat_n(
        indices
            .common()
            .into_iter()
            .chain([indices.transcript()])
            .collect::<Vec<_>>(),
        counts.transcript,
    ));
    circuits.extend(repeat_n(indices.common(), counts.work()));
    circuits.extend(repeat_n(
        indices
            .common()
            .into_iter()
            .chain([indices.digits()])
            .collect::<Vec<_>>(),
        counts.digits,
    ));
    circuits.push(vec![0]);
    circuits.push(indices.common());
    let transcript = counts.transcript as u32;
    let work = (counts.transcript + counts.work()) as u32;
    Extension {
        circuits,
        stages: indices.stages(),
        final_masks: vec![
            (transcript..work).chain([binding]).collect(),
            (0..transcript).collect(),
            (work..statement).collect(),
            vec![statement],
        ],
        statement: Some(statement),
        binding: Some(Binding {
            circuit: binding,
            stages: (0..runs as u32)
                .chain([nested.lifts(), nested.digits()])
                .collect(),
            // The step's online Fq polynomial, which holds the nested
            // IPA's s(X): its commitment is that IPA's G'.
            online: vec![0],
            native_online: Vec::new(),
            openings: Vec::new(),
        }),
    }
}

/// The nested layout of the chunk circuits `counts` describes, for proofs
/// of `runs` runs, which runs no transcript chunks, and the binding
/// circuit after them: every chunk circuit loads the run stages, the
/// trailing stage and the lifts and work stages, a digits one the digits
/// stage after them, and the binding circuit the same stages as the rest,
/// under the work stage's final mask then the digits stage's. The binding
/// circuit recomputes the native extension's digits stage and exposes, after
/// it, both application commitments and the host IPA helper's commitment,
/// then, as elements,
/// the point and value at which the proof opened its online Fq polynomial.
///
/// # Panics
///
/// Panics if `counts` has transcript circuits or more digits circuits
/// than chunk circuits.
pub(crate) fn nested_layout(counts: Counts, runs: usize) -> Extension {
    assert_eq!(
        counts.transcript, 0,
        "the scalar-field side runs no transcript chunks"
    );
    assert!(
        counts.digits <= counts.circuits,
        "the digits circuits are among the chunk circuits"
    );
    let indices = Indices::nested(runs);
    let binding = counts.circuits as u32;
    let work = counts.work() as u32;
    let mut circuits = Vec::with_capacity(counts.circuits + 1);
    circuits.extend(repeat_n(indices.common(), counts.work()));
    circuits.extend(repeat_n(
        indices
            .common()
            .into_iter()
            .chain([indices.digits()])
            .collect::<Vec<_>>(),
        counts.digits,
    ));
    circuits.push(indices.common());
    Extension {
        circuits,
        stages: indices.stages(),
        final_masks: vec![
            (0..work).chain([binding]).collect(),
            (work..binding).collect(),
        ],
        statement: None,
        binding: Some(Binding {
            circuit: binding,
            stages: vec![Indices::native().digits()],
            online: vec![0, 1],
            native_online: vec![online::HOST_IPA as u32],
            // The step's online Fq polynomial, which holds the nested
            // IPA's s(X): the chunks hold its opening to s at that point.
            openings: vec![0],
        }),
    }
}

/// The circuit counts of side `S`'s schedule: its chunk circuits and,
/// among them, the transcript ones first and the digits ones last.
///
/// # Errors
///
/// Fails if the circuits are not in that order, which the layouts do not
/// represent.
fn counts<C, S, K, R, const HEADER_SIZE: usize>() -> Result<Counts>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Side<C>,
    K: Rank,
    R: Rank,
{
    let schedule = super::program::schedule::<C, S, K, R, HEADER_SIZE>()?;
    let circuits = schedule.circuits.len();
    let kind = |index: usize| last(&schedule, index);
    let transcript = (0..circuits)
        .take_while(|&index| kind(index) == Last::Transcript)
        .count();
    let digits = (0..circuits)
        .rev()
        .take_while(|&index| kind(index) == Last::Digits)
        .count();
    if (transcript..circuits - digits).any(|index| kind(index) != Last::Work) {
        return Err(Error::Initialization(
            "the circuits are not in transcript, work, digits order".into(),
        ));
    }
    Ok(Counts {
        circuits,
        transcript,
        digits,
    })
}

/// The native circuit counts for proofs over `C` at rank `K` with
/// `HEADER_SIZE` headers, as chunk circuits at rank `R`.
#[cfg(test)]
pub(crate) fn native_counts<C, K, R, const HEADER_SIZE: usize>() -> Result<Counts>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    counts::<C, Native, K, R, HEADER_SIZE>()
}

/// The nested circuit counts, as [`native_counts`].
///
/// # Errors
///
/// Fails if the nested schedule has a transcript circuit, which its side
/// has no stage for.
#[cfg(test)]
pub(crate) fn nested_counts<C, K, R, const HEADER_SIZE: usize>() -> Result<Counts>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    let counts = counts::<C, Nested, K, R, HEADER_SIZE>()?;
    if counts.transcript > 0 {
        return Err(Error::Initialization(
            "a transcript circuit on a side without a transcript stage".into(),
        ));
    }
    Ok(counts)
}

/// The native extension: the circuit-field side's chunks over its six
/// stages, for proofs over `C` at rank `K` with `HEADER_SIZE` headers, as
/// chunk circuits at rank `R`, with its statement and binding circuits.
#[cfg(test)]
pub(crate) fn native<C, K, R, const HEADER_SIZE: usize>() -> Result<Extension>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    Ok(native_layout(
        native_counts::<C, K, R, HEADER_SIZE>()?,
        num_runs::<K>(),
    ))
}

/// The nested extension: the scalar-field side's chunks over its five
/// stages, with its binding circuit.
#[cfg(test)]
pub(crate) fn nested<C, K, R, const HEADER_SIZE: usize>() -> Result<Extension>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    Ok(nested_layout(
        nested_counts::<C, K, R, HEADER_SIZE>()?,
        num_runs::<K>(),
    ))
}

/// The schedule of side `S`, checked against the counts the profile
/// declared the side's chunk circuits at: the declaration and the circuits
/// are the same list, or the proof carries circuits that never run.
fn pinned_schedule<C, S, K, R, const HEADER_SIZE: usize>(
    pinned: Counts,
) -> Result<Arc<super::program::Schedule>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Side<C>,
    K: Rank,
    R: Rank,
{
    if counts::<C, S, K, R, HEADER_SIZE>()? != pinned {
        return Err(Error::Initialization(
            "the schedule's circuits are not the declared ones".into(),
        ));
    }
    super::program::schedule::<C, S, K, R, HEADER_SIZE>()
}

/// Registers chunk circuit `circuit` of side `S` into `slot`, by the kind
/// of chunks it runs: a
/// [`circuits::TranscriptCircuit`], a [`circuits::DigitsCircuit`] or a
/// [`circuits::Circuit`].
fn register_circuit<'params, C, S, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: Counts,
    slot: CircuitSlot<'params, S::F, R>,
    params: &'params C::Params,
) -> Result<Registered<'params, S::F, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Front<C, K, R, HEADER_SIZE>,
    K: Rank,
    R: Rank,
{
    let schedule = pinned_schedule::<C, S, K, R, HEADER_SIZE>(pinned)?;
    if circuit >= schedule.circuits.len() {
        return Err(Error::Initialization("no such circuit".into()));
    }
    match last(&schedule, circuit) {
        Last::Transcript => {
            slot.register_staged(circuits::TranscriptCircuit::<C, S, K, R, HEADER_SIZE>::new(
                circuit, schedule, params,
            ))
        }
        Last::Digits => slot.register_staged(
            circuits::DigitsCircuit::<C, S, K, R, HEADER_SIZE>::new(circuit, schedule, params),
        ),
        Last::Work => slot.register_staged(circuits::Circuit::<C, S, K, R, HEADER_SIZE>::new(
            circuit, schedule, params,
        )),
    }
}

/// Registers mask `mask` of side `S`, by `indices`: the stages'
/// masks in stage order, then the final mask of the chunks whose last
/// stage is the work stage, on a side with a transcript stage of those
/// whose last is the transcript stage, of those whose last is the digits
/// stage, and on a side with a transcript stage of the statement circuit,
/// whose last is the instance stage.
fn register_mask<'params, C, S, K, R, const HEADER_SIZE: usize>(
    mask: usize,
    slot: MaskSlot<'params, S::F, R>,
    indices: Indices,
) -> Result<Registered<'params, S::F, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Front<C, K, R, HEADER_SIZE>,
    K: Rank,
    R: Rank,
{
    type Instance<C, S, K, R, const H: usize> = InstanceStage<C, S, K, R, H>;
    type Lifts<C, S, K, R, const H: usize> = LiftsStage<C, S, K, R, H>;
    type Work<C, S, K, R, const H: usize> = WorkStage<C, S, K, R, H>;
    type Transcript<C, S, K, R, const H: usize> = TranscriptStage<C, S, K, R, H>;
    type Digits<C, S, K, R, const H: usize> = DigitsStage<C, S, K, R, H>;
    if mask < indices.front {
        return S::register_stage_mask(mask, slot);
    }
    let with_transcript = indices.with_transcript;
    let stages = indices.stages() as u32;
    let digits_final = stages + 1 + with_transcript as u32;
    match mask as u32 {
        index if index == indices.lifts() => {
            slot.register_stage_mask::<Lifts<C, S, K, R, HEADER_SIZE>>()
        }
        index if index == indices.work() => {
            slot.register_stage_mask::<Work<C, S, K, R, HEADER_SIZE>>()
        }
        index if with_transcript && index == indices.transcript() => {
            slot.register_stage_mask::<Transcript<C, S, K, R, HEADER_SIZE>>()
        }
        index if index == indices.digits() => {
            slot.register_stage_mask::<Digits<C, S, K, R, HEADER_SIZE>>()
        }
        index if index == stages => slot.register_final_mask::<Work<C, S, K, R, HEADER_SIZE>>(),
        index if with_transcript && index == stages + 1 => {
            slot.register_final_mask::<Transcript<C, S, K, R, HEADER_SIZE>>()
        }
        index if index == digits_final => {
            slot.register_final_mask::<Digits<C, S, K, R, HEADER_SIZE>>()
        }
        index if with_transcript && index == digits_final + 1 => {
            slot.register_final_mask::<Instance<C, S, K, R, HEADER_SIZE>>()
        }
        _ => Err(Error::Initialization("no such mask".into())),
    }
}

/// Registers native circuit `circuit` of a side declared at `pinned`
/// chunk circuits: a chunk circuit, at the index past them the statement
/// circuit, and at the next the binding circuit; see [`native_layout`]
/// for the layout.
pub(crate) fn register_native_circuit<'params, C, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: Counts,
    slot: CircuitSlot<'params, C::CircuitField, R>,
    params: &'params C::Params,
) -> Result<Registered<'params, C::CircuitField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    if circuit == pinned.circuits {
        let schedule = pinned_schedule::<C, Native, K, R, HEADER_SIZE>(pinned)?;
        return slot.register_staged(
            circuits::StatementCircuit::<C, Native, K, R, HEADER_SIZE>::new(schedule),
        );
    }
    if circuit == pinned.circuits + 1 {
        let schedule = pinned_schedule::<C, Native, K, R, HEADER_SIZE>(pinned)?;
        return slot.register_staged(
            circuits::BindingCircuit::<C, Native, K, R, HEADER_SIZE>::new(schedule),
        );
    }
    register_circuit::<C, Native, K, R, HEADER_SIZE>(circuit, pinned, slot, params)
}

/// Registers native mask `mask`; see [`native_layout`] for the layout.
pub(crate) fn register_native_mask<'params, C, K, R, const HEADER_SIZE: usize>(
    mask: usize,
    slot: MaskSlot<'params, C::CircuitField, R>,
) -> Result<Registered<'params, C::CircuitField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    register_mask::<C, Native, K, R, HEADER_SIZE>(mask, slot, Indices::native())
}

/// Registers nested circuit `circuit` of a side declared at `pinned`
/// chunk circuits: a chunk circuit, or at the index past them the binding
/// circuit; see [`nested_layout`] for the layout.
pub(crate) fn register_nested_circuit<'params, C, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: Counts,
    slot: CircuitSlot<'params, C::ScalarField, R>,
    params: &'params C::Params,
) -> Result<Registered<'params, C::ScalarField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
{
    if circuit == pinned.circuits {
        let schedule = pinned_schedule::<C, Nested, K, R, HEADER_SIZE>(pinned)?;
        return slot.register_staged(
            circuits::BindingCircuit::<C, Nested, K, R, HEADER_SIZE>::new(schedule),
        );
    }
    register_circuit::<C, Nested, K, R, HEADER_SIZE>(circuit, pinned, slot, params)
}

/// Registers nested mask `mask`; see [`nested_layout`] for the layout.
pub(crate) fn register_nested_mask<'params, C, K, R, const HEADER_SIZE: usize>(
    mask: usize,
    slot: MaskSlot<'params, C::ScalarField, R>,
) -> Result<Registered<'params, C::ScalarField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
{
    register_mask::<C, Nested, K, R, HEADER_SIZE>(mask, slot, Indices::nested(num_runs::<K>()))
}

#[cfg(test)]
#[path = "../../tests/decompression/aggregator.rs"]
mod tests;
