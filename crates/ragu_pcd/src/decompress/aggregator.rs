//! The aggregator profile: the fuse plus the circuits that verify a
//! wallet's compressed proof, declared as its extension, with the layout
//! the profile declares to carry them and the hooks that register them.
//! The public types are re-exported through [`profile`](crate::profile).
//!
//! Each side of the verification is one circuit, the side's verifier
//! ([`SideCircuit`](super::common::SideCircuit)), cut into
//! pages: a side's extension is its pages, each a circuit over the side's
//! stages and the circuit's carry stage. On the native side the stages are
//! the instance, messages, lifts and digits stages every page loads, and
//! the carry stage, which every page loads last. After the pages comes the
//! statement circuit, which loads the instance stage alone and exposes the
//! output header the pages verified, then the step binding as its public
//! output, under a final mask (see [`StatementCircuit`](super::common::StatementCircuit)).
//! On the nested side the stages are one per run of the compression's
//! transcript, then the trailing and lifts stages (see [`Front`]), the
//! digits stage and the carry stage. A side's last page carries its whole
//! circuit's public output, so it is the side's binding circuit: on the
//! native side it exposes the commitments of the scalar-field side's run
//! stages the transcript absorbed, the side's recomputations of that
//! side's lifts and digits stages and the nested IPA's $G'$; on the nested
//! side its recomputation of the circuit-field side's digits stage, both
//! output commitments of the step that proves the pages and the commitment
//! of the host IPA's $s(X)$ in that step's native batch. A page's own
//! polynomial is under the mask of its own gates, which the pages that
//! load the same stages share.
//!
//! Every circuit of either side loads the aggregator's two online stages
//! of the side's field, which the fuse commits, before the extension's
//! (see [`OnlineInputStage`](super::stages::OnlineInputStage)).
//!
//! The pages verify a standard-profile compressed proof at rank `K` as
//! circuits at the profile's rank `R`, so the hooks take the base cycle
//! the profile extends and build the circuits over it. A profile's
//! declaration is a constant, so [`Aggregator`] declares the layout from
//! pinned page counts ([`native_layout`] and [`nested_layout`]), and the
//! hooks cut each side's circuit into the pages pinned, check the pages
//! against the circuit and refuse a circuit that does not cut.

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::any::TypeId;

use ragu_circuits::{
    paging::Planned,
    polynomials::{AggregatorRank, Rank, WalletRank},
    registry::Registry,
};
use ragu_core::{Error, Result};
use rand::CryptoRng;

use super::{
    common,
    native::Native,
    nested::{Nested, Runs},
    online,
    prover::{Decompressed, Decompression},
    stages::{DigitsStage, Front, InstanceStage, LiftsStage, num_runs},
};
use crate::{
    SelectableBackend,
    header::{NUM_INTERNAL_SUFFIXES, Suffix},
    ipa::IpaCycle,
    profile::{
        AGGREGATOR_NAME, Binding, BuiltIn, CircuitSlot, Extension, ExtensionRxs, MaskSlot,
        PageCount, PageCounts, Profile, ProfiledCycle, Registered, Standard,
        online::{Layout, SourceRegistry, circuit::Witness, mesh::Mesh, stages as online_stages},
        paging::ExtensionPages,
    },
};

// TODO(#1039): these pins hold for every header size from 1 through 195, so
// each is the most any size takes. Once the header size Tachyon uses is
// fixed, pin them for that size.
/// What the aggregator profile pins for the decompression's native side:
/// the pages its whole circuit is cut into, and the values its carry stage
/// holds. They hold for every header size from 1 through 195: the circuit
/// grows with the header, and where it cuts into fewer pages some hold no
/// gates of its own. How many pages it takes and how many values they
/// carry at each size is the census's to report (`decompression_census`).
///
/// Changing the carry capacity changes how many gates of its own each
/// page can hold, so the census measures page count and capacity together
/// at every supported header size. Every page loads the whole carry stage,
/// so a value it has room for costs half a gate on each page, whether or
/// not a page reads it: the stage is sized to what the pages carry, with
/// a margin the census prints, and not above it.
///
/// Both numbers are set by hand from that census, as the fuse's are
/// ([`Profile::PAGE_COUNTS`]), and the prover and the verifier each build
/// the side's pages from them. At these numbers the native circuit does
/// not cut into 67 pages at header size 189, and the nested one into 42
/// at any size.
pub(crate) const NATIVE_PAGES: PageCount = PageCount::new(68).carrying(608);

/// What the profile pins for the decompression's nested side, likewise.
pub(crate) const NESTED_PAGES: PageCount = PageCount::new(43).carrying(192);

/// The aggregator profile: the fuse plus the circuits that verify a
/// [`Standard`] compressed proof in circuit, for wallet proofs over
/// [`Pasta`](ragu_core::pasta::Pasta) at the wallet rank with `HEADER_SIZE`-element headers.
///
/// The circuits are the pages of the decompression module's two whole
/// circuits, one for each side, laid out as its extension, which an
/// aggregator proves at [`AggregatorRank`], the wallet's: each polynomial a
/// profile adds is one more commitment the
/// fuse's hashing circuits absorb, one more evaluation its compute-v
/// circuit takes, two more claims its collapse circuits fold and a longer
/// walk whose every step loads the longer points stage. With the
/// extension's polynomials every circuit of the fuse still fits a
/// polynomial of that rank whole, each walk step with the Standard
/// profile's eight endoscalings
/// ([`ENDOSCALINGS_PER_STEP`](Self::ENDOSCALINGS_PER_STEP)), so the profile
/// pages none of them ([`PAGE_COUNTS`](Profile::PAGE_COUNTS)). The hooks
/// refuse any other rank.
///
/// Applications can choose a header size from 1 through 195 field
/// elements. Decompression uses the same width on both sides, so
/// the wallet application must also fit at [`WalletRank`].
/// The profile declares its page counts at compile time, and a side's
/// circuit that does not cut into them is refused when its pages are
/// registered.
///
/// Every proof of the profile carries the pages' polynomials, so
/// every fuse runs both circuits over a compressed proof, a step that
/// decompresses nothing included (see the decompression module's *What
/// remains*). The application
/// holds a [`Decompression`] of the wallet application it aggregates, taken
/// at [`finalize_with`](crate::ApplicationBuilder::finalize_with), whose
/// canonical compressed proof every fuse decompresses, except the
/// decompression step: it decompresses the wallet proof it is given
/// ([`decompress`](crate::Application::decompress)) and outputs that
/// proof's header. The extension's statement circuit exposes the header
/// the native side verified, and its claim's $k(y)$ holds a proof of the
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
/// The compressed proof's fields are witnesses for the pages. The
/// consumer binds each run commitment the transcript absorbs to the stage
/// holding the values the nested side checks. Honest proofs use the same run
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
/// final generators are bound, each through the polynomial the step
/// commits in the online batch of its field, over round challenges the
/// transcript digest the decompression step stages fixes before its
/// challenge. The decompression module's *Registry evaluations* and *The
/// step binding* give the arguments. The construction is unaudited.
///
/// # Privacy
///
/// A decompressed proof carries the wallet proof's online commitments
/// unchanged, and [`Pcd::polynomials`](crate::Pcd::polynomials) returns
/// the coefficients given to the decompression, so the proof links to the
/// compressed wallet proof.
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
    /// What the profile pins for the decompression's native side: the
    /// pages its whole circuit is cut into and the values its carry stage
    /// holds, the same for every header size. Every page loads all of the
    /// circuit's stages. A census pass finds both numbers
    /// (`decompression_census`, with the crate's `test-utils` feature).
    pub const NATIVE_PAGES: PageCount = NATIVE_PAGES;

    /// What the profile pins for the decompression's nested side, as
    /// [`NATIVE_PAGES`](Self::NATIVE_PAGES) for the native side.
    pub const NESTED_PAGES: PageCount = NESTED_PAGES;

    /// The census pass over the decompression's two whole circuits, the
    /// native side's and then the nested side's, as
    /// [`native_census`](crate::profile::paging::native_census) is over
    /// the fuse's circuits: sizes each at rank `R`, cuts it as the profile
    /// pins ([`NATIVE_PAGES`](Self::NATIVE_PAGES) and
    /// [`NESTED_PAGES`](Self::NESTED_PAGES)), holds the pages to the
    /// circuit, and with `fewest` finds the fewest pages each cuts in over
    /// the carry stage pinned.
    ///
    /// # Errors
    ///
    /// Propagates any error from walking a circuit. A circuit that does not
    /// cut is reported in its
    /// [`Sizing::pages`](crate::profile::paging::Sizing::pages).
    #[cfg(feature = "test-utils")]
    pub fn decompression_census<Base, R>(
        params: &Base::Params,
        fewest: bool,
    ) -> Result<Vec<crate::profile::paging::Sizing>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
    {
        use super::{common::tables, native, nested};
        Ok(vec![
            crate::profile::paging::sized_extension(
                "decompression.native",
                NATIVE_PAGES,
                fewest,
                native::Circuit::<Base, WalletRank, R, HEADER_SIZE>::new(
                    tables::<Base, Native, WalletRank, R, HEADER_SIZE>()?,
                    params,
                ),
            )?,
            crate::profile::paging::sized_extension(
                "decompression.nested",
                NESTED_PAGES,
                fewest,
                nested::Circuit::<Base, WalletRank, R, HEADER_SIZE>::new(
                    tables::<Base, Nested, WalletRank, R, HEADER_SIZE>()?,
                    params,
                ),
            )?,
        ])
    }

    /// The profile's header size, held to the sizes it takes.
    ///
    /// # Panics
    ///
    /// A header size outside 1 through 195 panics. This fails at compile
    /// time when evaluating the profile's associated constants.
    const HEADER_SIZE: usize = {
        assert!(
            1 <= HEADER_SIZE && HEADER_SIZE <= 195,
            "the aggregator header size must be between 1 and 195"
        );
        HEADER_SIZE
    };

    /// The endoscalings a step of either walk performs: eight, as the
    /// Standard profile's steps perform, so that a step fits one polynomial
    /// whole beside the stages it loads, with little to spare. A step of
    /// more would be cut into pages of eight each, and would add a
    /// polynomial for each page and one for its carry stage.
    pub const ENDOSCALINGS_PER_STEP: usize = 8;

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
    // The pages, the statement circuit and the stages on the native side;
    // the pages and the stages on the nested side. A side's last page is
    // its binding circuit.
    const NATIVE_EXTENSION: usize = {
        let _ = Self::HEADER_SIZE;
        NATIVE_PAGES.num_pages() + 1 + NATIVE_STAGES
    };
    const NESTED_EXTENSION: usize =
        NESTED_PAGES.num_pages() + nested_stages(num_runs::<WalletRank>());

    // The wallet registry's evaluations the two sides read, as openings of
    // its restrictions, which the meshes hold to the registry, and each
    // IPA's s(X) in the batch of its field.
    const NATIVE_ONLINE: Layout = online::NATIVE;
    const NESTED_ONLINE: Layout = online::NESTED;
    const NATIVE_MESH: Option<Mesh> = Some(online::MESH);
    const NESTED_MESH: Option<Mesh> = Some(online::MESH);
    // The proof's own circuit is one of the wallet registry's: its domain
    // point, at which the claims' restriction is opened, is held to that
    // registry's domain, as the native verifier holds the circuit id.
    const NATIVE_DOMAIN_INPUTS: &'static [usize] = &[online::input::CIRCUIT];
    // Every circuit of either extension loads its field's online stages
    // first: the pages, which read them, and the statement circuit,
    // which shares the pages' stages after them.
    const NATIVE_ONLINE_CONSUMERS: &'static [u32] = online::consumers(NATIVE_PAGES.num_pages() + 1);
    const NESTED_ONLINE_CONSUMERS: &'static [u32] = online::consumers(NESTED_PAGES.num_pages());

    const NATIVE_ENDOSCALINGS_PER_STEP: usize = Self::ENDOSCALINGS_PER_STEP;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = Self::ENDOSCALINGS_PER_STEP;

    // Every circuit of the fuse fits a polynomial of the aggregator rank
    // whole, with the extension's polynomials, at every header size the
    // census checks, so none is paged. A count is the fewest pages the
    // census finds its circuit cut into at the header sizes it samples
    // (`fewest_aggregator` in `tests/paging.rs`): a count above that leaves
    // pages with no gates of their own, each still a polynomial of every
    // proof.
    const PAGE_COUNTS: PageCounts = PageCounts::WHOLE;

    type Context<'params, Base, R, B>
        = Decompression<'params, Base, R, HEADER_SIZE, B>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    /// The pages are registered over the parameters the
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
                "the aggregator finalizes over other parameters than its wallet application: the pages registered over the aggregator's must match the traces built over the wallet's"
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
    /// meshes certify the evaluations the two sides read as theirs.
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

    fn nested_online_polynomials<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        phase: crate::profile::online::Phase,
        _: &[Base::ScalarField],
        _: crate::profile::online::PreparationChallenges<Base::ScalarField>,
    ) -> Result<alloc::vec::Vec<ragu_circuits::polynomials::sparse::Polynomial<Base::ScalarField, R>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        Ok(if phase == crate::profile::online::Phase::BeforeY {
            alloc::vec![context.nested_ipa_polynomial(source)]
        } else {
            alloc::vec::Vec::new()
        })
    }

    fn native_extension() -> Extension {
        native_layout(NATIVE_PAGES.num_pages(), num_runs::<WalletRank>())
    }

    fn nested_extension() -> Extension {
        nested_layout(NESTED_PAGES.num_pages(), num_runs::<WalletRank>())
    }

    /// The native side's whole circuit, cut into the pages pinned and held
    /// to the circuit, once for a registry build.
    fn native_extension_pages<'params, Base, R: Rank, const H: usize>(
        params: &'params Base::Params,
    ) -> Result<Vec<ExtensionPages<'params, Base::CircuitField, R>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(H)?;
        let checked = common::checked::<Base, Native, WalletRank, R, H>(params)?;
        Ok(vec![ExtensionPages::new(0, &checked)?])
    }

    /// The nested side's, likewise.
    fn nested_extension_pages<'params, Base, R: Rank>(
        params: &'params Base::Params,
    ) -> Result<Vec<ExtensionPages<'params, Base::ScalarField, R>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(HEADER_SIZE)?;
        let checked = common::checked::<Base, Nested, WalletRank, R, HEADER_SIZE>(params)?;
        Ok(vec![ExtensionPages::new(0, &checked)?])
    }

    /// The statement circuit: the one native circuit that is not a page.
    fn register_native_circuit<'params, Base, R: Rank, const H: usize>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(H)?;
        register_native_circuit::<Base, WalletRank, R, H>(circuit, slot)
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

    /// Every nested circuit is a page, which the registry build registers
    /// ([`nested_extension_pages`](Self::nested_extension_pages)).
    fn register_nested_circuit<'params, Base, R: Rank>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::ScalarField, R>,
        params: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = (circuit, slot, params);
        Err(Error::Initialization("no such circuit".into()))
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
        pages: &[Planned<Base::CircuitField>],
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
        let planned = pages
            .first()
            .ok_or_else(|| Error::Initialization(NO_PAGES.into()))?;
        context.native_rxs::<Self>(
            planned,
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
        registry: &Registry<'params, Base::ScalarField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let _ = (context, source, output_commitments, registry, rng);
        Err(Error::Initialization(NO_ONLINE_STAGES.into()))
    }

    fn nested_extension_rxs_with_online<'params, Base, R, const H: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        output_commitments: &[Base::HostCurve; crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::ScalarField, R>,
        online: Option<&Witness<'_, Base::ScalarField, Self, online_stages::Nested>>,
        native_online_commitments: &[Base::HostCurve],
        pages: &[Planned<Base::ScalarField>],
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
        let planned = pages
            .first()
            .ok_or_else(|| Error::Initialization(NO_PAGES.into()))?;
        context.nested_rxs::<Self>(
            planned,
            source,
            *output_commitments,
            native_online_commitments[online::slot::IPA],
            registry,
            online::stages(online),
            rng,
        )
    }
}

/// The pages load the online stages the step's fuse committed, so their
/// traces are built with them.
const NO_ONLINE_STAGES: &str = "the aggregator's pages are traced over the step's online stages";

/// A side's whole circuit is traced in the pages its registry build cut it
/// into and registered. A prover that cut it again would do so for every
/// proof, so one that was not given the build's pages is refused.
const NO_PAGES: &str =
    "the aggregator's pages are traced by the cut its registry build kept, which was not given";

/// A side's stage indices among its extension's stages: its front's
/// first, `front` of them, then the lifts stage, the digits stage and the
/// carry stage of the side's whole circuit. The final masks follow the
/// stages: one mask over every page's own gates, and on the native side
/// the statement circuit's final mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Indices {
    /// The front stages.
    pub front: usize,
    /// Whether the side has a statement circuit.
    pub with_statement: bool,
}

impl Indices {
    /// The native side's: the instance and messages stages in front, and a
    /// statement circuit.
    pub(crate) const fn native() -> Self {
        Indices {
            front: 2,
            with_statement: true,
        }
    }

    /// The nested side's for a proof of `runs` runs: a stage per run and
    /// the trailing stage in front, no statement circuit.
    pub(crate) const fn nested(runs: usize) -> Self {
        Indices {
            front: runs + 1,
            with_statement: false,
        }
    }

    pub(crate) const fn lifts(self) -> u32 {
        self.front as u32
    }

    pub(crate) const fn digits(self) -> u32 {
        self.front as u32 + 1
    }

    /// The carry stage of the side's whole circuit.
    pub(crate) const fn carry(self) -> u32 {
        self.front as u32 + 2
    }

    /// The stages.
    pub(crate) const fn stages(self) -> usize {
        self.front + 3
    }

    /// The stages every page loads, including the carry stage.
    fn pages(self, pages: usize) -> Vec<Vec<u32>> {
        (0..pages)
            .map(|_| (0..self.stages() as u32).collect())
            .collect()
    }
}

/// The native extension's stages: the instance, messages, lifts and digits
/// stages and the carry stage.
pub(crate) const NATIVE_STAGES: usize = Indices::native().stages();

/// The nested extension's stages for a proof of `runs` runs: a stage per
/// run, the trailing, lifts and digits stages and the carry stage.
pub(crate) const fn nested_stages(runs: usize) -> usize {
    Indices::nested(runs).stages()
}

/// The native layout of a whole circuit cut as `pages` tells, for proofs
/// of `runs` runs, and the statement circuit after its pages: every page
/// loads the instance, messages, lifts and digits stages, then the carry
/// stage. The statement circuit loads the instance stage alone. A mask
/// binds every page to its own gates, and a final mask binds the statement
/// circuit by its last stage. The last page is the binding circuit: it
/// exposes the nested extension's run
/// stages, which the transcript absorbed, its recomputations of that
/// extension's lifts and digits stages, and the nested IPA's $G'$, which
/// the proof's consumer holds to the commitment of $s(X)$ in the step's
/// nested batch, in that order.
///
/// # Panics
///
/// Panics if no page is declared.
pub(crate) fn native_layout(pages: usize, runs: usize) -> Extension {
    assert!(pages > 0, "the decompression's native side takes a page");
    let indices = Indices::native();
    let nested = Indices::nested(runs);
    let statement = pages as u32;
    let mut circuits = indices.pages(pages);
    circuits.push(vec![0]);
    Extension {
        circuits,
        stages: indices.stages(),
        final_masks: vec![(0..statement).collect(), vec![statement]],
        statement: Some(statement),
        binding: Some(Binding {
            circuit: statement - 1,
            stages: (0..runs as u32)
                .chain([nested.lifts(), nested.digits()])
                .collect(),
            online: Vec::new(),
            // The nested batch's s(X) of the nested IPA: its commitment
            // is that IPA's G'.
            batch: vec![online::slot::IPA as u32],
        }),
    }
}

/// The nested layout of a whole circuit cut as `pages` tells, for proofs
/// of `runs` runs: every page loads the run, trailing, lifts and digits
/// stages, then the carry stage. One mask covers their own gates. The last
/// page is the binding circuit: it recomputes the native extension's digits
/// stage and exposes,
/// after it, both application commitments and the commitment of the host
/// IPA's $s(X)$ in the step's native batch.
///
/// # Panics
///
/// Panics if no page is declared.
pub(crate) fn nested_layout(pages: usize, runs: usize) -> Extension {
    assert!(pages > 0, "the decompression's nested side takes a page");
    let indices = Indices::nested(runs);
    let binding = pages as u32 - 1;
    Extension {
        circuits: indices.pages(pages),
        stages: indices.stages(),
        final_masks: vec![(0..=binding).collect()],
        statement: None,
        binding: Some(Binding {
            circuit: binding,
            stages: vec![Indices::native().digits()],
            online: vec![0, 1],
            // The native batch's s(X) of the host IPA.
            batch: vec![online::slot::IPA as u32],
        }),
    }
}

/// Registers mask `mask` of side `S`, by `indices`: the stages' masks in
/// stage order, the carry stage's last among them, then the carry stage's
/// final mask, which holds every page's own polynomial off the stages, and
/// on the native side the statement circuit's final mask, whose last stage
/// is the instance stage.
///
/// The carry stage is a stage as the others are
/// ([`WholeCarry`](common::WholeCarry)), of the size the side pins, so its
/// masks are its type's: no cut of the circuit is asked for here.
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
    type Digits<C, S, K, R, const H: usize> = DigitsStage<C, S, K, R, H>;
    type Carry<C, S, K, R, const H: usize> = common::WholeCarry<C, S, K, R, H>;
    if mask < indices.front {
        return S::register_stage_mask(mask, slot);
    }
    let stages = indices.stages() as u32;
    match mask as u32 {
        index if index == indices.lifts() => {
            slot.register_stage_mask::<Lifts<C, S, K, R, HEADER_SIZE>>()
        }
        index if index == indices.digits() => {
            slot.register_stage_mask::<Digits<C, S, K, R, HEADER_SIZE>>()
        }
        index if index == indices.carry() => {
            slot.register_stage_mask::<Carry<C, S, K, R, HEADER_SIZE>>()
        }
        index if index == stages => slot.register_final_mask::<Carry<C, S, K, R, HEADER_SIZE>>(),
        index if indices.with_statement && index == stages + 1 => {
            slot.register_final_mask::<Instance<C, S, K, R, HEADER_SIZE>>()
        }
        _ => Err(Error::Initialization("no such mask".into())),
    }
}

/// Registers native circuit `circuit` that is not a page: the statement
/// circuit, at the index past the pages; see [`native_layout`] for the
/// layout.
pub(crate) fn register_native_circuit<'params, C, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    slot: CircuitSlot<'params, C::CircuitField, R>,
) -> Result<Registered<'params, C::CircuitField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    if circuit != NATIVE_PAGES.num_pages() {
        return Err(Error::Initialization("no such circuit".into()));
    }
    slot.register_staged(common::StatementCircuit::<C, Native, K, R, HEADER_SIZE>::new())
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
