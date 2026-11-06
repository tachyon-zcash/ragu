//! # Online polynomial oracles, by example
//!
//! This file is a tutorial written as a test suite. Every step below is a
//! complete [`Step`] you can copy, and the tests at the end show how an
//! application registers the steps, proves, verifies and compresses. The
//! design is in the book (`book/src/protocol/poly-oracle.md`): its use cases
//! T1–T5 and capabilities C1–C4 label the sections.
//!
//! | Section | Use case | API shown |
//! |---|---|---|
//! | [1. Headers](#1-headers) | C1: two polynomial slots per header | [`Header`], [`HEADER_POLYNOMIALS`], padding |
//! | [2. Seed a set](#2-seed-a-set) | T2, T3: private roots, challenge | [`Step::polynomials`], [`Step::NUM_STAGED`], [`Step::staged`], [`Oracles::zeta`], [`Oracles::query`], [`Oracles::staged`] |
//! | [3. Insert into a set](#3-insert-into-a-set) | T2: public and private polynomials | a left input's polynomial, [`HeaderInput`] |
//! | [4. Merge two sets](#4-merge-two-sets) | T1: public polynomials only | left, right and output slots |
//! | [5. Membership](#5-membership) | T4: evaluation at a witnessed point | [`Oracles::query`] |
//! | [6. Anchor chain](#6-anchor-chain) | T5: hashing a commitment | [`Oracles::bridge_hash`], [`Application::bridge_hash`], [`Application::commit`], [`Pcd::commitments`] |
//! | [7. Every slot](#7-every-slot) | C4: all six slots at once | [`Slot::left`], [`Slot::right`], [`Slot::output`] |
//! | [8. The application](#8-the-application) | | [`ApplicationBuilder`], `seed`, `fuse`, `rerandomize`, verify, compress, the wire format |
//!
//! ## The rule for checks at $\zeta$
//!
//! $\zeta$ is drawn after every slot's polynomial and every staged value
//! is committed. A check at $\zeta$ must read only values fixed before it:
//!
//! - openings at $\zeta$, or at a point that is itself fixed before $\zeta$;
//! - the inputs' header fields;
//! - staged values, and wires computed from all of the above;
//! - in-circuit hash outputs, or values from a small set (such as a bit).
//!
//! Any other value the circuit witnesses, including the output header's
//! fields, is the prover's choice after $\zeta$. For example, a check
//! $O(\zeta) = L(\zeta)(\zeta - t)$ holds for $t = \zeta - O(\zeta)/L(\zeta)$
//! whatever the polynomials are. So stage $t$, as [`InsertTachygram`] does.
//!
//! ## Running
//!
//! The suite proves at the production rank, so its tests are ignored in the
//! platform matrix. CI runs it in the `corruption (exhaustive)` job:
//! `cargo test --release -p ragu_pcd --all-features --test online_oracles -- --include-ignored`.

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue, emulator::Emulator},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::{EpAffine, Fp, Pasta},
};
use ragu_pcd::{
    Application, ApplicationBuilder, Pcd, Proof,
    header::{HEADER_POLYNOMIALS, Header, Suffix},
    step::{Encoded, HeaderInput, Index, Oracles, Slot, Step},
};
use ragu_primitives::{
    Element, GadgetExt,
    allocator::{Allocator, Standard},
    poseidon::Sponge,
    vec::{ConstLen, FixedVec},
};
use rand::{SeedableRng, rngs::StdRng};
use udon::{curve::Affine as _, field::Field};

type C = Pasta;
type R = ProductionRank;
/// The header size: every header is padded to this many field elements.
const HEADER_SIZE: usize = 4;
type App = Application<'static, C, R, HEADER_SIZE>;

// # 1. Headers
//
// C1. Every header carries `HEADER_POLYNOMIALS` (two) polynomial commitments
// beside its field data. What each slot holds is the application's
// convention for that header, which the steps that produce the header
// constrain, as they do its fields. An unused slot holds the constant one
// (the padding): a step that outputs the header opens such a slot at zeta
// and holds it to one, so that no prover can put a polynomial of its own
// choosing there.

/// A set of tachygrams $\{t_i\}$: the set's size as the data, and the set
/// polynomial $\prod_i (X - t_i)$ in slot 0. Slot 1 is padding.
struct TgSet;

impl Header<Fp> for TgSet {
    const SUFFIX: Suffix = Suffix::new(10);
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

/// A chain of anchors: the latest anchor as the data, and the set
/// polynomial the anchor covers in slot 1, the slot whose digest a step can
/// read (see section 6). Slot 0 is padding.
struct Anchor;

impl Header<Fp> for Anchor {
    const SUFFIX: Suffix = Suffix::new(11);
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

/// A header whose two slots both carry a real polynomial, $X + a_0$ and
/// $2X + a_1$, for its data $(a_0, a_1)$ (see section 7).
struct Pair;

impl Header<Fp> for Pair {
    const SUFFIX: Suffix = Suffix::new(12);
    type Data = [Fp; 2];
    type Output = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<2>>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, [Fp; 2]>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        FixedVec::try_from_fn(|i| Element::alloc(dr, allocator, witness.as_ref().map(|w| w[i])))
    }
}

/// The padding polynomial: the constant one.
fn padding() -> Vec<Fp> {
    vec![Fp::ONE]
}

/// Opens `slot` at zeta and holds it to one: how a step pins a padding slot
/// of its output header.
fn pin_padding<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    oracles: &mut Oracles<'_, 'dr, D>,
    slot: Slot,
) -> Result<()> {
    let zeta = oracles.zeta().clone();
    let value = oracles.query(dr, slot, &zeta)?;
    value.enforce_equal(dr, &Element::one())
}

/// The coefficients of $\prod_i (X - t_i)$, ascending in degree.
fn vanishing(roots: &[Fp]) -> Vec<Fp> {
    roots
        .iter()
        .fold(vec![Fp::ONE], |poly, root| times_linear(&poly, *root))
}

/// The coefficients of `poly * (X - root)`.
fn times_linear(poly: &[Fp], root: Fp) -> Vec<Fp> {
    let mut out = vec![Fp::ZERO; poly.len() + 1];
    for (i, coeff) in poly.iter().enumerate() {
        out[i + 1] += *coeff;
        out[i] -= *coeff * root;
    }
    out
}

/// The coefficients of `a * b`.
fn times(a: &[Fp], b: &[Fp]) -> Vec<Fp> {
    let mut out = vec![Fp::ZERO; a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            out[i + j] += *x * *y;
        }
    }
    out
}

// # 2. Seed a set
//
// T2 and T3. A step commits a polynomial built from secret roots, and checks
// it at zeta against those roots. A step proves in two phases:
//
// 1. Before zeta is drawn: `polynomials` returns the output header's
//    polynomials (coefficients, not wires), and `staged` returns the values
//    the checks at zeta will read but no header carries. Ragu commits both.
// 2. After zeta is drawn: `witness` builds the circuit. `Oracles` gives it
//    zeta, the six slots and the staged values.

/// The number of tachygrams [`SeedSet`] takes.
const SEED_SIZE: usize = 3;

/// Seeds a [`TgSet`] from `SEED_SIZE` secret tachygrams.
struct SeedSet;

impl Step<C> for SeedSet {
    const INDEX: Index = Index::new(0);
    /// The tachygrams are secret, and the check at zeta reads them, so they
    /// are staged: committed before zeta is drawn.
    const NUM_STAGED: usize = SEED_SIZE;
    type Witness<'source> = Vec<Fp>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = TgSet;

    fn polynomials<'source>(
        &self,
        tachygrams: &Vec<Fp>,
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<[Vec<Fp>; HEADER_POLYNOMIALS]> {
        Ok([vanishing(tachygrams), padding()])
    }

    fn staged<'source>(
        &self,
        tachygrams: &Vec<Fp>,
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<Vec<Fp>> {
        Ok(tachygrams.clone())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, Vec<Fp>>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, TgSet, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        // O0(zeta) = prod_i (zeta - t_i), over the staged tachygrams.
        let zeta = oracles.zeta().clone();
        let mut product = Element::one();
        for tachygram in oracles.staged().to_vec() {
            let factor = zeta.sub(dr, &tachygram);
            product = product.mul(dr, &factor)?;
        }
        let set = oracles.query(dr, Slot::output(0), &zeta)?;
        set.enforce_equal(dr, &product)?;
        pin_padding(dr, oracles, Slot::output(1))?;

        let size = Element::constant(dr, Fp::from(SEED_SIZE as u64));
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(size),
            ),
            D::just(|| Fp::from(SEED_SIZE as u64)),
            D::unit(),
        ))
    }
}

// # 3. Insert into a set
//
// T2. The output polynomial is the left input's polynomial times
// (X - t), with t secret, so the relation mixes a public polynomial (the
// left slot) with a private one (X - t, from a staged root).

/// Inserts one secret tachygram into a [`TgSet`].
struct InsertTachygram;

impl Step<C> for InsertTachygram {
    const INDEX: Index = Index::new(1);
    const NUM_STAGED: usize = 1;
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = TgSet;
    type Right = ();
    type Output = TgSet;

    /// The left input's polynomials arrive as coefficients: the output's
    /// is computed from them.
    fn polynomials<'source>(
        &self,
        tachygram: &Fp,
        left: HeaderInput<'_, Fp, TgSet>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<[Vec<Fp>; HEADER_POLYNOMIALS]> {
        Ok([times_linear(&left.polynomials[0], *tachygram), padding()])
    }

    fn staged<'source>(
        &self,
        tachygram: &Fp,
        _: HeaderInput<'_, Fp, TgSet>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<Vec<Fp>> {
        Ok(vec![*tachygram])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, Fp>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, TgSet, HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, TgSet, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left: Encoded<'dr, D, TgSet, HS> = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;

        // O0(zeta) = L0(zeta) * (zeta - t), with t staged, never witnessed
        // here: see the rule at the top of this file.
        let tachygram = oracles.staged()[0].clone();
        let zeta = oracles.zeta().clone();
        let input = oracles.query(dr, Slot::left(0), &zeta)?;
        let output = oracles.query(dr, Slot::output(0), &zeta)?;
        let factor = zeta.sub(dr, &tachygram);
        let expected = input.mul(dr, &factor)?;
        output.enforce_equal(dr, &expected)?;
        pin_padding(dr, oracles, Slot::output(1))?;

        let size = left.as_gadget().add(dr, &Element::one());
        let data = size.value().map(|v| *v);
        Ok(((left, right, Encoded::from_gadget(size)), data, D::unit()))
    }
}

// # 4. Merge two sets
//
// T1. Every polynomial in the relation is public: the left and right
// inputs' and the output's, so nothing is staged.

/// Merges two [`TgSet`]s: the output polynomial is the inputs' product.
struct MergeSets;

impl Step<C> for MergeSets {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = TgSet;
    type Right = TgSet;
    type Output = TgSet;

    fn polynomials<'source>(
        &self,
        _: &(),
        left: HeaderInput<'_, Fp, TgSet>,
        right: HeaderInput<'_, Fp, TgSet>,
    ) -> Result<[Vec<Fp>; HEADER_POLYNOMIALS]> {
        Ok([
            times(&left.polynomials[0], &right.polynomials[0]),
            padding(),
        ])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, TgSet, HS>,
            Encoded<'dr, D, TgSet, HS>,
            Encoded<'dr, D, TgSet, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left: Encoded<'dr, D, TgSet, HS> = Encoded::new(dr, allocator, left)?;
        let right: Encoded<'dr, D, TgSet, HS> = Encoded::new(dr, allocator, right)?;

        // O0(zeta) = L0(zeta) * R0(zeta).
        let zeta = oracles.zeta().clone();
        let l = oracles.query(dr, Slot::left(0), &zeta)?;
        let r = oracles.query(dr, Slot::right(0), &zeta)?;
        let output = oracles.query(dr, Slot::output(0), &zeta)?;
        let expected = l.mul(dr, &r)?;
        output.enforce_equal(dr, &expected)?;
        pin_padding(dr, oracles, Slot::output(1))?;

        let size = left.as_gadget().add(dr, right.as_gadget());
        let data = size.value().map(|v| *v);
        Ok(((left, right, Encoded::from_gadget(size)), data, D::unit()))
    }
}

// # 5. Membership
//
// T4. A slot can be opened at any wire, not only at zeta: here at a
// witnessed element. This is not a check at zeta, so the rule above does not
// apply: the claim "the committed polynomial vanishes at this element" is
// meaningful for any element the prover picks.

/// Proves a witnessed element is in the left [`TgSet`]: the set polynomial
/// vanishes there.
struct ProveMember;

impl Step<C> for ProveMember {
    const INDEX: Index = Index::new(3);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = TgSet;
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        member: DriverValue<D, Fp>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, TgSet, HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let member = Element::alloc(dr, allocator, member)?;
        oracles
            .query(dr, Slot::left(0), &member)?
            .enforce_zero(dr)?;
        unit_output(dr, oracles, left, right)
    }
}

/// Proves a witnessed element is not in the left [`TgSet`]: the set
/// polynomial does not vanish there.
struct ProveNonMember;

impl Step<C> for ProveNonMember {
    const INDEX: Index = Index::new(4);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = TgSet;
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        element: DriverValue<D, Fp>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, TgSet, HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let element = Element::alloc(dr, allocator, element)?;
        oracles
            .query(dr, Slot::left(0), &element)?
            .enforce_nonzero(dr)?;
        unit_output(dr, oracles, left, right)
    }
}

/// Finishes a step whose output is the unit header: both of its slots are
/// padding.
#[allow(clippy::type_complexity)]
fn unit_output<'dr, D: Driver<'dr, F = Fp>, L: Header<Fp>, Rh: Header<Fp>, const HS: usize>(
    dr: &mut D,
    oracles: &mut Oracles<'_, 'dr, D>,
    left: Encoded<'dr, D, L, HS>,
    right: Encoded<'dr, D, Rh, HS>,
) -> Result<(
    (
        Encoded<'dr, D, L, HS>,
        Encoded<'dr, D, Rh, HS>,
        Encoded<'dr, D, (), HS>,
    ),
    DriverValue<D, ()>,
    DriverValue<D, ()>,
)> {
    pin_padding(dr, oracles, Slot::output(0))?;
    pin_padding(dr, oracles, Slot::output(1))?;
    Ok((
        (left, right, Encoded::from_gadget(())),
        D::unit(),
        D::unit(),
    ))
}

/// A seed of the unit header, to fill a step's unused right input.
struct UnitSeed;

impl Step<C> for UnitSeed {
    const INDEX: Index = Index::new(5);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        unit_output(
            dr,
            oracles,
            Encoded::from_gadget(()),
            Encoded::from_gadget(()),
        )
    }
}

// # 6. Anchor chain
//
// T5. A hash chain over a polynomial commitment:
// `anchor' = Poseidon(anchor, H(cm))`, where `cm` is the commitment of a
// set polynomial. The circuit cannot hash `cm` itself: it is a point on the
// other curve of the cycle. Instead, `Oracles::bridge_hash` gives the step
// $H^{bridge}(O_1)$, a binding digest of its own output's slot 1, as two
// field elements. Outside the circuit, `Application::bridge_hash` computes
// the same digest, so an application can recompute every anchor from the
// sets alone, with `Application::commit`.
//
// Only the step's own slot 1 has a digest. To hash an input's polynomial,
// the step copies it into its output's slot 1 and proves the copy at zeta.

/// Starts an [`Anchor`] chain at anchor zero, covering no set.
struct GenesisAnchor;

impl Step<C> for GenesisAnchor {
    const INDEX: Index = Index::new(6);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Anchor;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, Anchor, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        pin_padding(dr, oracles, Slot::output(0))?;
        pin_padding(dr, oracles, Slot::output(1))?;
        let anchor = Element::zero(dr);
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(anchor),
            ),
            D::just(|| Fp::ZERO),
            D::unit(),
        ))
    }
}

/// Advances an [`Anchor`] chain over a block's [`TgSet`]: the output's
/// slot 1 is the block's set polynomial, and the new anchor is
/// `Poseidon(previous anchor, H(set commitment))`.
struct AdvanceAnchor {
    poseidon: &'static <Pasta as Cycle>::CircuitPoseidon,
}

impl Step<C> for AdvanceAnchor {
    const INDEX: Index = Index::new(7);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = TgSet;
    type Right = Anchor;
    type Output = Anchor;

    /// Slot 1 copies the block's set polynomial, the left input's slot 0.
    fn polynomials<'source>(
        &self,
        _: &(),
        block: HeaderInput<'_, Fp, TgSet>,
        _: HeaderInput<'_, Fp, Anchor>,
    ) -> Result<[Vec<Fp>; HEADER_POLYNOMIALS]> {
        Ok([padding(), block.polynomials[0].clone()])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        block: DriverValue<D, Fp>,
        previous: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, TgSet, HS>,
            Encoded<'dr, D, Anchor, HS>,
            Encoded<'dr, D, Anchor, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let block: Encoded<'dr, D, TgSet, HS> = Encoded::new(dr, allocator, block)?;
        let previous: Encoded<'dr, D, Anchor, HS> = Encoded::new(dr, allocator, previous)?;

        // The copy: O1(zeta) = L0(zeta), so O1 is the block's set polynomial.
        let zeta = oracles.zeta().clone();
        let set = oracles.query(dr, Slot::left(0), &zeta)?;
        let copy = oracles.query(dr, Slot::output(1), &zeta)?;
        copy.enforce_equal(dr, &set)?;
        pin_padding(dr, oracles, Slot::output(0))?;

        // anchor' = Poseidon(anchor, H(O1)).
        let [x, y] = oracles.bridge_hash().clone();
        let mut sponge = Sponge::new(dr, self.poseidon);
        sponge.absorb(dr, previous.as_gadget())?;
        sponge.absorb(dr, &x)?;
        sponge.absorb(dr, &y)?;
        let anchor = sponge.squeeze(dr)?;

        let data = anchor.value().map(|v| *v);
        Ok((
            (block, previous, Encoded::from_gadget(anchor)),
            data,
            D::unit(),
        ))
    }
}

/// The anchor after `previous` over a set whose commitment is `set`, as an
/// application computes it outside the circuit: the same Poseidon, over the
/// digest [`Application::bridge_hash`] gives.
fn next_anchor(app: &App, previous: Fp, set: <Pasta as Cycle>::HostCurve) -> Result<Fp> {
    let digest: EpAffine = app.bridge_hash(set)?;
    let (x, y) = digest
        .coordinates()
        .ok_or_else(|| Error::InvalidWitness("identity digest".into()))?;
    let mut dr = Emulator::execute();
    let mut sponge = Sponge::new(&mut dr, Pasta::circuit_poseidon(ragu_pcd::pasta::baked()));
    for value in [previous, x, y] {
        let value = Element::constant(&mut dr, value);
        sponge.absorb(&mut dr, &value)?;
    }
    Ok(*sponge.squeeze(&mut dr)?.value().take())
}

// # 7. Every slot
//
// C4. One step opens all six slots: the left and right inputs' and the
// output's, both polynomials each, every one at its own point.

/// The polynomials of a [`Pair`] header with data `a`.
fn pair_polys(a: [Fp; 2]) -> [Vec<Fp>; HEADER_POLYNOMIALS] {
    [vec![a[0], Fp::ONE], vec![a[1], Fp::from(2)]]
}

/// Seeds a [`Pair`] from staged data, checking both output slots at zeta.
struct PairSeed;

impl Step<C> for PairSeed {
    const INDEX: Index = Index::new(8);
    const NUM_STAGED: usize = 2;
    type Witness<'source> = [Fp; 2];
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Pair;

    fn polynomials<'source>(
        &self,
        a: &[Fp; 2],
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<[Vec<Fp>; HEADER_POLYNOMIALS]> {
        Ok(pair_polys(*a))
    }

    fn staged<'source>(
        &self,
        a: &[Fp; 2],
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<Vec<Fp>> {
        Ok(a.to_vec())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, [Fp; 2]>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, Pair, HS>,
        ),
        DriverValue<D, [Fp; 2]>,
        DriverValue<D, ()>,
    )> {
        let a = oracles.staged().to_vec();
        let zeta = oracles.zeta().clone();
        let two = Element::constant(dr, Fp::from(2));
        let o0 = oracles.query(dr, Slot::output(0), &zeta)?;
        let expected = zeta.add(dr, &a[0]);
        o0.enforce_equal(dr, &expected)?;
        let o1 = oracles.query(dr, Slot::output(1), &zeta)?;
        let expected = zeta.mul(dr, &two)?.add(dr, &a[1]);
        o1.enforce_equal(dr, &expected)?;
        let data = D::just(|| [*a[0].value().take(), *a[1].value().take()]);
        let output = FixedVec::try_from(a)?;
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(output),
            ),
            data,
            D::unit(),
        ))
    }
}

/// The point slot `i` is opened at in [`PairFuse`].
fn point(i: usize) -> Fp {
    Fp::from(101 + i as u64)
}

/// Fuses two [`Pair`]s into their sum, opening each of the six slots at
/// its own point and checking every value against the headers' data, so
/// that exchanging any two slots would break a check.
struct PairFuse;

impl Step<C> for PairFuse {
    const INDEX: Index = Index::new(9);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Pair;
    type Right = Pair;
    type Output = Pair;

    fn polynomials<'source>(
        &self,
        _: &(),
        left: HeaderInput<'_, Fp, Pair>,
        right: HeaderInput<'_, Fp, Pair>,
    ) -> Result<[Vec<Fp>; HEADER_POLYNOMIALS]> {
        Ok(pair_polys([
            left.data[0] + right.data[0],
            left.data[1] + right.data[1],
        ]))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, [Fp; 2]>,
        right: DriverValue<D, [Fp; 2]>,
    ) -> Result<(
        (
            Encoded<'dr, D, Pair, HS>,
            Encoded<'dr, D, Pair, HS>,
            Encoded<'dr, D, Pair, HS>,
        ),
        DriverValue<D, [Fp; 2]>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left: Encoded<'dr, D, Pair, HS> = Encoded::new(dr, allocator, left)?;
        let right: Encoded<'dr, D, Pair, HS> = Encoded::new(dr, allocator, right)?;
        let sum: Vec<_> = (0..2)
            .map(|k| left.as_gadget()[k].add(dr, &right.as_gadget()[k]))
            .collect();
        let slots = [
            (Slot::left(0), left.as_gadget()[0].clone()),
            (Slot::left(1), left.as_gadget()[1].clone()),
            (Slot::right(0), right.as_gadget()[0].clone()),
            (Slot::right(1), right.as_gadget()[1].clone()),
            (Slot::output(0), sum[0].clone()),
            (Slot::output(1), sum[1].clone()),
        ];
        for (i, (slot, a)) in slots.into_iter().enumerate() {
            // The points are constants, fixed before zeta.
            let x = Element::constant(dr, point(i));
            let slope = Element::constant(dr, Fp::from(1 + slot.index() as u64));
            let y = oracles.query(dr, slot, &x)?;
            let expected = x.mul(dr, &slope)?.add(dr, &a);
            y.enforce_equal(dr, &expected)?;
        }
        let data = D::just(|| [*sum[0].value().take(), *sum[1].value().take()]);
        let output = FixedVec::try_from(sum)?;
        Ok(((left, right, Encoded::from_gadget(output)), data, D::unit()))
    }
}

// # 8. The application
//
// Register every step in `INDEX` order, then finalize. The application
// stage holds as many values as the largest `NUM_STAGED` registered (here
// `SEED_SIZE`), and every step circuit reserves room for it.

fn app() -> App {
    let poseidon = Pasta::circuit_poseidon(ragu_pcd::pasta::baked());
    ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(SeedSet)
        .and_then(|b| b.register(InsertTachygram))
        .and_then(|b| b.register(MergeSets))
        .and_then(|b| b.register(ProveMember))
        .and_then(|b| b.register(ProveNonMember))
        .and_then(|b| b.register(UnitSeed))
        .and_then(|b| b.register(GenesisAnchor))
        .and_then(|b| b.register(AdvanceAnchor { poseidon }))
        .and_then(|b| b.register(PairSeed))
        .and_then(|b| b.register(PairFuse))
        .expect("the application must build")
        .finalize(ragu_pcd::pasta::baked())
        .expect("the application must build")
}

fn tachygrams(from: u64) -> Vec<Fp> {
    (from..from + SEED_SIZE as u64).map(Fp::from).collect()
}

fn unit(app: &App) -> Result<Pcd<C, R, ()>> {
    Ok(app.seed(&mut StdRng::seed_from_u64(0), UnitSeed, ())?.0)
}

/// What an application does with a proof: verify it, compress it and
/// verify the compressed proof, and send it over the wire. Also checks that
/// the proof carries the `expected` polynomials.
fn check<H: Header<Fp>>(
    app: &App,
    pcd: &Pcd<C, R, H>,
    expected: [Vec<Fp>; HEADER_POLYNOMIALS],
    seed: u64,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    assert!(app.verify_uncompressed(pcd, &mut rng).unwrap());
    let compressed = app.compress(pcd, &mut rng).unwrap();
    assert!(app.verify_compressed(&compressed).unwrap());
    assert_eq!(pcd.polynomials(), expected);

    let bytes = pcd.proof().to_bytes().unwrap();
    let decoded = Proof::<C, R>::from_bytes(&bytes)
        .unwrap()
        .carry::<H>(pcd.data().clone());
    assert_eq!(decoded.polynomials(), expected);
    assert!(app.verify_uncompressed(&decoded, &mut rng).unwrap());
}

/// T1 to T4 in one tree: seed two sets (T2, T3), insert into one (T2),
/// merge them (T1), and prove membership and non-membership (T4).
/// Rerandomization keeps the polynomial.
#[test]
#[ignore = "proves at production rank; run in the PR job"]
fn sets_prove_and_verify() -> Result<()> {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0xacc);

    let (a, ()) = app.seed(&mut rng, SeedSet, tachygrams(1))?;
    let set_a = vanishing(&tachygrams(1));
    check(&app, &a, [set_a.clone(), padding()], 1);
    assert_eq!(*a.data(), Fp::from(SEED_SIZE as u64));

    let (a, ()) = app.fuse(&mut rng, InsertTachygram, Fp::from(10), a, unit(&app)?)?;
    let set_a = times_linear(&set_a, Fp::from(10));
    check(&app, &a, [set_a.clone(), padding()], 2);
    assert_eq!(*a.data(), Fp::from(SEED_SIZE as u64 + 1));

    let (b, ()) = app.seed(&mut rng, SeedSet, tachygrams(20))?;
    let (ab, ()) = app.fuse(&mut rng, MergeSets, (), a, b)?;
    let set_ab = times(&set_a, &vanishing(&tachygrams(20)));
    check(&app, &ab, [set_ab.clone(), padding()], 3);

    let (member, ()) = app.fuse(&mut rng, ProveMember, Fp::from(21), ab.clone(), unit(&app)?)?;
    check(&app, &member, [padding(), padding()], 4);
    let (non_member, ()) = app.fuse(
        &mut rng,
        ProveNonMember,
        Fp::from(99),
        ab.clone(),
        unit(&app)?,
    )?;
    check(&app, &non_member, [padding(), padding()], 5);

    let rerandomized = app.rerandomize(ab, &mut rng)?;
    check(&app, &rerandomized, [set_ab, padding()], 6);
    let (again, ()) = app.fuse(
        &mut rng,
        ProveMember,
        Fp::from(1),
        rerandomized,
        unit(&app)?,
    )?;
    check(&app, &again, [padding(), padding()], 7);
    Ok(())
}

/// T5: an anchor chain over two blocks' sets. Each anchor the proofs carry
/// equals the one recomputed outside the circuit from the sets alone.
#[test]
#[ignore = "proves at production rank; run in the PR job"]
fn anchor_chain_hashes_set_commitments() -> Result<()> {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0xa4c);
    let (genesis, ()) = app.seed(&mut rng, GenesisAnchor, ())?;
    assert_eq!(*genesis.data(), Fp::ZERO);

    let mut chain = genesis;
    let mut expected = Fp::ZERO;
    for (i, start) in [1u64, 40].into_iter().enumerate() {
        let (block, ()) = app.seed(&mut rng, SeedSet, tachygrams(start))?;
        let advance = AdvanceAnchor {
            poseidon: Pasta::circuit_poseidon(ragu_pcd::pasta::baked()),
        };
        let (next, ()) = app.fuse(&mut rng, advance, (), block, chain)?;

        // Recompute the anchor from the block's tachygrams alone.
        let set = vanishing(&tachygrams(start));
        expected = next_anchor(&app, expected, app.commit(&set)?)?;
        assert_eq!(*next.data(), expected);
        assert_eq!(next.commitments()[1], app.commit(&set)?);
        check(&app, &next, [padding(), set], 10 + i as u64);
        chain = next;
    }
    Ok(())
}

/// C4: six distinct polynomials opened at six distinct points. The fuse
/// proves, and so does a parent that opens its output's slots as its own
/// inputs'. Moving any slot's point or value, or editing either of the
/// step's own polynomials, is rejected.
#[test]
#[ignore = "proves at production rank; run in the PR job"]
fn every_slot_proves_and_verifies() -> Result<()> {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x51075);
    let a = app.seed(&mut rng, PairSeed, [Fp::from(3), Fp::from(5)])?.0;
    let b = app.seed(&mut rng, PairSeed, [Fp::from(7), Fp::from(11)])?.0;
    let (ab, ()) = app.fuse(&mut rng, PairFuse, (), a, b)?;
    assert_eq!(*ab.data(), [Fp::from(10), Fp::from(16)]);
    check(&app, &ab, pair_polys([Fp::from(10), Fp::from(16)]), 20);
    let (abab, ()) = app.fuse(&mut rng, PairFuse, (), ab.clone(), ab.clone())?;
    check(&app, &abab, pair_polys([Fp::from(20), Fp::from(32)]), 21);

    #[cfg(feature = "unstable-fuzzing")]
    {
        use ragu_pcd::fuzzing::corrupt::Corruption;
        let rejected = |corruption: Corruption<C>, what: &str, rng: &mut StdRng| {
            let (mut proof, data) = ab.clone().into_parts();
            proof.corrupt(corruption);
            let pcd = proof.carry::<Pair>(data);
            assert!(
                !app.verify_differential(&pcd, rng).unwrap(),
                "{what} must be rejected"
            );
        };
        for slot in 0..6 {
            for value in [false, true] {
                rejected(
                    Corruption::OnlineQuery {
                        slot,
                        value,
                        delta: Fp::ONE,
                    },
                    &format!("slot {slot}'s {}", if value { "value" } else { "point" }),
                    &mut rng,
                );
            }
        }
        for index in 0..HEADER_POLYNOMIALS {
            rejected(
                Corruption::OnlineCoeff {
                    index,
                    coeff: 0,
                    delta: Fp::ONE,
                },
                &format!("own polynomial {index}"),
                &mut rng,
            );
        }
    }
    Ok(())
}

// # 9. What cannot prove

/// A proof attempt is refused when proving fails outright, or when it
/// yields a proof that does not verify.
fn refused<H: Header<Fp>>(app: &App, attempt: Result<Pcd<C, R, H>>, what: &str) {
    if let Ok(pcd) = attempt {
        let mut rng = StdRng::seed_from_u64(0xdead);
        assert!(
            !app.verify_uncompressed(&pcd, &mut rng).unwrap(),
            "{what}: the verifier accepted a false claim"
        );
    }
}

/// A membership claim about an element the set does not hold, or a
/// non-membership claim about one it does, is refused.
#[test]
#[ignore = "proves at production rank; run in the PR job"]
fn a_false_membership_claim_cannot_prove() -> Result<()> {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0xfa15e);
    let (a, ()) = app.seed(&mut rng, SeedSet, tachygrams(1))?;
    let member = app
        .fuse(&mut rng, ProveMember, Fp::from(99), a.clone(), unit(&app)?)
        .map(|(pcd, ())| pcd);
    refused(&app, member, "a non-member claimed as a member");
    let non_member = app
        .fuse(&mut rng, ProveNonMember, Fp::from(2), a, unit(&app)?)
        .map(|(pcd, ())| pcd);
    refused(&app, non_member, "a member claimed as a non-member");
    Ok(())
}

/// [`InsertTachygram`] with a first phase that misbehaves: it returns the
/// zero polynomial (`ZERO`), or the input polynomial unchanged while the
/// circuit claims the insertion (`STALE`).
struct Faulty<const FAULT: u8>;

const ZERO: u8 = 1;
const STALE: u8 = 2;

impl<const FAULT: u8> Step<C> for Faulty<FAULT> {
    const INDEX: Index = Index::new(1);
    const NUM_STAGED: usize = 1;
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = TgSet;
    type Right = ();
    type Output = TgSet;

    fn polynomials<'source>(
        &self,
        _: &Fp,
        left: HeaderInput<'_, Fp, TgSet>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<[Vec<Fp>; HEADER_POLYNOMIALS]> {
        let first = match FAULT {
            ZERO => vec![Fp::ZERO; 4],
            _ => left.polynomials[0].clone(),
        };
        Ok([first, padding()])
    }

    fn staged<'source>(
        &self,
        tachygram: &Fp,
        left: HeaderInput<'_, Fp, TgSet>,
        right: HeaderInput<'_, Fp, ()>,
    ) -> Result<Vec<Fp>> {
        InsertTachygram.staged(tachygram, left, right)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Fp>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, TgSet, HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, TgSet, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        InsertTachygram.witness::<D, HS>(dr, oracles, witness, left, right)
    }
}

/// [`UnitSeed`] at the index the faulty application has free.
struct UnitAt2;

impl Step<C> for UnitAt2 {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
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
        UnitSeed.witness::<D, HS>(dr, oracles, witness, left, right)
    }
}

/// A step whose first phase returns a zero polynomial cannot prove. One
/// whose committed polynomial is not the one its circuit claims yields a
/// proof the verifier rejects: the oracle answers for the committed
/// polynomial, so the circuit's relation fails.
#[test]
#[ignore = "proves at production rank; run in the PR job"]
fn a_misstated_polynomial_cannot_prove() -> Result<()> {
    fn attempt<const FAULT: u8>() -> (App, Result<Pcd<C, R, TgSet>>) {
        let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
            .register(SeedSet)
            .and_then(|b| b.register(Faulty::<FAULT>))
            .and_then(|b| b.register(UnitAt2))
            .expect("the application must build")
            .finalize(ragu_pcd::pasta::baked())
            .expect("the application must build");
        let mut rng = StdRng::seed_from_u64(0xbad);
        let (a, ()) = app.seed(&mut rng, SeedSet, tachygrams(1)).unwrap();
        let (unit, ()) = app.seed(&mut rng, UnitAt2, ()).unwrap();
        let attempt = app
            .fuse(&mut rng, Faulty::<FAULT>, Fp::from(10), a, unit)
            .map(|(pcd, ())| pcd);
        (app, attempt)
    }
    assert!(matches!(attempt::<ZERO>().1, Err(Error::InvalidWitness(_))));
    let (app, stale) = attempt::<STALE>();
    refused(&app, stale, "stale polynomial");
    Ok(())
}
