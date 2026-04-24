//! GGM (Goldreich–Goldwasser–Micali) PRF tree derivation example with
//! late-delegation blinding.

#![allow(clippy::type_complexity)]

use ff::{Field, PrimeField};
use ragu_arithmetic::{Coeff, Cycle};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, emulator::Emulator},
    gadgets::{Bound, Gadget, Kind},
    maybe::{Always, Maybe, MaybeKind},
};
use ragu_pcd::{
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};
use ragu_primitives::{
    Boolean, Element,
    allocator::{Allocator, Standard},
    io::Write,
    poseidon::Sponge,
};

pub const HEADER_SIZE: usize = 6;

pub const GGM_ARITY: u8 = 0b1 << 2;
pub const GGM_DEPTH: u8 = 6;
pub const GGM_CHUNK_SIZE: u8 = GGM_ARITY.ilog2() as u8;

pub type GgmIndex = u16;
pub const GGM_MAX: GgmIndex = (GGM_ARITY as u16).pow(GGM_DEPTH as u32) - 1;

/// Shared helpers for benches/tests to build and walk the GGM app.
pub mod fixtures {
    use ragu_circuits::polynomials::ProductionRank;
    use ragu_pcd::{Application, ApplicationBuilder, Pcd};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    pub type App<C> = Application<'static, C, ProductionRank, HEADER_SIZE>;

    pub fn seeded_rng() -> StdRng {
        StdRng::seed_from_u64(1234)
    }

    pub fn sample_seed<C: Cycle>(rng: &mut StdRng) -> GgmSeed<<C as Cycle>::CircuitField>
    where
        C::CircuitField: Field,
    {
        GgmSeed {
            nk: <C as Cycle>::CircuitField::random(&mut *rng),
            note: GgmNote {
                pk: <C as Cycle>::CircuitField::random(&mut *rng),
                value: <C as Cycle>::CircuitField::from(100_000_000u64),
                psi: <C as Cycle>::CircuitField::random(&mut *rng),
                rcm: <C as Cycle>::CircuitField::random(&mut *rng),
            },
        }
    }

    pub fn build_app<C: Cycle>(
        params: &'static C::Params,
        poseidon_params: &'static C::CircuitPoseidon,
    ) -> (App<C>, &'static C::CircuitPoseidon)
    where
        C::CircuitField: PrimeField,
    {
        let app = ApplicationBuilder::<C, ProductionRank, HEADER_SIZE>::new()
            .register(GgmMasterSeed::<C> { poseidon_params })
            .unwrap()
            .register(GgmMasterStep::<C> { poseidon_params })
            .unwrap()
            .register(GgmNodeStep::<C> { poseidon_params })
            .unwrap()
            .register(GgmBlindStep::<C> { poseidon_params })
            .unwrap()
            .register(GgmDelegateStep::<C> { poseidon_params })
            .unwrap()
            .register(GgmNullifierStep::<C> { poseidon_params })
            .unwrap()
            .finalize(params)
            .unwrap();

        (app, poseidon_params)
    }

    pub fn seed_master<C: Cycle>(
        app: &App<C>,
        poseidon_params: &<C as Cycle>::CircuitPoseidon,
        rng: &mut StdRng,
        seed: GgmSeed<<C as Cycle>::CircuitField>,
    ) -> Pcd<C, ProductionRank, GgmMasterHeader>
    where
        C::CircuitField: PrimeField,
    {
        app.seed(rng, GgmMasterSeed::<C> { poseidon_params }, seed)
            .unwrap()
            .0
    }

    pub fn master_step<C: Cycle>(
        app: &App<C>,
        poseidon_params: &<C as Cycle>::CircuitPoseidon,
        rng: &mut StdRng,
        master_pcd: Pcd<C, ProductionRank, GgmMasterHeader>,
        chunk: u8,
    ) -> Pcd<C, ProductionRank, GgmPrivateHeader>
    where
        C::CircuitField: PrimeField,
    {
        let trivial_pcd = app.seeded_trivial_pcd(rng);
        app.fuse(
            rng,
            GgmMasterStep::<C> { poseidon_params },
            chunk,
            master_pcd,
            trivial_pcd,
        )
        .unwrap()
        .0
    }

    pub fn node_step<C: Cycle>(
        app: &App<C>,
        poseidon_params: &<C as Cycle>::CircuitPoseidon,
        rng: &mut StdRng,
        node_pcd: Pcd<C, ProductionRank, GgmPrivateHeader>,
        chunk: u8,
    ) -> Pcd<C, ProductionRank, GgmPrivateHeader>
    where
        C::CircuitField: PrimeField,
    {
        let trivial_pcd = app.seeded_trivial_pcd(rng);
        app.fuse(
            rng,
            GgmNodeStep::<C> { poseidon_params },
            chunk,
            node_pcd,
            trivial_pcd,
        )
        .unwrap()
        .0
    }

    pub fn blind_step<C: Cycle>(
        app: &App<C>,
        poseidon_params: &<C as Cycle>::CircuitPoseidon,
        rng: &mut StdRng,
        node_pcd: Pcd<C, ProductionRank, GgmPrivateHeader>,
        trap: C::CircuitField,
    ) -> Pcd<C, ProductionRank, GgmDelegateHeader>
    where
        C::CircuitField: PrimeField,
    {
        let trivial_pcd = app.seeded_trivial_pcd(rng);
        app.fuse(
            rng,
            GgmBlindStep::<C> { poseidon_params },
            trap,
            node_pcd,
            trivial_pcd,
        )
        .unwrap()
        .0
    }

    pub fn delegate_step<C: Cycle>(
        app: &App<C>,
        poseidon_params: &<C as Cycle>::CircuitPoseidon,
        rng: &mut StdRng,
        delegate_pcd: Pcd<C, ProductionRank, GgmDelegateHeader>,
        chunk: u8,
    ) -> Pcd<C, ProductionRank, GgmDelegateHeader>
    where
        C::CircuitField: PrimeField,
    {
        let trivial_pcd = app.seeded_trivial_pcd(rng);
        app.fuse(
            rng,
            GgmDelegateStep::<C> { poseidon_params },
            chunk,
            delegate_pcd,
            trivial_pcd,
        )
        .unwrap()
        .0
    }

    pub fn nullifier_step<C: Cycle>(
        app: &App<C>,
        poseidon_params: &<C as Cycle>::CircuitPoseidon,
        rng: &mut StdRng,
        delegate_pcd: Pcd<C, ProductionRank, GgmDelegateHeader>,
    ) -> Pcd<C, ProductionRank, GgmNullifierHeader>
    where
        C::CircuitField: PrimeField,
    {
        let trivial_pcd = app.seeded_trivial_pcd(rng);
        app.fuse(
            rng,
            GgmNullifierStep::<C> { poseidon_params },
            (),
            delegate_pcd,
            trivial_pcd,
        )
        .unwrap()
        .0
    }

    pub fn walk_measured<C: Cycle>(
        app: &App<C>,
        poseidon: &<C as Cycle>::CircuitPoseidon,
        rng: &mut StdRng,
        master_pcd: Pcd<C, ProductionRank, GgmMasterHeader>,
    ) -> Pcd<C, ProductionRank, GgmPrivateHeader>
    where
        C::CircuitField: PrimeField,
    {
        let mut node_pcd = master_step(app, poseidon, rng, master_pcd, 0);
        for _ in 1..GGM_DEPTH {
            node_pcd = node_step(app, poseidon, rng, node_pcd, 0);
        }
        node_pcd
    }

    pub fn setup_seed<C: Cycle>(
        params: &'static C::Params,
        poseidon: &'static C::CircuitPoseidon,
    ) -> (
        App<C>,
        &'static <C as Cycle>::CircuitPoseidon,
        StdRng,
        GgmSeed<<C as Cycle>::CircuitField>,
    )
    where
        C::CircuitField: PrimeField,
    {
        let (app, poseidon) = build_app(params, poseidon);
        let mut rng = seeded_rng();
        let seed = sample_seed::<C>(&mut rng);
        (app, poseidon, rng, seed)
    }

    pub fn setup_node_step<C: Cycle>(
        params: &'static C::Params,
        poseidon: &'static C::CircuitPoseidon,
    ) -> (
        App<C>,
        &'static <C as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<C, ProductionRank, GgmPrivateHeader>,
        Pcd<C, ProductionRank, ()>,
    )
    where
        C::CircuitField: PrimeField,
    {
        let (app, poseidon) = build_app(params, poseidon);
        let mut rng = seeded_rng();
        let seed = sample_seed::<C>(&mut rng);
        let master_pcd = seed_master(&app, poseidon, &mut rng, seed);
        let node_pcd = master_step(&app, poseidon, &mut rng, master_pcd, 0);
        let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
        (app, poseidon, rng, node_pcd, trivial_pcd)
    }

    pub fn setup_walk<C: Cycle>(
        params: &'static C::Params,
        poseidon: &'static C::CircuitPoseidon,
    ) -> (
        App<C>,
        &'static <C as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<C, ProductionRank, GgmMasterHeader>,
    )
    where
        C::CircuitField: PrimeField,
    {
        let (app, poseidon) = build_app(params, poseidon);
        let mut rng = seeded_rng();
        let seed = sample_seed::<C>(&mut rng);
        let master = seed_master(&app, poseidon, &mut rng, seed);
        (app, poseidon, rng, master)
    }

    pub fn setup_blind<C: Cycle>(
        params: &'static C::Params,
        poseidon: &'static C::CircuitPoseidon,
    ) -> (
        App<C>,
        &'static <C as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<C, ProductionRank, GgmPrivateHeader>,
        Pcd<C, ProductionRank, ()>,
        <C as Cycle>::CircuitField,
    )
    where
        C::CircuitField: PrimeField,
    {
        let (app, poseidon) = build_app(params, poseidon);
        let mut rng = seeded_rng();
        let seed = sample_seed::<C>(&mut rng);
        let master = seed_master(&app, poseidon, &mut rng, seed);
        let mut node_pcd = master_step(&app, poseidon, &mut rng, master, 0);
        for _ in 1..GGM_DEPTH {
            node_pcd = node_step(&app, poseidon, &mut rng, node_pcd, 0);
        }
        let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
        let trap = <C as Cycle>::CircuitField::random(&mut rng);
        (app, poseidon, rng, node_pcd, trivial_pcd, trap)
    }

    pub fn setup_delegate<C: Cycle>(
        params: &'static C::Params,
        poseidon: &'static C::CircuitPoseidon,
    ) -> (
        App<C>,
        &'static <C as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<C, ProductionRank, GgmDelegateHeader>,
        Pcd<C, ProductionRank, ()>,
    )
    where
        C::CircuitField: PrimeField,
    {
        let (app, poseidon) = build_app(params, poseidon);
        let mut rng = seeded_rng();
        let seed = sample_seed::<C>(&mut rng);
        let master = seed_master(&app, poseidon, &mut rng, seed);
        let node_pcd = master_step(&app, poseidon, &mut rng, master, 0);
        let trap = <C as Cycle>::CircuitField::random(&mut rng);
        let delegate_pcd = blind_step(&app, poseidon, &mut rng, node_pcd, trap);
        let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
        (app, poseidon, rng, delegate_pcd, trivial_pcd)
    }

    pub fn setup_final<C: Cycle>(
        params: &'static C::Params,
        poseidon: &'static C::CircuitPoseidon,
    ) -> (
        App<C>,
        &'static <C as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<C, ProductionRank, GgmDelegateHeader>,
        Pcd<C, ProductionRank, ()>,
    )
    where
        C::CircuitField: PrimeField,
    {
        let (app, poseidon) = build_app(params, poseidon);
        let mut rng = seeded_rng();
        let seed = sample_seed::<C>(&mut rng);
        let master = seed_master(&app, poseidon, &mut rng, seed);
        let mut node_pcd = master_step(&app, poseidon, &mut rng, master, 0);
        for _ in 1..GGM_DEPTH {
            node_pcd = node_step(&app, poseidon, &mut rng, node_pcd, 0);
        }
        let trap = <C as Cycle>::CircuitField::random(&mut rng);
        let delegate_pcd = blind_step(&app, poseidon, &mut rng, node_pcd, trap);
        let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
        (app, poseidon, rng, delegate_pcd, trivial_pcd)
    }
}

pub mod domain {
    pub const CM: &[u8; 16] = b"EXAMPLEGgmCommit";
    pub const MK: &[u8; 16] = b"EXAMPLEGgmMaster";
    pub const TN: &[u8; 16] = b"EXAMPLE  GgmStep";
    pub const NF: &[u8; 16] = b"EXAMPLE  GgmNull";
    pub const ID: &[u8; 16] = b"EXAMPLE GgmBlind";
}

/// Pack a 16-byte tag into a field element.
pub fn tag<F: PrimeField>(t: &[u8; 16]) -> F {
    F::from_u128(u128::from_le_bytes(*t))
}

fn alloc_chunk<'dr, D, A>(
    dr: &mut D,
    allocator: &mut A,
    witness: DriverValue<D, u8>,
) -> Result<Element<'dr, D>>
where
    D: Driver<'dr>,
    D::F: PrimeField,
    A: Allocator<'dr, D>,
{
    let mut acc = Element::zero(dr);
    for i in 0..GGM_CHUNK_SIZE {
        let bit_w = witness.as_ref().map(move |c| (*c >> i) & 1 != 0);
        let bit = Boolean::alloc(dr, allocator, bit_w)?;
        let scale = D::F::from(1u64 << i);
        acc = acc.add_coeff(dr, &bit.element(), Coeff::Arbitrary(scale));
    }
    Ok(acc)
}

/// Note fields carried into [`GgmMasterSeed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GgmNote<F> {
    pub pk: F,
    pub value: F,
    pub psi: F,
    pub rcm: F,
}

/// Host-side witness for [`GgmMasterSeed`]: a note paired with the viewer's
/// nullifier key `nk`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GgmSeed<F> {
    pub nk: F,
    pub note: GgmNote<F>,
}

/// Host-side data for [`GgmMasterHeader`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GgmMasterData<F> {
    pub mk: F,
    pub cm: F,
}

/// In-circuit gadget for [`GgmMasterHeader`].
#[derive(Gadget, Write)]
pub struct GgmMaster<'dr, D: Driver<'dr>> {
    pub mk: Element<'dr, D>,
    pub cm: Element<'dr, D>,
}

/// Pre-blind, pre-descent: carries `(mk, cm)`. Produced by
/// `GgmMasterSeed`.
pub struct GgmMasterHeader;

impl<F: PrimeField> Header<F> for GgmMasterHeader {
    const SUFFIX: Suffix = Suffix::new(10);
    type Data = GgmMasterData<F>;
    type Output = Kind![F; GgmMaster<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(GgmMaster {
            mk: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.mk))?,
            cm: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.cm))?,
        })
    }
}

/// Host-side data for [`GgmPrivateHeader`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GgmPrivateData<F> {
    pub node: F,
    pub depth: F,
    pub index: F,
    pub mk: F,
    pub cm: F,
}

/// In-circuit gadget for [`GgmPrivateHeader`].
#[derive(Gadget, Write)]
pub struct GgmPrivate<'dr, D: Driver<'dr>> {
    pub node: Element<'dr, D>,
    pub depth: Element<'dr, D>,
    pub index: Element<'dr, D>,
    pub mk: Element<'dr, D>,
    pub cm: Element<'dr, D>,
}

/// Pre-blind, descending: carries `(node, depth, index, mk, cm)`.
/// `(mk, cm)` is the lineage threaded through every pre-blind step.
pub struct GgmPrivateHeader;

impl<F: PrimeField> Header<F> for GgmPrivateHeader {
    const SUFFIX: Suffix = Suffix::new(11);
    type Data = GgmPrivateData<F>;
    type Output = Kind![F; GgmPrivate<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(GgmPrivate {
            node: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.node))?,
            depth: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.depth))?,
            index: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.index))?,
            mk: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.mk))?,
            cm: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.cm))?,
        })
    }
}

/// Host-side data for [`GgmDelegateHeader`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GgmDelegateData<F> {
    pub node: F,
    pub depth: F,
    pub index: F,
    pub delegation_id: F,
}

/// In-circuit gadget for [`GgmDelegateHeader`].
#[derive(Gadget, Write)]
pub struct GgmDelegate<'dr, D: Driver<'dr>> {
    pub node: Element<'dr, D>,
    pub depth: Element<'dr, D>,
    pub index: Element<'dr, D>,
    pub delegation_id: Element<'dr, D>,
}

/// Post-blind: carries `(node, depth, index, delegation_id)`. Produced
/// by `GgmBlindStep` and advanced by `GgmDelegateStep`.
pub struct GgmDelegateHeader;

impl<F: PrimeField> Header<F> for GgmDelegateHeader {
    const SUFFIX: Suffix = Suffix::new(12);
    type Data = GgmDelegateData<F>;
    type Output = Kind![F; GgmDelegate<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(GgmDelegate {
            node: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.node))?,
            depth: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.depth))?,
            index: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.index))?,
            delegation_id: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|d| d.delegation_id),
            )?,
        })
    }
}

/// Host-side data for [`GgmNullifierHeader`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GgmNullifierData<F> {
    pub nullifier: F,
    pub epoch: F,
    pub delegation_id: F,
}

/// In-circuit gadget for [`GgmNullifierHeader`].
#[derive(Gadget, Write)]
pub struct GgmNullifier<'dr, D: Driver<'dr>> {
    pub nullifier: Element<'dr, D>,
    pub epoch: Element<'dr, D>,
    pub delegation_id: Element<'dr, D>,
}

/// Terminal: carries `(nullifier, epoch, delegation_id)`.
pub struct GgmNullifierHeader;

impl<F: PrimeField> Header<F> for GgmNullifierHeader {
    const SUFFIX: Suffix = Suffix::new(13);
    type Data = GgmNullifierData<F>;
    type Output = Kind![F; GgmNullifier<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(GgmNullifier {
            nullifier: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.nullifier))?,
            epoch: Element::alloc(dr, allocator, witness.as_ref().map(|d| d.epoch))?,
            delegation_id: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|d| d.delegation_id),
            )?,
        })
    }
}

/// Seed step: derives `cm` and `mk` from realistic note fields. Emits a
/// `GgmMasterHeader` carrying the `(mk, cm)` lineage. No trapdoor.
pub struct GgmMasterSeed<'params, C: Cycle> {
    /// Poseidon parameters used for all in-circuit sponges.
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmMasterSeed<'_, C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(0);
    type Witness<'source> = GgmSeed<C::CircuitField>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = GgmMasterHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let (nk, pk, value, psi, rcm) = witness
            .map(
                |GgmSeed {
                     nk,
                     note:
                         GgmNote {
                             pk,
                             value,
                             psi,
                             rcm,
                         },
                 }| (nk, pk, value, psi, rcm),
            )
            .cast();
        let nk = Element::alloc(dr, allocator, nk)?;
        let pk = Element::alloc(dr, allocator, pk)?;
        let value = Element::alloc(dr, allocator, value)?;
        let psi = Element::alloc(dr, allocator, psi)?;
        let rcm = Element::alloc(dr, allocator, rcm)?;

        // cm = Poseidon(CM, rcm, pk, value, psi).
        let cm = {
            let t = Element::constant(dr, tag::<C::CircuitField>(domain::CM));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &t)?;
            sp.absorb(dr, &rcm)?;
            sp.absorb(dr, &pk)?;
            sp.absorb(dr, &value)?;
            sp.absorb(dr, &psi)?;
            sp.squeeze(dr)?
        };

        // mk = Poseidon(MK, psi, nk).
        let mk = {
            let t = Element::constant(dr, tag::<C::CircuitField>(domain::MK));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &t)?;
            sp.absorb(dr, &psi)?;
            sp.absorb(dr, &nk)?;
            sp.squeeze(dr)?
        };

        let output_data = D::just(|| GgmMasterData {
            mk: *mk.value().take(),
            cm: *cm.value().take(),
        });
        let output = Encoded::from_gadget(GgmMaster { mk, cm });

        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            output_data,
            D::unit(),
        ))
    }
}

/// First pre-blind descent: `GgmMasterHeader` → `GgmPrivateHeader` at
/// depth 1.
pub struct GgmMasterStep<'params, C: Cycle> {
    /// Poseidon parameters used for the tree-step sponge.
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmMasterStep<'_, C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(1);
    type Witness<'source> = u8;
    type Aux<'source> = ();
    type Left = GgmMasterHeader;
    type Right = ();
    type Output = GgmPrivateHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<C::CircuitField>>::Data>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::from_gadget(());
        let chunk = alloc_chunk::<D, _>(dr, allocator, witness)?;

        let GgmMaster { mk, cm } = left.as_gadget();

        // node = Poseidon(GGM, mk, chunk).
        let node = {
            let t = Element::constant(dr, tag::<C::CircuitField>(domain::TN));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &t)?;
            sp.absorb(dr, mk)?;
            sp.absorb(dr, &chunk)?;
            sp.squeeze(dr)?
        };

        let depth = Element::constant(dr, C::CircuitField::ONE);
        let index = chunk;
        let mk = mk.clone();
        let cm = cm.clone();

        let output_data = D::just(|| GgmPrivateData {
            node: *node.value().take(),
            depth: *depth.value().take(),
            index: *index.value().take(),
            mk: *mk.value().take(),
            cm: *cm.value().take(),
        });

        let output = Encoded::from_gadget(GgmPrivate {
            node,
            depth,
            index,
            mk,
            cm,
        });

        Ok(((left, right, output), output_data, D::unit()))
    }
}

/// Recursive pre-blind descent: `GgmPrivateHeader` → `GgmPrivateHeader`.
/// Asserts `depth < DEPTH` via `(depth - DEPTH).invert(dr)?`.
pub struct GgmNodeStep<'params, C: Cycle> {
    /// Poseidon parameters used for the tree-step sponge.
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmNodeStep<'_, C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(2);
    type Witness<'source> = u8;
    type Aux<'source> = ();
    type Left = GgmPrivateHeader;
    type Right = ();
    type Output = GgmPrivateHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<C::CircuitField>>::Data>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::from_gadget(());
        let chunk = alloc_chunk::<D, _>(dr, allocator, witness)?;

        let GgmPrivate {
            node: prev_node,
            depth: prev_depth,
            index: prev_index,
            mk,
            cm,
        } = left.as_gadget();

        // Assert depth < DEPTH via depth != DEPTH (combined with the
        // chain's depth+1 invariant, this is equivalent given depth ≥ 1).
        let depth_constant = Element::constant(dr, C::CircuitField::from(GGM_DEPTH as u64));
        let diff = prev_depth.sub(dr, &depth_constant);
        let _ = diff.invert(dr)?;

        // node' = Poseidon(GGM, prev_node, chunk).
        let node = {
            let t = Element::constant(dr, tag::<C::CircuitField>(domain::TN));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &t)?;
            sp.absorb(dr, prev_node)?;
            sp.absorb(dr, &chunk)?;
            sp.squeeze(dr)?
        };

        let one = Element::one();
        let depth = prev_depth.add(dr, &one);
        let k = C::CircuitField::from(1u64 << GGM_CHUNK_SIZE);
        let index = prev_index.scale(dr, Coeff::Arbitrary(k)).add(dr, &chunk);
        let mk = mk.clone();
        let cm = cm.clone();

        let output_data = D::just(|| GgmPrivateData {
            node: *node.value().take(),
            depth: *depth.value().take(),
            index: *index.value().take(),
            mk: *mk.value().take(),
            cm: *cm.value().take(),
        });

        let output = Encoded::from_gadget(GgmPrivate {
            node,
            depth,
            index,
            mk,
            cm,
        });

        Ok(((left, right, output), output_data, D::unit()))
    }
}

/// Transition: `GgmPrivateHeader` → `GgmDelegateHeader`. Applies the
/// delegation trapdoor, producing a delegation-tagged header. Passes
/// through `(node, depth, index)`; consumes `(mk, cm)`.
pub struct GgmBlindStep<'params, C: Cycle> {
    /// Poseidon parameters used for the delegation-id sponge.
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmBlindStep<'_, C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(3);
    type Witness<'source> = C::CircuitField;
    type Aux<'source> = ();
    type Left = GgmPrivateHeader;
    type Right = ();
    type Output = GgmDelegateHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<C::CircuitField>>::Data>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::from_gadget(());
        let trap = Element::alloc(dr, allocator, witness)?;

        let GgmPrivate {
            node,
            depth,
            index,
            mk,
            cm,
        } = left.as_gadget();

        // delegation_id = Poseidon(ID, mk, cm, trap).
        let delegation_id = {
            let t = Element::constant(dr, tag::<C::CircuitField>(domain::ID));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &t)?;
            sp.absorb(dr, mk)?;
            sp.absorb(dr, cm)?;
            sp.absorb(dr, &trap)?;
            sp.squeeze(dr)?
        };

        let node = node.clone();
        let depth = depth.clone();
        let index = index.clone();

        let output_data = D::just(|| GgmDelegateData {
            node: *node.value().take(),
            depth: *depth.value().take(),
            index: *index.value().take(),
            delegation_id: *delegation_id.value().take(),
        });

        let output = Encoded::from_gadget(GgmDelegate {
            node,
            depth,
            index,
            delegation_id,
        });

        Ok(((left, right, output), output_data, D::unit()))
    }
}

/// Recursive post-blind descent: `GgmDelegateHeader` →
/// `GgmDelegateHeader`. Same GGM hash as `GgmNodeStep`; `delegation_id`
/// passes through. Asserts `depth < DEPTH`.
pub struct GgmDelegateStep<'params, C: Cycle> {
    /// Poseidon parameters used for the tree-step sponge.
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmDelegateStep<'_, C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(4);
    type Witness<'source> = u8;
    type Aux<'source> = ();
    type Left = GgmDelegateHeader;
    type Right = ();
    type Output = GgmDelegateHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<C::CircuitField>>::Data>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::from_gadget(());
        let chunk = alloc_chunk::<D, _>(dr, allocator, witness)?;

        let GgmDelegate {
            node: prev_node,
            depth: prev_depth,
            index: prev_index,
            delegation_id,
        } = left.as_gadget();

        let depth_constant = Element::constant(dr, C::CircuitField::from(GGM_DEPTH as u64));
        let diff = prev_depth.sub(dr, &depth_constant);
        let _ = diff.invert(dr)?;

        // node' = Poseidon(GGM, prev_node, chunk) — same domain as pre-blind walk.
        let node = {
            let t = Element::constant(dr, tag::<C::CircuitField>(domain::TN));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &t)?;
            sp.absorb(dr, prev_node)?;
            sp.absorb(dr, &chunk)?;
            sp.squeeze(dr)?
        };

        let one = Element::one();
        let depth = prev_depth.add(dr, &one);
        let k = C::CircuitField::from(1u64 << GGM_CHUNK_SIZE);
        let index = prev_index.scale(dr, Coeff::Arbitrary(k)).add(dr, &chunk);
        let delegation_id = delegation_id.clone();

        let output_data = D::just(|| GgmDelegateData {
            node: *node.value().take(),
            depth: *depth.value().take(),
            index: *index.value().take(),
            delegation_id: *delegation_id.value().take(),
        });

        let output = Encoded::from_gadget(GgmDelegate {
            node,
            depth,
            index,
            delegation_id,
        });

        Ok(((left, right, output), output_data, D::unit()))
    }
}

/// Terminal step: asserts `depth == DEPTH`, derives
/// `nullifier = Poseidon(NF, leaf_node)`, and re-emits
/// `(nullifier, epoch=index, delegation_id)`.
pub struct GgmNullifierStep<'params, C: Cycle> {
    /// Poseidon parameters used for the final-value sponge.
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmNullifierStep<'_, C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(5);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = GgmDelegateHeader;
    type Right = ();
    type Output = GgmNullifierHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<C::CircuitField>>::Data>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::from_gadget(());

        let GgmDelegate {
            node,
            depth,
            index,
            delegation_id,
        } = left.as_gadget();

        // Assert depth == DEPTH.
        let expected_depth = Element::constant(dr, C::CircuitField::from(GGM_DEPTH as u64));
        let diff = depth.sub(dr, &expected_depth);
        diff.enforce_zero(dr)?;

        // nullifier = Poseidon(NF, node).
        let nullifier = {
            let t = Element::constant(dr, tag::<C::CircuitField>(domain::NF));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &t)?;
            sp.absorb(dr, node)?;
            sp.squeeze(dr)?
        };

        let epoch = index.clone();
        let delegation_id = delegation_id.clone();

        let output_data = D::just(|| GgmNullifierData {
            nullifier: *nullifier.value().take(),
            epoch: *epoch.value().take(),
            delegation_id: *delegation_id.value().take(),
        });

        let output = Encoded::from_gadget(GgmNullifier {
            nullifier,
            epoch,
            delegation_id,
        });

        Ok(((left, right, output), output_data, D::unit()))
    }
}

/// Native Poseidon walk, mirroring the in-circuit steps.
pub fn native_ggm<C: Cycle>(
    poseidon_params: &C::CircuitPoseidon,
    seed: GgmSeed<C::CircuitField>,
    trap: C::CircuitField,
    epoch: u32,
) -> Result<GgmNullifierData<C::CircuitField>>
where
    C::CircuitField: PrimeField,
{
    let GgmSeed {
        nk,
        note:
            GgmNote {
                pk,
                value,
                psi,
                rcm,
            },
    } = seed;
    let mut dr = Emulator::execute();
    let allocator = &mut Standard::new();
    let dr = &mut dr;

    let just = |v: C::CircuitField| Always::maybe_just(|| v);
    let nk_e = Element::alloc(dr, allocator, just(nk))?;
    let pk_e = Element::alloc(dr, allocator, just(pk))?;
    let value_e = Element::alloc(dr, allocator, just(value))?;
    let psi_e = Element::alloc(dr, allocator, just(psi))?;
    let rcm_e = Element::alloc(dr, allocator, just(rcm))?;
    let trap_e = Element::alloc(dr, allocator, just(trap))?;

    // cm = Poseidon(CM, rcm, pk, value, psi).
    let cm = {
        let t = Element::constant(dr, tag::<C::CircuitField>(domain::CM));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &rcm_e)?;
        sp.absorb(dr, &pk_e)?;
        sp.absorb(dr, &value_e)?;
        sp.absorb(dr, &psi_e)?;
        sp.squeeze(dr)?
    };

    // mk = Poseidon(MK, psi, nk).
    let mk = {
        let t = Element::constant(dr, tag::<C::CircuitField>(domain::MK));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &psi_e)?;
        sp.absorb(dr, &nk_e)?;
        sp.squeeze(dr)?
    };

    // delegation_id = Poseidon(ID, mk, cm, trap).
    let delegation_id = {
        let t = Element::constant(dr, tag::<C::CircuitField>(domain::ID));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &mk)?;
        sp.absorb(dr, &cm)?;
        sp.absorb(dr, &trap_e)?;
        sp.squeeze(dr)?
    };

    // Walk the GGM tree MSB-first, CHUNK_SIZE bits at a time.
    let chunk_mask: u32 = (1u32 << GGM_CHUNK_SIZE) - 1;
    let mut node = mk;
    for i in 0..GGM_DEPTH {
        let shift = GGM_CHUNK_SIZE * (GGM_DEPTH - 1 - i);
        let chunk = (epoch >> shift) & chunk_mask;
        let chunk_e = Element::alloc(dr, allocator, just(C::CircuitField::from(u64::from(chunk))))?;

        let t = Element::constant(dr, tag::<C::CircuitField>(domain::TN));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &node)?;
        sp.absorb(dr, &chunk_e)?;
        node = sp.squeeze(dr)?;
    }

    // nullifier = Poseidon(NF, leaf_node).
    let nullifier = {
        let t = Element::constant(dr, tag::<C::CircuitField>(domain::NF));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &node)?;
        sp.squeeze(dr)?
    };

    Ok(GgmNullifierData {
        nullifier: *nullifier.value().take(),
        epoch: C::CircuitField::from(u64::from(epoch)),
        delegation_id: *delegation_id.value().take(),
    })
}
