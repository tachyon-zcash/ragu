#![allow(clippy::type_complexity)]

use ff::{Field, PrimeField};
use ragu_arithmetic::Cycle;
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

#[derive(Gadget, Write)]
pub struct ChunkGadget<'dr, D: Driver<'dr>> {
    pub bits: [Boolean<'dr, D>; GGM_CHUNK_SIZE as usize],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkWitness(pub [bool; GGM_CHUNK_SIZE as usize]);

#[derive(Gadget, Write)]
pub struct DelegationIdGadget<'dr, D: Driver<'dr>> {
    pub inner: Element<'dr, D>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegationIdWitness<F: Field>(pub F);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DelegationTrapdoorWitness<F: Field>(pub F);

#[derive(Gadget, Write)]
pub struct DelegationTrapdoorGadget<'dr, D: Driver<'dr>> {
    pub inner: Element<'dr, D>,
}

#[derive(Gadget, Write)]
pub struct MasterKeyGadget<'dr, D: Driver<'dr>> {
    pub inner: Element<'dr, D>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MasterKeyWitness<F: Field>(pub F);

#[derive(Gadget, Write)]
pub struct NoteCommitmentGadget<'dr, D: Driver<'dr>> {
    pub inner: Element<'dr, D>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoteCommitmentWitness<F: Field>(pub F);

#[derive(Gadget, Write)]
pub struct NoteGadget<'dr, D: Driver<'dr>> {
    pub pk: Element<'dr, D>,
    pub value: Element<'dr, D>,
    pub psi: Element<'dr, D>,
    pub rcm: Element<'dr, D>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteWitness<F: Field> {
    pub pk: F,
    pub value: F,
    pub psi: F,
    pub rcm: F,
}

#[derive(Gadget, Write)]
pub struct NullifierGadget<'dr, D: Driver<'dr>> {
    pub inner: Element<'dr, D>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NullifierWitness<F: Field>(pub F);

#[derive(Gadget, Write)]
pub struct NullifierKeyGadget<'dr, D: Driver<'dr>> {
    pub inner: Element<'dr, D>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NullifierKeyWitness<F: Field>(pub F);

#[derive(Gadget, Write)]
pub struct PrefixKeyGadget<'dr, D: Driver<'dr>> {
    pub depth: Element<'dr, D>,
    pub index: Element<'dr, D>,
    pub inner: Element<'dr, D>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixKeyWitness<F: Field> {
    pub depth: u8,
    pub index: u16,
    pub inner: F,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochIndexWitness<F: Field>(pub F);

#[derive(Gadget, Write)]
pub struct EpochIndexGadget<'dr, D: Driver<'dr>> {
    pub inner: Element<'dr, D>,
}

pub mod domain {
    pub const CM: &[u8; 16] = b"EXAMPLEGgmCommit";
    pub const MK: &[u8; 16] = b"EXAMPLEGgmMaster";
    pub const TN: &[u8; 16] = b"EXAMPLE  GgmStep";
    pub const NF: &[u8; 16] = b"EXAMPLE  GgmNull";
    pub const ID: &[u8; 16] = b"EXAMPLE GgmBlind";
    pub const PK: &[u8; 16] = b"EXAMPLE  GgmPubK";
}

/// Pack a 16-byte tag into a field element.
pub fn tag<F: PrimeField>(t: &[u8; 16]) -> F {
    F::from_u128(u128::from_le_bytes(*t))
}

// Little-endian truncating extractors. Ideally these'd be `impl
// From<FieldElement> for u8/u16` in a shared crate, but there's no such
// impl upstream — the repr route via `to_repr()` is the public API.
fn fe_to_u8<F: PrimeField>(f: F) -> u8 {
    f.to_repr().as_ref()[0]
}

fn fe_to_u16<F: PrimeField>(f: F) -> u16 {
    let bytes = f.to_repr();
    let bytes = bytes.as_ref();
    u16::from_le_bytes([bytes[0], bytes[1]])
}

/// Allocate `GGM_CHUNK_SIZE` booleans (little-endian bit order) from a
/// `ChunkWitness`. The bits are exposed directly on `ChunkGadget`; callers
/// that need the packed digit go through [`multipack`].
fn alloc_chunk<'dr, D, A>(
    dr: &mut D,
    allocator: &mut A,
    witness: DriverValue<D, ChunkWitness>,
) -> Result<ChunkGadget<'dr, D>>
where
    D: Driver<'dr>,
    A: Allocator<'dr, D>,
{
    let mut bits = Vec::with_capacity(GGM_CHUNK_SIZE as usize);
    for i in 0..GGM_CHUNK_SIZE as usize {
        let bit_w = witness.as_ref().map(move |c| c.0[i]);
        bits.push(Boolean::alloc(dr, allocator, bit_w)?);
    }
    let bits: [Boolean<'dr, D>; GGM_CHUNK_SIZE as usize] = bits
        .try_into()
        .ok()
        .expect("loop pushes exactly GGM_CHUNK_SIZE bits");
    Ok(ChunkGadget { bits })
}

mod routines;

use routines::{Blind, DeriveMk, DeriveNext, DeriveNullifier, DerivePrefix, NoteCommit};

pub struct GgmMasterHeader;

impl<F: PrimeField> Header<F> for GgmMasterHeader {
    const SUFFIX: Suffix = Suffix::new(10);
    type Data = (MasterKeyWitness<F>, NoteCommitmentWitness<F>);
    type Output = Kind![F; (MasterKeyGadget<'_, _>, NoteCommitmentGadget<'_, _>)];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        let (mk, cm) = witness.cast();
        let mk_f = mk.map(|m| m.0);
        let cm_f = cm.map(|c| c.0);

        Ok((
            MasterKeyGadget {
                inner: Element::alloc(dr, allocator, mk_f)?,
            },
            NoteCommitmentGadget {
                inner: Element::alloc(dr, allocator, cm_f)?,
            },
        ))
    }
}

pub struct GgmPrivateHeader;

impl<F: PrimeField> Header<F> for GgmPrivateHeader {
    const SUFFIX: Suffix = Suffix::new(11);
    type Data = (
        PrefixKeyWitness<F>,
        MasterKeyWitness<F>,
        NoteCommitmentWitness<F>,
    );
    // Right-nested 2-tuple: only 2-tuples have a `GadgetKind` blanket impl.
    type Output = Kind![F;
        (PrefixKeyGadget<'_, _>, (MasterKeyGadget<'_, _>, NoteCommitmentGadget<'_, _>))
    ];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        let (prefix_w, mk_w, cm_w) = witness.cast();
        let (depth_w, index_w, inner_w) = prefix_w
            .map(|w| {
                (
                    F::from(u64::from(w.depth)),
                    F::from(u64::from(w.index)),
                    w.inner,
                )
            })
            .cast();

        Ok((
            PrefixKeyGadget {
                depth: Element::alloc(dr, allocator, depth_w)?,
                index: Element::alloc(dr, allocator, index_w)?,
                inner: Element::alloc(dr, allocator, inner_w)?,
            },
            (
                MasterKeyGadget {
                    inner: Element::alloc(dr, allocator, mk_w.map(|w| w.0))?,
                },
                NoteCommitmentGadget {
                    inner: Element::alloc(dr, allocator, cm_w.map(|w| w.0))?,
                },
            ),
        ))
    }
}

pub struct GgmDelegateHeader;

impl<F: PrimeField> Header<F> for GgmDelegateHeader {
    const SUFFIX: Suffix = Suffix::new(12);
    type Data = (PrefixKeyWitness<F>, DelegationIdWitness<F>);
    type Output = Kind![F; (PrefixKeyGadget<'_, _>, DelegationIdGadget<'_, _>)];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        let (prefix_w, did_w) = witness.cast();
        let (depth_w, index_w, inner_w) = prefix_w
            .map(|w| {
                (
                    F::from(u64::from(w.depth)),
                    F::from(u64::from(w.index)),
                    w.inner,
                )
            })
            .cast();

        Ok((
            PrefixKeyGadget {
                depth: Element::alloc(dr, allocator, depth_w)?,
                index: Element::alloc(dr, allocator, index_w)?,
                inner: Element::alloc(dr, allocator, inner_w)?,
            },
            DelegationIdGadget {
                inner: Element::alloc(dr, allocator, did_w.map(|w| w.0))?,
            },
        ))
    }
}

pub struct GgmNullifierHeader;

impl<F: PrimeField> Header<F> for GgmNullifierHeader {
    const SUFFIX: Suffix = Suffix::new(13);
    type Data = (
        NullifierWitness<F>,
        EpochIndexWitness<F>,
        DelegationIdWitness<F>,
    );
    // Right-nested 2-tuple: only 2-tuples have a `GadgetKind` blanket impl.
    type Output = Kind![F;
        (NullifierGadget<'_, _>, (EpochIndexGadget<'_, _>, DelegationIdGadget<'_, _>))
    ];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        let (nf_w, ep_w, did_w) = witness.cast();
        Ok((
            NullifierGadget {
                inner: Element::alloc(dr, allocator, nf_w.map(|w| w.0))?,
            },
            (
                EpochIndexGadget {
                    inner: Element::alloc(dr, allocator, ep_w.map(|w| w.0))?,
                },
                DelegationIdGadget {
                    inner: Element::alloc(dr, allocator, did_w.map(|w| w.0))?,
                },
            ),
        ))
    }
}

pub struct GgmMasterSeed<C: Cycle> {
    pub poseidon_params: &'static C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmMasterSeed<C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(0);
    type Witness<'source> = (
        NullifierKeyWitness<C::CircuitField>,
        NoteWitness<C::CircuitField>,
    );
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
        let (nk_w, note_w) = witness.cast();

        let nk = NullifierKeyGadget {
            inner: Element::alloc(dr, allocator, nk_w.map(|w| w.0))?,
        };
        let (pk_w, v_w, psi_w, rcm_w) = note_w.map(|w| (w.pk, w.value, w.psi, w.rcm)).cast();
        let note = NoteGadget {
            pk: Element::alloc(dr, allocator, pk_w)?,
            value: Element::alloc(dr, allocator, v_w)?,
            psi: Element::alloc(dr, allocator, psi_w)?,
            rcm: Element::alloc(dr, allocator, rcm_w)?,
        };

        let cm = dr.routine(NoteCommit::from(self.poseidon_params), note.clone())?;
        let mk = dr.routine(
            DeriveMk::from(self.poseidon_params),
            (nk.clone(), note.clone()),
        )?;

        let output_data = D::just(|| {
            (
                MasterKeyWitness(*mk.inner.value().take()),
                NoteCommitmentWitness(*cm.inner.value().take()),
            )
        });
        let output = Encoded::from_gadget((mk, cm));
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            output_data,
            D::unit(),
        ))
    }
}

pub struct GgmMasterStep<C: Cycle> {
    pub poseidon_params: &'static C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmMasterStep<C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ChunkWitness;
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
        let chunk = alloc_chunk(dr, allocator, witness)?;

        let (mk, cm) = left.as_gadget();
        let prefix = dr.routine(
            DerivePrefix::from(self.poseidon_params),
            (mk.clone(), chunk),
        )?;

        let output_data = D::just(|| {
            (
                PrefixKeyWitness {
                    depth: fe_to_u8(*prefix.depth.value().take()),
                    index: fe_to_u16(*prefix.index.value().take()),
                    inner: *prefix.inner.value().take(),
                },
                MasterKeyWitness(*mk.inner.value().take()),
                NoteCommitmentWitness(*cm.inner.value().take()),
            )
        });
        let output = Encoded::from_gadget((prefix, (mk.clone(), cm.clone())));
        Ok(((left, right, output), output_data, D::unit()))
    }
}

pub struct GgmNodeStep<C: Cycle> {
    pub poseidon_params: &'static C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmNodeStep<C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ChunkWitness;
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
        let chunk = alloc_chunk(dr, allocator, witness)?;

        let (prefix, (mk, cm)) = left.as_gadget();
        let next = dr.routine(
            DeriveNext::from(self.poseidon_params),
            (prefix.clone(), chunk),
        )?;

        let output_data = D::just(|| {
            (
                PrefixKeyWitness {
                    depth: fe_to_u8(*next.depth.value().take()),
                    index: fe_to_u16(*next.index.value().take()),
                    inner: *next.inner.value().take(),
                },
                MasterKeyWitness(*mk.inner.value().take()),
                NoteCommitmentWitness(*cm.inner.value().take()),
            )
        });
        let output = Encoded::from_gadget((next, (mk.clone(), cm.clone())));
        Ok(((left, right, output), output_data, D::unit()))
    }
}

pub struct GgmBlindStep<C: Cycle> {
    pub poseidon_params: &'static C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmBlindStep<C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(3);
    type Witness<'source> = DelegationTrapdoorWitness<C::CircuitField>;
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
        let trap = DelegationTrapdoorGadget {
            inner: Element::alloc(dr, allocator, witness.map(|w| w.0))?,
        };

        let (prefix, (mk, cm)) = left.as_gadget();
        let did = dr.routine(
            Blind::from(self.poseidon_params),
            (mk.clone(), (cm.clone(), trap)),
        )?;

        let output_data = D::just(|| {
            (
                PrefixKeyWitness {
                    depth: fe_to_u8(*prefix.depth.value().take()),
                    index: fe_to_u16(*prefix.index.value().take()),
                    inner: *prefix.inner.value().take(),
                },
                DelegationIdWitness(*did.inner.value().take()),
            )
        });
        let output = Encoded::from_gadget((prefix.clone(), did));
        Ok(((left, right, output), output_data, D::unit()))
    }
}

pub struct GgmDelegateStep<C: Cycle> {
    pub poseidon_params: &'static C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmDelegateStep<C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(4);
    type Witness<'source> = ChunkWitness;
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
        let chunk = alloc_chunk(dr, allocator, witness)?;

        let (prefix, did) = left.as_gadget();
        let next = dr.routine(
            DeriveNext::from(self.poseidon_params),
            (prefix.clone(), chunk),
        )?;

        let output_data = D::just(|| {
            (
                PrefixKeyWitness {
                    depth: fe_to_u8(*next.depth.value().take()),
                    index: fe_to_u16(*next.index.value().take()),
                    inner: *next.inner.value().take(),
                },
                DelegationIdWitness(*did.inner.value().take()),
            )
        });
        let output = Encoded::from_gadget((next, did.clone()));
        Ok(((left, right, output), output_data, D::unit()))
    }
}

pub struct GgmNullifierStep<C: Cycle> {
    pub poseidon_params: &'static C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmNullifierStep<C>
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

        let (prefix, did) = left.as_gadget();
        let nullifier = dr.routine(
            DeriveNullifier::from(self.poseidon_params),
            prefix.clone(),
        )?;
        let epoch = EpochIndexGadget {
            inner: prefix.index.clone(),
        };

        let output_data = D::just(|| {
            (
                NullifierWitness(*nullifier.inner.value().take()),
                EpochIndexWitness(*epoch.inner.value().take()),
                DelegationIdWitness(*did.inner.value().take()),
            )
        });
        let output = Encoded::from_gadget((nullifier, (epoch, did.clone())));
        Ok(((left, right, output), output_data, D::unit()))
    }
}

pub fn native_ggm<C: Cycle>(
    poseidon_params: &C::CircuitPoseidon,
    nk: NullifierKeyWitness<C::CircuitField>,
    note: NoteWitness<C::CircuitField>,
    trap: DelegationTrapdoorWitness<C::CircuitField>,
    epoch: u32,
) -> Result<(
    NullifierWitness<C::CircuitField>,
    EpochIndexWitness<C::CircuitField>,
    DelegationIdWitness<C::CircuitField>,
)>
where
    C::CircuitField: PrimeField,
{
    let mut dr = Emulator::execute();
    let allocator = &mut Standard::new();
    let dr = &mut dr;

    let just = |v: C::CircuitField| Always::maybe_just(|| v);

    let nk_e = Element::alloc(dr, allocator, just(nk.0))?;

    let note_e = {
        let pk_e = Element::alloc(dr, allocator, just(note.pk))?;
        let value_e = Element::alloc(dr, allocator, just(note.value))?;
        let psi_e = Element::alloc(dr, allocator, just(note.psi))?;
        let rcm_e = Element::alloc(dr, allocator, just(note.rcm))?;

        NoteGadget {
            pk: pk_e,
            value: value_e,
            psi: psi_e,
            rcm: rcm_e,
        }
    };

    let trap_e = Element::alloc(dr, allocator, just(trap.0))?;

    // cm = Poseidon(CM, rcm, pk, value, psi).
    let cm = {
        let t = Element::constant(dr, tag::<C::CircuitField>(domain::CM));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &note_e.rcm)?;
        sp.absorb(dr, &note_e.pk)?;
        sp.absorb(dr, &note_e.value)?;
        sp.absorb(dr, &note_e.psi)?;
        sp.squeeze(dr)?
    };

    // mk = Poseidon(MK, psi, nk).
    let mk = {
        let t = Element::constant(dr, tag::<C::CircuitField>(domain::MK));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &note_e.psi)?;
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

    // Walk the GGM tree MSB-first, CHUNK_SIZE bits at a time. Each chunk is
    // absorbed bit-by-bit (LE within the chunk) to match the in-circuit
    // `derive_prefix`/`derive_next` absorb shape.
    let chunk_mask: u32 = (1u32 << GGM_CHUNK_SIZE) - 1;
    let mut node = mk;
    for i in 0..GGM_DEPTH {
        let shift = GGM_CHUNK_SIZE * (GGM_DEPTH - 1 - i);
        let chunk = (epoch >> shift) & chunk_mask;

        let mut bit_es = Vec::with_capacity(GGM_CHUNK_SIZE as usize);
        for j in 0..GGM_CHUNK_SIZE as usize {
            let bit = (chunk >> j) & 1;
            bit_es.push(Element::alloc(
                dr,
                allocator,
                just(C::CircuitField::from(u64::from(bit))),
            )?);
        }

        let t = Element::constant(dr, tag::<C::CircuitField>(domain::TN));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &node)?;
        for bit_e in &bit_es {
            sp.absorb(dr, bit_e)?;
        }
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

    let epoch_e = Element::alloc(dr, allocator, just(C::CircuitField::from(u64::from(epoch))))?;

    Ok((
        NullifierWitness(*nullifier.value().take()),
        EpochIndexWitness(*epoch_e.value().take()),
        DelegationIdWitness(*delegation_id.value().take()),
    ))
}
