//! PCD `Step` impls for the ggm app — the seed/fuse nodes that drive the
//! tree from a master seed through prefix descent, blinding, delegation,
//! and nullifier extraction. Each `witness` body composes the routines
//! defined in [`super::routines`].

use ff::PrimeField;
use ragu_arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_pcd::{
    header::Header,
    step::{Encoded, Index, Step},
};
use ragu_primitives::{Element, allocator::Standard};

use super::{
    ChunkWitness, DelegationIdWitness, DelegationTrapdoorGadget, DelegationTrapdoorWitness,
    EpochIndexGadget, EpochIndexWitness, GgmDelegateHeader, GgmMasterHeader, GgmNullifierHeader,
    GgmPrivateHeader, MasterKeyWitness, NoteCommitmentWitness, NoteGadget, NoteWitness,
    NullifierKeyGadget, NullifierKeyWitness, NullifierWitness, PrefixKeyWitness, alloc_chunk,
    fe_to_u16, fe_to_u8,
    routines::{Blind, DeriveMk, DeriveNext, DeriveNullifier, DerivePrefix, NoteCommit},
};

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
