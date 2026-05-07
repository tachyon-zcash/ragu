//! PCD `Header` impls for the ggm app — the typed witness/output payloads
//! that flow through the proof tree.

use ff::PrimeField;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::header::{Header, Suffix};
use ragu_primitives::{Element, allocator::Allocator};

use super::{
    DelegationIdGadget, DelegationIdWitness, EpochIndexGadget, EpochIndexWitness, MasterKeyGadget,
    MasterKeyWitness, NoteCommitmentGadget, NoteCommitmentWitness, NullifierGadget,
    NullifierWitness, PrefixKeyGadget, PrefixKeyWitness,
};

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
