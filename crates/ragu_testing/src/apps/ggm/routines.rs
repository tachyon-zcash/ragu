//! Routines that transform one ggm gadget into another. Each one wraps a
//! Poseidon-shaped sub-circuit, giving the driver a fingerprint it can
//! memoise across invocations.
//!
//! These are set up independently of the ggm gadget types: they hold a
//! `&'static P` and are invoked via [`Driver::routine`] from circuit code
//! (e.g. the `Step::witness` impls). `'static` neatly sidesteps the
//! lifetime mismatch that arises when a routine struct holds borrowed
//! state and tries to feed it to a `'dr`-bound API like
//! [`Sponge::new`] — the only callers in this app already source params
//! from `Pasta::circuit_poseidon(Pasta::baked())`, which produces a
//! `&'static`.

use core::marker::PhantomData;

use ff::{Field, PrimeField};
use ragu_arithmetic::PoseidonPermutation;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    routines::{Prediction, Routine},
};
use ragu_primitives::{Element, multipack, poseidon::Sponge};

use super::{
    ChunkGadget, DelegationIdGadget, DelegationTrapdoorGadget, GGM_ARITY, GGM_DEPTH,
    MasterKeyGadget, NoteCommitmentGadget, NoteGadget, NullifierGadget, NullifierKeyGadget,
    PrefixKeyGadget, domain, tag,
};

pub struct NoteCommit<F: Field, P: PoseidonPermutation<F>> {
    params: &'static P,
    _marker: PhantomData<F>,
}

impl<F: Field, P: PoseidonPermutation<F>> From<&'static P> for NoteCommit<F, P> {
    fn from(params: &'static P) -> Self {
        NoteCommit {
            params,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, P: PoseidonPermutation<F>> Clone for NoteCommit<F, P> {
    fn clone(&self) -> Self {
        NoteCommit {
            params: self.params,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField, P: PoseidonPermutation<F>> Routine<F> for NoteCommit<F, P> {
    type Input = Kind![F; NoteGadget<'_, _>];
    type Output = Kind![F; NoteCommitmentGadget<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        note: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let t = Element::constant(dr, tag::<F>(domain::CM));
        let mut sp = Sponge::new(dr, self.params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &note.rcm)?;
        sp.absorb(dr, &note.pk)?;
        sp.absorb(dr, &note.value)?;
        sp.absorb(dr, &note.psi)?;
        Ok(NoteCommitmentGadget {
            inner: sp.squeeze(dr)?,
        })
    }

    fn predict<'dr, D: Driver<'dr, F = F, Wire = ()>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

pub struct DeriveMk<F: Field, P: PoseidonPermutation<F>> {
    params: &'static P,
    _marker: PhantomData<F>,
}

impl<F: Field, P: PoseidonPermutation<F>> From<&'static P> for DeriveMk<F, P> {
    fn from(params: &'static P) -> Self {
        DeriveMk {
            params,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, P: PoseidonPermutation<F>> Clone for DeriveMk<F, P> {
    fn clone(&self) -> Self {
        DeriveMk {
            params: self.params,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField, P: PoseidonPermutation<F>> Routine<F> for DeriveMk<F, P> {
    type Input = Kind![F; (NullifierKeyGadget<'_, _>, NoteGadget<'_, _>)];
    type Output = Kind![F; MasterKeyGadget<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (nk, note) = input;
        let t = Element::constant(dr, tag::<F>(domain::MK));
        let mut sp = Sponge::new(dr, self.params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &note.psi)?;
        sp.absorb(dr, &nk.inner)?;
        Ok(MasterKeyGadget {
            inner: sp.squeeze(dr)?,
        })
    }

    fn predict<'dr, D: Driver<'dr, F = F, Wire = ()>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

pub struct DerivePrefix<F: Field, P: PoseidonPermutation<F>> {
    params: &'static P,
    _marker: PhantomData<F>,
}

impl<F: Field, P: PoseidonPermutation<F>> From<&'static P> for DerivePrefix<F, P> {
    fn from(params: &'static P) -> Self {
        DerivePrefix {
            params,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, P: PoseidonPermutation<F>> Clone for DerivePrefix<F, P> {
    fn clone(&self) -> Self {
        DerivePrefix {
            params: self.params,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField, P: PoseidonPermutation<F>> Routine<F> for DerivePrefix<F, P> {
    type Input = Kind![F; (MasterKeyGadget<'_, _>, ChunkGadget<'_, _>)];
    type Output = Kind![F; PrefixKeyGadget<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (mk, chunk) = input;
        let chunk_digit = multipack(dr, &chunk.bits)?
            .into_iter()
            .next()
            .expect("multipack returns one element for a non-empty slice");
        let t = Element::constant(dr, tag::<F>(domain::TN));
        let mut sp = Sponge::new(dr, self.params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &mk.inner)?;
        for bit in &chunk.bits {
            sp.absorb(dr, &bit.element())?;
        }
        Ok(PrefixKeyGadget {
            depth: Element::one(),
            index: chunk_digit,
            inner: sp.squeeze(dr)?,
        })
    }

    fn predict<'dr, D: Driver<'dr, F = F, Wire = ()>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

pub struct Blind<F: Field, P: PoseidonPermutation<F>> {
    params: &'static P,
    _marker: PhantomData<F>,
}

impl<F: Field, P: PoseidonPermutation<F>> From<&'static P> for Blind<F, P> {
    fn from(params: &'static P) -> Self {
        Blind {
            params,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, P: PoseidonPermutation<F>> Clone for Blind<F, P> {
    fn clone(&self) -> Self {
        Blind {
            params: self.params,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField, P: PoseidonPermutation<F>> Routine<F> for Blind<F, P> {
    // Right-nested 2-tuple: only 2-tuples have a `GadgetKind` blanket impl.
    type Input = Kind![F;
        (MasterKeyGadget<'_, _>, (NoteCommitmentGadget<'_, _>, DelegationTrapdoorGadget<'_, _>))
    ];
    type Output = Kind![F; DelegationIdGadget<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (mk, (cm, trap)) = input;
        let t = Element::constant(dr, tag::<F>(domain::ID));
        let mut sp = Sponge::new(dr, self.params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &mk.inner)?;
        sp.absorb(dr, &cm.inner)?;
        sp.absorb(dr, &trap.inner)?;
        Ok(DelegationIdGadget {
            inner: sp.squeeze(dr)?,
        })
    }

    fn predict<'dr, D: Driver<'dr, F = F, Wire = ()>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

pub struct DeriveNext<F: Field, P: PoseidonPermutation<F>> {
    params: &'static P,
    _marker: PhantomData<F>,
}

impl<F: Field, P: PoseidonPermutation<F>> From<&'static P> for DeriveNext<F, P> {
    fn from(params: &'static P) -> Self {
        DeriveNext {
            params,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, P: PoseidonPermutation<F>> Clone for DeriveNext<F, P> {
    fn clone(&self) -> Self {
        DeriveNext {
            params: self.params,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField, P: PoseidonPermutation<F>> Routine<F> for DeriveNext<F, P> {
    type Input = Kind![F; (PrefixKeyGadget<'_, _>, ChunkGadget<'_, _>)];
    type Output = Kind![F; PrefixKeyGadget<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (prefix, chunk) = input;
        let depth = prefix.depth.add(dr, &Element::one());

        let chunk_digit = multipack(dr, &chunk.bits)?
            .into_iter()
            .next()
            .expect("multipack returns one element for a non-empty slice");

        let index = {
            let arity = Element::constant(dr, F::from(GGM_ARITY as u64));
            let scale_index = prefix.index.mul(dr, &arity)?;
            scale_index.add(dr, &chunk_digit)
        };

        let t = Element::constant(dr, tag::<F>(domain::TN));
        let mut sp = Sponge::new(dr, self.params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &prefix.inner)?;
        for bit in &chunk.bits {
            sp.absorb(dr, &bit.element())?;
        }

        Ok(PrefixKeyGadget {
            depth,
            index,
            inner: sp.squeeze(dr)?,
        })
    }

    fn predict<'dr, D: Driver<'dr, F = F, Wire = ()>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

pub struct DeriveNullifier<F: Field, P: PoseidonPermutation<F>> {
    params: &'static P,
    _marker: PhantomData<F>,
}

impl<F: Field, P: PoseidonPermutation<F>> From<&'static P> for DeriveNullifier<F, P> {
    fn from(params: &'static P) -> Self {
        DeriveNullifier {
            params,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, P: PoseidonPermutation<F>> Clone for DeriveNullifier<F, P> {
    fn clone(&self) -> Self {
        DeriveNullifier {
            params: self.params,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField, P: PoseidonPermutation<F>> Routine<F> for DeriveNullifier<F, P> {
    type Input = Kind![F; PrefixKeyGadget<'_, _>];
    type Output = Kind![F; NullifierGadget<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        prefix: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let max_depth = Element::constant(dr, F::from(GGM_DEPTH as u64));
        prefix.depth.enforce_equal(dr, &max_depth)?;

        let t = Element::constant(dr, tag::<F>(domain::NF));
        let mut sp = Sponge::new(dr, self.params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &prefix.inner)?;
        Ok(NullifierGadget {
            inner: sp.squeeze(dr)?,
        })
    }

    fn predict<'dr, D: Driver<'dr, F = F, Wire = ()>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}
