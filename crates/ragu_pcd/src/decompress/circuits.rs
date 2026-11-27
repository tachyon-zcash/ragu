//! What a side's circuits share beside its verifier: the stages' wires as
//! the verifier reads them, the side's prepared witness, and the statement
//! circuit.
//!
//! A side's verifier ([`verifier`](super::verifier)) runs in one circuit,
//! the side's whole circuit ([`WholeCircuit`](super::whole::WholeCircuit)),
//! which the pager cuts into the pages the aggregator registers. It loads
//! its stages unenforced, as the fuse's endoscaling steps load theirs: the
//! aggregator's two online stages ([`OnlineInputStage`] and
//! [`OnlineQueryStage`]), then the side's front stages (see
//! [`Front`](super::stages::Front)), the lifts stage and the digits stage.
//! The stages' masks bind the layout the verifier reads.
//!
//! Beside the whole circuit, a [`StatementCircuit`] loads the online stages
//! and the instance stage, and no other, and exposes the output header the
//! verifier checked, then the step binding, as its public output, the one
//! place the decompressed statement reaches a claim. The whole circuit's
//! own public output is the points the side exposes, the other side's
//! stage commitments the side absorbed or recomputed and the commitments
//! it took of the step's own online polynomials, which the proof's
//! consumer holds to those commitments through the claim of the circuit's
//! last page, the side's binding circuit (see
//! [`Binding`](crate::profile::Binding)).

use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point, Uendo,
    vec::{ConstLen, FixedVec, Len},
};
use udon::curve::EndomorphismAffine as Affine;

use super::{
    side::Side,
    stages::{InstanceStage, OnlineInputStage, OnlineQueryStage, Values, step},
    verifier::Tables,
};

/// The statement circuit of side `S`: the circuit whose public output is
/// the output header of the compressed proof the side verified, then the
/// step binding ([`step`]), both read off the instance stage. The verifier
/// binds the header to the proof it verifies, so a claim on this circuit's
/// output is a claim on the decompressed proof's statement, which the
/// decompression step's verifier makes through the circuit's $k(y)$ (see
/// [`statement_ky`](crate::internal::native::stages::preamble::ProofInputs::statement_ky)).
/// The same claim binds the decompression flag and staged transcript digest.
pub(crate) struct StatementCircuit<C: Cycle, S, K, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<fn() -> (C, S, K, R)>,
}

impl<C: Cycle, S, K, R, const HEADER_SIZE: usize> Clone
    for StatementCircuit<C, S, K, R, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        StatementCircuit {
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>
    StatementCircuit<C, S, K, R, HEADER_SIZE>
{
    /// The statement circuit over the side's instance stage.
    pub(crate) fn new() -> MultiStage<S::F, R, Self> {
        MultiStage::new(StatementCircuit {
            _marker: PhantomData,
        })
    }
}

impl<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize> MultiStageCircuit<S::F, R>
    for StatementCircuit<C, S, K, R, HEADER_SIZE>
{
    type Last = InstanceStage<C, S, K, R, HEADER_SIZE>;
    /// The output header and the step binding the instance stage holds.
    type Instance<'source> = (
        FixedVec<S::F, ConstLen<HEADER_SIZE>>,
        FixedVec<S::F, ConstLen<{ step::LEN }>>,
    );
    type Witness<'source> = &'source Prepared<C, S>;
    type Output = Kind![S::F; (
        FixedVec<Element<'_, _>, ConstLen<HEADER_SIZE>>,
        FixedVec<Element<'_, _>, ConstLen<{ step::LEN }>>,
    )];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let header = FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), instance.as_ref().map(|(header, _)| header[i]))
        })?;
        let step = FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), instance.as_ref().map(|(_, step)| step[i]))
        })?;
        Ok((header, step))
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (online_input, dr) = dr.add_stage::<OnlineInputStage<C, S, R>>()?;
        let (online_query, dr) = dr.add_stage::<OnlineQueryStage<C, S, R>>()?;
        let (instance, dr) = dr.add_stage::<InstanceStage<C, S, K, R, HEADER_SIZE>>()?;
        let dr = dr.finish();
        // The online stages come first in every circuit of the side; this
        // one reads nothing off them.
        online_input.unenforced(dr, witness.as_ref().map(|w| &w.online_input))?;
        online_query.unenforced(dr, witness.as_ref().map(|w| &w.online_query))?;
        let instance = instance.unenforced(dr, witness.as_ref().map(|w| &w.instance))?;
        let layout = S::layout::<K, HEADER_SIZE>().instance;
        let read = |span: super::stages::Span| {
            span.positions()
                .map(|position| instance.elements[position].clone())
                .collect::<alloc::vec::Vec<_>>()
        };
        let header = FixedVec::try_from(read(layout.output_header))?;
        let step = FixedVec::try_from(read(layout.step))?;
        Ok(WithAux::new((header, step), D::unit()))
    }
}

/// Length type for the points side `S`'s whole circuit exposes for a
/// proof at rank `K`: [`Side::exposed`].
pub(crate) struct Exposed<C, S, K>(PhantomData<fn() -> (C, S, K)>);

impl<C: Cycle, S: Side<C>, K: Rank> Len for Exposed<C, S, K> {
    fn len() -> usize {
        S::exposed::<K>()
    }
}

/// One stage's wires as a side's verifier reads them.
pub(crate) struct View<'a, 'dr, D: Driver<'dr>, P: Affine<Base = D::F>> {
    pub points: &'a [Point<'dr, D, P>],
    pub elements: &'a [Element<'dr, D>],
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> Clone for View<'_, 'dr, D, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> Copy for View<'_, 'dr, D, P> {}

/// What a side's verifier allocates beyond the stages: the challenges
/// squeezed on the other side as their endoscalars' bits, and the other
/// field's full-width scalars.
#[derive(Clone)]
pub(crate) struct Aux<G> {
    /// Every compression challenge the side did not squeeze, by index: the
    /// reduction it checks in its field, the fuse's $x$, $y$, $u$ and $w$,
    /// then the reduction whose points it checks.
    pub challenge_bits: Vec<Uendo>,
    /// The other field's values the side scales by, by index: $v$, $c$
    /// and $c b z$ of the reduction whose points the side checks, then
    /// what the side's [`Prepare::foreign`](super::prover::Prepare::foreign) adds.
    pub foreign: Vec<G>,
    /// The other side's flags, by index: unset until the step that proves
    /// the side sets them.
    pub flags: Vec<bool>,
    /// Test seam: other bits than the challenge's for what reads the
    /// challenge at an index after the side has lifted it, as a prover
    /// that scaled by other bits than it lifted would allocate.
    #[cfg(test)]
    pub read: Option<(usize, Uendo)>,
}

impl<G> Aux<G> {
    /// The bits a read of the challenge at `id` allocates: the
    /// challenge's.
    pub(crate) fn read(&self, id: usize) -> Uendo {
        #[cfg(test)]
        if let Some((_, bits)) = self.read.filter(|(other, _)| *other == id) {
            return bits;
        }
        self.challenge_bits[id]
    }
}

/// What the prover supplies a side's verifier beside the stages: values
/// the verifier allocates where it reads them and holds to the stages or
/// to the claims of the step that proves it.
#[derive(Clone)]
pub(crate) struct Supplied<F, P> {
    /// Circuit-field side: the commitments of the transcript's runs, by
    /// run ([`Run`](super::stages::Run)), which the transcript absorbs and
    /// the side exposes for the proof's consumer to hold to the run
    /// stages. Empty on the scalar-field side, whose stages they are.
    pub runs: Vec<P>,
    /// The registry restriction at $(r, y)$ of each circuit a claim of the
    /// side's reduction names, in the order the claims first name them.
    pub restrictions: Vec<F>,
    /// The registry restriction at the compression's $w$.
    pub restriction_at_w: F,
    /// The wire bindings' values, by binding and wire: the verifier reads
    /// those the registry gives, and takes the others off the instance.
    pub bindings: Vec<Vec<F>>,
    /// The IPA's witness points $u_j^{-1} L_j$.
    pub inverse_scaled: Vec<P>,
    /// $G'$.
    pub g_prime: P,
    /// Scalar-field side: the two application output commitments of the
    /// step that proves the side, bound to the wallet proof under the
    /// decompression flag; a placeholder outside a step.
    pub outputs: Vec<P>,
    /// Scalar-field side: the commitment of the host IPA's $s(X)$ in that
    /// step's native batch, likewise.
    pub host_ipa: P,
}

/// Everything a side's verifier needs: the stages' values, the lifts and
/// digits stages as the prover's run of the side fills them, the auxiliary
/// witnesses and the side's tables.
pub(crate) struct Prepared<C: Cycle, S: Side<C>> {
    pub tables: Arc<Tables>,
    pub instance: Values<S::F, S::P>,
    pub messages: Values<S::F, S::P>,
    pub lifts: Values<S::F, S::P>,
    pub digits: Values<S::F, S::P>,
    /// The aggregator's online input stage of the side's field, elements
    /// alone, in the order the fuse lays the stage out. Prepared with the
    /// proof's inputs; the step that proves the side sets the rest, the
    /// stage its fuse committed
    /// ([`with_online`](Self::with_online)).
    pub online_input: Values<S::F, S::P>,
    /// The online query stage, likewise: prepared with the evaluations the
    /// verifier reads, as the native verifier computed them.
    pub online_query: Values<S::F, S::P>,
    pub aux: Aux<S::Other>,
    pub supplied: Supplied<S::F, S::P>,
    pub extra: Arc<S::Extra>,
    /// Circuit-field side: the compression transcript's digest, its last
    /// squeeze, as the prover's run of the side leaves it.
    pub digest: Option<S::F>,
}

impl<C: Cycle, S: Side<C>> Clone for Prepared<C, S> {
    fn clone(&self) -> Self {
        Prepared {
            tables: self.tables.clone(),
            instance: self.instance.clone(),
            messages: self.messages.clone(),
            lifts: self.lifts.clone(),
            digits: self.digits.clone(),
            online_input: self.online_input.clone(),
            online_query: self.online_query.clone(),
            aux: self.aux.clone(),
            supplied: self.supplied.clone(),
            extra: self.extra.clone(),
            digest: self.digest,
        }
    }
}
