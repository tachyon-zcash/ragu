//! Places the private batch's stages and helper inside the extension layout.

use alloc::{vec, vec::Vec};

use ragu_circuits::{
    BondingObject,
    polynomials::Rank,
    staging::{MultiStage, StageExt},
};
use ragu_core::{Error, Result};
use udon::field::Field;

use super::{
    circuit,
    stages::{EvalStage, InputStage, Native, Nested, QueryStage, Side},
};
use crate::profile::{CircuitSlot, Extension, Profile, Registered};

/// The input, query and evaluation stages, before the user extension's stages.
pub const STAGES: usize = 3;
/// One helper circuit and its three stages.
pub const RXS: usize = STAGES + 1;

/// Number of built-in stages preceding the user's stages on this side.
pub fn stage_offset<P: Profile, S: Side>() -> usize {
    if S::layout::<P>().is_empty() {
        0
    } else {
        STAGES
    }
}

/// User circuits that share the private input and query stage prefix.
pub fn consumers<P: Profile, S: Side>() -> &'static [u32] {
    if S::NATIVE {
        P::NATIVE_ONLINE_CONSUMERS
    } else {
        P::NESTED_ONLINE_CONSUMERS
    }
}

/// The profile's own declaration, before adding the private batch.
pub fn declared<P: Profile, S: Side>() -> Extension {
    if S::NATIVE {
        P::native_extension()
    } else {
        P::nested_extension()
    }
}

/// The built-in helper's index, if this field has a private batch.
pub fn helper<P: Profile, S: Side>() -> Option<u32> {
    (!S::layout::<P>().is_empty()).then(|| declared::<P, S>().circuits.len() as u32)
}

/// The complete extension declaration used by registry and claim indexing.
pub fn layout<P: Profile, S: Side>() -> Extension {
    let mut extension = declared::<P, S>();
    let offset = stage_offset::<P, S>() as u32;
    if offset != 0 {
        let users = consumers::<P, S>();
        let mut direct = Vec::new();
        for (circuit, stages) in extension.circuits.iter_mut().enumerate() {
            for stage in stages.iter_mut() {
                *stage += offset;
            }
            if users.contains(&(circuit as u32)) {
                if stages.is_empty() {
                    direct.push(circuit as u32);
                }
                stages.splice(0..0, [0, 1]);
            }
        }
        let helper = extension.circuits.len() as u32;
        extension.circuits.push(vec![0, 1, 2]);
        extension.stages += STAGES;
        extension.final_masks.push(vec![helper]);
        if !direct.is_empty() {
            extension.final_masks.push(direct);
        }
    }
    let other_offset = if S::NATIVE {
        stage_offset::<P, Nested>()
    } else {
        stage_offset::<P, Native>()
    } as u32;
    if let Some(binding) = &mut extension.binding {
        for stage in &mut binding.stages {
            *stage += other_offset;
        }
    }
    extension
}

/// Checks consumer indices and that the merged declarations remain consistent.
pub fn check<P: Profile, S: Side>() -> Result<()> {
    let declared = declared::<P, S>();
    let consumers = consumers::<P, S>();
    if (!consumers.is_empty() && S::layout::<P>().is_empty())
        || consumers.iter().enumerate().any(|(i, &circuit)| {
            circuit as usize >= declared.circuits.len() || consumers[..i].contains(&circuit)
        })
        || !layout::<P, S>().is_consistent()
    {
        return Err(Error::Initialization(
            "the private batch's extension consumers are not well formed".into(),
        ));
    }
    Ok(())
}

/// Registers the private helper at its automatically assigned circuit index.
pub fn register_circuit<'params, F: Field, R: Rank, P: Profile, S: Side>(
    slot: CircuitSlot<'params, F, R>,
) -> Result<Registered<'params, F, R>> {
    slot.register(MultiStage::<F, R, _>::new(
        circuit::Circuit::<P, S>::default(),
    ))
}

/// A bonding belongs to the private batch or to the user's declaration.
pub enum Bonding<'params, F: Field, R: Rank> {
    /// An automatically registered private stage mask or final mask.
    Private(BondingObject<'params, F, R>),
    /// The original index passed to the profile's registration hook.
    User(usize),
}

/// Resolves a merged bonding index to its private mask or original user index.
pub fn bonding<'params, F: Field, R: Rank, P: Profile, S: Side>(
    index: usize,
) -> Result<Bonding<'params, F, R>> {
    let offset = stage_offset::<P, S>();
    let declared = declared::<P, S>();
    if index >= layout::<P, S>().bondings() {
        return Err(Error::Initialization(
            "private batch bonding index is out of range".into(),
        ));
    }
    if offset == 0 {
        return Ok(Bonding::User(index));
    }
    let mask = match index {
        0 => <InputStage<P, S> as StageExt<F, R>>::mask()?,
        1 => <QueryStage<P, S> as StageExt<F, R>>::mask()?,
        2 => <EvalStage<P, S> as StageExt<F, R>>::mask()?,
        j if j < offset + declared.bondings() => return Ok(Bonding::User(j - offset)),
        j if j == offset + declared.bondings() => {
            <EvalStage<P, S> as StageExt<F, R>>::final_mask()?
        }
        _ => <QueryStage<P, S> as StageExt<F, R>>::final_mask()?,
    };
    Ok(Bonding::Private(mask))
}
