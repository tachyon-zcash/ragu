use ff::Field;
use ragu_core::{
    Result,
    drivers::emulator::Emulator,
    maybe::{Always, Maybe, MaybeKind},
};
use ragu_primitives::GadgetExt;

use alloc::{vec, vec::Vec};

use super::Circuit;

pub fn eval<F: Field, C: Circuit<F>>(circuit: &C, instance: C::Instance<'_>) -> Result<Vec<F>> {
    let mut dr = Emulator::extractor();
    let mut pubinputs = vec![];
    circuit
        .instance(&mut dr, Always::maybe_just(|| instance))?
        .write(&mut dr, &mut pubinputs)?;

    Ok(pubinputs
        .into_iter()
        .map(|x| x.wire().clone().value().take())
        .chain(Some(F::ONE))
        .rev()
        .collect())
}
