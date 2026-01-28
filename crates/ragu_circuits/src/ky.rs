use ff::Field;
use ragu_core::{
    Result,
    drivers::emulator::Emulator,
    maybe::{Always, MaybeKind},
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
        .map(|x| x.wire().clone().value())
        .chain(Some(F::ONE))
        .rev()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::SquareCircuit;
    use ragu_pasta::Fp;

    #[test]
    fn test_ky() {
        let circuit = SquareCircuit { times: 10 };
        let instance: Fp = Fp::from(3);
        let ky = eval::<Fp, _>(&circuit, instance).unwrap();
        assert_eq!(ky.len(), 2);
        assert_eq!(ky[0], Fp::ONE);
        assert_eq!(ky[1], Fp::from(3));
    }
}
