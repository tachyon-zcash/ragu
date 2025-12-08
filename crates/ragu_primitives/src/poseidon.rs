use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind},
    routines::{Prediction, Routine},
};

use alloc::{vec, vec::Vec};
use core::{marker::PhantomData, panic};

use crate::{
    Element,
    io::Buffer,
    multiadd,
    vec::{FixedVec, Len},
};

pub struct T<F: Field, P: arithmetic::PoseidonPermutation<F>>(F, P);

impl<F: Field, P: arithmetic::PoseidonPermutation<F>> Len for T<F, P> {
    fn len() -> usize {
        P::T
    }
}

enum Mode<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> {
    Squeeze {
        values: Vec<Element<'dr, D>>,
        state: SpongeState<'dr, D, P>,
    },
    Absorb {
        values: Vec<Element<'dr, D>>,
        state: SpongeState<'dr, D, P>,
    },
}

/// The [Poseidon](https://eprint.iacr.org/2019/458) sponge function.
pub struct Sponge<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> {
    mode: Mode<'dr, D, P>,
    params: &'dr P,
}

impl<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> Buffer<'dr, D>
    for Sponge<'dr, D, P>
{
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        self.absorb(dr, value)
    }
}

impl<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> Sponge<'dr, D, P> {
    /// Initialize the sponge in absorb mode with a zero initial state.
    pub fn new(dr: &mut D, params: &'dr P) -> Self {
        Sponge {
            mode: Mode::Absorb {
                values: vec![],
                state: SpongeState {
                    values: vec![Element::zero(dr); P::T]
                        .try_into()
                        .expect("P::T is the state length"),
                },
            },
            params,
        }
    }

    /// Initialize the sponge in absorb mode with an initial state.
    pub fn new_with_state(params: &'dr P, initial_state: &[Element<'dr, D>]) -> Self {
        assert_eq!(
            initial_state.len(),
            P::T,
            "initial_state must have P::T elements"
        );
        Sponge {
            mode: Mode::Absorb {
                values: vec![],
                state: SpongeState {
                    values: initial_state
                        .to_vec()
                        .try_into()
                        .expect("P::T is the state length"),
                },
            },
            params,
        }
    }

    /// Run the permutation and return the full state.
    ///
    /// This is primarily for testing interoperability.
    pub fn permute_and_get_state(&mut self, dr: &mut D) -> Result<Vec<Element<'dr, D>>> {
        self.permute(dr)?;
        match &self.mode {
            Mode::Squeeze { state, .. } | Mode::Absorb { state, .. } => {
                Ok(state.values.clone().into_inner())
            }
        }
    }

    fn permute(&mut self, dr: &mut D) -> Result<()> {
        match &mut self.mode {
            Mode::Squeeze { values, state } => {
                *state = dr.routine(Permutation::from(self.params), state.clone())?;
                *values = state.get_rate();
            }
            Mode::Absorb { values, state } => {
                for (state, v) in state.values.iter_mut().zip(values.iter()) {
                    *state = state.add(dr, v);
                }
                values.clear();
                *state = dr.routine(Permutation::from(self.params), state.clone())?;
            }
        }

        Ok(())
    }

    /// Squeeze a value from the sponge.
    pub fn squeeze(&mut self, dr: &mut D) -> Result<Element<'dr, D>> {
        match &mut self.mode {
            Mode::Squeeze { values, .. } => {
                if values.is_empty() {
                    // Nothing to squeeze, we need to permute first
                    self.permute(dr)?;
                } else {
                    // Squeeze a value and return it
                    return Ok(values.pop().unwrap());
                }
            }
            Mode::Absorb { values, state } => {
                if values.is_empty() {
                    // Nothing was absorbed, so we can switch to squeeze mode
                    // with the same state.
                    self.mode = Mode::Squeeze {
                        values: state.get_rate(),
                        state: state.clone(),
                    };
                } else {
                    // Before we can switch to squeeze mode, we need to permute
                    self.permute(dr)?;
                }
            }
        }

        self.squeeze(dr)
    }

    /// Absorb a value into the sponge.
    pub fn absorb(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        match &mut self.mode {
            Mode::Squeeze { state, .. } => {
                // Switch to absorb mode with the same state
                self.mode = Mode::Absorb {
                    values: vec![],
                    state: state.clone(),
                };
            }
            Mode::Absorb { values, .. } => {
                if values.len() == P::RATE {
                    // We've absorbed too much, time to permute
                    self.permute(dr)?;
                } else {
                    // Directly absorb and complete
                    values.push(value.clone());
                    return Ok(());
                }
            }
        }

        // Second attempt, which always succeeds
        self.absorb(dr, value)
    }
}

#[derive(Gadget)]
pub struct SpongeState<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> {
    #[ragu(gadget)]
    values: FixedVec<Element<'dr, D>, T<D::F, P>>,
}

impl<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> SpongeState<'dr, D, P> {
    fn get_rate(&self) -> Vec<Element<'dr, D>> {
        let mut tmp = self.values.clone().into_inner();
        tmp.truncate(P::RATE);
        tmp.reverse();
        tmp
    }
}

fn sbox<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>>(
    dr: &mut D,
    input: &mut [Element<'dr, D>],
) -> Result<()> {
    for x in input {
        *x = match P::ALPHA {
            5 => x.square(dr)?.square(dr)?.mul(dr, x)?,
            _ => panic!("only alpha = 5 is supported in this implementation"),
        }
    }

    Ok(())
}

fn mds<'i, 'dr, D: Driver<'dr>>(
    dr: &mut D,
    state: &mut [Element<'dr, D>],
    matrix: impl ExactSizeIterator<Item = &'i [D::F]>,
) -> Result<()> {
    assert_eq!(state.len(), matrix.len());
    let tmp = state
        .iter()
        .zip(matrix)
        .map(|(_, coeffs)| multiadd(dr, state, coeffs))
        .collect::<Result<Vec<_>>>()?;
    state.clone_from_slice(&tmp[..]);

    Ok(())
}

fn add_round_constants<'dr, D: Driver<'dr>>(
    dr: &mut D,
    state: &mut [Element<'dr, D>],
    round_constants: &[D::F],
) {
    assert_eq!(state.len(), round_constants.len());
    for (x, c) in state.iter_mut().zip(round_constants) {
        *x = x.add_coeff(dr, &Element::one(), Coeff::Arbitrary(*c));
    }
}

struct Permutation<'a, F: Field, P: arithmetic::PoseidonPermutation<F>> {
    params: &'a P,
    _marker: PhantomData<F>,
}

impl<'a, F: Field, P: arithmetic::PoseidonPermutation<F>> From<&'a P> for Permutation<'a, F, P> {
    fn from(params: &'a P) -> Self {
        Permutation {
            params,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, P: arithmetic::PoseidonPermutation<F>> Clone for Permutation<'_, F, P> {
    fn clone(&self) -> Self {
        Permutation {
            params: self.params,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, P: arithmetic::PoseidonPermutation<F>> Routine<F> for Permutation<'_, F, P> {
    type Input = SpongeState<'static, PhantomData<F>, P>;
    type Output = SpongeState<'static, PhantomData<F>, P>;
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        mut state: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let mut rcs = self.params.round_constants();

        let mut round = |dr: &mut D, elems| {
            add_round_constants(dr, &mut state.values[..], rcs.next().unwrap());
            sbox::<_, P>(dr, &mut state.values[0..elems])?;
            mds(dr, &mut state.values[..], self.params.mds_matrix())?;

            Ok(())
        };

        for elems in core::iter::repeat_n(P::T, P::FULL_ROUNDS / 2)
            .chain(core::iter::repeat_n(1, P::PARTIAL_ROUNDS))
            .chain(core::iter::repeat_n(P::T, P::FULL_ROUNDS / 2))
        {
            round(dr, elems)?;
        }

        Ok(state)
    }

    /// Poseidon is not more efficient to predict than it is to directly
    /// execute.
    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: &<Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<
        Prediction<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>, DriverValue<D, Self::Aux<'dr>>>,
    > {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

#[test]
fn test_permutation_constraints() -> Result<()> {
    use arithmetic::Cycle;
    use ragu_pasta::{Fp, Pasta};

    type Simulator = crate::Simulator<Fp>;

    let params = Pasta::baked();

    let sim = Simulator::simulate(Fp::from(1), |dr, value| {
        let mut sponge =
            Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(dr, params.circuit_poseidon());
        let value = Element::alloc(dr, value)?;
        sponge.absorb(dr, &value)?;
        sponge.squeeze(dr)?;

        Ok(())
    })?;

    assert_eq!(sim.num_allocations(), 1);

    // This is failing because it's 288 for T = 5, not sure
    // what it should be for T = 3, and not important
    // for what we're testing right now.
    assert_eq!(sim.num_multiplications(), 288);

    Ok(())
}
