//! Poseidon sponge hash function implementation.
//!
//! This module provides [`Sponge`], an implementation of the
//! [Poseidon](https://eprint.iacr.org/2019/458) sponge construction for
//! in-circuit hashing.

use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Consistent, Gadget, GadgetKind},
    routines::{Prediction, Routine},
};

use alloc::{vec, vec::Vec};
use core::{marker::PhantomData, panic};

use crate::{
    Element,
    io::{Buffer, Write},
    multiadd,
    vec::{FixedVec, Len},
};

/// Error type for sponge save operations.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveError {
    /// Cannot save: sponge is already in squeeze mode.
    #[error("sponge is already in squeeze mode")]
    AlreadyInSqueezeMode,
    /// Cannot save: no values have been absorbed (permutation would not occur).
    #[error("no values have been absorbed")]
    NothingAbsorbed,
}

/// A type-level length marker for the Poseidon state size (`P::T`).
///
/// This type implements [`Len`] and is used to parameterize [`FixedVec`]
/// containers holding sponge state elements.
pub struct PoseidonStateLen<F: Field, P: arithmetic::PoseidonPermutation<F>>(PhantomData<(F, P)>);

impl<F: Field, P: arithmetic::PoseidonPermutation<F>> Len for PoseidonStateLen<F, P> {
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

impl<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> Clone for Mode<'dr, D, P> {
    fn clone(&self) -> Self {
        match self {
            Mode::Squeeze { values, state } => Mode::Squeeze {
                values: values.clone(),
                state: state.clone(),
            },
            Mode::Absorb { values, state } => Mode::Absorb {
                values: values.clone(),
                state: state.clone(),
            },
        }
    }
}

/// The [Poseidon](https://eprint.iacr.org/2019/458) sponge function.
pub struct Sponge<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> {
    mode: Mode<'dr, D, P>,
    params: &'dr P,
}

impl<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> Clone for Sponge<'dr, D, P> {
    fn clone(&self) -> Self {
        Sponge {
            mode: self.mode.clone(),
            params: self.params,
        }
    }
}

impl<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> Buffer<'dr, D>
    for Sponge<'dr, D, P>
{
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        self.absorb(dr, value)
    }
}

impl<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> Sponge<'dr, D, P> {
    /// Initialize the sponge in absorb mode with a fixed initial state.
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

    /// Save the internal [`SpongeState`].
    ///
    /// This method requires the [`Sponge`] to have absorbed elements that are
    /// still pending for permutation internally. This method will perform a
    /// permutation, consume the sponge, and return the raw [`SpongeState`].
    ///
    /// Later, the [`SpongeState`] can be used to resume squeezing via
    /// [`Self::resume_and_squeeze`].
    ///
    /// # Errors
    /// - [`SaveError::AlreadyInSqueezeMode`] if in the squeezing mode already
    /// - [`SaveError::NothingAbsorbed`] if no pending absorbed values are
    ///   present
    pub fn save_state(
        mut self,
        dr: &mut D,
    ) -> core::result::Result<SpongeState<'dr, D, P>, SaveError> {
        match &self.mode {
            Mode::Squeeze { .. } => Err(SaveError::AlreadyInSqueezeMode),
            Mode::Absorb { values, .. } => {
                if values.is_empty() {
                    Err(SaveError::NothingAbsorbed)
                } else {
                    // permute() absorbs pending values into state
                    self.permute(dr).expect("permutation should not fail");
                    // After permute in absorb mode, we're still in absorb mode with cleared buffer
                    match self.mode {
                        Mode::Absorb { state, .. } => Ok(state),
                        Mode::Squeeze { .. } => unreachable!(),
                    }
                }
            }
        }
    }

    /// Resume a [`Sponge`] from a saved [`SpongeState`] and immediately squeeze
    /// one value from the sponge.
    pub fn resume_and_squeeze(
        dr: &mut D,
        state: SpongeState<'dr, D, P>,
        params: &'dr P,
    ) -> Result<(Element<'dr, D>, Self)> {
        let mut sponge = Sponge {
            mode: Mode::Squeeze {
                values: state.get_rate(),
                state,
            },
            params,
        };
        // get_rate() returns rate elements, so squeeze won't need permutation
        let element = sponge.squeeze(dr)?;
        Ok((element, sponge))
    }
}

/// The raw state of a Poseidon sponge permutation.
///
/// This type holds `P::T` field elements representing the internal state
/// of the sponge. It can be used to save and resume sponge progress via
/// [`Sponge::save_state`] and [`Sponge::resume_and_squeeze`].
#[derive(Gadget, Write, Consistent)]
pub struct SpongeState<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> {
    #[ragu(gadget)]
    values: FixedVec<Element<'dr, D>, PoseidonStateLen<D::F, P>>,
}

impl<'dr, D: Driver<'dr>, P: arithmetic::PoseidonPermutation<D::F>> SpongeState<'dr, D, P> {
    /// Create a [`SpongeState`] from a [`FixedVec`] of [`Element`]s.
    ///
    /// The vector must have exactly `P::T` elements (enforced by the
    /// [`PoseidonStateLen`] type parameter).
    pub fn from_elements(values: FixedVec<Element<'dr, D>, PoseidonStateLen<D::F, P>>) -> Self {
        Self { values }
    }

    /// Consume this [`SpongeState`] and return the raw [`Element`]s.
    pub fn into_elements(self) -> FixedVec<Element<'dr, D>, PoseidonStateLen<D::F, P>> {
        self.values
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use arithmetic::Cycle;
    use ragu_core::maybe::Maybe;
    use ragu_pasta::{Fp, Pasta};

    type Simulator = crate::Simulator<Fp>;

    #[test]
    fn test_permutation_constraints() -> Result<()> {
        let params = Pasta::baked();

        let sim = Simulator::simulate(Fp::from(1), |dr, value| {
            let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            let value = Element::alloc(dr, value)?;
            sponge.absorb(dr, &value)?;
            sponge.squeeze(dr)?;

            Ok(())
        })?;

        assert_eq!(sim.num_allocations(), 1);
        assert_eq!(sim.num_multiplications(), 288);

        Ok(())
    }

    #[test]
    fn test_save_state_nothing_absorbed() -> Result<()> {
        let params = Pasta::baked();

        Simulator::simulate((), |dr, _| {
            let sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            // Try to save without absorbing anything
            let result = sponge.save_state(dr);
            assert!(matches!(result, Err(SaveError::NothingAbsorbed)));

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_save_state_already_in_squeeze_mode() -> Result<()> {
        let params = Pasta::baked();

        Simulator::simulate(Fp::from(1), |dr, value| {
            let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            let value = Element::alloc(dr, value)?;
            sponge.absorb(dr, &value)?;
            // Squeeze to enter squeeze mode
            sponge.squeeze(dr)?;
            // Now try to save - should fail
            let result = sponge.save_state(dr);
            assert!(matches!(result, Err(SaveError::AlreadyInSqueezeMode)));

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_save_state_succeeds_after_absorb() -> Result<()> {
        let params = Pasta::baked();

        Simulator::simulate(Fp::from(1), |dr, value| {
            let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            let value = Element::alloc(dr, value)?;
            sponge.absorb(dr, &value)?;
            // Save should succeed
            let _state = sponge.save_state(dr).expect("save_state should succeed");

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_resume_and_squeeze() -> Result<()> {
        let params = Pasta::baked();

        Simulator::simulate(Fp::from(42), |dr, value| {
            let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            let value = Element::alloc(dr, value)?;
            sponge.absorb(dr, &value)?;
            let state = sponge.save_state(dr).expect("save_state should succeed");

            // Resume and squeeze
            let (element, _sponge) =
                Sponge::resume_and_squeeze(dr, state, Pasta::circuit_poseidon(params))?;

            // Just verify we got an element (the actual value depends on Poseidon params)
            let _ = element.value().take();

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_save_resume_produces_same_output_as_normal_sponge() -> Result<()> {
        use core::cell::Cell;

        let params = Pasta::baked();

        // Use Cell to extract the output values from inside the closures
        let normal_output = Cell::new(Fp::ZERO);
        let save_resume_output = Cell::new(Fp::ZERO);

        // Run normal sponge flow and get squeezed value
        Simulator::simulate(Fp::from(123), |dr, value| {
            let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            let value = Element::alloc(dr, value)?;
            sponge.absorb(dr, &value)?;
            let squeezed = sponge.squeeze(dr)?;
            normal_output.set(*squeezed.value().take());
            Ok(())
        })?;

        // Run save/resume flow and get squeezed value
        Simulator::simulate(Fp::from(123), |dr, value| {
            let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            let value = Element::alloc(dr, value)?;
            sponge.absorb(dr, &value)?;
            let state = sponge.save_state(dr).expect("save_state should succeed");
            let (squeezed, _) =
                Sponge::resume_and_squeeze(dr, state, Pasta::circuit_poseidon(params))?;
            save_resume_output.set(*squeezed.value().take());
            Ok(())
        })?;

        // Both should produce identical output
        assert_eq!(normal_output.get(), save_resume_output.get());

        Ok(())
    }
}
