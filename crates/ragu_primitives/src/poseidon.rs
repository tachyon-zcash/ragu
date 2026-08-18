//! Poseidon sponge hash function implementation.
//!
//! This module provides [`Sponge`], an implementation of the
//! [Poseidon](https://eprint.iacr.org/2019/458) sponge construction for
//! in-circuit hashing.

use alloc::{vec, vec::Vec};
use core::{marker::PhantomData, panic};

use ragu_arithmetic::{Coeff, ff::Field};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget},
    maybe::Maybe,
    routines::{Prediction, Routine},
};

use crate::{
    Element,
    comparison::GadgetEquals,
    consistent::Consistent,
    io::{Buffer, Write},
    multiadd,
    vec::{FixedVec, Len},
};

/// Error type for sponge save operations.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SaveError {
    /// Cannot save: sponge is already in squeeze mode.
    #[error("sponge is already in squeeze mode")]
    AlreadyInSqueezeMode,
    /// Cannot save: no values have been absorbed (permutation would not occur).
    #[error("no values have been absorbed")]
    NothingAbsorbed,
}

/// Internal adapter for supplying native Poseidon results to Ragu's routine
/// prediction machinery.
///
/// This is not a backend interface. Backends implement
/// `ragu_backend::Backend::poseidon_permute`; Ragu decides when to use that
/// operation for witness prediction. The circuit implementation remains
/// canonical and is always used by drivers that emit or check constraints.
#[doc(hidden)]
pub trait PoseidonPrediction: Send + 'static {
    /// Whether native prediction is enabled for this implementation.
    const ENABLED: bool;

    /// Applies the native permutation to `state`.
    fn permute<F: Field, P: ragu_arithmetic::PoseidonPermutation<F>>(params: &P, state: &mut [F]) {
        ragu_arithmetic::poseidon_permute(params, state);
    }
}

/// Disables native Poseidon prediction and retains circuit execution.
#[doc(hidden)]
pub struct NoPoseidonPrediction;

impl PoseidonPrediction for NoPoseidonPrediction {
    const ENABLED: bool = false;
}

/// A type-level length marker for the Poseidon state size (`P::T`).
///
/// This type implements [`Len`] and is used to parameterize [`FixedVec`]
/// containers holding sponge state elements.
pub struct PoseidonStateLen<F: Field, P: ragu_arithmetic::PoseidonPermutation<F>>(
    PhantomData<(F, P)>,
);

impl<F: Field, P: ragu_arithmetic::PoseidonPermutation<F>> Len for PoseidonStateLen<F, P> {
    fn len() -> usize {
        P::T
    }
}

enum Mode<'dr, D: Driver<'dr>, P: ragu_arithmetic::PoseidonPermutation<D::F>> {
    Squeeze {
        values: Vec<Element<'dr, D>>,
        state: SpongeState<'dr, D, P>,
    },
    Absorb {
        values: Vec<Element<'dr, D>>,
        state: SpongeState<'dr, D, P>,
    },
}

impl<'dr, D: Driver<'dr>, P: ragu_arithmetic::PoseidonPermutation<D::F>> Clone for Mode<'dr, D, P> {
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
///
/// Intended for fixed-length inputs only. The sponge never records how many
/// elements it absorbed, so absorbing a trailing zero looks identical to
/// absorbing nothing: feeding it `[x]` and `[x, 0]` produces the same output.
/// Only use it where the number of absorbed elements is fixed by the protocol;
/// to absorb variable-length data, absorb its length first.
pub struct Sponge<
    'dr,
    D: Driver<'dr>,
    P: ragu_arithmetic::PoseidonPermutation<D::F>,
    N: PoseidonPrediction = NoPoseidonPrediction,
> {
    mode: Mode<'dr, D, P>,
    params: &'dr P,
    _native: PhantomData<N>,
}

impl<'dr, D: Driver<'dr>, P: ragu_arithmetic::PoseidonPermutation<D::F>, N: PoseidonPrediction>
    Clone for Sponge<'dr, D, P, N>
{
    fn clone(&self) -> Self {
        Sponge {
            mode: self.mode.clone(),
            params: self.params,
            _native: PhantomData,
        }
    }
}

impl<'dr, D: Driver<'dr>, P: ragu_arithmetic::PoseidonPermutation<D::F>, N: PoseidonPrediction>
    Buffer<'dr, D> for Sponge<'dr, D, P, N>
{
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        self.absorb(dr, value)
    }
}

impl<'dr, D: Driver<'dr>, P: ragu_arithmetic::PoseidonPermutation<D::F>, N: PoseidonPrediction>
    Sponge<'dr, D, P, N>
{
    /// Initializes a sponge that uses Ragu's internal `N` adapter for optional
    /// native prediction.
    #[doc(hidden)]
    pub fn new_with_prediction(dr: &mut D, params: &'dr P) -> Self {
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
            _native: PhantomData,
        }
    }

    fn permute(&mut self, dr: &mut D) -> Result<()> {
        match &mut self.mode {
            Mode::Squeeze { values, state } => {
                *state = dr.routine(Permutation::<D::F, P, N>::from(self.params), state.clone())?;
                *values = state.get_rate();
            }
            Mode::Absorb { values, state } => {
                for (state, v) in state.values.iter_mut().zip(values.iter()) {
                    *state = state.add(dr, v);
                }
                values.clear();
                *state = dr.routine(Permutation::<D::F, P, N>::from(self.params), state.clone())?;
            }
        }

        Ok(())
    }

    /// Get the current pending values in the sponge.
    #[inline(always)]
    fn values(&self) -> &[Element<'dr, D>] {
        match &self.mode {
            Mode::Squeeze { values, .. } => values,
            Mode::Absorb { values, .. } => values,
        }
    }

    /// Get the current internal state of the sponge.
    #[inline(always)]
    fn state(&self) -> &SpongeState<'dr, D, P> {
        match &self.mode {
            Mode::Squeeze { state, .. } => state,
            Mode::Absorb { state, .. } => state,
        }
    }

    /// Squeeze a value from the sponge.
    ///
    /// # Errors
    ///
    /// Returns [`ragu_core::Error::Initialization`] if no values have been
    /// absorbed yet, or any synthesis error from the internal permutation.
    pub fn squeeze(&mut self, dr: &mut D) -> Result<Element<'dr, D>> {
        match &mut self.mode {
            Mode::Squeeze { values, .. } => {
                if values.is_empty() {
                    // Nothing to squeeze, we need to permute first
                    self.permute(dr)?;
                } else {
                    // Squeeze a value and return it
                    return Ok(values.pop().expect("values is not empty, so pop succeeds"));
                }
            }
            Mode::Absorb { values, .. } => {
                if values.is_empty() {
                    return Err(ragu_core::Error::Initialization(
                        "cannot squeeze from empty sponge: no values absorbed".into(),
                    ));
                } else {
                    // Before we can switch to squeeze mode, we need to permute
                    // to absorb the pending values into the state.
                    self.permute(dr)?;

                    // This is the same state boundary that save_state/resume
                    // operates on: save_state permutes pending values, then
                    // resume enters squeeze mode with rate values extracted
                    // from the post-permutation state.
                    let state = self.state();
                    self.mode = Mode::Squeeze {
                        values: state.get_rate(),
                        state: state.clone(),
                    };
                }
            }
        }

        self.squeeze(dr)
    }

    /// Absorb a value into the sponge.
    ///
    /// # Errors
    ///
    /// Propagates any synthesis error from the internal permutation needed
    /// when the absorb buffer is full or when switching out of squeeze mode.
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
        self.absorb(dr, value)?;
        assert!(
            !self.values().is_empty(),
            "Post condition: values should never be empty after absorb"
        );
        Ok(())
    }

    /// Save the internal [`SpongeState`].
    ///
    /// This method requires the [`Sponge`] to have absorbed elements that are
    /// still pending for permutation internally. This method will perform a
    /// permutation, consume the sponge, and return the raw [`SpongeState`].
    ///
    /// Later, the [`SpongeState`] can be passed to `Transcript::resume_from_state`
    /// to continue the protocol.
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
                    // Post condition of absorb is that values is never empty,
                    // so empty values implies that nothing was absorbed.
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

    /// Resumes a [`Sponge`] from a saved [`SpongeState`].
    ///
    /// This method allows resuming a sponge and then performing custom operations
    /// before squeezing. Used by the `Transcript` API.
    #[doc(hidden)]
    pub fn resume_with_prediction(state: SpongeState<'dr, D, P>, params: &'dr P) -> Self {
        Sponge {
            mode: Mode::Squeeze {
                values: state.get_rate(),
                state,
            },
            params,
            _native: PhantomData,
        }
    }
}

impl<'dr, D: Driver<'dr>, P: ragu_arithmetic::PoseidonPermutation<D::F>>
    Sponge<'dr, D, P, NoPoseidonPrediction>
{
    /// Initialize the sponge in absorb mode with a fixed initial state.
    pub fn new(dr: &mut D, params: &'dr P) -> Self {
        Self::new_with_prediction(dr, params)
    }

    /// Resumes a [`Sponge`] from a saved [`SpongeState`].
    pub fn resume(state: SpongeState<'dr, D, P>, params: &'dr P) -> Self {
        Self::resume_with_prediction(state, params)
    }
}

/// The raw state of a Poseidon sponge permutation.
///
/// This type holds `P::T` field elements representing the internal state
/// of the sponge. It can be used to save and resume sponge progress via
/// [`Sponge::save_state`] and [`Sponge::resume`], or passed to
/// `Transcript::resume_from_state`.
#[derive(Gadget, Write, Consistent, GadgetEquals)]
pub struct SpongeState<'dr, D: Driver<'dr>, P: ragu_arithmetic::PoseidonPermutation<D::F>> {
    #[ragu(gadget)]
    values: FixedVec<Element<'dr, D>, PoseidonStateLen<D::F, P>>,
}

impl<'dr, D: Driver<'dr>, P: ragu_arithmetic::PoseidonPermutation<D::F>> SpongeState<'dr, D, P> {
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
        self.values.iter().take(P::RATE).cloned().rev().collect()
    }
}

fn sbox<'dr, D: Driver<'dr>, P: ragu_arithmetic::PoseidonPermutation<D::F>>(
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
    scratch: &mut Vec<Element<'dr, D>>,
) -> Result<()> {
    assert_eq!(state.len(), matrix.len());
    scratch.clear();
    scratch.extend(
        state
            .iter()
            .zip(matrix)
            .map(|(_, coeffs)| multiadd(dr, state, coeffs)),
    );
    state.clone_from_slice(&scratch[..]);

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

struct Permutation<'a, F: Field, P: ragu_arithmetic::PoseidonPermutation<F>, N: PoseidonPrediction>
{
    params: &'a P,
    _marker: PhantomData<(F, N)>,
}

impl<'a, F: Field, P: ragu_arithmetic::PoseidonPermutation<F>, N: PoseidonPrediction> From<&'a P>
    for Permutation<'a, F, P, N>
{
    fn from(params: &'a P) -> Self {
        Permutation {
            params,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, P: ragu_arithmetic::PoseidonPermutation<F>, N: PoseidonPrediction> Clone
    for Permutation<'_, F, P, N>
{
    fn clone(&self) -> Self {
        Permutation {
            params: self.params,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, P: ragu_arithmetic::PoseidonPermutation<F>, N: PoseidonPrediction> Routine<F>
    for Permutation<'_, F, P, N>
{
    type Input = SpongeState<'static, PhantomData<F>, P>;
    type Output = SpongeState<'static, PhantomData<F>, P>;
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        mut state: Bound<'dr, D, Self::Input>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let mut rcs = self.params.round_constants();
        let mut mds_scratch = Vec::with_capacity(P::T);

        let mut round = |dr: &mut D, elems| {
            add_round_constants(
                dr,
                &mut state.values[..],
                rcs.next().expect("round constants match total round count"),
            );
            sbox::<_, P>(dr, &mut state.values[0..elems])?;
            mds(
                dr,
                &mut state.values[..],
                self.params.mds_matrix(),
                &mut mds_scratch,
            )?;

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

    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        if !N::ENABLED {
            return Ok(Prediction::Unknown(D::unit()));
        }

        let values = D::just(|| {
            let mut values = input
                .values
                .iter()
                .map(|element| *element.value().take())
                .collect::<Vec<_>>();
            N::permute(self.params, &mut values);
            values
        });
        let values = FixedVec::try_from_fn(|index| {
            Element::alloc(dr, &mut (), values.clone().map(|values| values[index]))
        })?;

        Ok(Prediction::Known(SpongeState { values }, D::unit()))
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use ragu_arithmetic::{Cycle, PoseidonPermutation};
    use ragu_core::maybe::Maybe;
    use ragu_pasta::{Fp, Pasta};

    use super::*;

    type Simulator = crate::Simulator<Fp>;
    use crate::allocator::Standard;

    #[test]
    fn test_permutation_constraints() -> Result<()> {
        let params = Pasta::baked();

        let sim = Simulator::simulate(Fp::from(1), |dr, value| {
            let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            let allocator = &mut Standard::new();
            let value = Element::alloc(dr, allocator, value)?;
            sponge.absorb(dr, &value)?;

            dr.reset();
            sponge.squeeze(dr)?;

            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 288);

        Ok(())
    }

    #[test]
    fn native_permutation_matches_circuit_permutation() -> Result<()> {
        type P = <Pasta as Cycle>::CircuitPoseidon;

        let params = Pasta::baked();
        let poseidon = Pasta::circuit_poseidon(params);
        let mut expected = (1..=P::T)
            .map(|value| Fp::from(value as u64))
            .collect::<Vec<_>>();
        ragu_arithmetic::poseidon_permute(poseidon, &mut expected);

        let mut dr = Simulator::new();
        let state = SpongeState::<_, P>::from_elements(FixedVec::from_fn(|index| {
            Element::constant(&mut dr, Fp::from(index as u64 + 1))
        }));
        let actual = dr.routine(
            Permutation::<Fp, P, NoPoseidonPrediction>::from(poseidon),
            state,
        )?;

        assert_eq!(
            actual
                .values
                .iter()
                .map(|element| *element.value().take())
                .collect::<Vec<_>>(),
            expected,
        );

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
    fn test_squeeze_before_any_absorb() -> Result<()> {
        let params = Pasta::baked();
        let mut dr = Simulator::new();
        let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
            &mut dr,
            Pasta::circuit_poseidon(params),
        );

        // Squeeze without absorbing anything should fail
        assert!(sponge.squeeze(&mut dr).is_err());
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
            let allocator = &mut Standard::new();
            let value = Element::alloc(dr, allocator, value)?;
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
            let allocator = &mut Standard::new();
            let value = Element::alloc(dr, allocator, value)?;
            sponge.absorb(dr, &value)?;
            // Save should succeed
            let _state = sponge.save_state(dr).expect("save_state should succeed");

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_save_resume_produces_same_output_as_normal_sponge() -> Result<()> {
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
            let allocator = &mut Standard::new();
            let value = Element::alloc(dr, allocator, value)?;
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
            let allocator = &mut Standard::new();
            let value = Element::alloc(dr, allocator, value)?;
            sponge.absorb(dr, &value)?;
            let state = sponge.save_state(dr).expect("save_state should succeed");
            let mut sponge = Sponge::resume(state, Pasta::circuit_poseidon(params));
            let squeezed = sponge.squeeze(dr)?;
            save_resume_output.set(*squeezed.value().take());
            Ok(())
        })?;

        // Both should produce identical output
        assert_eq!(normal_output.get(), save_resume_output.get());

        Ok(())
    }

    #[test]
    // Misuse: forgetting to squeeze after resuming put sponge in a bad state.
    fn test_absorb_before_squeeze_after_resume() -> Result<()> {
        let params = Pasta::baked();

        let normal_output = Cell::new(Fp::ZERO);
        let bad_resume_output = Cell::new(Fp::ZERO);

        let witness = (Fp::from(1), Fp::from(2));

        // Normal flow: absorb v1, absorb v2, squeeze
        Simulator::simulate(witness, |dr, v| {
            let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            let (v1, v2) = v.cast();
            let allocator = &mut Standard::new();
            let v1 = Element::alloc(dr, allocator, v1)?;
            let v2 = Element::alloc(dr, allocator, v2)?;
            sponge.absorb(dr, &v1)?;
            sponge.absorb(dr, &v2)?;
            let squeezed = sponge.squeeze(dr)?;
            normal_output.set(*squeezed.value().take());
            Ok(())
        })?;

        // Wrong flow: absorb v1, save, resume, absorb v2 (without squeezing first), squeeze.
        // On resume the sponge enters squeeze mode; absorbing without squeezing first
        // switches back to absorb mode mid-stream, producing a different state than
        // the continuous absorb path above.
        Simulator::simulate(witness, |dr, v| {
            let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            let (v1, v2) = v.cast();
            let allocator = &mut Standard::new();
            let v1 = Element::alloc(dr, allocator, v1)?;
            let v2 = Element::alloc(dr, allocator, v2)?;
            sponge.absorb(dr, &v1)?;
            let state = sponge.save_state(dr).expect("save_state should succeed");
            let mut sponge = Sponge::resume(state, Pasta::circuit_poseidon(params));

            // Misuse: absorb before squeezing corrupts the transcript
            sponge.absorb(dr, &v2)?;
            let squeezed = sponge.squeeze(dr)?;
            bad_resume_output.set(*squeezed.value().take());
            Ok(())
        })?;

        // The misuse produces a different hash, demonstrating the bad state.
        assert_ne!(normal_output.get(), bad_resume_output.get());

        Ok(())
    }
}
