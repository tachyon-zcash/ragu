//! Streaming structural hash of the wiring polynomial $s(X, Y)$.
//!
//! This module provides [`eval`], which hashes the symbolic structure of a
//! circuit's wiring polynomial into a BLAKE2b state. Unlike the other `s/`
//! evaluators which compute polynomial values at specific points, this module
//! captures the polynomial's *identity* — which wires appear in each
//! constraint, with which scalar coefficients — for use in registry key
//! derivation.
//!
//! # Design
//!
//! The hasher driver assigns each wire a **symbolic identity** via
//! [`WireIndex`] (wire type + gate index) and hashes these identities
//! alongside their scalar coefficients.
//!
//! For each circuit synthesis, the hash captures:
//! - For each [`add()`](ragu_core::drivers::Driver::add): sentinel + virtual
//!   wire ID + collected `(wire_id, effective_coeff)` pairs
//! - For each [`enforce_zero()`](ragu_core::drivers::Driver::enforce_zero):
//!   sentinel + collected `(wire_id, effective_coeff)` pairs
//!
//! # Binding argument
//!
//! Each `(WireIndex, scalar)` pair uniquely identifies one monomial coefficient
//! of the constraint polynomial. Two circuits with distinct coefficient
//! matrices produce **distinct hash inputs** with certainty. Combined with
//! BLAKE2b collision resistance, the resulting key is unconditionally binding.
//!
//! [`WireIndex`]: super::common::WireIndex

use ff::PrimeField;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, LinearExpression, emulator::Emulator},
    gadgets::{Bound, GadgetKind},
    maybe::Empty,
    routines::Routine,
};
use ragu_primitives::GadgetExt;

use alloc::vec::Vec;
use core::marker::PhantomData;

// Re-export WireIndex and hashing helpers for use by other crate modules
// (e.g., staging/mask.rs).
pub(crate) use super::common::{WireIndex, hash_coeff, hash_wire_index};

use super::DriverExt;
use crate::{Circuit, FreshB, polynomials::Rank};

/// Sentinel byte for [`Driver::enforce_zero`] constraints.
pub(crate) const SENTINEL_ENFORCE: [u8; 1] = [0xEE];

/// Sentinel byte for [`Driver::add`] virtual wire definitions.
// Not used by hand-rolled implementations (StageMask has no `add` operations).
const SENTINEL_ADD: [u8; 1] = [0xAD];

/// Collects wire references and coefficients during synthesis for structural
/// hashing.
struct HashTerms<F: ff::Field> {
    terms: Vec<(WireIndex, Coeff<F>)>,
    gain: Coeff<F>,
}

impl<F: ff::Field> HashTerms<F> {
    fn new() -> Self {
        HashTerms {
            terms: Vec::new(),
            gain: Coeff::One,
        }
    }
}

impl<F: PrimeField> LinearExpression<WireIndex, F> for HashTerms<F> {
    fn add_term(mut self, wire: &WireIndex, coeff: Coeff<F>) -> Self {
        self.terms.push((*wire, coeff * self.gain));
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain = self.gain * coeff;
        self
    }
}

/// A [`Driver`] that hashes the structural identity of a circuit's wiring
/// polynomial into a BLAKE2b state.
///
/// Instead of evaluating the polynomial at any point, this driver captures
/// the symbolic wire identities and scalar coefficients that define the
/// polynomial's structure.
struct Hasher<'a, F, R> {
    /// Mutable reference to the running BLAKE2b hash state.
    state: &'a mut blake2b_simd::State,

    /// Number of multiplication gates consumed so far.
    multiplication_constraints: usize,

    /// Number of linear constraints processed so far.
    linear_constraints: usize,

    /// Counter for assigning virtual wire IDs.
    next_virtual_id: usize,

    /// Stashed $b$ wire from paired allocation.
    available_b: Option<WireIndex>,

    _marker: PhantomData<(F, R)>,
}

impl<F: PrimeField, R: Rank> FreshB<Option<WireIndex>> for Hasher<'_, F, R> {
    fn available_b(&mut self) -> &mut Option<WireIndex> {
        &mut self.available_b
    }
}

impl<F: PrimeField, R: Rank> DriverTypes for Hasher<'_, F, R> {
    type MaybeKind = Empty;
    type LCadd = HashTerms<F>;
    type LCenforce = HashTerms<F>;
    type ImplField = F;
    type ImplWire = WireIndex;
}

impl<'dr, F: PrimeField, R: Rank> Driver<'dr> for Hasher<'dr, F, R> {
    type F = F;
    type Wire = WireIndex;

    const ONE: Self::Wire = WireIndex::C(0);

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(wire) = self.available_b.take() {
            Ok(wire)
        } else {
            let (a, b, _) = self.mul(|| unreachable!())?;
            self.available_b = Some(b);
            Ok(a)
        }
    }

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let index = self.multiplication_constraints;
        if index == R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }
        self.multiplication_constraints += 1;

        Ok((
            WireIndex::A(index),
            WireIndex::B(index),
            WireIndex::C(index),
        ))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let terms = lc(HashTerms::new());
        let id = self.next_virtual_id;
        self.next_virtual_id += 1;

        // Hash: sentinel + virtual ID + terms
        self.state.update(&SENTINEL_ADD);
        self.state.update(&(id as u64).to_le_bytes());
        for (wire, coeff) in &terms.terms {
            hash_wire_index(self.state, wire);
            hash_coeff::<F>(self.state, coeff);
        }

        WireIndex::Virtual(id)
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let q = self.linear_constraints;
        if q == R::num_coeffs() {
            return Err(Error::LinearBoundExceeded(R::num_coeffs()));
        }
        self.linear_constraints += 1;

        let terms = lc(HashTerms::new());

        // Hash: sentinel + terms
        self.state.update(&SENTINEL_ENFORCE);
        for (wire, coeff) in &terms.terms {
            hash_wire_index(self.state, wire);
            hash_coeff::<F>(self.state, coeff);
        }

        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        self.with_fresh_b(|this| {
            let mut dummy = Emulator::wireless();
            let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
            let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
            routine.execute(this, input, aux)
        })
    }
}

/// Hashes the structural identity of a circuit's wiring polynomial into the
/// provided BLAKE2b state.
///
/// This function runs circuit synthesis with the [`Hasher`] driver, which
/// records wire identities and scalar coefficients rather than evaluating
/// the polynomial.
///
/// # Arguments
///
/// - `circuit`: The circuit whose structure to hash.
/// - `state`: The BLAKE2b state to hash into.
pub fn eval<F: PrimeField, C: Circuit<F>, R: Rank>(
    circuit: &C,
    state: &mut blake2b_simd::State,
) -> Result<()> {
    let mut hasher = Hasher::<F, R> {
        state,
        multiplication_constraints: 0,
        linear_constraints: 0,
        next_virtual_id: 0,
        available_b: None,
        _marker: PhantomData,
    };

    // NOTE: Unlike sx/sy/sxy, there is no key-wire mul() + enforce_registry_key()
    // prefix here. The registry key does not exist at derivation time and must be
    // excluded from the hash. Adding such a prefix would shift all gate indices
    // by one and produce a different (incorrect) digest.
    let mut outputs = Vec::new();
    let (io, _) = circuit.witness(&mut hasher, Empty)?;
    io.write(&mut hasher, &mut outputs)?;

    hasher.enforce_public_outputs(outputs.iter().map(|output| output.wire()))?;
    hasher.enforce_one()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use blake2b_simd::Params;
    use proptest::prelude::*;
    use ragu_pasta::Fp;

    use crate::{
        CircuitExt, CircuitObject,
        polynomials::{R, Rank},
        staging::mask::StageMask,
        tests::SquareCircuit,
    };

    type TestRank = R<8>;

    fn circuit_digest<C: crate::Circuit<Fp>>(circuit: &C) -> blake2b_simd::Hash {
        let mut state = Params::new().to_state();
        super::eval::<Fp, _, TestRank>(circuit, &mut state).unwrap();
        state.finalize()
    }

    fn object_digest(obj: &dyn CircuitObject<Fp, TestRank>) -> blake2b_simd::Hash {
        let mut state = Params::new().to_state();
        obj.hash(&mut state);
        state.finalize()
    }

    // --- Binding: equal circuits hash equally, distinct circuits hash distinctly ---

    proptest! {
        #[test]
        fn binding(i in 0usize..20, j in 0usize..20) {
            let a = circuit_digest(&SquareCircuit { times: i });
            let b = circuit_digest(&SquareCircuit { times: j });
            if i == j {
                prop_assert_eq!(a, b);
            } else {
                prop_assert_ne!(a, b);
            }
        }
    }

    // --- ProcessedCircuit hash matches hash::eval ---

    #[test]
    fn processed_circuit_matches_eval() {
        for times in [0, 1, 2, 5, 10] {
            let circuit = SquareCircuit { times };
            let object = circuit.into_object::<TestRank>().unwrap();
            assert_eq!(
                circuit_digest(&SquareCircuit { times }),
                object_digest(&*object),
                "mismatch for SquareCircuit {{ times: {} }}",
                times
            );
        }
    }

    // --- StageMask hand-rolled hash matches hash::eval ---

    #[test]
    fn stage_mask_handrolled_matches_driver() {
        for skip in 0..5 {
            for num in 0..(TestRank::n() - skip - 1) {
                let mask = StageMask::<TestRank>::new(skip, num).unwrap();
                assert_eq!(
                    circuit_digest(&mask),
                    object_digest(&mask),
                    "StageMask hash mismatch for skip={}, num={}",
                    skip,
                    num
                );
            }
        }
    }

    // --- StageMask binding ---

    proptest! {
        #[test]
        fn stage_mask_binding(
            s1 in 0..TestRank::n(), n1 in 0..TestRank::n(),
            s2 in 0..TestRank::n(), n2 in 0..TestRank::n(),
        ) {
            prop_assume!(s1 + n1 < TestRank::n());
            prop_assume!(s2 + n2 < TestRank::n());
            prop_assume!((s1, n1) != (s2, n2));
            // When num=0, all skip values produce identical constraints (every
            // non-ONE gate is constrained), so the hashes are legitimately equal.
            prop_assume!(n1 > 0 || n2 > 0);

            let a = object_digest(&StageMask::<TestRank>::new(s1, n1).unwrap());
            let b = object_digest(&StageMask::<TestRank>::new(s2, n2).unwrap());
            prop_assert_ne!(a, b);
        }
    }
}
