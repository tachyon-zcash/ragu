//! Layer 5: a generated program as a registerable [`Circuit`], plus the
//! satisfying-witness steering that constraint-level oracles rely on.
//!
//! [`ProgramCircuit`] splits a [`Program`] into circuit *structure* (the
//! ops, the constant preamble slots, the anchor constants) and circuit
//! *witness* (the values of the witness-allocated preamble slots). The same
//! registered circuit can therefore be traced with an honest witness
//! ([`Preamble::values`]) or a mutated one — the registry tag, floor
//! plan, and `ky` stay fixed, which is what the constraint-identity oracles
//! (`fuzz_circuit_cheat`, `fuzz_witness_pinning`) require.
//!
//! [`steer`] is the satisfying-witness mode: it rewrites a program so that
//! its *honest* evaluation never hits a value-dependent skip (inverting
//! zero, dividing by zero, non-canonical raw bytes), replacing each
//! would-skip op with an infallible op of the same stack arity. Steered
//! programs have value-independent stack progression for the honest
//! witness, so shadow slots, synthesis wires, and trace gates line up.
//!
//! [`Preamble::values`]: super::Preamble::values

use ff::PrimeField;
use ragu_circuits::{Circuit, WithAux};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
};
use ragu_primitives::allocator::Standard;

use super::{
    AdviceSlot, Capabilities, Op, Overrides, Preamble, Program, shadow_eval,
    synthesize_with_witness,
};

/// A generated program as a [`Circuit`].
///
/// The witness is the array of preamble values; constant preamble slots
/// ignore it (their values are circuit structure). Anchor constants are
/// typically the honest shadow's anchor observations, making the honest
/// witness satisfying by construction for steered programs.
///
/// Registering a large program can exceed the rank's gate budget; consumers
/// should treat registry-construction failure as a skip, as the historical
/// `fuzz_circuit_cheat` does.
#[derive(Clone, Copy)]
pub struct ProgramCircuit<'a, F> {
    /// The program to synthesize.
    pub program: &'a Program,
    /// Pinned constant for each [`Op::Anchor`], in encounter order.
    pub anchors: &'a [F],
}

impl<'a, F: PrimeField<Repr = [u8; 32]>> Circuit<F> for ProgramCircuit<'a, F> {
    type Instance<'instance> = ();
    type Output = Kind![F; ()];
    type Witness<'witness> = [F; Preamble::LEN];
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Ok(())
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>>
    where
        Self: 'dr,
    {
        synthesize_with_witness(
            dr,
            &mut Standard::new(),
            self.program,
            witness,
            self.anchors,
        )?;
        Ok(WithAux::new((), D::unit()))
    }
}

/// Rewrites `program` so its honest evaluation never hits a value-dependent
/// skip: each [`Op::Invert`] of zero, [`Op::Divide`] by zero, or
/// non-canonical [`Op::AllocRaw`] is replaced by an infallible op pushing
/// the same number of elements ([`Op::Double`], [`Op::Add`], and
/// [`Op::AllocSpecial`] respectively).
///
/// After steering, the honest run executes every op, so stack progression
/// is determined by the ops alone. Note the guarantee is for the *honest*
/// witness only: a mutated witness or advice override can still drive a
/// divisor to zero. Consumers that need progression stability across
/// overridden runs should additionally mask
/// [`Capabilities::VALUE_FALLIBLE`] out of their vocabulary.
pub fn steer<F: PrimeField<Repr = [u8; 32]>>(program: &Program) -> Program {
    let mut steered = Program {
        preamble: program.preamble.clone(),
        ops: Vec::new(),
    };
    for op in &program.ops {
        let mut chosen = *op;
        if op
            .kind()
            .capabilities()
            .contains(Capabilities::VALUE_FALLIBLE)
        {
            let before = shadow_eval::<F>(&steered, Overrides::none()).elems.len();
            let mut probe = steered.clone();
            probe.ops.push(*op);
            let after = shadow_eval::<F>(&probe, Overrides::none()).elems.len();
            if after == before {
                chosen = match *op {
                    Op::Invert(a) => Op::Double(a),
                    Op::Divide(a, b) => Op::Add(a, b),
                    Op::AllocRaw(bytes) => Op::AllocSpecial(bytes[0]),
                    _ => unreachable!("only Invert/Divide/AllocRaw are value-fallible"),
                };
            }
        }
        steered.ops.push(chosen);
    }
    steered
}

/// Appends an [`Op::Anchor`] for every *derived* element-stack slot the
/// honest run leaves live, maximizing the observability of the
/// constraint-level oracles: a cheat that propagates anywhere is caught by
/// some anchor, instead of relying on the random program having placed one
/// downstream.
///
/// Advice slots are deliberately **not** anchored: pinning an advice wire
/// to its honest value makes every cheat on it trivially rejected at the
/// pin itself, so ragu and the native oracle agree before the cheat ever
/// reaches the gadget under test — masking downstream bugs rather than
/// exposing them.
pub fn anchor_tail<F: PrimeField<Repr = [u8; 32]>>(program: &Program) -> Program {
    let shadow = shadow_eval::<F>(program, Overrides::none());
    let advice: Vec<usize> = shadow
        .advice
        .iter()
        .filter_map(|a| match a {
            AdviceSlot::Elem(i) => Some(*i),
            _ => None,
        })
        .collect();
    let mut anchored = program.clone();
    for slot in 0..shadow.elems.len().min(u8::MAX as usize + 1) {
        if !advice.contains(&slot) {
            anchored.ops.push(Op::Anchor(slot as u8));
        }
    }
    anchored
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use proptest::prelude::*;
    use ragu_circuits::{CircuitExt, polynomials::TestRank, registry::RegistryBuilder};
    use ragu_pasta::Fp;

    use super::{
        super::{Limits, OpSet, program_strategy},
        *,
    };

    fn test_preamble() -> Preamble {
        Preamble {
            seeds: [3, 5, 7, 11],
            large_seeds: [[1, 2, 3, 4], [5, 6, 7, 8]],
            special_seeds: [1, 11],
            constant_mask: 0b0000_0101,
        }
    }

    /// Number of element pushes each op performs when nothing skips,
    /// tracking the boolean stack for the structurally guarded ops.
    fn expected_elem_len(program: &Program) -> usize {
        let mut elen = Preamble::LEN;
        let mut blen = 0usize;
        for op in &program.ops {
            match op {
                Op::Add(..)
                | Op::Sub(..)
                | Op::Mul(..)
                | Op::Square(..)
                | Op::Double(..)
                | Op::Negate(..)
                | Op::Invert(..)
                | Op::Divide(..)
                | Op::Scale(..)
                | Op::Fold(..)
                | Op::AllocConst(..)
                | Op::AllocSpecial(..)
                | Op::AllocRaw(..) => elen += 1,
                Op::AllocSquare(..) => elen += 2,
                Op::IsZero(..) | Op::BoolAlloc(..) => blen += 1,
                Op::BoolNot(..) | Op::BoolAnd(..) => {
                    if blen > 0 {
                        blen += 1;
                    }
                }
                Op::ConditionalSelect(..) => {
                    if blen > 0 {
                        elen += 1;
                    }
                }
                Op::Anchor(..) => {}
            }
        }
        elen
    }

    /// Steering replaces exactly the would-skip ops, preserving arity.
    #[test]
    fn steer_substitutes_would_skip_ops() {
        let program = Program {
            preamble: test_preamble(),
            ops: vec![
                Op::Sub(0, 0),            // slot 8 = 0
                Op::Invert(8),            // would skip: inverting zero
                Op::Divide(1, 8),         // would skip: dividing by zero
                Op::AllocRaw([0xff; 32]), // would skip: non-canonical
                Op::Invert(1),            // fine: 5 is invertible
            ],
        };
        let steered = steer::<Fp>(&program);
        assert_eq!(
            steered.ops,
            vec![
                Op::Sub(0, 0),
                Op::Double(8),
                Op::Add(1, 8),
                Op::AllocSpecial(0xff),
                Op::Invert(1),
            ],
        );
    }

    proptest! {
        /// After steering, the honest shadow executes every op: the element
        /// stack length matches the no-skip arity count.
        #[test]
        fn proptest_steered_programs_never_skip(
            program in program_strategy(OpSet::ALL, Limits::default().max_ops),
        ) {
            let steered = steer::<Fp>(&program);
            let shadow = shadow_eval::<Fp>(&steered, Overrides::none());
            prop_assert_eq!(shadow.elems.len(), expected_elem_len(&steered));
        }

        /// Steered generated programs register, trace with the honest
        /// witness, and assemble — or are skipped for rank overflow, never
        /// panicking.
        #[test]
        fn proptest_program_circuit_traces(
            program in program_strategy(OpSet::ALL, Limits::default().max_ops),
        ) {
            let steered = steer::<Fp>(&program);
            let honest = shadow_eval::<Fp>(&steered, Overrides::none());
            let circuit = ProgramCircuit {
                program: &steered,
                anchors: &honest.anchors,
            };
            let registry = RegistryBuilder::<Fp, TestRank>::new()
                .register_circuit(circuit)
                .and_then(|b| b.finalize());
            if let Ok(registry) = registry {
                let trace = circuit
                    .trace(steered.preamble.values())
                    .expect("honest witness must trace")
                    .into_output();
                registry
                    .assemble_with_alpha(
                        &trace,
                        ragu_circuits::registry::CircuitIndex::new(0),
                        Fp::ZERO,
                    )
                    .expect("honest trace must assemble");
            }
        }
    }
}
