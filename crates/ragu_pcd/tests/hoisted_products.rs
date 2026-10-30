//! Check the product contracts at their owners, independently of walk traces.
//!
//! Corrupting a finished proof while retaining honest walk witnesses can be
//! rejected by the walk even if its product owner stops checking products.
//! Here only the owning circuit runs, with the reserved product wires changed
//! and all other stage values and instance values held fixed.

use ragu_circuits::{
    Circuit,
    polynomials::ProductionRank,
    staging::{stage_wire_indices, wires_of},
};
use ragu_core::{Result, pasta::Fp};
use ragu_primitives::{ENDOSCALAR_BITS, ENDOSCALAR_DIGITS, ENDOSCALAR_PRODUCTS};
use ragu_testing::patcher::{capture_with_stage_values, constraints_hold, playback, repair};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use crate::{
    fuzzing::patcher::{
        CircuitSpec, InternalCircuitVisitor, capture_internal_circuits,
        capture_internal_circuits_bootstrap,
    },
    internal::{endoscalar::EndoscalarStage, native::stages::points::WalkStage},
    profile::ProfiledCycle,
    proof::recursive_propagation_tests::support,
};

#[derive(Default)]
struct ProductOwners {
    native: usize,
    nested: usize,
}

/// A wrong `p` with `q = p * s` isolates the first product equation. A wrong
/// `q` with honest `p` isolates the second. Both mutations remain Boolean, so
/// a Booleanity check alone cannot make either negative control pass.
fn check_products<'w, F: Field, Cir: Circuit<F>>(
    name: &str,
    circuit: &Cir,
    stage_values: &[F],
    endoscalar: &[usize],
    make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
) -> Result<()> {
    assert_eq!(endoscalar.len(), ENDOSCALAR_BITS + ENDOSCALAR_PRODUCTS);
    let honest = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
    let rec = &honest.recorder;
    assert!(playback(circuit, make_witness()?, rec.values.clone())?);
    let mut fixed = honest.stage_wires.clone();
    fixed.extend(&honest.instance);

    for digit in 0..ENDOSCALAR_DIGITS {
        let s = stage_values[endoscalar[2 + 3 * digit]];
        let e1 = stage_values[endoscalar[3 + 3 * digit]];
        let e2 = stage_values[endoscalar[4 + 3 * digit]];
        let p = honest.stage_wires[endoscalar[ENDOSCALAR_BITS + 2 * digit]];
        let q = honest.stage_wires[endoscalar[ENDOSCALAR_BITS + 2 * digit + 1]];
        for bit in [s, e1, e2] {
            assert!(bit == F::ZERO || bit == F::ONE);
        }
        assert_eq!(rec.values[p], e1 * e2);
        assert_eq!(rec.values[q], e1 * e2 * s);

        for product in ["p", "q"] {
            let mut changed = rec.values.clone();
            if product == "p" {
                changed[p] = F::ONE - changed[p];
                changed[q] = changed[p] * s;
            } else {
                changed[q] = F::ONE - changed[q];
            }
            // Allow internal gate witnesses to follow the changed products,
            // including the p input and output of q's multiplication gate.
            // Hold every stage wire and instance wire at its chosen value.
            let committed = changed.clone();
            repair(&rec.events, &mut changed, &fixed);
            assert!(fixed.iter().all(|&wire| changed[wire] == committed[wire]));
            let recorded = constraints_hold(&rec.events, &changed);
            let replayed = playback(circuit, make_witness()?, changed)?;
            assert_eq!(
                recorded, replayed,
                "{name}: capture and playback must agree"
            );
            assert!(
                !replayed,
                "{name}: digit {digit}'s malformed {product} must be rejected by its owner",
            );
        }
    }
    Ok(())
}

impl<C: ProfiledCycle> InternalCircuitVisitor<C> for ProductOwners {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if spec.name == "bind_endoscalar" {
            let indices = stage_wire_indices::<
                C::CircuitField,
                ProductionRank,
                WalkStage<C::NestedCurve, C::Profile>,
            >(|walk| wires_of(&walk.endoscalar))?;
            check_products(&spec.name, circuit, stage_values, &indices, make_witness)?;
            self.native += 1;
        }
        Ok(())
    }

    fn visit_nested<'w, Cir: Circuit<C::ScalarField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::ScalarField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if spec.name == "nested_collapse" {
            let indices =
                stage_wire_indices::<C::ScalarField, ProductionRank, EndoscalarStage>(|endo| {
                    wires_of(&endo)
                })?;
            check_products(&spec.name, circuit, stage_values, &indices, make_witness)?;
            self.nested += 1;
        }
        Ok(())
    }
}

#[test]
fn product_owners_reject_malformed_hoisted_products() -> Result<()> {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(180897);
        let mut owners = ProductOwners::default();
        capture_internal_circuits_bootstrap(app, &mut rng, &mut owners)?;
        assert_eq!((owners.native, owners.nested), (1, 1));

        let (left, _) = app.seed(&mut rng, support::Seed::new(), Fp::from(42u64))?;
        let (right, _) = app.seed(&mut rng, support::Seed::new(), Fp::from(73u64))?;
        capture_internal_circuits(
            app,
            &mut rng,
            support::Merge::new(),
            Fp::from(19u64),
            left,
            right,
            &mut owners,
        )?;
        assert_eq!((owners.native, owners.nested), (2, 2));
        Ok(())
    })
}
