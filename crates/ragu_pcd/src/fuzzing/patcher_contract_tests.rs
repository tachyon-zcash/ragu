//! V03/V04: isolate membership and Booleanity from routing and arithmetic.
//!
//! Every directly equal wire follows an edit; all other stage/instance wires
//! stay pinned. Point edits also preserve the independent R05 Loading routes.
//! Repair runs with only the named contract equations removed. The resulting
//! candidate must satisfy every remaining event, then reject in the complete
//! graph and live circuit. This supplies a satisfying local cut control, not
//! an inference from unsuccessful repair or a recursive forgery.
//!
//! Native bit pairs preserve the canonical source's recomposition. Nested
//! pairs preserve their contribution to beta's lift; ComputeV must accept
//! those same stage edits, whereas Export owns and rejects their Booleanity.
//! Calibration: temporarily omit Point::alloc's curve equation, or
//! Boolean::alloc's complement equation, keeping all allocation/copy gates.
//! The corresponding production circuit must then accept the bad candidate.

use alloc::collections::BTreeSet;

use ragu_arithmetic::{CurveAffine, ff::WithSmallOrderMulGroup};
use ragu_testing::patcher::{Capture, Event};

use super::*;

type Leaf = HeaderStep<(), (), ApplicationHeader, 0>;
type Both = HeaderStep<ApplicationHeader, ApplicationHeader, ApplicationHeader, 1>;

/// Equivalence classes of explicit copies, never equal-valued honest wires.
struct Copies(Vec<usize>);

impl Copies {
    fn new<F: Field>(cap: &Capture<F>) -> Self {
        let mut copies = Self((0..cap.recorder.values.len()).collect());
        for event in &cap.recorder.events {
            match event {
                Event::Enforce { terms } if terms.len() == 2 => {
                    let [(a, ca), (b, cb)] = terms[..] else {
                        unreachable!()
                    };
                    if ca != F::ZERO && ca == -cb {
                        copies.join(a, b);
                    }
                }
                Event::Lin { out, terms } if terms.len() == 1 && terms[0].1 == F::ONE => {
                    copies.join(*out, terms[0].0);
                }
                _ => {}
            }
        }
        copies
    }

    fn root(&self, mut wire: usize) -> usize {
        while self.0[wire] != wire {
            wire = self.0[wire];
        }
        wire
    }

    fn join(&mut self, a: usize, b: usize) {
        let (a, b) = (self.root(a), self.root(b));
        self.0[b] = a;
    }

    fn same(&self, a: usize, b: usize) -> bool {
        self.root(a) == self.root(b)
    }
}

fn candidate<F: Field>(
    cap: &Capture<F>,
    copies: &Copies,
    edits: &[(usize, F)],
    cuts: &BTreeSet<usize>,
    context: &str,
) -> Vec<F> {
    let mut values = cap.recorder.values.clone();
    let mut pins: BTreeSet<_> = cap
        .instance
        .iter()
        .chain(&cap.stage_wires)
        .copied()
        .collect();
    let mut changed = BTreeSet::new();
    for &(wire, value) in edits {
        assert_ne!(value, values[wire], "{context}: nonzero edit");
        assert!(!copies.same(wire, 0), "{context}: constants are frozen");
        for (w, assigned) in values.iter_mut().enumerate() {
            if copies.same(wire, w) {
                assert!(changed.insert(w), "{context}: disjoint copy classes");
                *assigned = value;
                pins.insert(w);
            }
        }
    }
    let before = values.clone();
    let remaining: Vec<_> = cap
        .recorder
        .events
        .iter()
        .enumerate()
        .filter(|(i, _)| !cuts.contains(i))
        .map(|(_, event)| event.clone())
        .collect();
    repair(
        &remaining,
        &mut values,
        &pins.iter().copied().collect::<Vec<_>>(),
    );
    for pin in pins {
        assert_eq!(values[pin], before[pin], "{context}: pin {pin}");
    }
    assert!(
        constraints_hold(&remaining, &values),
        "{context}: exact satisfying cut control"
    );
    for w in 0..values.len() {
        assert_eq!(values[w], values[copies.root(w)], "{context}: copy {w}");
    }
    values
}

fn check_live<'w, F: Field, Cir: Circuit<F>>(
    cap: &Capture<F>,
    circuit: &Cir,
    make_witness: &impl Fn() -> Result<Cir::Witness<'w>>,
    values: Vec<F>,
    accepts: bool,
    context: &str,
) -> Result<()> {
    let recorded = constraints_hold(&cap.recorder.events, &values);
    let live = playback(circuit, make_witness()?, values)?;
    assert_eq!(recorded, live, "{context}: exact/live agreement");
    assert_eq!(live, accepts, "{context}: contract verdict");
    Ok(())
}

/// Identify the membership equation from its y-square gate and constant b.
/// Copy constraints, square/cube gates, and all other contracts remain live.
fn membership_cuts<F: Field>(cap: &Capture<F>, copies: &Copies, y: usize, b: F) -> BTreeSet<usize> {
    let squares: BTreeSet<_> = cap
        .recorder
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Gate { a, b, c } if copies.same(*a, y) && copies.same(*b, y) => Some(*c),
            _ => None,
        })
        .collect();
    cap.recorder
        .events
        .iter()
        .enumerate()
        .filter_map(|(i, event)| match event {
            Event::Enforce { terms }
                if terms.len() == 3
                    && terms.contains(&(0, b))
                    && terms
                        .iter()
                        .any(|(wire, coeff)| squares.contains(wire) && *coeff == -F::ONE) =>
            {
                Some(i)
            }
            _ => None,
        })
        .collect()
}

/// Remove only a+b=1 for the edited Boolean allocation, retaining c=0,
/// a*b=c, donated-wire constraints, and every equality to a staged bit.
fn boolean_cuts<F: Field>(cap: &Capture<F>, copies: &Copies, bits: &[usize]) -> BTreeSet<usize> {
    let pairs: Vec<_> = cap
        .recorder
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Gate { a, b, .. } if bits.iter().any(|bit| copies.same(*bit, *a)) => {
                Some((*a, *b))
            }
            _ => None,
        })
        .collect();
    cap.recorder
        .events
        .iter()
        .enumerate()
        .filter_map(|(i, event)| match event {
            Event::Enforce { terms }
                if terms.len() == 3
                    && terms.contains(&(0, F::ONE))
                    && pairs.iter().any(|(a, b)| {
                        terms.contains(&(*a, -F::ONE)) && terms.contains(&(*b, -F::ONE))
                    }) =>
            {
                Some(i)
            }
            _ => None,
        })
        .collect()
}

fn check_points<'w, C: CurveAffine, Cir: Circuit<C::Base>>(
    cap: &Capture<C::Base>,
    circuit: &Cir,
    make_witness: &impl Fn() -> Result<Cir::Witness<'w>>,
    positions: &[usize],
    routes: &[(usize, usize)],
) -> Result<()> {
    let mut copies = Copies::new(cap);
    for &(dst, src) in routes {
        let (dst, src) = (cap.stage_wires[dst], cap.stage_wires[src]);
        assert_eq!(cap.recorder.values[dst], cap.recorder.values[src]);
        copies.join(dst, src);
    }
    for (slot, xy) in positions.chunks_exact(2).enumerate() {
        let context = format!("point contract {slot}");
        let (x, y) = (cap.stage_wires[xy[0]], cap.stage_wires[xy[1]]);
        let old = &cap.recorder.values;
        assert_eq!(old[x].square() * old[x] + C::b(), old[y].square());
        // Avoid both y=0 and the other honest root -y.
        let replacement = [C::Base::ONE, C::Base::from(2), C::Base::from(3)]
            .into_iter()
            .map(|delta| old[y] + delta)
            .find(|v| *v != C::Base::ZERO && v.square() != old[y].square())
            .unwrap();
        let residual = old[x].square() * old[x] + C::b() - replacement.square();
        assert_ne!(residual, C::Base::ZERO);
        let cuts = membership_cuts(cap, &copies, y, C::b());
        let values = candidate(cap, &copies, &[(y, replacement)], &cuts, &context);
        assert_eq!(values[x], old[x]);
        assert_eq!(values[y], replacement);
        assert!(bool::from(C::from_xy(values[x], values[y]).is_none()));
        for &(dst, src) in routes {
            assert_eq!(values[cap.stage_wires[dst]], values[cap.stage_wires[src]]);
        }
        // Check rejection before the count, so a real production omission
        // is detected by its accepting bad witness, not graph shape alone.
        check_live(cap, circuit, make_witness, values.clone(), false, &context)?;
        assert!(!cuts.is_empty());
        for cut in cuts {
            let Event::Enforce { terms } = &cap.recorder.events[cut] else {
                unreachable!()
            };
            assert_eq!(
                terms.iter().map(|(w, c)| values[*w] * c).sum::<C::Base>(),
                residual
            );
        }
    }
    Ok(())
}

/// Algebraic extension of the endoscalar lift to arbitrary field-valued
/// coordinates. Each pair contributes (1-2n)*(1+(zeta-1)e).
fn extended_lift<F: WithSmallOrderMulGroup<3>>(bits: &[F]) -> F {
    assert_eq!(bits.len(), 128);
    bits.chunks_exact(2)
        .fold((F::ZETA + F::ONE).double(), |acc, pair| {
            acc.double() + (F::ONE - pair[0].double()) * (F::ONE + (F::ZETA - F::ONE) * pair[1])
        })
}

#[derive(Clone, Copy)]
enum Contract {
    NativePoints,
    NestedPoints,
    NativeBits,
    NestedBits,
}

struct Checker {
    contract: Contract,
    visited: usize,
}

impl<C: Cycle> InternalCircuitVisitor<C> for Checker {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if spec.name != "bind_endoscalar"
            || !matches!(self.contract, Contract::NativePoints | Contract::NativeBits)
        {
            return Ok(());
        }
        let cap = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
        check_live(
            &cap,
            circuit,
            &make_witness,
            cap.recorder.values.clone(),
            true,
            "honest native",
        )?;
        if matches!(self.contract, Contract::NativePoints) {
            let mut points = Vec::new();
            macro_rules! stage {
                ($stage:ident) => {
                    points.extend(stage_wire_indices::<
                        C::CircuitField,
                        R,
                        native_points::$stage<C::NestedCurve>,
                    >(|s| wires_of(&s))?);
                };
            }
            stage!(BindingStage);
            stage!(ChildrenStage);
            stage!(RegistryWxStage);
            stage!(AbStage);
            stage!(FStage);
            assert_eq!(points.len(), 198);
            check_points::<C::NestedCurve, _>(&cap, circuit, &make_witness, &points, &[])?;
        } else {
            let positions =
                stage_wire_indices::<C::CircuitField, R, native_points::WalkStage<C::NestedCurve>>(
                    |s| wires_of(&s.endoscalar),
                )?;
            let bits: Vec<_> = positions.into_iter().map(|i| cap.stage_wires[i]).collect();
            assert_eq!(bits.len(), 128);
            let copies = Copies::new(&cap);
            let source = cap.instance[unified_slot_positions("pre_beta")[0]];
            for (pair, bits) in bits.chunks_exact(2).enumerate() {
                let context = format!("native Boolean pair {pair}");
                let old = &cap.recorder.values;
                let edits = [
                    (bits[0], old[bits[0]] + C::CircuitField::from(4)),
                    (bits[1], old[bits[1]] - C::CircuitField::from(2)),
                ];
                assert_eq!(
                    edits[0].1 + edits[1].1.double(),
                    old[bits[0]] + old[bits[1]].double()
                );
                let cuts = boolean_cuts(&cap, &copies, bits);
                let values = candidate(&cap, &copies, &edits, &cuts, &context);
                assert_eq!(values[source], old[source]);
                for &(bit, value) in &edits {
                    assert_ne!(
                        value * (value - C::CircuitField::ONE),
                        C::CircuitField::ZERO
                    );
                    assert_eq!(values[bit], value);
                }
                check_live(&cap, circuit, &make_witness, values, false, &context)?;
                assert_eq!(cuts.len(), 2);
            }
        }
        self.visited += 1;
        Ok(())
    }

    fn visit_nested<'w, Cir: Circuit<C::ScalarField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::ScalarField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        let export = spec.name == "nested_export";
        if !(matches!(self.contract, Contract::NestedPoints) && export
            || matches!(self.contract, Contract::NestedBits)
                && (export || spec.name == "nested_compute_v"))
        {
            return Ok(());
        }
        let cap = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
        check_live(
            &cap,
            circuit,
            &make_witness,
            cap.recorder.values.clone(),
            true,
            "honest nested",
        )?;
        if matches!(self.contract, Contract::NestedPoints) {
            let points =
                stage_wire_indices::<C::ScalarField, R, nested::PointsStage<C::HostCurve>>(|s| {
                    wires_of(&s)
                })?;
            assert_eq!(points.len(), 282);
            // R05's independently enumerated semantic routes use the same
            // reservation indices in either capture of this circuit layout.
            let routes: Vec<_> = nested::circuits::loading::tests::stage_routes()?
                .into_iter()
                .map(|r| (r.destination, r.source))
                .collect();
            check_points::<C::HostCurve, _>(&cap, circuit, &make_witness, &points, &routes)?;
        } else {
            let positions =
                stage_wire_indices::<C::ScalarField, R, EndoscalarStage>(|s| wires_of(&s))?;
            let bits: Vec<_> = positions.into_iter().map(|i| cap.stage_wires[i]).collect();
            let beta = stage_wire_indices::<
                C::ScalarField,
                R,
                nested::stages::challenges::Stage<C::HostCurve, R>,
            >(|s| wires_of(&s.beta.lift))?;
            let beta = cap.stage_wires[beta[0]];
            let copies = Copies::new(&cap);
            let old = &cap.recorder.values;
            assert_eq!(
                extended_lift(&bits.iter().map(|i| old[*i]).collect::<Vec<_>>()),
                old[beta]
            );
            for (pair, pair_bits) in bits.chunks_exact(2).enumerate() {
                let context = format!("{} Boolean pair {pair}", spec.name);
                let [n, e] = [old[pair_bits[0]], old[pair_bits[1]]];
                let term = (C::ScalarField::ONE - n.double())
                    * (C::ScalarField::ONE + (C::ScalarField::ZETA - C::ScalarField::ONE) * e);
                let new_n = C::ScalarField::from(2);
                let new_e = (term * (C::ScalarField::ONE - new_n.double()).invert().unwrap()
                    - C::ScalarField::ONE)
                    * (C::ScalarField::ZETA - C::ScalarField::ONE)
                        .invert()
                        .unwrap();
                let cuts = boolean_cuts(&cap, &copies, pair_bits);
                let values = candidate(
                    &cap,
                    &copies,
                    &[(pair_bits[0], new_n), (pair_bits[1], new_e)],
                    &cuts,
                    &context,
                );
                for bit in pair_bits {
                    assert_ne!(
                        values[*bit] * (values[*bit] - C::ScalarField::ONE),
                        C::ScalarField::ZERO
                    );
                }
                assert_eq!(values[beta], old[beta]);
                assert_eq!(
                    extended_lift(&bits.iter().map(|i| values[*i]).collect::<Vec<_>>()),
                    values[beta]
                );
                check_live(&cap, circuit, &make_witness, values, !export, &context)?;
                assert_eq!(cuts.len(), if export { 2 } else { 0 });
            }
        }
        self.visited += 1;
        Ok(())
    }
}

fn check_tree(contract: Contract) -> Result<()> {
    let app = ApplicationBuilder::<Pasta, R, 4>::new()
        .register(Leaf::new())?
        .register(Both::new())?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x873_0304);
    let mut checker = Checker {
        contract,
        visited: 0,
    };
    capture_internal_circuits_seeded(&app, &mut rng, Leaf::new(), Fp::from(7), &mut checker)?;
    let (left, _) = app.seed(&mut rng, Leaf::new(), Fp::from(19))?;
    let (right, _) = app.seed(&mut rng, Leaf::new(), Fp::from(43))?;
    capture_internal_circuits(
        &app,
        &mut rng,
        Both::new(),
        Fp::from(71),
        left,
        right,
        &mut checker,
    )?;
    assert_eq!(
        checker.visited,
        if matches!(contract, Contract::NestedBits) {
            4
        } else {
            2
        }
    );
    Ok(())
}

#[test]
fn native_membership_with_consistent_copies() -> Result<()> {
    check_tree(Contract::NativePoints)
}

#[test]
fn nested_membership_with_consistent_routes() -> Result<()> {
    check_tree(Contract::NestedPoints)
}

#[test]
fn native_boolean_contract_with_fixed_recomposition() -> Result<()> {
    check_tree(Contract::NativeBits)
}

#[test]
fn nested_boolean_contract_with_fixed_lift() -> Result<()> {
    check_tree(Contract::NestedBits)
}
