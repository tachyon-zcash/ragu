//! Split the scalar PCS quotient batch over two application steps.
//!
//! The input header binds alpha, u, and four ordered (x, v, p(u)) claims.
//! This exercises the scalar batching equation used by ComputeV, not the
//! transcript or commitment checks that establish those input claims.

use ragu_circuits::horner::Horner;
use ragu_primitives::{
    GadgetExt,
    vec::{ConstLen, FixedVec},
};

use super::*;

const HS: usize = 16;
const INPUTS: usize = 14;
type BatchApp = Application<'static, Pasta, R, HS>;

struct BatchInputs;

impl Header<Fp> for BatchInputs {
    const SUFFIX: Suffix = Suffix::new(1);
    type Data = [Fp; INPUTS];
    type Output = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<INPUTS>>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        (0..INPUTS)
            .map(|i| Element::alloc(dr, allocator, witness.as_ref().map(|values| values[i])))
            .collect::<Result<alloc::vec::Vec<_>>>()?
            .try_into()
    }
}

struct InputStep<const INDEX: usize>;

impl<const INDEX: usize> Step<Pasta> for InputStep<INDEX> {
    const INDEX: Index = Index::new(INDEX);
    type Shared = ();
    type Witness<'source> = [Fp; INPUTS];
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = BatchInputs;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), H>,
            Encoded<'dr, D, (), H>,
            Encoded<'dr, D, BatchInputs, H>,
        ),
        (),
        DriverValue<D, [Fp; INPUTS]>,
        DriverValue<D, ()>,
    )> {
        let output = Encoded::new(dr, &mut Standard::new(), witness.clone())?;
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            (),
            witness,
            D::unit(),
        ))
    }
}

#[derive(Gadget, Shared)]
struct PartialBatch<'dr, D: Driver<'dr>> {
    prefix: Element<'dr, D>,
    suffix: Element<'dr, D>,
}

struct BatchStep<const SECOND: bool, const PARALLEL: bool>;

fn quotient_term<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    inputs: &FixedVec<Element<'dr, D>, ConstLen<INPUTS>>,
    claim: usize,
) -> Result<Element<'dr, D>> {
    let at = 2 + 3 * claim;
    let denominator = inputs[1].sub(dr, &inputs[at]);
    let inverse = denominator.invert(dr)?;
    let numerator = inputs[at + 2].sub(dr, &inputs[at + 1]);
    numerator.mul(dr, &inverse)
}

impl<const SECOND: bool, const PARALLEL: bool> Step<Pasta> for BatchStep<SECOND, PARALLEL> {
    const INDEX: Index = Index::new(1 + SECOND as usize);
    type Shared = Kind![Fp; PartialBatch<'_, _>];
    // Each step computes its own partial and takes the other as advice.
    type Witness<'source> = ([Fp; 2], Fp);
    type Aux<'source> = ();
    type Left = BatchInputs;
    type Right = ();
    type Output = Number;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, [Fp; INPUTS]>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, BatchInputs, H>,
            Encoded<'dr, D, (), H>,
            Encoded<'dr, D, Number, H>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left: Encoded<'dr, D, BatchInputs, H> = Encoded::new(dr, allocator, left)?;
        let inputs = left.as_gadget();
        let alpha = &inputs[0];
        // These fixed, disjoint ranges preserve the registered claim order.
        let start = if SECOND { 2 } else { 0 };
        let terms = [
            quotient_term(dr, inputs, start)?,
            quotient_term(dr, inputs, start + 1)?,
        ];
        let mut horner = Horner::new(alpha);
        for term in &terms {
            term.write(dr, &mut horner)?;
        }
        let computed = horner.finish(dr);
        let (partials, result) = witness.cast();
        let other = Element::alloc(
            dr,
            allocator,
            partials.map(|partials| partials[usize::from(!SECOND)]),
        )?;
        let (prefix, suffix) = if SECOND {
            (other, computed)
        } else {
            (computed, other)
        };
        let output = Element::alloc(dr, allocator, result)?;
        if SECOND {
            let combined = if PARALLEL {
                // Independently computed halves need the global alpha weights.
                let alpha_squared = alpha.square(dr)?;
                prefix.mul(dr, &alpha_squared)?.add(dr, &suffix)
            } else {
                // Continue the first step's actual accumulator through our claims.
                let mut continuation = Horner::new(alpha);
                prefix.write(dr, &mut continuation)?;
                for term in &terms {
                    term.write(dr, &mut continuation)?;
                }
                continuation.finish(dr)
            };
            combined.enforce_equal(dr, &output)?;
        }
        let data = output.value().map(|value| *value);
        Ok((
            (left, Encoded::from_gadget(()), Encoded::from_gadget(output)),
            PartialBatch { prefix, suffix },
            data,
            D::unit(),
        ))
    }
}

fn app<const PARALLEL: bool>() -> BatchApp {
    ApplicationBuilder::new()
        .register(InputStep::<0>)
        .unwrap()
        .register_bundle((BatchStep::<false, PARALLEL>, BatchStep::<true, PARALLEL>))
        .unwrap()
        .register(Carry)
        .unwrap()
        .register_bundle((InputStep::<4>, InputStep::<5>))
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap()
}

fn inputs() -> [Fp; INPUTS] {
    let mut inputs = [Fp::ZERO; INPUTS];
    inputs[0] = Fp::from(7);
    inputs[1] = Fp::from(11);
    let u = inputs[1];
    for i in 0..4 {
        let x = Fp::from(2 + i as u64);
        let a = Fp::from(1 + i as u64);
        let b = Fp::from(3 + 2 * i as u64);
        let c = Fp::from(5 + i as u64);
        let evaluate = |x: Fp| a + b * x + c * x.square();
        inputs[2 + 3 * i..5 + 3 * i].copy_from_slice(&[x, evaluate(x), evaluate(u)]);
    }
    inputs
}

/// Explicit weights, independent of the circuit's Horner implementation.
fn expected(inputs: &[Fp; INPUTS]) -> ([Fp; 2], Fp) {
    let alpha = inputs[0];
    let terms: [Fp; 4] = core::array::from_fn(|i| {
        let at = 2 + 3 * i;
        (inputs[at + 2] - inputs[at + 1]) * (inputs[1] - inputs[at]).invert().unwrap()
    });
    (
        [alpha * terms[0] + terms[1], alpha * terms[2] + terms[3]],
        alpha.pow_u64(3) * terms[0] + alpha.square() * terms[1] + alpha * terms[2] + terms[3],
    )
}

fn run<const PARALLEL: bool>() {
    let app = app::<PARALLEL>();
    let mut rng = StdRng::seed_from_u64(89520 + u64::from(PARALLEL));
    let inputs = inputs();
    let (partials, evaluation) = expected(&inputs);
    assert_ne!(
        partials[0], partials[1],
        "different partial results must be supported"
    );
    let left = app.seed(&mut rng, InputStep::<0>, inputs).unwrap().0;
    let right = app.bootstrap_pcd();
    let steps = || (BatchStep::<false, PARALLEL>, BatchStep::<true, PARALLEL>);
    let witness = (partials, evaluation);
    let honest = app
        .fuse_bundle(
            &mut rng,
            steps(),
            (witness, witness),
            left.clone(),
            right.clone(),
        )
        .unwrap()
        .0;
    check_through_recursion(&app, honest.clone(), &honest, &mut rng, true);

    for order in [
        Preparation::Sequential,
        Preparation::Reverse,
        Preparation::Parallel,
    ] {
        let (first, second) = prepare(
            &app,
            &mut rng,
            order,
            steps(),
            (witness, witness),
            &left,
            &right,
        );
        assert_eq!(first.0.shared, partials);
        assert_eq!(first.0.shared, second.shared);
        let (pcd, ()) = app
            .fuse_prepared::<_, BatchStep<false, PARALLEL>>(
                &mut rng,
                first,
                left.clone().into_parts().0,
                right.clone().into_parts().0,
                alloc::vec![second],
            )
            .unwrap();
        assert_eq!(*pcd.data(), evaluation);
        check(&app, &pcd, &mut rng, true);
    }

    for field in 0..2 {
        let mut altered = partials;
        altered[field] += Fp::ONE;
        // Keep each local equation valid: a wrong consumed midpoint changes
        // the claimed output; a wrong advised suffix leaves the output alone.
        let claimed = if field == 0 {
            evaluation + inputs[0].square()
        } else {
            evaluation
        };
        let witnesses = if field == 0 {
            ((partials, claimed), (altered, claimed))
        } else {
            ((altered, claimed), (partials, claimed))
        };
        assert!(
            app.fuse_bundle(&mut rng, steps(), witnesses, left.clone(), right.clone())
                .is_err()
        );
        let (first, mut second) = prepare(
            &app,
            &mut rng,
            Preparation::Sequential,
            steps(),
            witnesses,
            &left,
            &right,
        );
        assert_ne!(first.0.shared[field], second.shared[field]);
        assert_eq!(first.0.shared[1 - field], second.shared[1 - field]);
        // Bypass the host equality check while retaining the actual circuit wires.
        second.shared.clone_from(&first.0.shared);
        let (forged, ()) = app
            .fuse_prepared::<_, BatchStep<false, PARALLEL>>(
                &mut rng,
                first,
                left.clone().into_parts().0,
                right.clone().into_parts().0,
                alloc::vec![second],
            )
            .unwrap();
        check_through_recursion(&app, forged, &honest, &mut rng, false);
    }

    // Shared values agreeing is insufficient if the final batching equation is false.
    let bad_output = (partials, evaluation + Fp::ONE);
    let (forged, ()) = app
        .fuse_bundle(&mut rng, steps(), (bad_output, bad_output), left, right)
        .unwrap();
    check(&app, &forged, &mut rng, false);

    let bundle = BatchStep::<false, PARALLEL>::INDEX
        .bundle(&app.application_bundles)
        .unwrap();
    for second in [false, true] {
        // Report complete circuit costs, including headers and automatic bindings.
        let counts = if second {
            ragu_circuits::testing::synthesis_counts(
                &Adapter::<Pasta, BatchStep<true, PARALLEL>, R, HS>::new(
                    BatchStep,
                    bundle,
                    app.shared_size,
                )
                .unwrap(),
            )
            .unwrap()
        } else {
            ragu_circuits::testing::synthesis_counts(
                &Adapter::<Pasta, BatchStep<false, PARALLEL>, R, HS>::new(
                    BatchStep,
                    bundle,
                    app.shared_size,
                )
                .unwrap(),
            )
            .unwrap()
        };
        std::println!(
            "PCS scalar batch: parallel={PARALLEL}, second={second}: {} gates, {} constraints",
            counts.num_gates,
            counts.num_constraints
        );
    }
}

#[test]
fn sequential_scalar_batching_binds_the_midpoint() {
    run::<false>();
}

#[test]
fn parallel_scalar_batching_combines_distinct_partials() {
    run::<true>();
}

#[test]
fn steps_registered_in_an_empty_bundle_cannot_be_proved_alone() {
    let app = app::<false>();
    let mut rng = StdRng::seed_from_u64(89522);
    let inputs = inputs();
    assert!(app.seed(&mut rng, InputStep::<4>, inputs).is_err());
    assert!(app.seed(&mut rng, InputStep::<5>, inputs).is_err());
    let (pcd, ()) = app
        .seed_bundle(&mut rng, (InputStep::<4>, InputStep::<5>), (inputs, inputs))
        .unwrap();
    check(&app, &pcd, &mut rng, true);
}
