use alloc::{string::ToString, vec::Vec};
use core::marker::PhantomData;

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
    pasta::Fp,
};
use ragu_primitives::{
    Element, GadgetExt, Simulator,
    allocator::Allocator,
    io::{Buffer, Write},
    shared::Shared,
};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::{assert_invalid_witness, test_params};
use crate::{ApplicationBuilder, Encoded, Header, Index, Pcd, Proof, Step, StepCtx, Suffix};

struct ScalarHeader;

impl Header for ScalarHeader {
    const SUFFIX: Suffix = Suffix::new(40);
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

#[derive(Gadget, Shared)]
struct SharedPair<'dr, D: Driver<'dr>> {
    left: Element<'dr, D>,
    right: Element<'dr, D>,
}

struct ScalarSeed;

impl Step for ScalarSeed {
    const INDEX: Index = Index::new(0);
    type Shared = ();
    type Witness<'source> = Fp;
    type Left = ();
    type Right = ();
    type Output = ScalarHeader;
    type Aux<'source> = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Fp>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, ScalarHeader, HS>,
        ),
        (),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let output = Encoded::new(ctx.dr, &mut (), witness.clone())?;
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            (),
            witness,
            D::unit(),
        ))
    }
}

struct ComputedMerge {
    wrong_data: bool,
    substitute_input: Option<bool>,
}

impl Step for ComputedMerge {
    const INDEX: Index = Index::new(1);
    type Shared = Kind![Fp; SharedPair<'_, _>];
    type Witness<'source> = ();
    type Left = ScalarHeader;
    type Right = ScalarHeader;
    type Output = ScalarHeader;
    type Aux<'source> = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, ScalarHeader, HS>,
            Encoded<'dr, D, ScalarHeader, HS>,
            Encoded<'dr, D, ScalarHeader, HS>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let mut left = ScalarHeader::encode(ctx.dr, &mut (), left)?;
        let mut right = ScalarHeader::encode(ctx.dr, &mut (), right)?;
        let one = Element::constant(ctx.dr, Fp::ONE);
        match self.substitute_input {
            Some(false) => left = left.add(ctx.dr, &one),
            Some(true) => right = right.add(ctx.dr, &one),
            None => {}
        }
        let sum = left.add(ctx.dr, &right);
        let data = sum
            .value()
            .map(|v| if self.wrong_data { *v + Fp::ONE } else { *v });
        Ok((
            (
                Encoded::from_gadget(left.clone()),
                Encoded::from_gadget(right.clone()),
                Encoded::from_gadget(sum),
            ),
            SharedPair { left, right },
            data,
            D::unit(),
        ))
    }
}

#[test]
fn proof_binds_computed_output_wires_and_both_input_headers() {
    let mut rng = StdRng::seed_from_u64(80);
    let app = ApplicationBuilder::<4>::new(test_params())
        .register(ScalarSeed)
        .unwrap()
        .register(ComputedMerge {
            wrong_data: false,
            substitute_input: None,
        })
        .unwrap()
        .finalize()
        .unwrap();
    let (left, ()) = app.seed(&mut rng, ScalarSeed, Fp::from(7u64)).unwrap();
    let (right, ()) = app.seed(&mut rng, ScalarSeed, Fp::from(11u64)).unwrap();
    let (honest, ()) = app
        .fuse(
            &mut rng,
            ComputedMerge {
                wrong_data: false,
                substitute_input: None,
            },
            (),
            left.clone(),
            right.clone(),
        )
        .unwrap();
    assert_eq!(*honest.data(), Fp::from(18u64));
    assert!(app.verify(&honest, &mut rng).unwrap());

    // Returning unrelated native data must not replace the computed output.
    let (lying, ()) = app
        .fuse(
            &mut rng,
            ComputedMerge {
                wrong_data: true,
                substitute_input: None,
            },
            (),
            left.clone(),
            right.clone(),
        )
        .unwrap();
    assert_eq!(*lying.data(), Fp::from(19u64));
    assert!(!app.verify(&lying, &mut rng).unwrap());
    let (proof, _) = lying.into_parts();
    assert!(
        app.verify(&proof.carry::<ScalarHeader>(Fp::from(18u64)), &mut rng)
            .unwrap()
    );

    for side in [false, true] {
        let result = app.fuse(
            &mut rng,
            ComputedMerge {
                wrong_data: false,
                substitute_input: Some(side),
            },
            (),
            left.clone(),
            right.clone(),
        );
        let error = match result {
            Ok(_) => panic!("substituted input must fail"),
            Err(error) => error,
        };
        assert_invalid_witness(error, "input header does not match child proof");
    }
    let (proof, _) = left.into_parts();
    let tampered = proof.carry::<ScalarHeader>(Fp::from(8u64));
    let result = app.fuse(
        &mut rng,
        ComputedMerge {
            wrong_data: false,
            substitute_input: None,
        },
        (),
        tampered,
        right,
    );
    let error = match result {
        Ok(_) => panic!("tampered child data must fail"),
        Err(error) => error,
    };
    assert_invalid_witness(error, "input header does not match child proof");
}

#[test]
fn encoded_headers_preserve_gadgets_and_reference_padding() {
    let mut dr = Simulator::<Fp>::new();
    let encoded = Encoded::<_, ScalarHeader, 4>::new(
        &mut dr,
        &mut (),
        Simulator::<Fp>::just(|| Fp::from(9u64)),
    )
    .unwrap();
    assert_eq!(*encoded.as_gadget().value().take(), Fp::from(9u64));
    let mut elements = Vec::new();
    encoded.clone().write(&mut dr, &mut elements).unwrap();
    assert_eq!(
        elements
            .iter()
            .map(|e| *e.value().take())
            .collect::<Vec<_>>(),
        alloc::vec![
            Fp::from(9u64),
            Fp::ZERO,
            Fp::ZERO,
            Fp::from(ScalarHeader::SUFFIX.get())
        ]
    );
    let mut cloned = Vec::new();
    encoded.write(&mut dr, &mut cloned).unwrap();
    assert_eq!(
        cloned.iter().map(|e| *e.value().take()).collect::<Vec<_>>(),
        elements
            .iter()
            .map(|e| *e.value().take())
            .collect::<Vec<_>>()
    );
    let too_small =
        Encoded::<_, ScalarHeader, 1>::new(&mut dr, &mut (), Simulator::<Fp>::just(|| Fp::ONE))
            .unwrap();
    let error = too_small.write(&mut dr, &mut Vec::new()).unwrap_err();
    assert!(matches!(error, ragu_core::Error::MalformedEncoding(message)
        if message.to_string() == "Header encoding size exceeded HEADER_SIZE - 1 (0)"));
}

#[derive(Gadget)]
struct ZeroGadget<'dr, D: Driver<'dr>, const ON_WRITE: bool> {
    value: Element<'dr, D>,
}

impl<F: Field, const ON_WRITE: bool> Write<F> for ZeroGadget<'static, PhantomData<F>, ON_WRITE> {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Bound<'dr, D, Self>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        if ON_WRITE {
            this.value.enforce_zero(dr)?;
        }
        this.value.write(dr, buf)
    }
}

struct ZeroHeader<const ON_WRITE: bool>;

impl<const ON_WRITE: bool> Header for ZeroHeader<ON_WRITE> {
    const SUFFIX: Suffix = Suffix::new(41);
    type Data = Fp;
    type Output = Kind![Fp; ZeroGadget<'_, _, ON_WRITE>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let value = Element::alloc(dr, allocator, witness)?;
        if !ON_WRITE {
            value.enforce_zero(dr)?;
        }
        Ok(ZeroGadget { value })
    }
}

struct ZeroMerge<const ON_WRITE: bool>;

impl<const ON_WRITE: bool> Step for ZeroMerge<ON_WRITE> {
    const INDEX: Index = Index::new(0);
    type Shared = ();
    type Witness<'source> = Fp;
    type Left = ZeroHeader<ON_WRITE>;
    type Right = ZeroHeader<ON_WRITE>;
    type Output = ZeroHeader<ON_WRITE>;
    type Aux<'source> = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Fp>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HS>,
            Encoded<'dr, D, Self::Right, HS>,
            Encoded<'dr, D, Self::Output, HS>,
        ),
        (),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        Ok((
            (
                Encoded::new(ctx.dr, &mut (), left)?,
                Encoded::new(ctx.dr, &mut (), right)?,
                Encoded::new(ctx.dr, &mut (), witness.clone())?,
            ),
            (),
            witness,
            D::unit(),
        ))
    }
}

fn zero_child<const ON_WRITE: bool>(value: Fp) -> Pcd<ZeroHeader<ON_WRITE>> {
    Proof::new(
        ZeroHeader::<ON_WRITE>::SUFFIX,
        Index::new(0),
        &[
            Fp::ZERO,
            Fp::ZERO,
            Fp::ZERO,
            Fp::from(ZeroHeader::<ON_WRITE>::SUFFIX.get()),
        ],
        &[],
    )
    .unwrap()
    .carry(value)
}

fn check_header_constraints<const ON_WRITE: bool>() {
    let mut rng = StdRng::seed_from_u64(81);
    let app = ApplicationBuilder::<4>::new(test_params())
        .register(ZeroMerge::<ON_WRITE>)
        .unwrap()
        .finalize()
        .unwrap();
    let (good, ()) = app
        .fuse(
            &mut rng,
            ZeroMerge::<ON_WRITE>,
            Fp::ZERO,
            zero_child(Fp::ZERO),
            zero_child(Fp::ZERO),
        )
        .unwrap();
    assert!(app.verify(&good, &mut rng).unwrap());
    for (left, right, output) in [
        (Fp::ONE, Fp::ZERO, Fp::ZERO),
        (Fp::ZERO, Fp::ONE, Fp::ZERO),
        (Fp::ZERO, Fp::ZERO, Fp::ONE),
    ] {
        let result = app.fuse(
            &mut rng,
            ZeroMerge::<ON_WRITE>,
            output,
            zero_child(left),
            zero_child(right),
        );
        let error = match result {
            Ok(_) => panic!("header constraints must run on the checked driver"),
            Err(error) => error,
        };
        assert_invalid_witness(error, "constraint failed");
    }
    let (proof, _) = good.into_parts();
    let result = app.verify(&proof.carry::<ZeroHeader<ON_WRITE>>(Fp::ONE), &mut rng);
    assert_invalid_witness(result.unwrap_err(), "constraint failed");
}

#[test]
fn header_allocation_and_serialization_constraints_are_checked() {
    check_header_constraints::<false>();
    check_header_constraints::<true>();
}

#[test]
fn fuse_rejects_unregistered_step_before_execution() {
    let mut rng = StdRng::seed_from_u64(82);
    let app = ApplicationBuilder::<4>::new(test_params())
        .finalize()
        .unwrap();
    let result = app.seed(&mut rng, ScalarSeed, Fp::ONE);
    assert!(
        matches!(result, Err(ragu_core::Error::Initialization(message))
        if message.to_string() == "attempted to use application Step index that exceeds Application registered steps")
    );
}

#[test]
fn application_header_width_is_enforced_in_fuse_and_verify() {
    let mut rng = StdRng::seed_from_u64(83);
    let narrow = ApplicationBuilder::<1>::new(test_params())
        .register(ScalarSeed)
        .unwrap()
        .finalize()
        .unwrap();
    let result = narrow.seed(&mut rng, ScalarSeed, Fp::ONE);
    assert!(
        matches!(result, Err(ragu_core::Error::MalformedEncoding(message))
        if message.to_string() == "Header encoding size exceeded HEADER_SIZE - 1 (0)")
    );

    let app = ApplicationBuilder::<4>::new(test_params())
        .register(ScalarSeed)
        .unwrap()
        .finalize()
        .unwrap();
    let (pcd, ()) = app.seed(&mut rng, ScalarSeed, Fp::ONE).unwrap();
    let different_width = ApplicationBuilder::<5>::new(test_params())
        .register(ScalarSeed)
        .unwrap()
        .finalize()
        .unwrap();
    assert!(!different_width.verify(&pcd, &mut rng).unwrap());
}
