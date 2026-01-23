use arithmetic::{Cycle, Uendo};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ff::Field;
use group::prime::PrimeCurveAffine;
use ragu_core::drivers::emulator::{Emulator, Wireless};
use ragu_core::maybe::{Always, Maybe};
use ragu_pasta::{EpAffine, Fp, Fq, Pasta};
use ragu_primitives::poseidon::Sponge;
use ragu_primitives::{Boolean, Element, Endoscalar, Point, multiadd, multipack};
use rand::Rng;
use rand::rngs::mock::StepRng;

type BenchEmulator = Emulator<Wireless<Always<()>, Fp>>;

fn mock_rng() -> StepRng {
    let seed_bytes: [u8; 8] = "12345666".as_bytes().try_into().unwrap();
    StepRng::new(u64::from_le_bytes(seed_bytes), 0x1234_5666_1234_5666)
}

fn bench_element_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("primitives/element/mul", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (a, b) = witness.cast();
                    let a = Element::alloc(dr, a)?;
                    let b = Element::alloc(dr, b)?;
                    a.mul(dr, &b)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/invert", |b| {
        b.iter_batched(
            || Fp::random(&mut rng),
            |input| {
                BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let a = Element::alloc(dr, witness)?;
                    a.invert(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/fold_8", |b| {
        b.iter_batched(
            || {
                let values: [Fp; 8] = core::array::from_fn(|_| Fp::random(&mut rng));
                let scale = Fp::random(&mut rng);
                (values, scale)
            },
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (vals, scale) = witness.cast();
                    let elements: Vec<_> = (0..8)
                        .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    let scale = Element::alloc(dr, scale)?;
                    Element::fold(dr, &elements, &scale)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/is_zero", |b| {
        b.iter_batched(
            || Fp::random(&mut rng),
            |input| {
                BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let a = Element::alloc(dr, witness)?;
                    a.is_zero(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/multiadd_8", |b| {
        b.iter_batched(
            || {
                let values: [Fp; 8] = core::array::from_fn(|_| Fp::random(&mut rng));
                let coeffs: [Fp; 8] = core::array::from_fn(|_| Fp::random(&mut rng));
                (values, coeffs)
            },
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (vals, coeffs) = witness.cast();
                    let elements: Vec<_> = (0..8)
                        .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    let coeffs: Vec<_> = (0..8)
                        .map(|i| *coeffs.view().map(|c| c[i]).snag())
                        .collect();
                    multiadd(dr, &elements, &coeffs)
                })
            },
            BatchSize::SmallInput,
        )
    });
}

fn random_point(rng: &mut impl Rng) -> EpAffine {
    (EpAffine::generator() * Fq::random(rng)).into()
}

fn bench_point_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("primitives/point/double", |b| {
        b.iter_batched(
            || random_point(&mut rng),
            |point| {
                BenchEmulator::emulate_wireless(point, |dr, witness| {
                    let p = Point::alloc(dr, witness)?;
                    p.double(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/add_incomplete", |b| {
        b.iter_batched(
            || (random_point(&mut rng), random_point(&mut rng)),
            |points| {
                BenchEmulator::emulate_wireless(points, |dr, witness| {
                    let (p, q) = witness.cast();
                    let p = Point::alloc(dr, p)?;
                    let q = Point::alloc(dr, q)?;
                    p.add_incomplete(dr, &q, None)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/double_and_add_incomplete", |b| {
        b.iter_batched(
            || (random_point(&mut rng), random_point(&mut rng)),
            |points| {
                BenchEmulator::emulate_wireless(points, |dr, witness| {
                    let (p, q) = witness.cast();
                    let p = Point::alloc(dr, p)?;
                    let q = Point::alloc(dr, q)?;
                    p.double_and_add_incomplete(dr, &q)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/endo", |b| {
        b.iter_batched(
            || random_point(&mut rng),
            |point| {
                BenchEmulator::emulate_wireless(point, |dr, witness| {
                    let p = Point::alloc(dr, witness)?;
                    p.endo(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_boolean_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("primitives/boolean/multipack_256", |b| {
        b.iter_batched(
            || core::array::from_fn::<bool, 256, _>(|_| rng.r#gen()),
            |bits| {
                BenchEmulator::emulate_wireless(bits, |dr, witness| {
                    let bools: Vec<_> = (0..256)
                        .map(|i| Boolean::alloc(dr, witness.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    multipack(dr, &bools)
                })
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_sponge_ops(c: &mut Criterion) {
    let pasta = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);
    let mut rng = mock_rng();

    c.bench_function("primitives/sponge/absorb_squeeze", |b| {
        b.iter_batched(
            || Fp::random(&mut rng),
            |input| {
                BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let mut sponge = Sponge::new(dr, poseidon);
                    let elem = Element::alloc(dr, witness)?;
                    sponge.absorb(dr, &elem)?;
                    sponge.squeeze(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_endoscalar_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("primitives/endoscalar/group_scale", |b| {
        b.iter_batched(
            || (random_point(&mut rng), rng.r#gen::<Uendo>()),
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (p, scalar) = witness.cast();
                    let p = Point::alloc(dr, p)?;
                    let scalar = Endoscalar::alloc(dr, scalar)?;
                    scalar.group_scale(dr, &p)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/endoscalar/extract", |b| {
        b.iter_batched(
            || Fp::random(&mut rng),
            |input| {
                BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let elem = Element::alloc(dr, witness)?;
                    Endoscalar::extract(dr, elem)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/endoscalar/field_scale", |b| {
        b.iter_batched(
            || rng.r#gen::<Uendo>(),
            |scalar| {
                BenchEmulator::emulate_wireless(scalar, |dr, witness| {
                    let scalar = Endoscalar::alloc(dr, witness)?;
                    scalar.field_scale(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = endoscalar_ops;
    config = Criterion::default();
    targets = bench_endoscalar_ops
}

criterion_group! {
    name = element_ops;
    config = Criterion::default();
    targets = bench_element_ops
}

criterion_group! {
    name = point_ops;
    config = Criterion::default();
    targets = bench_point_ops
}

criterion_group! {
    name = boolean_ops;
    config = Criterion::default();
    targets = bench_boolean_ops
}

criterion_group! {
    name = sponge_ops;
    config = Criterion::default();
    targets = bench_sponge_ops
}

criterion_main!(
    element_ops,
    point_ops,
    boolean_ops,
    sponge_ops,
    endoscalar_ops
);
