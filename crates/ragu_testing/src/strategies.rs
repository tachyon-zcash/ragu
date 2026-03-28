//! Shared proptest strategies for Ragu crates.

use ff::PrimeField;
use proptest::{prelude::*, sample::select, strategy::BoxedStrategy};
use ragu_arithmetic::{Coeff, Domain};

fn edge_u64() -> impl Strategy<Value = u64> + Clone {
    let edges = vec![
        0,
        1,
        2,
        7,
        8,
        15,
        16,
        31,
        32,
        63,
        64,
        127,
        128,
        255,
        256,
        511,
        512,
        1023,
        1024,
        u16::MAX as u64,
        u32::MAX as u64,
        u64::MAX,
    ];
    prop_oneof![
        (select(edges), 0u64..64).prop_map(|(e, d)| e.wrapping_add(d)),
        any::<u64>(),
    ]
}

fn edge_field_element<F>() -> impl Strategy<Value = F> + Clone
where
    F: PrimeField + From<u64> + 'static,
{
    prop_oneof![
        Just(F::ZERO),
        Just(F::ONE),
        Just(F::ONE.double()),
        Just(-F::ONE),
        edge_u64().prop_map(F::from),
        edge_u64().prop_map(|x| -F::from(x)),
        edge_u64().prop_map(|x| F::from(x) * F::MULTIPLICATIVE_GENERATOR),
        edge_u64().prop_map(|x| F::from(x) * F::DELTA),
    ]
}

/// Generates field elements with mixed edge-biased and broad coverage.
pub fn prime_field_element<F>() -> BoxedStrategy<F>
where
    F: PrimeField + From<u64> + 'static,
{
    prop_oneof![
        6 => edge_field_element(),
        8 => (any::<u64>(), any::<u64>())
            .prop_map(|(a, b)| F::from(a) + F::from(b) * F::MULTIPLICATIVE_GENERATOR),
        4 => (any::<u64>(), any::<u64>())
            .prop_map(|(a, b)| F::from(a) * F::DELTA + F::from(b)),
    ]
    .boxed()
}

fn nonzero_prime_field_element<F>() -> BoxedStrategy<F>
where
    F: PrimeField + From<u64> + 'static,
{
    prime_field_element::<F>()
        .prop_filter("non-zero field element", |value| {
            !bool::from(value.is_zero())
        })
        .boxed()
}

/// Generates all coefficient variants, including arbitrary field elements.
pub fn coeff<F>() -> BoxedStrategy<Coeff<F>>
where
    F: PrimeField + From<u64> + 'static,
{
    prop_oneof![
        Just(Coeff::Zero),
        Just(Coeff::One),
        Just(Coeff::Two),
        Just(Coeff::NegativeOne),
        prime_field_element::<F>().prop_map(Coeff::Arbitrary),
        nonzero_prime_field_element::<F>().prop_map(Coeff::NegativeArbitrary),
    ]
    .boxed()
}

/// Generates root multisets that exercise boundary sizes, repeated roots, and roots of unity.
pub fn poly_with_roots<F>() -> BoxedStrategy<Vec<F>>
where
    F: PrimeField + From<u64> + 'static,
{
    let w = Domain::<F>::new(6).omega();

    prop_oneof![
        select(vec![
            0usize, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 633,
        ])
        .prop_map(|n| (0..n).map(|i| F::from(i as u64) + F::DELTA).collect()),
        Just(vec![F::from(7); 2]),
        Just(vec![F::from(3); 4]),
        Just(vec![F::from(5); 8]),
        Just(vec![F::ZERO, F::from(1), F::from(2)]),
        Just(vec![F::ZERO; 5]),
        Just((0..4).map(|i| w.pow([i * 16])).collect()),
        Just((0..16).map(|i| w.pow([i * 4])).collect()),
        Just((0..64).map(|i| w.pow([i as u64])).collect()),
        Just(vec![
            w,
            w,
            w.square(),
            w.square(),
            F::from(42),
            F::from(123),
        ]),
        (1usize..100).prop_flat_map(|n| proptest::collection::vec(prime_field_element::<F>(), n)),
        (prime_field_element::<F>(), 1usize..20).prop_map(|(root, n)| vec![root; n]),
    ]
    .boxed()
}
