//! How many Poseidon permutations fit in one application step

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::ProductionRank, registry::CircuitIndex};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{
    ApplicationBuilder,
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
    poseidon::Sponge,
};

const HEADER_SIZE: usize = 2;

/// 1-element input header, sized to fit a single `Fp` plus the suffix slot.
struct InputHeader;

impl<F: Field> Header<F> for InputHeader {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

/// Step performing exactly K Poseidon permutations chained linearly. Each
/// iteration creates a fresh sponge so the total work is K independent
/// permutations regardless of sponge rate.
struct HashK<const K: usize>;

impl<const K: usize> Step<Pasta> for HashK<K> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = InputHeader;
    type Right = ();
    type Output = InputHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HS>,
            Encoded<'dr, D, Self::Right, HS>,
            Encoded<'dr, D, Self::Output, HS>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::from_gadget(());

        let l: &Element<'dr, D> = left.as_gadget();
        let mut current: Element<'dr, D> = l.clone();
        for _ in 0..K {
            let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(Pasta::baked()),
            );
            sponge.absorb(dr, &current)?;
            current = sponge.squeeze(dr)?;
        }

        let output_data = current.value().map(|v| *v);
        let output = Encoded::from_gadget(current);
        Ok(((left, right, output), output_data, D::unit()))
    }
}

fn measure<const K: usize>() -> Result<(usize, usize)> {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .register(HashK::<K>)?
        .finalize(pasta)?;
    let last = CircuitIndex::new(app.native_registry().num_circuits() - 1);
    Ok(app.native_registry().constraint_counts(last))
}

fn report<const K: usize>() -> Result<()> {
    match measure::<K>() {
        Ok((g, c)) => {
            std::println!("{K:>10}{g:>10}{c:>10}");
            Ok(())
        }
        Err(e) => {
            std::println!("{K:>10}  {e}");
            Err(e)
        }
    }
}

#[test]
fn k_sweep() {
    std::println!("\n{:>10}{:>10}{:>10}", "K", "gates", "constr");

    report::<1>().expect("should fit");
    report::<2>().expect("should fit");
    report::<3>().expect("should fit");
    report::<4>().expect("should fit");
    report::<5>().expect("should fit");
    report::<6>().expect("should fit");
    report::<7>().expect("should fit");
    report::<8>().expect_err("should bust");
}
