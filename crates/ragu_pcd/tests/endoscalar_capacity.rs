//! How many endoscalar `group_scale` calls fit in one application step

use ff::Field;
use ragu_circuits::{polynomials::ProductionRank, registry::CircuitIndex};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pasta::{EpAffine, Fp, Pasta};
use ragu_pcd::{
    ApplicationBuilder,
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};
use ragu_primitives::{
    Element, Endoscalar, Point,
    allocator::{Allocator, Standard},
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

/// Step performing exactly K endoscalar `group_scale` calls chained against
/// a running point accumulator. Each iteration scales the accumulator by the
/// same allocated scalar, so the total work is K independent scalings.
struct ScaleK<const K: usize>;

impl<const K: usize> Step<Pasta> for ScaleK<K> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = (EpAffine, u128);
    type Aux<'source> = ();
    type Left = InputHeader;
    type Right = ();
    type Output = InputHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, (EpAffine, u128)>,
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

        let (p, r) = witness.cast();
        let mut acc = Point::alloc(dr, p)?;
        let r = Endoscalar::alloc(dr, r)?;
        for _ in 0..K {
            acc = r.group_scale(dr, &acc)?;
        }

        let l: &Element<'dr, D> = left.as_gadget();
        let output_gadget: Element<'dr, D> = l.clone();
        let output_data = output_gadget.value().map(|v| *v);
        let output = Encoded::from_gadget(output_gadget);
        Ok(((left, right, output), output_data, D::unit()))
    }
}

fn measure<const K: usize>() -> Result<(usize, usize)> {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .register(ScaleK::<K>)?
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
    report::<5>().expect_err("should bust");
}
