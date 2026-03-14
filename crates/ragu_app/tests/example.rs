use group::prime::PrimeCurveAffine;
use ragu_app::{Bound, Cycle, Driver, DriverValue, Header, Result, application, header};
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::maybe::Maybe;
use ragu_pasta::{EpAffine, Fp, Pasta};
use ragu_primitives::{Element, Endoscalar, Point, poseidon::Sponge};
use rand::SeedableRng;
use rand::rngs::StdRng;

// ==========================================================================
// Headers
// ==========================================================================

/// Header for a hashed leaf value.
#[header(data = F, gadget = Element)]
pub struct LeafNode;

/// Header for a hash node whose value serves as an endoscalar source.
#[header(data = F, gadget = Element)]
pub struct ExponentNode;

/// Header carrying a scaled curve point.
#[header(data = EpAffine, gadget = Point<EpAffine>, field = Fp)]
pub struct ScaledPoint;

// ==========================================================================
// Steps
// ==========================================================================

/// Hash a witness field element to produce a leaf.
pub struct WitnessLeaf<'params, C: Cycle> {
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> ragu_app::Step<C> for WitnessLeaf<'_, C> {
    type Witness = C::CircuitField;
    type Left = ();
    type Right = ();
    type Output = LeafNode;
    type Aux = ();

    fn synthesize<'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness>,
        _left: &Bound<'dr, D, <Self::Left as Header<C::CircuitField>>::Output>,
        _right: &Bound<'dr, D, <Self::Right as Header<C::CircuitField>>::Output>,
    ) -> Result<(
        Bound<'dr, D, <Self::Output as Header<C::CircuitField>>::Output>,
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux>,
    )>
    where
        Self: 'dr,
    {
        let leaf = Element::alloc(dr, witness)?;
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, &leaf)?;
        let output = sponge.squeeze(dr)?;
        let output_data = output.value().map(|v| *v);
        Ok((output, output_data, D::unit()))
    }
}

/// Hash two leaf children into an internal node.
pub struct Hash2<'params, C: Cycle> {
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> ragu_app::Step<C> for Hash2<'_, C> {
    type Witness = ();
    type Left = LeafNode;
    type Right = LeafNode;
    type Output = ExponentNode;
    type Aux = ();

    fn synthesize<'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _witness: DriverValue<D, Self::Witness>,
        left: &Bound<'dr, D, <Self::Left as Header<C::CircuitField>>::Output>,
        right: &Bound<'dr, D, <Self::Right as Header<C::CircuitField>>::Output>,
    ) -> Result<(
        Bound<'dr, D, <Self::Output as Header<C::CircuitField>>::Output>,
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux>,
    )>
    where
        Self: 'dr,
    {
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, left)?;
        sponge.absorb(dr, right)?;
        let output = sponge.squeeze(dr)?;
        let output_data = output.value().map(|v| *v);
        Ok((output, output_data, D::unit()))
    }
}

/// Extract an endoscalar from the internal node hash and perform
/// endoscalar group scaling on the generator point.
pub struct Endoscale;

impl ragu_app::Step<Pasta> for Endoscale {
    type Witness = ();
    type Left = ExponentNode;
    type Right = ();
    type Output = ScaledPoint;
    type Aux = ();

    fn synthesize<'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _witness: DriverValue<D, Self::Witness>,
        left: &Bound<'dr, D, <Self::Left as Header<Fp>>::Output>,
        _right: &Bound<'dr, D, <Self::Right as Header<Fp>>::Output>,
    ) -> Result<(
        Bound<'dr, D, <Self::Output as Header<Fp>>::Output>,
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux>,
    )>
    where
        Self: 'dr,
    {
        // Extract endoscalar from the internal node's hash element.
        let endo = Endoscalar::extract(dr, left.clone())?;

        // Create a constant generator point on the nested curve.
        let point = Point::<D, EpAffine>::constant(dr, EpAffine::generator())?;

        // Perform endoscalar group scaling.
        let scaled = endo.group_scale(dr, &point)?;

        let output_data = scaled.value();
        Ok((scaled, output_data, D::unit()))
    }
}

// ==========================================================================
// Application
// ==========================================================================

/// Example PCD application demonstrating a three-step pipeline:
/// Poseidon hashing, Merkle-style merging, and endoscalar group scaling.
///
/// ```text
/// WitnessLeaf  WitnessLeaf
///     |            |
/// [LeafNode]   [LeafNode]
///       \        /
///          Hash2
///            |
///     [ExponentNode]  [trivial right]
///            \         /
///             Endoscale
///                 |
///           [ScaledPoint]
/// ```
#[application]
pub enum ExampleApp<'params, C: Cycle> {
    #[step(output = LeafNode)]
    WitnessLeaf(WitnessLeaf<'params, C>),

    #[step(output = ExponentNode)]
    Hash2(Hash2<'params, C>),

    #[step(output = ScaledPoint)]
    Endoscale(Endoscale),
}

#[test]
fn example_pipeline() -> Result<()> {
    let pasta = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);

    let app = ExampleApp::<Pasta, ProductionRank, 4>::build(
        pasta,
        WitnessLeaf {
            poseidon_params: poseidon,
        },
        Hash2 {
            poseidon_params: poseidon,
        },
        Endoscale,
    )?;

    let mut rng = StdRng::seed_from_u64(5678);

    // Create two leaves.
    let (leaf1, _) = app.seed(
        &mut rng,
        WitnessLeaf {
            poseidon_params: poseidon,
        },
        Fp::from(100u64),
    )?;
    assert!(app.verify(&leaf1, &mut rng)?);

    let (leaf2, _) = app.seed(
        &mut rng,
        WitnessLeaf {
            poseidon_params: poseidon,
        },
        Fp::from(200u64),
    )?;
    assert!(app.verify(&leaf2, &mut rng)?);

    // Hash the two leaves into an internal node.
    let (internal, _) = app.fuse(
        &mut rng,
        Hash2 {
            poseidon_params: poseidon,
        },
        (),
        leaf1,
        leaf2,
    )?;
    assert!(app.verify(&internal, &mut rng)?);

    // Extract endoscalar from the hash and scale the generator.
    let trivial = app.trivial_pcd(&mut rng);
    let (scaled, _) = app.fuse(&mut rng, Endoscale, (), internal, trivial)?;
    assert!(app.verify(&scaled, &mut rng)?);

    Ok(())
}
