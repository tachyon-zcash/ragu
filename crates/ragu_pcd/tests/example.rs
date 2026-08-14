use core::marker::PhantomData;

use group::CurveAffine;
use ragu_pasta::{EpAffine, Fp, Pasta};
use ragu_pcd::app::{
    Bound, Cycle, Driver, DriverValue, Error, Header, Maybe, ProductionRank, Result, Standard,
    application, header,
};
use ragu_primitives::{Element, Endoscalar, Point, poseidon::Sponge};
use rand::{SeedableRng, rngs::StdRng};

/// Header for a hashed leaf value.
#[header(data = F, gadget = Element)]
pub struct LeafNode;

type LeafNodeAlias = LeafNode;

/// Header for a hash node whose value serves as an endoscalar source.
#[header(data = F, gadget = Element)]
pub struct ExponentNode;

/// Header carrying a scaled curve point.
#[header(data = EpAffine, gadget = Point<EpAffine>, field = Fp, alloc = direct)]
pub struct ScaledPoint;

/// Hash a witness field element to produce a leaf.
pub struct WitnessLeaf<'params, C: Cycle> {
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> ragu_pcd::app::Step<C> for WitnessLeaf<'_, C> {
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
        let leaf = Element::alloc(dr, &mut Standard::new(), witness)?;
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, &leaf)?;
        let output = sponge.squeeze(dr)?;
        let output_data = output.value().map(|value| *value);
        Ok((output, output_data, D::unit()))
    }
}

/// Hash two leaf children into an internal node.
pub struct Hash2<'params, C: Cycle> {
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> ragu_pcd::app::Step<C> for Hash2<'_, C> {
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
///
/// Sound only because `ExponentNode` is a Poseidon squeeze: with a
/// prover-chosen element instead of a hash image, `Endoscalar::extract` is
/// ambiguous and one input could yield two valid scaled points. Do not copy
/// this pattern for non-hash headers.
pub struct Endoscale<'params, C: Cycle>(PhantomData<&'params C>);

impl ragu_pcd::app::Step<Pasta> for Endoscale<'_, Pasta> {
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
        // Extract the endoscalar; sound only for hash-image headers (see the
        // type-level note).
        let endo = Endoscalar::extract(dr, &mut Standard::new(), left.clone())?;

        // Create a constant generator point on the nested curve.
        let point = Point::<D, EpAffine>::constant(dr, EpAffine::generator())?;

        // Perform endoscalar group scaling.
        let scaled = endo.group_scale(dr, &point)?;

        let output_data = scaled.value();
        Ok((scaled, output_data, D::unit()))
    }
}

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
#[application(cycle = Pasta, rank = ProductionRank, header_size = 3)]
pub enum ExampleApp {
    // Canonicalization lets alternate paths or aliases share one suffix.
    #[produces(LeafNodeAlias, canonical = LeafNode)]
    WitnessLeaf,

    #[produces(ExponentNode)]
    Hash2,

    #[produces(ScaledPoint)]
    Endoscale,
}

macro_rules! boundary_application {
    ($module:ident, $header_size:expr) => {
        #[allow(dead_code)]
        mod $module {
            use super::*;

            #[header(data = F, gadget = Element)]
            pub struct BoundaryHeader;

            pub struct BoundaryStep<'params, C: Cycle>(PhantomData<&'params C>);

            impl<C: Cycle> ragu_pcd::app::Step<C> for BoundaryStep<'_, C> {
                type Witness = C::CircuitField;
                type Left = ();
                type Right = ();
                type Output = BoundaryHeader;
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
                    let output = Element::alloc(dr, &mut Standard::new(), witness)?;
                    let output_data = output.value().map(|value| *value);
                    Ok((output, output_data, D::unit()))
                }
            }

            #[application(cycle = Pasta, rank = ProductionRank, header_size = $header_size)]
            pub enum BoundaryApp {
                #[produces(BoundaryHeader)]
                BoundaryStep,
            }

            pub fn build() -> Result<BoundaryApp<'static, Pasta, ProductionRank>> {
                BoundaryApp::build(Pasta::baked(), BoundaryStep(PhantomData))
            }
        }
    };
}

boundary_application!(zero_header_size_app, 0);
boundary_application!(undersized_header_app, 1);

// Compile-time regression coverage for identifiers and paths that overlap
// names generated by the attribute macros.
#[allow(dead_code)]
mod macro_hygiene {
    use super::*;

    // This intentionally shadows the external crate for relative paths. The
    // absolute gadget path below must remain absolute in generated code.
    mod ragu_primitives {
        pub struct Element;
    }

    #[header(data = F, gadget = ::ragu_primitives::Element)]
    struct AbsoluteHeader;

    // This intentionally matches the macro's preferred driver parameter name;
    // generated identifiers must be made fresh before they are emitted.
    #[header(data = __RaguHeaderDriver, gadget = Element)]
    struct CollisionHeader;

    // `C` used to resolve to the cycle parameter emitted by `#[application]`
    // instead of this step type.
    struct C<'params, T: Cycle>(PhantomData<fn(&'params T)>);

    impl<T: Cycle> ragu_pcd::app::Step<T> for C<'_, T> {
        type Witness = T::CircuitField;
        type Left = ();
        type Right = ();
        type Output = CollisionHeader;
        type Aux = ();

        fn synthesize<'dr, D: Driver<'dr, F = T::CircuitField>, const HEADER_SIZE: usize>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness>,
            _left: &Bound<'dr, D, <Self::Left as Header<T::CircuitField>>::Output>,
            _right: &Bound<'dr, D, <Self::Right as Header<T::CircuitField>>::Output>,
        ) -> Result<(
            Bound<'dr, D, <Self::Output as Header<T::CircuitField>>::Output>,
            DriverValue<D, <Self::Output as Header<T::CircuitField>>::Data>,
            DriverValue<D, Self::Aux>,
        )>
        where
            Self: 'dr,
        {
            let output = Element::alloc(dr, &mut Standard::new(), witness)?;
            let output_data = output.value().map(|value| *value);
            Ok((output, output_data, D::unit()))
        }
    }

    #[application(cycle = Pasta, rank = ProductionRank, header_size = 2)]
    enum CollisionApp {
        #[produces(CollisionHeader)]
        C,
    }

    // An application named after the macro's preferred cycle parameter: the
    // generated wrapper's self type must keep resolving to the wrapper rather
    // than to a generic parameter.
    mod application_named_c {
        use super::*;

        #[header(data = F, gadget = Element)]
        pub struct NamedHeader;

        // Spelled like the generated assertion trait: the alias must stay
        // visible where the generated canonical-type assertion names it.
        type __RaguSameHeaderType = NamedHeader;

        pub struct NamedStep<'params, T: Cycle>(PhantomData<fn(&'params T)>);

        impl<T: Cycle> ragu_pcd::app::Step<T> for NamedStep<'_, T> {
            type Witness = T::CircuitField;
            type Left = ();
            type Right = ();
            type Output = NamedHeader;
            type Aux = ();

            fn synthesize<'dr, D: Driver<'dr, F = T::CircuitField>, const HEADER_SIZE: usize>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness>,
                _left: &Bound<'dr, D, <Self::Left as Header<T::CircuitField>>::Output>,
                _right: &Bound<'dr, D, <Self::Right as Header<T::CircuitField>>::Output>,
            ) -> Result<(
                Bound<'dr, D, <Self::Output as Header<T::CircuitField>>::Output>,
                DriverValue<D, <Self::Output as Header<T::CircuitField>>::Data>,
                DriverValue<D, Self::Aux>,
            )>
            where
                Self: 'dr,
            {
                let output = Element::alloc(dr, &mut Standard::new(), witness)?;
                let output_data = output.value().map(|value| *value);
                Ok((output, output_data, D::unit()))
            }
        }

        #[application(cycle = Pasta, rank = ProductionRank, header_size = 2)]
        pub enum C {
            #[produces(__RaguSameHeaderType, canonical = NamedHeader)]
            NamedStep,
        }
    }

    // Caller types spelled exactly like the generated generic parameters: the
    // macros must freshen their names rather than capture these.
    mod shadowed_parameter_names {
        use ::ragu_primitives::Element as __RaguHeaderAllocator;

        use super::*;

        type C = Pasta;
        type __R = ProductionRank;
        type __RaguHeaderDriver = Fp;

        #[header(data = F, gadget = __RaguHeaderAllocator)]
        pub struct AllocatorShadowHeader;

        // A field parameter named after the gadget is accepted when the
        // gadget path is absolute, which a generic parameter cannot shadow.
        #[header(data = Element, gadget = ::ragu_primitives::Element)]
        pub struct AbsoluteGadgetHeader;

        // The same in raw spelling: collision checks normalize raw
        // identifiers but must not over-reject absolute paths.
        #[header(data = r#Element, gadget = ::ragu_primitives::Element)]
        pub struct RawAbsoluteGadgetHeader;

        #[header(
            data = EpAffine,
            gadget = Point<EpAffine>,
            field = __RaguHeaderDriver,
            alloc = direct
        )]
        pub struct DriverShadowHeader;

        pub struct ShadowStep<'params, T: Cycle>(PhantomData<fn(&'params T)>);

        impl<T: Cycle> ragu_pcd::app::Step<T> for ShadowStep<'_, T> {
            type Witness = T::CircuitField;
            type Left = ();
            type Right = ();
            type Output = AllocatorShadowHeader;
            type Aux = ();

            fn synthesize<'dr, D: Driver<'dr, F = T::CircuitField>, const HEADER_SIZE: usize>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness>,
                _left: &Bound<'dr, D, <Self::Left as Header<T::CircuitField>>::Output>,
                _right: &Bound<'dr, D, <Self::Right as Header<T::CircuitField>>::Output>,
            ) -> Result<(
                Bound<'dr, D, <Self::Output as Header<T::CircuitField>>::Output>,
                DriverValue<D, <Self::Output as Header<T::CircuitField>>::Data>,
                DriverValue<D, Self::Aux>,
            )>
            where
                Self: 'dr,
            {
                let output = Element::alloc(dr, &mut Standard::new(), witness)?;
                let output_data = output.value().map(|value| *value);
                Ok((output, output_data, D::unit()))
            }
        }

        #[application(cycle = C, rank = __R, header_size = 2)]
        pub enum ShadowApp {
            #[produces(AllocatorShadowHeader)]
            ShadowStep,
        }
    }

    // A step named exactly like the marker trait the macro derives from the
    // enum name: the marker must be freshened away from it.
    mod marker_named_step {
        use super::*;

        #[header(data = F, gadget = Element)]
        pub struct MarkerHeader;

        pub struct __RaguApplicationStepForApp<'params, T: Cycle>(pub PhantomData<fn(&'params T)>);

        impl<T: Cycle> ragu_pcd::app::Step<T> for __RaguApplicationStepForApp<'_, T> {
            type Witness = T::CircuitField;
            type Left = ();
            type Right = ();
            type Output = MarkerHeader;
            type Aux = ();

            fn synthesize<'dr, D: Driver<'dr, F = T::CircuitField>, const HEADER_SIZE: usize>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness>,
                _left: &Bound<'dr, D, <Self::Left as Header<T::CircuitField>>::Output>,
                _right: &Bound<'dr, D, <Self::Right as Header<T::CircuitField>>::Output>,
            ) -> Result<(
                Bound<'dr, D, <Self::Output as Header<T::CircuitField>>::Output>,
                DriverValue<D, <Self::Output as Header<T::CircuitField>>::Data>,
                DriverValue<D, Self::Aux>,
            )>
            where
                Self: 'dr,
            {
                let output = Element::alloc(dr, &mut Standard::new(), witness)?;
                let output_data = output.value().map(|value| *value);
                Ok((output, output_data, D::unit()))
            }
        }

        #[application(cycle = Pasta, rank = ProductionRank, header_size = 2)]
        pub enum App {
            #[produces(MarkerHeader)]
            __RaguApplicationStepForApp,
        }
    }

    #[test]
    fn generated_identifiers_and_absolute_paths_compile() {
        fn assert_header_content<H: ragu_pcd::app::HeaderContent<Fp>>() {}

        assert_header_content::<AbsoluteHeader>();
        assert_header_content::<shadowed_parameter_names::DriverShadowHeader>();
        assert_header_content::<shadowed_parameter_names::AbsoluteGadgetHeader>();
        assert_header_content::<shadowed_parameter_names::RawAbsoluteGadgetHeader>();
        assert_eq!(
            <marker_named_step::MarkerHeader as Header<Fp>>::SUFFIX.get(),
            2
        );
        assert_eq!(<CollisionHeader as Header<Fp>>::SUFFIX.get(), 2);
        assert_eq!(
            <application_named_c::NamedHeader as Header<Fp>>::SUFFIX.get(),
            2
        );
        assert_eq!(
            <shadowed_parameter_names::AllocatorShadowHeader as Header<Fp>>::SUFFIX.get(),
            2
        );
    }
}

#[test]
fn zero_header_size_is_rejected() {
    let result = zero_header_size_app::build();
    assert!(matches!(result, Err(Error::Initialization(_))));
}

#[test]
fn undersized_header_is_rejected() {
    // A one-element header has room only for the suffix, but BoundaryHeader
    // also encodes one field element.
    let result = undersized_header_app::build();
    assert!(matches!(result, Err(Error::MalformedEncoding(_))));
}

#[test]
fn example_pipeline() -> Result<()> {
    let pasta = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);

    let app: ExampleApp = ExampleApp::build(
        pasta,
        WitnessLeaf {
            poseidon_params: poseidon,
        },
        Hash2 {
            poseidon_params: poseidon,
        },
        Endoscale(PhantomData),
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

    // The proof commits to the original leaf header. Reattaching different
    // carried data succeeds locally, but wrapper verification must reject it.
    let mismatched_leaf = leaf1
        .proof()
        .clone()
        .carry::<LeafNode>(*leaf1.data() + Fp::from(1u64));
    assert!(!app.verify(&mismatched_leaf, &mut rng)?);

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
    assert!(app.verify(&trivial, &mut rng)?);
    let (scaled, _) = app.fuse(&mut rng, Endoscale(PhantomData), (), internal, trivial)?;
    assert!(app.verify(&scaled, &mut rng)?);

    Ok(())
}
