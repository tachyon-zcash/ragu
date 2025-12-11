/// Generates a simple nested stage that witnesses a single curve point.
///
/// The `parent` argument specifies the Parent stage type for this stage.
/// Use `()` for stages with no parent, or a path like `super::nested_preamble::Stage`
/// for stages that depend on another.
macro_rules! define_nested_point_stage {
    (
        $(#[$meta:meta])*
        $mod_name:ident,
        parent = $parent:ty
    ) => {
        pub mod $mod_name {
            use arithmetic::CurveAffine;
            use ragu_circuits::polynomials::Rank;
            use ragu_core::{
                Result,
                drivers::{Driver, DriverValue},
                gadgets::{GadgetKind, Kind},
            };
            use ragu_primitives::Point;

            use core::marker::PhantomData;

            $(#[$meta])*
            pub struct Stage<C: CurveAffine, R> {
                _marker: PhantomData<(C, R)>,
            }

            impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
                type Parent = $parent;
                type Witness<'source> = C;
                type OutputKind = Kind![C::Base; Point<'_, _, C>];

                fn values() -> usize {
                    2
                }

                fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
                    dr: &mut D,
                    witness: DriverValue<D, Self::Witness<'source>>,
                ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
                where
                    Self: 'dr,
                {
                    Point::alloc(dr, witness)
                }
            }
        }
    };
}

/// Generates a simple nested stage module that witnesses multiple curve points.
///
/// Similar to `define_nested_point_stage!` but for multiple points.
macro_rules! define_nested_multi_point_stage {
    (
        $(#[$meta:meta])*
        $mod_name:ident,
        parent = $parent:ty
    ) => {
        pub mod $mod_name {
            use arithmetic::CurveAffine;
            use core::marker::PhantomData;
            use ragu_circuits::polynomials::Rank;
            use ragu_core::{
                Result,
                drivers::{Driver, DriverValue},
                gadgets::{GadgetKind, Kind},
                maybe::Maybe,
            };
            use ragu_primitives::{Point, vec::{CollectFixed, ConstLen, FixedVec}};

            $(#[$meta])*
            pub struct Stage<C: CurveAffine, R, const NUM: usize> {
                _marker: PhantomData<(C, R)>,
            }

            impl<C: CurveAffine, R: Rank, const NUM: usize> ragu_circuits::staging::Stage<C::Base, R>
                for Stage<C, R, NUM>
            {
                type Parent = $parent;
                type Witness<'source> = &'source [C; NUM];
                type OutputKind = Kind![C::Base; FixedVec<Point<'_, _, C>, ConstLen<NUM>>];

                fn values() -> usize {
                    NUM * 2
                }

                fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
                    dr: &mut D,
                    witness: DriverValue<D, Self::Witness<'source>>,
                ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
                where
                    Self: 'dr,
                {
                    (0..NUM)
                        .map(|i| Point::alloc(dr, witness.view().map(|w| w[i])))
                        .try_collect_fixed()
                }
            }
        }
    };
}

pub mod nested {
    define_nested_multi_point_stage!(preamble, parent = ());
    define_nested_point_stage!(query, parent = ());
    define_nested_point_stage!(f, parent = ());
    define_nested_point_stage!(eval, parent = ());
}

pub mod native {
    pub mod eval;
    pub mod preamble;
    pub mod query;
}
