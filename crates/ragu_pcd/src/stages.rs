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

pub mod nested {
    define_nested_point_stage!(preamble, parent = ());
}

pub mod native {
    pub mod preamble;
}
