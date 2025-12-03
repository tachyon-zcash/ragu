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
            //! Nested stage for merge operations.

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

// Use macro to generate the 7 identical nested point stages
// All currently have Parent = (), but this can change in the future
define_nested_point_stage!(
    /// The nested preamble stage witnesses the commitment point from the preamble stage.
    nested_preamble,
    parent = ()
);
define_nested_point_stage!(
    /// The nested s stage witnesses the mesh polynomial commitment at (x, y).
    nested_s,
    parent = ()
);
define_nested_point_stage!(
    /// The nested s'' stage witnesses the mesh polynomial commitment at (w, y).
    nested_s_doubleprime,
    parent = ()
);
define_nested_point_stage!(
    /// The nested error stage witnesses the error commitment point.
    nested_error,
    parent = ()
);
define_nested_point_stage!(
    /// The nested query stage witnesses the query commitment point.
    nested_query,
    parent = ()
);
define_nested_point_stage!(
    /// The nested eval stage witnesses the eval commitment point.
    nested_eval,
    parent = ()
);
define_nested_point_stage!(
    /// The nested F stage witnesses the F polynomial commitment point.
    nested_f,
    parent = ()
);

// Keep these as separate files (different structure - two points each):
pub mod nested_ab;
pub mod nested_s_prime;

// Keep other stages as separate files:
pub mod native_error;
pub mod native_eval;
pub mod native_preamble;
pub mod native_query;
