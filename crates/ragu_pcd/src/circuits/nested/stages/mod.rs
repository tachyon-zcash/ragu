//! Nested field stages for fuse operations.

/// Generates a nested stage module that witnesses curve points with named fields.
///
/// The `parent` argument specifies the Parent stage type for this stage.
/// Use `()` for stages with no parent, or a path like `super::nested_preamble::Stage`
/// for stages that depend on another.
///
/// The `fields` argument specifies named curve point fields.
///
/// # Example
///
/// ```ignore
/// define_nested_stage!(preamble, parent = (), fields = {
///     native_preamble: C,
///     left_application: C,
///     right_application: C,
/// });
/// ```
macro_rules! define_nested_stage {
    (
        $(#[$meta:meta])*
        $mod_name:ident,
        parent = $parent:ty,
        fields = {
            $( $field_name:ident : C ),+ $(,)?
        }
    ) => {
        pub mod $mod_name {
            use arithmetic::CurveAffine;
            use ragu_circuits::polynomials::Rank;
            use ragu_core::{
                Result,
                drivers::{Driver, DriverValue},
                gadgets::{Gadget, GadgetKind, Kind},
                maybe::Maybe,
            };
            use ragu_primitives::{Point, io::Write};

            use core::marker::PhantomData;

            /// Number of fields in this stage.
            pub const NUM: usize = define_nested_stage!(@count $($field_name)+);

            /// Witness data for this nested stage.
            $(#[$meta])*
            pub struct Witness<C: CurveAffine> {
                $( pub $field_name: C, )+
            }

            /// Output gadget for this nested stage.
            #[derive(Gadget, Write)]
            pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
                $(
                    #[ragu(gadget)]
                    pub $field_name: Point<'dr, D, C>,
                )+
            }

            $(#[$meta])*
            #[derive(Default)]
            pub struct Stage<C: CurveAffine, R> {
                _marker: PhantomData<(C, R)>,
            }

            impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R>
                for Stage<C, R>
            {
                type Parent = $parent;
                type Witness<'source> = &'source Witness<C>;
                type OutputKind = Kind![C::Base; Output<'_, _, C>];

                fn values() -> usize {
                    NUM * 2
                }

                fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
                    &self,
                    dr: &mut D,
                    witness: DriverValue<D, Self::Witness<'source>>,
                ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
                where
                    Self: 'dr,
                {
                    Ok(Output {
                        $(
                            $field_name: Point::alloc(
                                dr,
                                witness.view().map(|w| w.$field_name)
                            )?,
                        )+
                    })
                }
            }
        }
    };

    // Helper: count the number of tokens
    (@count $($token:tt)+) => {
        <[()]>::len(&[ $( define_nested_stage!(@replace $token ()) ),+ ])
    };
    (@replace $_:tt $sub:expr) => { $sub };
}

pub mod preamble;

define_nested_stage!(s_prime, parent = super::preamble::Stage<C, R>, fields = {
    registry_wx0: C,
    registry_wx1: C,
});

define_nested_stage!(error_m, parent = super::s_prime::Stage<C, R>, fields = {
    native_error_m: C,
    registry_wy: C,
});

define_nested_stage!(error_n, parent = super::error_m::Stage<C, R>, fields = {
    native_error_n: C,
});

define_nested_stage!(ab, parent = super::error_n::Stage<C, R>, fields = {
    a: C,
    b: C,
});

define_nested_stage!(query, parent = super::ab::Stage<C, R>, fields = {
    native_query: C,
    registry_xy: C,
});

define_nested_stage!(f, parent = super::query::Stage<C, R>, fields = {
    native_f: C,
});

define_nested_stage!(eval, parent = super::f::Stage<C, R>, fields = {
    native_eval: C,
});
