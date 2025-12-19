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
            use ragu_primitives::Point;

            use core::marker::PhantomData;

            /// Number of fields in this stage.
            pub const NUM: usize = define_nested_stage!(@count $($field_name)+);

            /// Witness data for this nested stage.
            $(#[$meta])*
            pub struct Witness<C: CurveAffine> {
                $( pub $field_name: C, )+
            }

            /// Output gadget for this nested stage.
            #[derive(Gadget)]
            pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine> {
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

pub mod nested {
    define_nested_stage!(preamble, parent = (), fields = {
        native_preamble: C,
        left_application: C,
        right_application: C,
        left_ky: C,
        right_ky: C,
        left_c: C,
        right_c: C,
        left_v: C,
        right_v: C,
        left_hashes_1: C,
        right_hashes_1: C,
        left_hashes_2: C,
        right_hashes_2: C,
    });

    define_nested_stage!(s_prime, parent = (), fields = {
        mesh_wx0: C,
        mesh_wx1: C,
    });

    define_nested_stage!(error_m, parent = (), fields = {
        native_error_m: C,
        mesh_wy: C,
    });

    define_nested_stage!(error_n, parent = (), fields = {
        native_error_n: C,
    });

    define_nested_stage!(ab, parent = (), fields = {
        a: C,
        b: C,
    });

    define_nested_stage!(query, parent = (), fields = {
        native_query: C,
        mesh_xy: C,
    });

    define_nested_stage!(f, parent = (), fields = {
        native_f: C,
    });

    define_nested_stage!(eval, parent = (), fields = {
        native_eval: C,
    });
}

pub mod native {
    pub mod error_m;
    pub mod error_n;
    pub mod eval;
    pub mod preamble;
    pub mod query;
}
