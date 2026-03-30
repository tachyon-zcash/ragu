//! Nested field stages for fuse operations.
//!
//! Each bridge stage witnesses curve points on the native curve and produces
//! commitments used for cross-curve accumulation.

/// Generates a bridge stage module that witnesses curve points with named fields.
///
/// The `parent` argument specifies the Parent stage type for this stage.
/// Use `()` for stages with no parent, or a path like `super::preamble::Stage`
/// for stages that depend on another.
///
/// The `fields` argument specifies named curve point fields.
///
/// # Example
///
/// ```ignore
/// define_bridge_stage!(preamble, parent = (), fields = {
///     native_preamble: C,
///     left_application: C,
///     right_application: C,
/// });
/// ```
macro_rules! define_bridge_stage {
    (
        $(#[$meta:meta])*
        $mod_name:ident,
        parent = $parent:ty,
        fields = {
            $( $field_name:ident : C ),+ $(,)?
        }
    ) => {
        pub mod $mod_name {
            use ragu_arithmetic::CurveAffine;
            use ragu_circuits::polynomials::Rank;
            use ragu_core::{
                Result,
                drivers::{Driver, DriverValue},
                gadgets::{Bound, Gadget, Kind},
                maybe::Maybe,
            };
            use ragu_primitives::{Point, io::Write};

            use core::marker::PhantomData;

            /// Number of fields in this stage.
            pub const NUM: usize = define_bridge_stage!(@count $($field_name)+);

            /// Witness data for this bridge stage.
            $(#[$meta])*
            pub struct Witness<C: CurveAffine> {
                $( pub $field_name: C, )+
            }

            /// Prover-internal output gadget for this bridge stage.
            ///
            /// This is stage communication data, not part of the circuit's
            /// public instance.
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
                ) -> Result<Bound<'dr, D, Self::OutputKind>>
                where
                    Self: 'dr,
                {
                    Ok(Output {
                        $(
                            $field_name: Point::alloc(
                                dr,
                                witness.as_ref().map(|w| w.$field_name)
                            )?,
                        )+
                    })
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use crate::internal::tests::{R, assert_stage_values};
                use ragu_pasta::EqAffine;

                #[test]
                fn stage_values_matches_wire_count() {
                    assert_stage_values(&Stage::<EqAffine, R>::default());
                }
            }
        }
    };

    // Helper: count the number of tokens
    (@count $($token:tt)+) => {
        <[()]>::len(&[ $( define_bridge_stage!(@replace $token ()) ),+ ])
    };
    (@replace $_:tt $sub:expr) => { $sub };
}

pub mod preamble;

define_bridge_stage!(s_prime, parent = super::preamble::Stage<C, R>, fields = {
    registry_wx0: C,
    registry_wx1: C,
});

define_bridge_stage!(inner_error, parent = super::s_prime::Stage<C, R>, fields = {
    native_inner_error: C,
    registry_wy: C,
    stashed_native_preamble: C,
});

define_bridge_stage!(outer_error, parent = super::inner_error::Stage<C, R>, fields = {
    native_outer_error: C,
});

define_bridge_stage!(ab, parent = super::outer_error::Stage<C, R>, fields = {
    a: C,
    b: C,
});

define_bridge_stage!(query, parent = super::ab::Stage<C, R>, fields = {
    native_query: C,
    registry_xy: C,
});

define_bridge_stage!(f, parent = super::query::Stage<C, R>, fields = {
    native_f: C,
});

define_bridge_stage!(eval, parent = super::f::Stage<C, R>, fields = {
    native_eval: C,
});
