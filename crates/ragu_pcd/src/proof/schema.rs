//! Crate-local proof schema. Every field is either retained with an explicit
//! codec or derived. Checked fields also name their polynomial and batch.
//! Generating both representations here makes an unclassified field a build
//! error without adding a general-purpose derive to another crate.

macro_rules! check_native {
    ($sink:ident, $proof:ident, native $field:ident $partner:ident) => {
        crate::wire::Checked::check($sink, &$proof.$partner, &$proof.$field);
    };
    ($sink:ident, $proof:ident, nested $field:ident $partner:ident) => {};
}
macro_rules! check_nested {
    ($sink:ident, $proof:ident, nested $field:ident $partner:ident) => {
        crate::wire::Checked::check($sink, &$proof.$partner, &$proof.$field);
    };
    ($sink:ident, $proof:ident, native $field:ident $partner:ident) => {};
}
pub(super) use check_native;
pub(super) use check_nested;

macro_rules! proof_schema {
    (
        $(#[$doc:meta])* <$C:ident, $R:ident>
        retained {
            $( $(#[$attr:meta])* $vis:vis $field:ident: $ty:ty => [$codec:ty] $(; $batch:ident $partner:ident)? , )*
        }
        derived {
            $( $(#[$dattr:meta])* $dvis:vis $derived:ident: $dty:ty, )*
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct Proof<$C: Cycle, $R: Rank> {
            $( $(#[$attr])* $vis $field: $ty, )*
            $( $(#[$dattr])* $dvis $derived: $dty, )*
        }

        /// Retained proof data. Transcript challenges and reconstructed stages
        /// are omitted; commitments remain and are checked during verification.
        /// Use [`crate::Application::proof_format`] for versioned transport.
        #[derive(Clone)]
        pub struct MinimalProof<$C: Cycle, $R: Rank> {
            $( $(#[$attr])* $vis $field: $ty, )*
        }

        struct ProofDerived<$C: Cycle, $R: Rank> {
            $( $derived: $dty, )*
        }

        impl<$C: Cycle, $R: Rank> Proof<$C, $R> {
            /// Clones the retained data, omitting derived fields.
            pub fn minimize(&self) -> MinimalProof<$C, $R> {
                MinimalProof { $( $field: self.$field.clone(), )* }
            }

            /// Moves the retained data without cloning polynomial buffers.
            pub fn into_minimal(self) -> MinimalProof<$C, $R> {
                let Self { $( $field, )* $( $derived: _, )* } = self;
                MinimalProof { $( $field, )* }
            }

            fn expand(minimal: MinimalProof<$C, $R>, derived: ProofDerived<$C, $R>) -> Self {
                Self { $( $field: minimal.$field, )* $( $derived: derived.$derived, )* }
            }

            pub(crate) fn for_each_checked_native<'p>(
                &'p self,
                sink: &mut CommitmentBatch<'p, $C::CircuitField, $C::HostCurve, $R>,
            ) {
                $( $( schema::check_native!(sink, self, $batch $field $partner); )? )*
            }

            pub(crate) fn for_each_checked_nested<'p>(
                &'p self,
                sink: &mut CommitmentBatch<'p, $C::ScalarField, $C::NestedCurve, $R>,
            ) {
                $( $( schema::check_nested!(sink, self, $batch $field $partner); )? )*
            }
        }

        impl<$C: Cycle, $R: Rank> Encode for MinimalProof<$C, $R> {
            fn encode(&self, output: &mut Vec<u8>) {
                $( <$ty as Encode<$codec>>::encode(&self.$field, output); )*
            }
        }
        impl<$C: Cycle, $R: Rank> Decode for MinimalProof<$C, $R> {
            fn min_encoded_len() -> usize {
                0usize $( .saturating_add(<$ty as Decode<$codec>>::min_encoded_len()) )*
            }
            fn decode<'a>(reader: &mut wire::Reader<'a>) -> core::result::Result<Self, wire::Error<'a>> {
                Ok(Self { $( $field: <$ty as Decode<$codec>>::decode(reader)?, )* })
            }
        }
    };
}
pub(super) use proof_schema;
