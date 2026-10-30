//! Crate-local proof schema. Every field is either retained with an explicit
//! codec or derived. Generating both representations here makes an
//! unclassified field a build error without adding a general-purpose derive
//! to another crate.

macro_rules! proof_schema {
    (
        $(#[$doc:meta])* <$C:ident, $R:ident, const $H:ident: usize>
        retained {
            $( $(#[$attr:meta])* $vis:vis $field:ident: $ty:ty => [$codec:ty], )*
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
        /// The profile, rank and header size fix its encoded length.
        /// Use [`crate::Application::proof_format`] for versioned transport.
        #[derive(Clone)]
        pub struct MinimalProof<$C: Cycle, $R: Rank, const $H: usize> {
            $( $(#[$attr])* $vis $field: $ty, )*
        }

        struct ProofDerived<$C: Cycle, $R: Rank> {
            $( $derived: $dty, )*
        }

        impl<$C: Cycle, $R: Rank> Proof<$C, $R> {
            /// Clones the retained data, omitting derived fields.
            pub fn minimize<const $H: usize>(&self) -> MinimalProof<$C, $R, $H> {
                MinimalProof { $( $field: self.$field.clone(), )* }
            }

            /// Moves the retained data without cloning polynomial buffers.
            pub fn into_minimal<const $H: usize>(self) -> MinimalProof<$C, $R, $H> {
                let Self { $( $field, )* $( $derived: _, )* } = self;
                MinimalProof { $( $field, )* }
            }

            fn expand<const $H: usize>(
                minimal: MinimalProof<$C, $R, $H>,
                derived: ProofDerived<$C, $R>,
            ) -> Self {
                Self { $( $field: minimal.$field, )* $( $derived: derived.$derived, )* }
            }
        }

        impl<$C: ProfiledCycle, $R: Rank, const $H: usize> Encode for MinimalProof<$C, $R, $H> {
            fn encode(&self, output: &mut Vec<u8>) {
                $( <$ty as Encode<$codec>>::encode(&self.$field, output); )*
            }
        }
        impl<$C: ProfiledCycle, $R: Rank, const $H: usize> Decode for MinimalProof<$C, $R, $H> {
            fn encoded_len() -> usize {
                0usize $( + <$ty as Decode<$codec>>::encoded_len() )*
            }
            fn decode<'a>(reader: &mut wire::Reader<'a>) -> core::result::Result<Self, wire::Error<'a>> {
                Ok(Self { $( $field: <$ty as Decode<$codec>>::decode(reader)?, )* })
            }
        }
    };
}
pub(super) use proof_schema;
