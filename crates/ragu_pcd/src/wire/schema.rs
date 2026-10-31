//! Crate-local proof schema. Every field names its codec, so generating the
//! struct and its codec from one declaration makes a field without an encoding
//! a build error without adding a general-purpose derive to another crate.

macro_rules! proof_schema {
    (
        $(#[$doc:meta])* <$C:ident, $R:ident> {
            $( $(#[$attr:meta])* $vis:vis $field:ident: $ty:ty => [$codec:ty], )*
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct Proof<$C: Cycle, $R: Rank> {
            $( $(#[$attr])* $vis $field: $ty, )*
        }

        // Checks each field against its codec: the shapes the dimensions fix,
        // and points other than the identity, which has no encoding.
        impl<$C: ProfiledCycle, $R: Rank> wire::Validate for Proof<$C, $R> {
            fn valid(&self, dims: wire::Dimensions) -> bool {
                true $( && <$ty as wire::Validate<$codec>>::valid(&self.$field, dims) )*
            }
        }

        impl<$C: ProfiledCycle, $R: Rank> Encode for Proof<$C, $R> {
            fn encode(&self, output: &mut Vec<u8>) {
                $( <$ty as Encode<$codec>>::encode(&self.$field, output); )*
            }
        }
        impl<$C: ProfiledCycle, $R: Rank> Decode for Proof<$C, $R> {
            fn encoded_len(dims: wire::Dimensions) -> usize {
                0usize $( + <$ty as Decode<$codec>>::encoded_len(dims) )*
            }
            fn decode<'a>(
                reader: &mut wire::Reader<'a>,
                dims: wire::Dimensions,
            ) -> core::result::Result<Self, wire::Error<'a>> {
                Ok(Self {
                    $( $field: <$ty as Decode<$codec>>::decode(reader, dims)?, )*
                })
            }
        }
    };
}
pub(crate) use proof_schema;
