//! Crate-local proof schema. Every field names its codec, and one declaration
//! generates the struct, its codec and its shape check, so a field without an
//! encoding is a build error and no vector escapes the shape check, without
//! adding a general-purpose derive to another crate.

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

        impl<$C: ProfiledCycle, $R: Rank> Proof<$C, $R> {
            /// Whether the headers, polynomial vectors and commitment-cache vectors
            /// have exactly the receiving profile's shape. Check before traversing
            /// components so that missing entries cannot panic and trailing ones
            /// cannot be ignored.
            pub(crate) fn well_formed<const HEADER_SIZE: usize>(&self) -> bool {
                <Self as wire::Validate>::has_shape(self, wire::Dimensions::of::<$R, HEADER_SIZE>())
            }
        }

        // Each field against its codec: the counts the dimensions fix, and
        // points other than the identity, which has no encoding.
        impl<$C: ProfiledCycle, $R: Rank> wire::Validate for Proof<$C, $R> {
            fn has_shape(&self, dims: wire::Dimensions) -> bool {
                true $( && <$ty as wire::Validate<$codec>>::has_shape(&self.$field, dims) )*
            }
            fn encodable(&self, dims: wire::Dimensions) -> bool {
                true $( && <$ty as wire::Validate<$codec>>::encodable(&self.$field, dims) )*
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
