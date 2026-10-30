//! Crate-local proof schema. Every field is either retained with an explicit
//! codec or derived, with the placeholder a decoded proof holds until the
//! application derives it. Generating the struct and its codec from one
//! declaration makes an unclassified field a build error without adding a
//! general-purpose derive to another crate.

macro_rules! proof_schema {
    (
        $(#[$doc:meta])* <$C:ident, $R:ident>
        retained {
            $( $(#[$attr:meta])* $vis:vis $field:ident: $ty:ty => [$codec:ty], )*
        }
        derived {
            $( $(#[$dattr:meta])* $dvis:vis $derived:ident: $dty:ty = $placeholder:expr, )*
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct Proof<$C: Cycle, $R: Rank> {
            $( $(#[$attr])* $vis $field: $ty, )*
            $( $(#[$dattr])* $dvis $derived: $dty, )*
            /// Whether the derived fields hold this proof's values. A decoded
            /// proof holds placeholders until the application derives them.
            complete: bool,
        }

        struct ProofDerived<$C: Cycle, $R: Rank> {
            $( $derived: $dty, )*
        }

        impl<$C: Cycle, $R: Rank> Proof<$C, $R> {
            /// Sets the derived fields, completing a decoded proof.
            fn fill(&mut self, derived: ProofDerived<$C, $R>) {
                $( self.$derived = derived.$derived; )*
                self.complete = true;
            }
        }

        impl<$C: ProfiledCycle, $R: Rank> Proof<$C, $R> {
            /// Checks retained field shapes and nonidentity point slots before
            /// indexing them.
            pub(crate) fn well_formed<const HEADER_SIZE: usize>(&self) -> bool {
                self.well_formed_in(wire::Dimensions::of::<$R, HEADER_SIZE>())
            }

            /// [`well_formed`](Self::well_formed) for a header size known only
            /// at runtime, as the `serde` adapter reads it from its prelude.
            pub(crate) fn well_formed_in(&self, dims: wire::Dimensions) -> bool {
                true $( && <$ty as wire::Validate<$codec>>::valid(&self.$field, dims) )*
            }
        }

        // The retained fields alone: the derived ones are recomputed rather
        // than read, so they have no encoding.
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
                    $( $derived: $placeholder, )*
                    complete: false,
                })
            }
        }
    };
}
pub(super) use proof_schema;
