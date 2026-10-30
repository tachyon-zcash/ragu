//! The shape check shared by expanded and minimal proofs.

use ragu_circuits::polynomials::Rank;
use ragu_primitives::vec::Len;

use super::{MinimalProof, Proof};
use crate::{
    internal::{native, nested},
    profile::{Profile, ProfiledCycle},
};

// Every field inspected here is retained in `MinimalProof`. Define the check
// once so the encoder and the verifier enforce the same shape.
macro_rules! impl_well_formed {
    ($($proof:ident<$($param:tt),*> where [$($generics:tt)*] fn well_formed $([$($fn_generics:tt)*])?;)+) => {$(
        impl<$($generics)*> $proof<$($param),*> {
            /// Whether the headers, polynomial vectors and commitment-cache vectors
            /// have exactly the receiving profile's shape. Check before traversing
            /// components so that missing entries cannot panic and trailing ones
            /// cannot be ignored.
            pub(crate) fn well_formed$(<$($fn_generics)*>)?(&self) -> bool {
                let native_steps = native::NumSteps::<C::Profile>::len();
                let nested_steps = nested::NumSteps::<C::Profile>::len();
                let native_extension = C::Profile::native_extension();
                let nested_extension = C::Profile::nested_extension();

                self.left_header.len() == HEADER_SIZE
                    && self.right_header.len() == HEADER_SIZE
                    && self.native_bind_challenges_rxs.len() == native::NUM_BINDERS
                    && self.native_bind_challenges_commitments.len() == native::NUM_BINDERS
                    && self.native_endoscaling_step_rxs.len() == native_steps
                    && self.native_endoscaling_step_commitments.len() == native_steps
                    && self.native_extension_circuit_rxs.len() == native_extension.circuits.len()
                    && self.native_extension_circuit_commitments.len() == native_extension.circuits.len()
                    && self.native_extension_stage_rxs.len() == native_extension.stages
                    && self.native_extension_stage_commitments.len() == native_extension.stages
                    && self.nested_endoscaling_step_rxs.len() == nested_steps
                    && self.nested_endoscaling_step_commitments.len() == nested_steps
                    && self.nested_extension_circuit_rxs.len() == nested_extension.circuits.len()
                    && self.nested_extension_circuit_commitments.len() == nested_extension.circuits.len()
                    && self.nested_extension_stage_rxs.len() == nested_extension.stages
                    && self.nested_extension_stage_commitments.len() == nested_extension.stages
            }
        }
    )+};
}

impl_well_formed! {
    Proof<C, R> where [C: ProfiledCycle, R: Rank] fn well_formed[const HEADER_SIZE: usize];
    MinimalProof<C, R, HEADER_SIZE> where [C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize] fn well_formed;
}
