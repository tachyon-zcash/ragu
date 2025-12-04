pub mod c;
pub mod dummy;
pub mod unified;

const DUMMY_CIRCUIT_ID: usize = 0;
const C_CIRCUIT_ID: usize = 1;

pub fn index(num_application_steps: usize, internal_index: usize) -> usize {
    num_application_steps + super::step::NUM_INTERNAL_STEPS + internal_index
}
