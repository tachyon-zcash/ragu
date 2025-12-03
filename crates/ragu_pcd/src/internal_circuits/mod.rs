pub mod dummy;
pub mod unified;

const DUMMY_CIRCUIT_ID: usize = 0;

pub fn index(num_application_steps: usize, index: usize) -> usize {
    num_application_steps + super::step::NUM_INTERNAL_STEPS + index
}
