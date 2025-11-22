pub mod dummy;

pub const DUMMY_CIRCUIT_ID: usize = 0;

pub fn internal_circuit_index(num_application_steps: usize, index: usize) -> usize {
    num_application_steps + super::step::NUM_INTERNAL_STEPS + index
}
