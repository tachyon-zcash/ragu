pub mod circuit_c;
pub mod circuit_v;
pub mod dummy;
pub mod unified;

const DUMMY_CIRCUIT_ID: usize = 0;
const C_CIRCUIT_ID: usize = 1;
const V_CIRCUIT_ID: usize = 2;

pub fn internal_circuit_index(num_application_steps: usize, index: usize) -> usize {
    num_application_steps + super::step::NUM_INTERNAL_STEPS + index
}
