pub mod c;
pub mod dummy;
pub mod unified;
pub mod v;

const DUMMY_CIRCUIT_ID: usize = 0;
const C_CIRCUIT_ID: usize = 1;
const V_CIRCUIT_ID: usize = 2;

pub fn internal_circuit_index(num_application_steps: usize, index: usize) -> usize {
    num_application_steps + super::step::NUM_INTERNAL_STEPS + index
}
