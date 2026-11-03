//! Decode hostile bytes, check canonical encoding, and reach production verification.
#![no_main]
use libfuzzer_sys::fuzz_target;
use ragu_testing_fuzz::proof_wire::{self, Kind};
fuzz_target!(init: { proof_wire::initialize(); }, |bytes: &[u8]| {
    proof_wire::exercise(Kind::Compressed, bytes);
});
