use ff::Field;
use pasta_curves::Fp;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pasta;
    use arithmetic::Cycle;
    use ff::PrimeField;
    use halo2_poseidon::{P128Pow5T3, Spec, test_vectors};
    use ragu_core::maybe::Maybe;
    use ragu_primitives::{Element, Simulator, Sponge};

    /// Compare ragu's permutation output against halo2's permutation.
    #[test]
    fn test_ragu_permutation_fp_matches_halo2_test_vectors() {
        let params = Pasta::default();

        // Get halo2's permutation test vectors and constants
        let test_vectors = test_vectors::fp::permute();
        let (halo2_round_constants, halo2_mds, _) = <P128Pow5T3 as Spec<Fp, 3, 2>>::constants();

        for (i, tv) in test_vectors.iter().enumerate() {
            let initial_state: [Fp; 3] = [
                Fp::from_repr(tv.initial_state[0]).unwrap(),
                Fp::from_repr(tv.initial_state[1]).unwrap(),
                Fp::from_repr(tv.initial_state[2]).unwrap(),
            ];

            let expected_state: [Fp; 3] = [
                Fp::from_repr(tv.final_state[0]).unwrap(),
                Fp::from_repr(tv.final_state[1]).unwrap(),
                Fp::from_repr(tv.final_state[2]).unwrap(),
            ];

            // Run halo2's permutation
            let mut halo2_state = initial_state;
            halo2_poseidon::test_only_permute::<Fp, P128Pow5T3, 3, 2>(
                &mut halo2_state,
                &halo2_mds,
                &halo2_round_constants,
            );

            // Verify halo2's output matches the test vector
            assert_eq!(
                halo2_state, expected_state,
                "halo2 permutation should match its own test vector {}",
                i
            );

            // Run ragu's permutation via Sponge with initial state
            let mut ragu_output = [Fp::ZERO; 3];
            Simulator::<Fp>::simulate(initial_state, |dr, witness| {
                let init = witness.take();
                let init_elements: [Element<'_, _>; 3] = [
                    Element::constant(dr, init[0]),
                    Element::constant(dr, init[1]),
                    Element::constant(dr, init[2]),
                ];

                let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new_with_state(
                    params.circuit_poseidon(),
                    &init_elements,
                );

                // Run the permutation and get the full state
                let state = sponge.permute_and_get_state(dr)?;

                ragu_output[0] = *state[0].value().take();
                ragu_output[1] = *state[1].value().take();
                ragu_output[2] = *state[2].value().take();

                Ok(())
            })
            .unwrap();

            // Compare ragu's output against halo2's
            assert_eq!(
                ragu_output, halo2_state,
                "Permutation output mismatch for test vector {}!\n Input: {:?}\n Ragu: {:?}\n Halo2: {:?}\n Expected: {:?}",
                i, initial_state, ragu_output, halo2_state, expected_state
            );
        }
    }
}
