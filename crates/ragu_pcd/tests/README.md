# Persisted regression cases

The recursive proof and backend-equivalence suites use proptest's
`WithSource("proptest-regressions")` persistence. Seed files live beside
their Rust sources, and `persisted_regressions_are_loaded` tests check that
proptest loads exactly the committed seeds using the source's `file!()` path.
This matters because the suites are mounted below `src/proof` with `#[path]`:
the default `SourceParallel` path could silently skip the old seed files in
a fresh checkout by traversing a missing `proptest-regressions/..` directory.

Keep the saved seeds. Each property in a file replays all its seeds before
generating fresh cases. To replay the two recursive properties that originally
failed and the hoisted-product corruption property, plus one fresh case each:

```sh
PROPTEST_CASES=1 cargo test --release -p ragu_pcd --locked --all-features --lib \
  -- --ignored --test-threads=1 \
  proof::recursive_boundary_tests::stages::same_lift_bit_substitutions_reject_through_two_generations \
  proof::recursive_boundary_tests::stages::corrupted_hoisted_products_reject_through_two_generations \
  proof::recursive_binding_tests::challenge_binding::partial_and_pre_beta_substitutions_reject_through_two_generations
```

Rust CI runs that command on PRs. Backend CI replays both backend seeds in
its existing equivalence properties. The scheduled heavy-tests workflow
runs all the ignored recursive properties with eight fresh cases each.
Set `PROPTEST_VERBOSE=2` and add `--nocapture` to see every replayed input;
the comments in seed files describe the historical shrunken failures, while
the seeds regenerate the original inputs before shrinking.
