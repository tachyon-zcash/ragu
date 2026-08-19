<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1/github-600x160.png">
</p>

# `ragu_acceleration`

This crate provides Ragu's accelerated computational backend. It inherits the
correctness-first defaults from `ragu_backend` except for individually tested
overrides.

The opt-in `native-msm` feature routes MSMs through Zakura's signed-Booth
multiexp (`zakura-halo2-proofs`), which is built over the same
`zakura-pasta-curves` types Ragu uses. The implementation is variable-time and
must only be used where Ragu's existing variable-time MSM is appropriate.

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).
