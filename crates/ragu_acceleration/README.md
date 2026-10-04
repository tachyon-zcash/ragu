<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1/github-600x160.png">
</p>

# `ragu_acceleration`

This crate provides Ragu's accelerated computational backend. It inherits the
defaults from `ragu_backend` except for individually tested overrides, and it
carries none today: the defaults call Udon's MSM and FFT implementations. It is
the home for the next overrides.

It carries no tests of its own: an override arrives with its differential
test against `ReferenceBackend`, and `ragu_pcd`'s `backend_equivalence` tests
hold `AcceleratedProver` to the reference end to end, in the `backend
equivalence` CI lane behind the required `backend-required` check.

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).
