<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1/github-600x160.png">
</p>

# `ragu_pcd`

This crate contains internal implementation code for the [`ragu`](https://crates.io/crates/ragu) crate.

The default features are `alloc` and `asm`. The `asm` feature enables Udon's
handwritten field arithmetic on AArch64. On x86-64, Udon uses its own assembly
only in a build whose target features include BMI2 and ADX, for example with
`-C target-cpu=native` on a supporting CPU or `-C target-feature=+adx,+bmi2`,
or with its `x86_64-asm` feature enabled. Udon does not detect the CPU at run
time: such a binary faults with an illegal instruction on a CPU without those
extensions, and any other x86-64 build uses portable Rust. Other targets and
Miri use the portable Rust kernels. Neither assembly backend requires `std` or
enables the separate `multicore` feature.

For portable arithmetic on AArch64, disable defaults while keeping `alloc`:

```sh
cargo build --release -p ragu_pcd --no-default-features --features alloc
```

On x86-64, a build compiled for BMI2 and ADX stays portable with Udon's
`portable` feature:

```sh
cargo build --release -p ragu_pcd --features udon/portable
```

Downstream dependencies can use `default-features = false, features = ["alloc"]`
and add other features as needed; an x86-64 build stays portable by also
depending on `zakura-udon` with its `portable` feature. Cargo features are
additive: no other dependency may enable Udon's `aarch64-asm` feature for an
AArch64 build to remain portable, while Udon's `portable` overrides any request
for its x86-64 assembly. Use `cargo tree -p ragu_pcd -e features -i zakura-udon`
with the same feature flags to inspect the resolved selection.

The [`pasta`](src/pasta/) module owns Ragu's fixed generator derivation and
loading. With the `baked` feature, `build.rs` derives the generators on the host
using `pasta_curves` only for hash-to-curve, converts them to checked Udon points,
and writes them through Bento POD. The runtime embeds those typed points with
Bento; `pasta::baked()` adapts them once into Udon's parameter containers without
decoding coordinates. The derivation preserves Ragu's existing generators. The
feature enables `alloc` and supports `no_std`.

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).
