<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1/github-600x160.png">
</p>

# `ragu_pcd`

This crate contains internal implementation code for the [`ragu`](https://crates.io/crates/ragu) crate.

The default features are `alloc` and `asm`. The `asm` feature enables Udon's
handwritten field arithmetic on AArch64. On x86-64, Udon includes its own
assembly in every build and uses it when the CPU supports BMI2 and ADX, with
portable Rust otherwise. Other targets and Miri use the portable Rust kernels.
Neither assembly backend requires `std` or enables the separate `multicore`
feature.

For portable arithmetic on AArch64, disable defaults while keeping `alloc`:

```sh
cargo build --release -p ragu_pcd --no-default-features --features alloc
```

On x86-64, enable Udon's `portable` feature instead:

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
