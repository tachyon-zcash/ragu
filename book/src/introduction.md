<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1/github-600x160.png">
</p>

```admonish warning
**Ragu is under heavy development and has not undergone auditing**. Do not use this software in production.
```

**Ragu** is a Rust-language [proof-carrying data (PCD)](concepts/pcd.md) framework that implements a modified version of the ECDLP-based recursive SNARK construction from [Halo [BGH19]](https://eprint.iacr.org/2019/1021). Ragu does not use a trusted setup. Developed for use with the [Pasta curves](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/) used in [Zcash](https://z.cash/), and designed specifically for use in [Project Tachyon](https://tachyon.z.cash/), Ragu targets performance and feature support that is competitive with other ECC-based [accumulation schemes](https://eprint.iacr.org/2020/499) schemes without complicated circuit arithmetizations.

* This book contains documentation about [how to use Ragu](guide/getting_started.md), the [protocol design](protocol/index.md), and [implementation details](implementation/arch.md).
* [The official Ragu source code repository.](https://github.com/tachyon-zcash/ragu)
* [Crate documentation](https://docs.rs/ragu) is available for official Ragu crate releases.
* [Internal documentation](https://tachyon.z.cash/ragu/internal/ragu/) is available for Ragu developers.
* This book's [source code](https://github.com/tachyon-zcash/ragu/tree/main/book) is developed within the Ragu repository.

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](https://github.com/tachyon-zcash/ragu/blob/main/LICENSE-APACHE), [LICENSE-MIT](https://github.com/tachyon-zcash/ragu/blob/main/LICENSE-MIT) and [COPYRIGHT](https://github.com/tachyon-zcash/ragu/blob/main/COPYRIGHT).
