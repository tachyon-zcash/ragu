<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1_github600x160.png">
</p>

**Ragu** is a Rust-language [proof-carrying data (PCD)](https://ic-people.epfl.ch/~achiesa/docs/CT10.pdf) framework that implements a modified version of the ECDLP-based recursive SNARK construction from [Halo [BGH19]](https://eprint.iacr.org/2019/1021). Ragu does not use a trusted setup. Developed for use with the [Pasta curves](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/) used in [Zcash](https://z.cash/), and designed specifically for use in [Project Tachyon](https://tachyon.z.cash/), Ragu targets performance and feature support that is competitive with other ECC-based [accumulation](https://eprint.iacr.org/2020/499)/[folding](https://eprint.iacr.org/2021/370) schemes without complicated circuit arithmetizations.

> ⚠️ Ragu is under active development and has not been audited.

This book contains documentation about [how to use Ragu](usage/index.md), [how it is developed](development/index.md) and details about how its underlying cryptographic protocol is [designed](design/index.md).