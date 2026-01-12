# Dependencies and Requirements

* The minimum supported [Rust](https://rust-lang.org/) version is currently **1.90.0**.
* Ragu requires minimal dependencies and currently strives to avoid using dependencies that are not already used in [Zebra](https://github.com/ZcashFoundation/zebra).
* Ragu does not require usage of the standard library in code that is compiled for the target architecture.

## Important Limitations

**Compile-time circuit definition.** Circuits in Ragu are defined at compile-time rather than runtime. This means:

- Circuits are compiled directly into the binary during `cargo build`
- Circuit serialization and deserialization to/from files is **not** supported
- Verifying keys cannot be serialized or deserialized
- Circuit definitions cannot be loaded dynamically at runtime

This design choice stems from Ragu's architecture: the protocol does not use preprocessing, and directly translates circuit descriptions into reduced polynomial evaluations. This makes Ragu unsuitable for IR-based circuit workflows, but enables non-uniform PCD across many circuits.

If your use case requires runtime circuit definition or serialized verifying keys, Ragu may not be suitable in its current form.
