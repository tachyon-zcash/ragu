# Ragu Book

## Development

You can render locally and test using `mdbook serve`. Ensure you have installed (using at least `Rust 1.88.0`)

* `mdbook v0.4.52`
* `mdbook-katex v0.9.4`
* `mdbook-mermaid v0.16.2`
* (optional) `mdbookkit v1.1.1` (for `mdbook-rustdoc-link`)
    * This renders links to the Ragu documentation from within the book.
    * Must be enabled by uncommenting `[preprocessor.rustdoc-link] after = ["links"]` in `book.toml`.
    * This requires the `rust-analyzer` component to be installed in your local toolchain.
    * This is expensive to perform re-renders with; try not to use this in
      `mdbook serve` mode until you need to test your documentation links resolve properly.
    * Locally, this will produce links to `docs.rs` which might not reflect the current state of `main`.

## Publication

The `main` branch of this repository, when modified, triggers a [`website`](https://github.com/tachyon-zcash/website) rebuild that will rerender this book on the public URL.
