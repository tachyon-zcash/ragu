import Lake
open Lake DSL

package Ragu where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩]

@[default_target]
lean_lib Ragu where
  -- Build every module under `Ragu/`, not just `Ragu.lean`'s import closure, so
  -- a `.lean` that no aggregator imports cannot silently escape CI.
  globs := #[`Ragu.*]

require clean from git "https://github.com/Verified-zkEVM/clean" @ "main"
