---
name: fv-preflight
description: Explicitly invoked only. Pre-PR audit of a ragu formal-verification branch against the violations reviewers flag most — coverage (exporter registration, generated files, lib glob, `--wfail`, fingerprint equivalence), unnecessary trust-base growth (trusted definitions, `native_decide`, axioms), computability of the fingerprinted path, vacuous `Assumptions` / `Spec`, overclaiming prose, and merge-artifact churn. Use before opening or updating a PR, when self-reviewing a branch, after a rebase or merge, when adding formal instances / `native_decide` / `noncomputable` / `Assumptions` clauses, or when asked to "preflight", "pre-PR check", or "audit the branch". Do NOT auto-trigger on general FV or Lean questions; only invoke when the user explicitly types `/fv-preflight` or asks by name.
---

# FV preflight (compiled from review feedback)

Every rule here is a violation reviewers have flagged more than once. The skill is an audit
procedure, not a style essay: run the checks against `git diff main...HEAD`, answer each
question, and fix or justify before handing over. Docstring register and structure are out of
scope — this skill owns what the prose *claims* and what the Lean *trusts*. Reimplementation
patterns (circuit type, `Spec` shape, mirroring Rust delegation, heartbeat design signals) are
owned by the `fv-review` skill; the book's FV part is the spec for every concept named below.

## 0. What CI checks — and what it leaves to this audit

The FV workflow runs four gates, in order: `cargo run --locked -p lean_extraction -- check`
(the generated Lean files match the exporter), the source-tree trust-boundary census,
`lake build --wfail` in `qa/fv` (every module under `Ragu/` elaborates, warnings fatal, and the
elaborated endpoint census passes), and the fingerprint equivalence check (the Rust extractor's
trace digests equal the ones Lean computes from the reimplementations). It does **not** check that
a new instance is registered at all, whether `Assumptions` or `Spec` mean anything, whether the
Lean interface mirrors the Rust one, or whether the prose is true. Those are the sections below.

## 1. Coverage — every new proof elaborates in CI, and every new instance is fingerprinted

A proof that exists but is never compared against the Rust circuit is the worst outcome: CI
stays green over a reimplementation of nothing. Check all five failure modes.

1. **Registered with the exporter.** Every new top-level formal instance has a Rust
   `CircuitInstance` under `qa/fv/extraction/src/instances/`, an `EXPORT_TARGETS` entry, and
   the regenerated `Ragu/Instances.lean` and `Ragu/Fingerprint/Instances.lean` committed
   (`cargo run -p lean_extraction -- export`). Coverage through a parent gadget that uses it as
   a subcircuit is not coverage of the child's own statement — an instance missing from
   `EXPORT_TARGETS` is never fingerprinted. A sub-gadget deliberately left without an instance
   (used only inside other gadgets) is fine, but the PR says so.
2. **The module is built.** `lean_lib Ragu` builds every module under `Ragu/` by glob, so a
   file there cannot escape CI; a file anywhere else (a new top-level directory, next to the
   lakefile) builds nothing. Hand-written lemma modules are also imported from
   `Ragu/Lemmas.lean`, so `import Ragu` exposes them.
3. **No `sorry`, no silenced warnings.** `--wfail` turns a `sorry` into a failure only if the
   warning reaches the build: no file-wide `set_option` that disables a linter or warning. A
   `set_option … in` scoped to one declaration, with a reason, is acceptable.
4. **Rebases drop entries silently.** After any rebase or merge, read
   `git diff main...HEAD` for `EXPORT_TARGETS`, `Ragu.lean`, `Ragu/Lemmas.lean`, and the two
   generated files, and account for every *deleted* line by name. A consolidation that loses
   another PR's instance passes CI and loses the guarantee. Re-run `export` and `check`.
5. **Endpoint axioms are checked automatically, but only for discovered endpoints.**
   `Ragu.Meta.TrustBoundary` directly pins every declaration carrying a `soundness`,
   `completeness`, error/security-bound, probability-bound, or capstone name component, both Pasta
   primality theorems, and the executable fingerprint boundary. The source and elaborated censuses
   reject a missing direct pin. Run `#print axioms`
   (or add an explicit census entry) for any differently named lemma that the book or a docstring
   cites as a result. The expected theorem tier is `propext`, `Classical.choice`, and
   `Quot.sound`; any broader set is a trust-surface change (§2) that the PR argues for explicitly.

Run the exporter `check` and the fingerprint comparison (recipe in the final sweep) before
handing over.

## 2. Trust surface — every extension of the trusted base is argued for

The governing rule is general, not a per-feature quota: **we shouldn't be unnecessarily
increasing the trust base.** In this tree the trusted base has a non-Lean half. Trusted, and
manually inspected: the Rust `CircuitInstance` impls, the extraction driver, the serialization,
and the fingerprint encoders on both sides; on the Lean side the `Inputs` / `Outputs` struct
definitions, `Spec`, `Assumptions`, and their prover-side variants. Untrusted: reimplementation
bodies and proofs, which the fingerprint check ties to the Rust circuit. A diff that touches a
trusted artifact is a trust change even when every proof still closes — name it in the PR and
justify it.

`native_decide` and `@[csimp]` both extend the trusted base and neither is free (what each
actually depends on is recorded in
[lean-native-trust-research.md](https://github.com/daira/CompElliptic/blob/main/design/lean-native-trust-research.md)).
`@[csimp]` extends it further — its equivalence proof rules out only a limited class of
mistakes, not the expansion itself — so no *new* `@[csimp]` is added at all. `native_decide` is
held to the same direction of travel, not a lower bar. Audit every use against the ladder below
instead of waving it through.

For each `native_decide` the diff adds, in order:

1. Does `decide` or `norm_num` close it? Then use that. (Reviewers have caught `native_decide`
   on facts like `(-1 : F p) ≠ 1`.)
2. Does a compositional proof from existing lemmas exist? Then prove it. Prefer certifying one
   general fact (an element's order, a generic congruence) over native-deciding an
   instance-specific table.
3. Is the statement minimal — one fact, no fused conjunctions, no re-evaluation of something
   cheap or already checked elsewhere?
4. Is it a concrete fact about a fixed parameter — a field or curve constant, a hash test
   vector — with no other source? That is the only category where a new `native_decide` is
   legitimate, and it is where the tree's existing uses live (`Ragu.Core.Primes`,
   `Circuits/Point/Spec.lean`, `Fingerprint/Sha256.lean`). Correctness properties of objects
   the repo derives itself are proved by construction or generically, not natively.

A survivor has to earn the trust it adds: a justification in the PR that says which rungs above
were tried and why each failed — "it was easier" and "it is only a constant" are not that.

The same logic bans bespoke axioms outright. The Pasta primality facts are theorems imported from
the direct, commit-pinned CompElliptic dependency; when a fact is proven upstream, use it rather
than assume it, and anything else is a theorem or a named hypothesis in `Assumptions`. There should
be no production uses of `@[extern]`, `@[implemented_by]`, `unsafe`, `partial`, or `opaque`, and
no new uses of `@[csimp]` — none exist today outside the deliberately forged declarations in
`Ragu.Meta.Tests`, so any other appearance is a review item by itself.

## 3. `noncomputable` — proofs may be, the fingerprinted path may not

`Ragu/Fingerprint/Main.lean` *evaluates* every registered instance: it runs `reimplementation`
on the deserialized canonical input to collect the operation trace, then `serializeOutput` on
the result, and digests both. Witness bodies are not run (the encoding records only how many
wires a `witness` allocates), but `main` is a plain `def`, so the compiler already rejects a
`noncomputable` dependency anywhere inside it.

For each `noncomputable` the diff adds:

- A marker is acceptable only when inert — the declaration appears inside theorems and never
  feeds `main`, the instance packaging, or the serialization. There are none in the tree
  today; if in doubt, drop the marker and let the compiler object.
- The enforcement is the build plus the fingerprint run, not a grep: a `noncomputable` leak
  into `main` fails to compile, and an instance that no longer evaluates fails the equivalence
  step — but only if it is registered (§1).

## 4. `Assumptions` and `Spec` — can the theorem hold for nothing?

The highest-value audit in the tree: formalizing is an under-constraint audit, and the place
a missing constraint hides is a hypothesis that was added to make a proof close.

For each new `Assumptions` / `ProverAssumptions` clause and each new or changed `Spec`:

- **Vacuity test.** Exhibit a concrete input satisfying every hypothesis. If none exists,
  soundness certifies nothing. Then try to satisfy `Spec` with a degenerate output — zero, the
  identity, a wire the constraints never touch: if `Spec` accepts an output the Rust gadget
  would reject, the spec is too weak and an under-constrained wire can hide behind it.
- **Caller obligation vs missing constraint.** An `Assumptions` clause is a precondition the
  caller can guarantee without the gadget (`IsBool x`, an on-curve input, a no-collision
  condition), named as such in the docstring with who guarantees it. A hypothesis discovered
  *while* proving soundness is classified before it is kept: a legitimate obligation goes to
  `Assumptions` and the caller is checked to actually guarantee it; anything else is a missing
  constraint in the Rust gadget, and the fix is there. Never bury a discovered precondition.
- **Satisfiability of every hypothesis.** Knowingly unsatisfiable hypotheses don't merge even
  with a caveat note. Empty-length and `Fin 0` cases and `getD`-style defaults must fail safe:
  a short input unsatisfies the spec rather than silently satisfying it.
- **Interface completeness.** The Lean `Inputs` / `Outputs` and hint types mirror the Rust
  interface. A silently narrower Lean interface (a fixed length where Rust is polymorphic, a
  hint exposing a sub-gadget's internals, an input the Rust gadget takes but Lean fixes)
  narrows the theorem; state a strictly-weaker framing as such. The fingerprint checks wire
  *order*, not wire *meaning*: `Inputs := { y, x }` plus a proof of `x < y` shadows a Rust
  gadget that checks the wrong direction, so field names are checked against the Rust struct
  by hand.

## 5. Claims — the prose may not outrun the proof term

For every touched docstring, module doc, book sentence, and the PR body:

- Does the proof term actually contain the asserted connection? "Formalizes `Element::invert`"
  claims a registered instance with a matching fingerprint *and* both theorems; if any piece is
  planned, write "to be discharged by X". State a discharge as intended rather than done, and
  qualify with the hypotheses and modelling gaps.
- Conditional results stay conditional. A soundness theorem under a non-trivial `Assumptions`
  is presented as such everywhere it is cited — docstrings, the book, the PR — never as an
  unconditional property of the Rust gadget.
- No dev-history narration, no stale identifiers, no tracker references in durable prose
  (doc comments, module docs, book pages). A reference that tracks a genuinely open gap is
  flagged for the author rather than deleted — removing it hides the gap. Constants and
  reimplementations cite the upstream Rust identifier they mirror, and the paper or spec
  section a bound comes from.
- **Every new theorem carries a description** — no exceptions for trivial or private lemmas,
  and none for a name that looks self-explanatory. The doc comment says what the statement
  means and why the declaration exists (what it is for downstream, what it assumes, where its
  hypotheses come from); it does not transliterate the name or restate the type in words. A
  statement whose purpose cannot be written down in a sentence is usually the wrong statement.
  An undocumented lemma is where an unexamined claim survives review.
- Cite papers that claims rely on, or that provide important context. Check that it's the
  right paper and covers what is claimed; ask the user to download it if you can't. Use this
  citation format: `(Author(s), linked title[, section/theorem][, venue year])`. For example:
  ```
  (Bowe–Grigg–Hopwood, <a href="https://eprint.iacr.org/2019/1021">Recursive Proof Composition without a Trusted Setup</a>, Appendix C)
  ```
  Link to full text if at all possible. Include the venue and year only if it is not an eprint
  and the version referenced is the one we want readers to look at; don't link to one version
  and then give the venue and year for another substantially different conference or journal
  version. Publication precedent doesn't matter for our purposes; pointing readers to a full,
  preferably open-access copy with all corrections does.

## 6. Diff hygiene — the diff contains only its own changes

- Read `git diff main...HEAD` hunk by hunk. Unrelated comment rewording, blank-line churn, and
  spelling regressions get reverted — prefer main on any comment the PR isn't about. An
  incidental formatting change needs a stated reason.
- After a rebase, check for resurrections (a declaration deleted on main reappearing) and merge
  zombies (a file restored into no build target, never elaborated). Self-review the generated
  files, `EXPORT_TARGETS`, and the trusted definitions in particular.
- New public declarations with zero consumers are wired, deleted, or explicitly kept as a named
  result with a comment saying so.

## 7. Interface and proof hygiene (quick checklist)

- Abstract in the middle, concrete at both ends. Circuits and lemmas are generic over the prime
  (`F p`) and the curve parameters, so they say something beyond the deployed instance; the
  formal instance is concrete (`AllocFp` over `Ragu.Core.Primes.p` with the Pallas parameters)
  so a reviewer does not have to chase a definition to see what is trusted. The instance
  packaging is the single bridge between the two, so the literal cannot drift from the model.
  No raised `maxHeartbeats` — seal the concrete definition (`@[irreducible]`) or restructure;
  a timeout is a design signal, not a budget.
- Never suppress a linter file-wide (`set_option linter.* false` at top level); `omit` the
  unused instances or scope the option to one declaration. The reason is not cosmetic: an
  unused instance argument is still a subterm that axiom collection traverses, so a consumer
  passing an axiom-carrying instance propagates that axiom into `#print axioms`.
- `@[simp]` only where the right-hand side is a genuine normal form wanted everywhere;
  otherwise consumers invoke the lemma explicitly.
- No unearned wrappers or generality; check Mathlib and Clean before deriving anything that
  smells standard, and grep Clean before claiming a limitation. A superseded route is removed
  in the same PR that supersedes it, or kept only with a stated reason and a tracking issue for
  its removal. Durable comments must not describe the new route by comparison against the
  superseded one ("unlike the old X …"): that inverts the present-state rule in §5 and goes
  stale exactly when the pruning happens.
- Hypotheses that are general facts get proved, not assumed — `Assumptions` is for caller
  obligations, not for lemmas nobody proved yet. Write the result type on any def or theorem
  whose body is a partial application (Lean silently appends hypotheses otherwise).
- Named structure fields over tuples and numeric accessors; no field defaults (an inherited
  default has produced a real modeling bug).
- No Mathlib glob imports — neither `import Mathlib` nor `import Mathlib.Tactic`; name the
  specific modules a file actually uses. This is not CI-gated here, so review is the gate, and
  the cost is build-wide rather than local: the umbrella multiplies import-load time and memory
  for every Lean process, and nothing fails when one creeps back in — builds just quietly get
  slow again.
- When narrowing an import, expect breakage beyond name resolution. The umbrella supplies
  definitions *and* simp / `norm_num` / `deriving` extensions transitively, so narrowing can
  break a file the change never touched: a lost extension turns a passing proof into a
  `sorryAx` that surfaces as a failure several modules away. Re-run `lake build --wfail` after
  any import trim and read failures for a dropped extension, not just a dropped name.
- Respect the layering. `Core` ← `Circuits` ← `Instances` ← `Fingerprint`: nothing under
  `Circuits/` imports `Instances/` or `Fingerprint/`. Hand-written mathematics that needs no
  Clean lives in `Lemmas/` and stays Clean-free. No dead imports; generic lemmas live beside
  their definitions, not where first used.
- Plain names (`circuit`, `Spec`, `Assumptions`, `soundness`, `completeness`, no `General*`
  prefix) and no unused parameters — the conventions in `fv-review`.

## 8. Generated files, dependencies, and process

- `Ragu/Instances.lean` and `Ragu/Fingerprint/Instances.lean` are never hand-edited, including
  comments — regeneration goes through `cargo run -p lean_extraction -- export`, and `check`
  must pass.
- A changed digest is a changed circuit. If a fingerprint moves, the PR says which instance's
  trace changed and why: a Rust circuit change (the reimplementation follows, proofs repaired
  in the same PR) or an extractor change (every digest moves together). A reimplementation-only
  refactor must leave every digest unchanged — that is the check that the refactor was one.
- Dependencies are pinned by `lake-manifest.json`; a Clean bump is its own commit naming the
  upstream change that motivates it, and `require` never points at a personal fork. The
  manifest diff is the reviewed artifact.
- The PR description is part of the reviewed artifact: refresh it after force-pushes, and close
  issues only with per-task accounting. Follow-up work gets a tracking issue, not only a
  docstring. Confirm CI ran on the exact head that merges — the FV workflow runs on pull
  requests and on `main`, not on branch pushes, so a pushed branch without a PR has been
  checked by nothing.

## Final sweep

Before handing over, from the repo root:

```sh
cargo run --locked -p lean_extraction -- check
scripts/check_fv_endpoint_census.sh
(cd qa/fv && lake build --wfail)
cargo run --locked -p lean_extraction -- fingerprint | sort > /tmp/fp-rust.txt
(cd qa/fv && lake env lean --run Ragu/Fingerprint/Main.lean) | sort > /tmp/fp-lean.txt
diff -u /tmp/fp-rust.txt /tmp/fp-lean.txt
typos
```

Add `cargo clippy -p lean_extraction --all-targets -- -D warnings` and the nightly `rustfmt`
check when the exporter changed (`just lint` bundles clippy, fmt, rustdoc, the FV source
checks, and the book build), and `mdbook build ./book` when a page under `book/src/fv/`
changed. `lake build --wfail` is
the default-target build — the one CI runs — not a single-module build, which elaborates less
than the coverage in §1 demands. Then one pass over the full diff with the coverage,
trust-surface, computability, vacuity, and claims questions above, reporting per file what was
fixed, what is compliant, and what needs author judgment.
