mod driver;
mod expr;
mod fingerprint;
mod instance;
mod instances;
mod linexp;
mod polynomial;
mod sha256;
mod wire_remap;

use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use instance::CircuitInstance;

use crate::instances::{
    boolean_alloc::BooleanAllocInstance,
    boolean_and::BooleanAndInstance,
    boolean_conditional_enforce_equal::BooleanConditionalEnforceEqualInstance,
    boolean_conditional_select::BooleanConditionalSelectInstance,
    boolean_consistent::BooleanConsistentInstance,
    core_mul::CoreMulInstance,
    element_alloc::ElementAllocInstance,
    element_alloc_square::ElementAllocSquareInstance,
    element_div_nonzero::ElementDivNonzeroInstance,
    element_enforce_invertible::ElementEnforceInvertibleInstance,
    element_enforce_nonzero::ElementEnforceNonzeroInstance,
    element_enforce_root_of_unity::{
        ElementEnforceRootOfUnityInstanceK2, ElementEnforceRootOfUnityInstanceK5,
    },
    element_enforce_zero::ElementEnforceZeroInstance,
    element_fold::{
        ElementFoldInstanceN2, ElementFoldInstanceN3, ElementFoldInstanceN7, ElementFoldInstanceN19,
    },
    element_invert::ElementInvertInstance,
    element_invert_with::ElementInvertWithInstance,
    element_invertible::ElementInvertibleInstance,
    element_invertible_consistent::ElementInvertibleConsistentInstance,
    element_is_equal::ElementIsEqualInstance,
    element_is_zero::ElementIsZeroInstance,
    element_mul::ElementMulInstance,
    element_square::ElementSquareInstance,
    endoscalar_alloc::EndoscalarAllocInstance,
    endoscalar_extract::EndoscalarExtractInstance,
    endoscalar_group_scale::EndoscalarGroupScaleInstance,
    endoscalar_lift::EndoscalarLiftInstance,
    hoisted_endoscalar_alloc::HoistedEndoscalarAllocInstance,
    hoisted_endoscalar_enforce_products::HoistedEndoscalarEnforceProductsInstance,
    hoisted_endoscalar_group_scale::HoistedEndoscalarGroupScaleInstance,
    hoisted_endoscalar_lift::HoistedEndoscalarLiftInstance,
    horner::{HornerInstanceN3, HornerInstanceN7, HornerInstanceN19, HornerKyInstanceN3},
    nonzero_bank_scope::{
        NonzeroBankScopeInstanceK0, NonzeroBankScopeInstanceK1, NonzeroBankScopeInstanceK2,
    },
    point_add_incomplete::PointAddIncompleteInstance,
    point_alloc::{PointAllocInstanceFp, PointAllocInstanceFq},
    point_conditional_endo::PointConditionalEndoInstance,
    point_conditional_negate::PointConditionalNegateInstance,
    point_consistent::{PointConsistentInstanceFp, PointConsistentInstanceFq},
    point_double::PointDoubleInstance,
    point_double_and_add_incomplete::PointDoubleAndAddIncompleteInstance,
    poseidon_sponge::{
        PoseidonBlocks1Tail2InstanceFp, PoseidonBlocks2Squeeze3InstanceFp, PoseidonHash1InstanceFp,
        PoseidonHash1InstanceFq, PoseidonHash4InstanceFp, PoseidonInterleavedInstanceFp,
        PoseidonSaveResumeInstanceFp,
    },
};

struct ExportTarget {
    /// Lean module name of the (handwritten) formal instance.
    name: &'static str,
    /// Computes the canonical digest of the instance's extracted trace.
    fingerprint: fn(&str, TargetMode) -> Result<String, String>,
}

#[derive(Clone, Copy)]
enum TargetMode {
    Exact,
    Polynomial {
        seed: [u8; 32],
        points: usize,
    },
    #[cfg(test)]
    Differential {
        seed: [u8; 32],
        points: usize,
    },
}

/// Single source of truth for every exported instance: `export`, `check` and
/// `fingerprint` all enumerate this table.
static EXPORT_TARGETS: &[ExportTarget] = &[
    ExportTarget {
        name: "Ragu.Instances.Point.AllocFp",
        fingerprint: fingerprint_instance::<PointAllocInstanceFp>,
    },
    ExportTarget {
        name: "Ragu.Instances.Point.AllocFq",
        fingerprint: fingerprint_instance::<PointAllocInstanceFq>,
    },
    ExportTarget {
        name: "Ragu.Instances.Point.Double",
        fingerprint: fingerprint_instance::<PointDoubleInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Point.DoubleAndAddIncomplete",
        fingerprint: fingerprint_instance::<PointDoubleAndAddIncompleteInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Point.AddIncomplete",
        fingerprint: fingerprint_instance::<PointAddIncompleteInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Point.ConditionalEndo",
        fingerprint: fingerprint_instance::<PointConditionalEndoInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Point.ConditionalNegate",
        fingerprint: fingerprint_instance::<PointConditionalNegateInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Point.ConsistentFp",
        fingerprint: fingerprint_instance::<PointConsistentInstanceFp>,
    },
    ExportTarget {
        name: "Ragu.Instances.Point.ConsistentFq",
        fingerprint: fingerprint_instance::<PointConsistentInstanceFq>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.Mul",
        fingerprint: fingerprint_instance::<ElementMulInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.Square",
        fingerprint: fingerprint_instance::<ElementSquareInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.Alloc",
        fingerprint: fingerprint_instance::<ElementAllocInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.AllocSquare",
        fingerprint: fingerprint_instance::<ElementAllocSquareInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.DivNonzero",
        fingerprint: fingerprint_instance::<ElementDivNonzeroInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.FoldN2",
        fingerprint: fingerprint_instance::<ElementFoldInstanceN2>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.FoldN3",
        fingerprint: fingerprint_instance::<ElementFoldInstanceN3>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.FoldN7",
        fingerprint: fingerprint_instance::<ElementFoldInstanceN7>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.FoldN19",
        fingerprint: fingerprint_instance::<ElementFoldInstanceN19>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.EnforceRootOfUnityK2",
        fingerprint: fingerprint_instance::<ElementEnforceRootOfUnityInstanceK2>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.EnforceRootOfUnityK5",
        fingerprint: fingerprint_instance::<ElementEnforceRootOfUnityInstanceK5>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.EnforceZero",
        fingerprint: fingerprint_instance::<ElementEnforceZeroInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.EnforceInvertible",
        fingerprint: fingerprint_instance::<ElementEnforceInvertibleInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.Invertible",
        fingerprint: fingerprint_instance::<ElementInvertibleInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.InvertibleConsistent",
        fingerprint: fingerprint_instance::<ElementInvertibleConsistentInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.Invert",
        fingerprint: fingerprint_instance::<ElementInvertInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.InvertWith",
        fingerprint: fingerprint_instance::<ElementInvertWithInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.EnforceNonzero",
        fingerprint: fingerprint_instance::<ElementEnforceNonzeroInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.NonzeroBank.ScopeK0",
        fingerprint: fingerprint_instance::<NonzeroBankScopeInstanceK0>,
    },
    ExportTarget {
        name: "Ragu.Instances.NonzeroBank.ScopeK1",
        fingerprint: fingerprint_instance::<NonzeroBankScopeInstanceK1>,
    },
    ExportTarget {
        name: "Ragu.Instances.NonzeroBank.ScopeK2",
        fingerprint: fingerprint_instance::<NonzeroBankScopeInstanceK2>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.IsEqual",
        fingerprint: fingerprint_instance::<ElementIsEqualInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Element.IsZero",
        fingerprint: fingerprint_instance::<ElementIsZeroInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Core.Mul",
        fingerprint: fingerprint_instance::<CoreMulInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Boolean.Alloc",
        fingerprint: fingerprint_instance::<BooleanAllocInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Boolean.And",
        fingerprint: fingerprint_instance::<BooleanAndInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Boolean.ConditionalSelect",
        fingerprint: fingerprint_instance::<BooleanConditionalSelectInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Boolean.Consistent",
        fingerprint: fingerprint_instance::<BooleanConsistentInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Boolean.ConditionalEnforceEqual",
        fingerprint: fingerprint_instance::<BooleanConditionalEnforceEqualInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Endoscalar.Alloc",
        fingerprint: fingerprint_instance::<EndoscalarAllocInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Endoscalar.Extract",
        fingerprint: fingerprint_instance::<EndoscalarExtractInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Endoscalar.GroupScale",
        fingerprint: fingerprint_instance::<EndoscalarGroupScaleInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Endoscalar.Lift",
        fingerprint: fingerprint_instance::<EndoscalarLiftInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Endoscalar.HoistedAlloc",
        fingerprint: fingerprint_instance::<HoistedEndoscalarAllocInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Endoscalar.HoistedGroupScale",
        fingerprint: fingerprint_instance::<HoistedEndoscalarGroupScaleInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Endoscalar.HoistedLift",
        fingerprint: fingerprint_instance::<HoistedEndoscalarLiftInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Endoscalar.EnforceProducts",
        fingerprint: fingerprint_instance::<HoistedEndoscalarEnforceProductsInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Horner.N3",
        fingerprint: fingerprint_instance::<HornerInstanceN3>,
    },
    ExportTarget {
        name: "Ragu.Instances.Horner.N7",
        fingerprint: fingerprint_instance::<HornerInstanceN7>,
    },
    ExportTarget {
        name: "Ragu.Instances.Horner.N19",
        fingerprint: fingerprint_instance::<HornerInstanceN19>,
    },
    ExportTarget {
        name: "Ragu.Instances.Horner.KyN3",
        fingerprint: fingerprint_instance::<HornerKyInstanceN3>,
    },
    ExportTarget {
        name: "Ragu.Instances.Poseidon.Hash1Fp",
        fingerprint: fingerprint_instance::<PoseidonHash1InstanceFp>,
    },
    ExportTarget {
        name: "Ragu.Instances.Poseidon.Hash4Fp",
        fingerprint: fingerprint_instance::<PoseidonHash4InstanceFp>,
    },
    ExportTarget {
        name: "Ragu.Instances.Poseidon.Hash1Fq",
        fingerprint: fingerprint_instance::<PoseidonHash1InstanceFq>,
    },
    ExportTarget {
        name: "Ragu.Instances.Poseidon.Blocks2Squeeze3Fp",
        fingerprint: fingerprint_instance::<PoseidonBlocks2Squeeze3InstanceFp>,
    },
    ExportTarget {
        name: "Ragu.Instances.Poseidon.Hash1SaveResumeFp",
        fingerprint: fingerprint_instance::<PoseidonSaveResumeInstanceFp>,
    },
    ExportTarget {
        name: "Ragu.Instances.Poseidon.InterleavedFp",
        fingerprint: fingerprint_instance::<PoseidonInterleavedInstanceFp>,
    },
    ExportTarget {
        name: "Ragu.Instances.Poseidon.Blocks1Tail2Squeeze2Fp",
        fingerprint: fingerprint_instance::<PoseidonBlocks1Tail2InstanceFp>,
    },
];

/// The Lean source tree (`qa/fv/`) is the parent directory of this crate.
fn default_lean_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR is absolute, so it has a parent")
        .to_path_buf()
}

#[derive(Parser)]
#[command(name = "lean_extraction")]
#[command(about = "Export/check generated Lean files and fingerprint extracted circuit traces")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Root directory that contains the Lean source tree.
    #[arg(default_value_os_t = default_lean_root())]
    lean_root: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Write the generated Lean files (the instance import root and the
    /// fingerprint instance list) to disk.
    Export,
    /// Compare the generated Lean files with the files already on disk.
    Check,
    /// Print the canonical fingerprint digest of every exported instance.
    ///
    /// CI compares this output against the same digests computed in Lean from
    /// the Clean reimplementations.
    Fingerprint,
    /// Directly evaluate the complete four-slot gate relation at fresh,
    /// explicitly supplied challenges. Prints one TSV record per instance.
    PolynomialFingerprint {
        /// A 32-byte comparison seed encoded as exactly 64 hexadecimal digits.
        #[arg(long)]
        seed: String,

        /// Number of independently derived evaluation points.
        #[arg(long, default_value_t = polynomial::DEFAULT_POINTS)]
        points: usize,
    },
}

/// Monomorphized helper used by the static export target table.
fn fingerprint_instance<I: CircuitInstance>(
    name: &str,
    mode: TargetMode,
) -> Result<String, String> {
    match mode {
        TargetMode::Exact => Ok(I::fingerprint()),
        TargetMode::Polynomial { seed, points } => {
            I::polynomial_record(name, seed, points).map(|record| record.line())
        }
        #[cfg(test)]
        TargetMode::Differential { seed, points } => {
            let direct = I::polynomial_record(name, seed, points)?;
            let extracted = I::polynomial_trace_record(name, seed, points)?;
            if direct != extracted {
                return Err(format!(
                    "{name}: direct evaluation differs from evaluation of the extracted trace"
                ));
            }
            Ok(String::new())
        }
    }
}

fn generated_instances_root(lean_root: &Path) -> (PathBuf, String) {
    let path = lean_root.join("Ragu/Instances.lean");
    let mut contents = EXPORT_TARGETS
        .iter()
        .map(|target| format!("import {}", target.name))
        .collect::<Vec<_>>()
        .join("\n");
    contents.push('\n');
    (path, contents)
}

/// Generated list pairing every formal instance with its module name, used by
/// both fingerprint evaluators on the Lean side.
fn generated_fingerprint_instances(lean_root: &Path) -> (PathBuf, String) {
    let path = lean_root.join("Ragu/Fingerprint/Instances.lean");
    let entries = EXPORT_TARGETS
        .iter()
        .map(|target| target.name)
        .map(|name| format!("  (\"{name}\", {name}.formal_instance)"))
        .collect::<Vec<_>>()
        .join(",\n");
    let contents = format!(
        "import Ragu.Fingerprint\nimport Ragu.Instances\n\nnamespace Ragu.Fingerprint\n\n\
         /-- Every exported circuit instance, paired with its Lean module name.\n\n\
         Autogenerated by `lean_extraction`; do not edit. Used by the exact and\n\
         randomized fingerprint executables, whose outputs CI compares against\n\
         the corresponding Rust evaluators. -/\n\
         def instances : List (String × Ragu.Core.Statements.FormalInstance) := [\n{entries}\n]\n\n\
         end Ragu.Fingerprint\n"
    );
    (path, contents)
}

fn export_all(lean_root: &Path) -> std::io::Result<()> {
    let (path, contents) = generated_instances_root(lean_root);
    fs::write(&path, contents)?;
    println!("wrote Ragu.Instances to {}", path.display());

    let (path, contents) = generated_fingerprint_instances(lean_root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, contents)?;
    println!("wrote Ragu.Fingerprint.Instances to {}", path.display());

    Ok(())
}

/// Print `<module name> <digest>` for every exported instance.
fn fingerprint_all(mode: TargetMode) -> Result<(), String> {
    for target in EXPORT_TARGETS {
        match mode {
            TargetMode::Exact => println!(
                "{} {}",
                target.name,
                (target.fingerprint)(target.name, mode)?
            ),
            TargetMode::Polynomial { .. } => {
                println!("{}", (target.fingerprint)(target.name, mode)?)
            }
            #[cfg(test)]
            TargetMode::Differential { .. } => {
                (target.fingerprint)(target.name, mode)?;
            }
        }
    }
    Ok(())
}

fn check_file(
    name: &str,
    path: PathBuf,
    expected: String,
    mismatches: &mut usize,
) -> std::io::Result<()> {
    match fs::read_to_string(&path) {
        Ok(actual) if actual == expected => {
            println!("ok {name}");
        }
        Ok(_) => {
            eprintln!("mismatch {name} at {}", path.display());
            *mismatches += 1;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("missing {name} at {}", path.display());
            *mismatches += 1;
        }
        Err(err) => return Err(err),
    }

    Ok(())
}

fn check_all(lean_root: &Path) -> std::io::Result<bool> {
    let mut mismatches = 0;

    let (path, expected) = generated_instances_root(lean_root);
    check_file("Ragu.Instances", path, expected, &mut mismatches)?;

    let (path, expected) = generated_fingerprint_instances(lean_root);
    check_file(
        "Ragu.Fingerprint.Instances",
        path,
        expected,
        &mut mismatches,
    )?;

    if mismatches > 0 {
        eprintln!(
            "\n{mismatches} generated Lean file(s) out of date.\n\
             hint: run `cargo run -p lean_extraction -- export` and commit the result."
        );
    }

    Ok(mismatches == 0)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result: Result<ExitCode, String> = match cli.command {
        Command::Export => export_all(&cli.lean_root)
            .map(|_| ExitCode::SUCCESS)
            .map_err(|error| error.to_string()),
        Command::Check => check_all(&cli.lean_root)
            .map(|ok| {
                if ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            })
            .map_err(|error| error.to_string()),
        Command::Fingerprint => fingerprint_all(TargetMode::Exact).map(|_| ExitCode::SUCCESS),
        Command::PolynomialFingerprint { seed, points } => polynomial::parse_seed(&seed)
            .and_then(|seed| fingerprint_all(TargetMode::Polynomial { seed, points }))
            .map(|_| ExitCode::SUCCESS),
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_instance_matches_the_exact_trace_at_fixed_points() {
        let seed = polynomial::parse_seed(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap();
        for target in EXPORT_TARGETS {
            (target.fingerprint)(target.name, TargetMode::Differential { seed, points: 2 })
                .unwrap();
        }
    }

    #[test]
    fn every_enrolled_instance_is_within_the_polynomial_degree_cap() {
        let seed = polynomial::parse_seed(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap();
        let mut moduli = std::collections::BTreeSet::new();
        let mut maximum = 0;

        for target in EXPORT_TARGETS {
            let line =
                (target.fingerprint)(target.name, TargetMode::Polynomial { seed, points: 1 })
                    .unwrap();
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(
                fields.len(),
                13,
                "{} emitted a malformed record",
                target.name
            );
            assert_eq!(fields[0], polynomial::FORMAT_TAG);
            assert_eq!(fields[2], target.name);
            assert_eq!(
                fields[9], "0",
                "{} unexpectedly used assign_extra",
                target.name
            );
            assert_eq!(fields[11], "1");

            let degree = fields[10].parse::<usize>().unwrap();
            assert!(
                degree <= polynomial::MAX_DEGREE_BOUND,
                "{} has degree bound {degree}",
                target.name
            );
            maximum = maximum.max(degree);
            moduli.insert(fields[3].to_owned());
        }

        assert_eq!(EXPORT_TARGETS.len(), 57);
        assert_eq!(moduli.len(), 2, "both Pasta fields must remain enrolled");
        assert_eq!(maximum, 1728);
    }
}
