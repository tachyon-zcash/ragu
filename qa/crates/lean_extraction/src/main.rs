mod codegen;
mod driver;
mod expr;
mod instance;
mod instances;
mod linexp;

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
    core_mul::CoreMulInstance,
    element_alloc::ElementAllocInstance,
    element_alloc_square::ElementAllocSquareInstance,
    element_div_nonzero::ElementDivNonzeroInstance,
    element_enforce_root_of_unity::{
        ElementEnforceRootOfUnityInstanceK2, ElementEnforceRootOfUnityInstanceK5,
    },
    element_enforce_zero::ElementEnforceZeroInstance,
    element_fold::{ElementFoldInstanceN3, ElementFoldInstanceN7},
    element_invert::ElementInvertInstance,
    element_invert_with::ElementInvertWithInstance,
    element_is_equal::ElementIsEqualInstance,
    element_is_zero::ElementIsZeroInstance,
    element_mul::ElementMulInstance,
    element_square::ElementSquareInstance,
    point_add_incomplete::PointAddIncompleteInstance,
    point_alloc::{PointAllocInstanceFp, PointAllocInstanceFq},
    point_conditional_endo::PointConditionalEndoInstance,
    point_conditional_negate::PointConditionalNegateInstance,
    point_double::PointDoubleInstance,
    point_double_and_add_incomplete::PointDoubleAndAddIncompleteInstance,
};

struct ExportTarget {
    name: &'static str,
    export: fn(&str, &Path) -> std::io::Result<PathBuf>,
    generated_file: fn(&str, &Path) -> (PathBuf, String),
}

/// Single source of truth for every exported instance: both `export` and `check`
static EXPORT_TARGETS: &[ExportTarget] = &[
    ExportTarget {
        name: "Ragu.Instances.Autogen.Point.AllocFp",
        export: export_instance::<PointAllocInstanceFp>,
        generated_file: generated_file_instance::<PointAllocInstanceFp>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Point.AllocFq",
        export: export_instance::<PointAllocInstanceFq>,
        generated_file: generated_file_instance::<PointAllocInstanceFq>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Point.Double",
        export: export_instance::<PointDoubleInstance>,
        generated_file: generated_file_instance::<PointDoubleInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Point.DoubleAndAddIncomplete",
        export: export_instance::<PointDoubleAndAddIncompleteInstance>,
        generated_file: generated_file_instance::<PointDoubleAndAddIncompleteInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Point.AddIncomplete",
        export: export_instance::<PointAddIncompleteInstance>,
        generated_file: generated_file_instance::<PointAddIncompleteInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Point.ConditionalEndo",
        export: export_instance::<PointConditionalEndoInstance>,
        generated_file: generated_file_instance::<PointConditionalEndoInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Point.ConditionalNegate",
        export: export_instance::<PointConditionalNegateInstance>,
        generated_file: generated_file_instance::<PointConditionalNegateInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.Mul",
        export: export_instance::<ElementMulInstance>,
        generated_file: generated_file_instance::<ElementMulInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.Square",
        export: export_instance::<ElementSquareInstance>,
        generated_file: generated_file_instance::<ElementSquareInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.Alloc",
        export: export_instance::<ElementAllocInstance>,
        generated_file: generated_file_instance::<ElementAllocInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.AllocSquare",
        export: export_instance::<ElementAllocSquareInstance>,
        generated_file: generated_file_instance::<ElementAllocSquareInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.DivNonzero",
        export: export_instance::<ElementDivNonzeroInstance>,
        generated_file: generated_file_instance::<ElementDivNonzeroInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.FoldN3",
        export: export_instance::<ElementFoldInstanceN3>,
        generated_file: generated_file_instance::<ElementFoldInstanceN3>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.FoldN7",
        export: export_instance::<ElementFoldInstanceN7>,
        generated_file: generated_file_instance::<ElementFoldInstanceN7>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.EnforceRootOfUnityK2",
        export: export_instance::<ElementEnforceRootOfUnityInstanceK2>,
        generated_file: generated_file_instance::<ElementEnforceRootOfUnityInstanceK2>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.EnforceRootOfUnityK5",
        export: export_instance::<ElementEnforceRootOfUnityInstanceK5>,
        generated_file: generated_file_instance::<ElementEnforceRootOfUnityInstanceK5>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.EnforceZero",
        export: export_instance::<ElementEnforceZeroInstance>,
        generated_file: generated_file_instance::<ElementEnforceZeroInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.Invert",
        export: export_instance::<ElementInvertInstance>,
        generated_file: generated_file_instance::<ElementInvertInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.InvertWith",
        export: export_instance::<ElementInvertWithInstance>,
        generated_file: generated_file_instance::<ElementInvertWithInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.IsEqual",
        export: export_instance::<ElementIsEqualInstance>,
        generated_file: generated_file_instance::<ElementIsEqualInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Element.IsZero",
        export: export_instance::<ElementIsZeroInstance>,
        generated_file: generated_file_instance::<ElementIsZeroInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Core.Mul",
        export: export_instance::<CoreMulInstance>,
        generated_file: generated_file_instance::<CoreMulInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Boolean.Alloc",
        export: export_instance::<BooleanAllocInstance>,
        generated_file: generated_file_instance::<BooleanAllocInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Boolean.And",
        export: export_instance::<BooleanAndInstance>,
        generated_file: generated_file_instance::<BooleanAndInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Boolean.ConditionalSelect",
        export: export_instance::<BooleanConditionalSelectInstance>,
        generated_file: generated_file_instance::<BooleanConditionalSelectInstance>,
    },
    ExportTarget {
        name: "Ragu.Instances.Autogen.Boolean.ConditionalEnforceEqual",
        export: export_instance::<BooleanConditionalEnforceEqualInstance>,
        generated_file: generated_file_instance::<BooleanConditionalEnforceEqualInstance>,
    },
];

impl ExportTarget {
    fn root_import_name(&self) -> String {
        // Drop only the first namespace marker
        self.name.replacen(".Autogen", "", 1)
    }
}

fn default_autogen_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../lean")
}

#[derive(Parser)]
#[command(name = "lean_extraction")]
#[command(about = "Export generated Lean instance files or check them for exact equality")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Root directory that contains the Lean source tree.
    #[arg(default_value_os_t = default_autogen_root())]
    autogen_root: PathBuf,
}

#[derive(Subcommand, Clone, Copy)]
enum Command {
    /// Write all generated Lean files to disk.
    Export,
    /// Compare the generated Lean files with the files already on disk.
    Check,
}

/// Monomorphized helper used by the static export table below.
fn export_instance<I: CircuitInstance>(
    module_name: &str,
    autogen_root: &Path,
) -> std::io::Result<PathBuf> {
    I::export(module_name, autogen_root)
}

/// Monomorphized helper used by `check` to compute the expected file contents.
fn generated_file_instance<I: CircuitInstance>(
    module_name: &str,
    autogen_root: &Path,
) -> (PathBuf, String) {
    I::generated_file(module_name, autogen_root)
}

fn generated_ragu_root(autogen_root: &Path) -> (PathBuf, String) {
    let path = autogen_root.join("Ragu.lean");
    let mut contents = EXPORT_TARGETS
        .iter()
        .map(|target| format!("import {}", target.root_import_name()))
        .collect::<Vec<_>>()
        .join("\n");
    contents.push('\n');
    (path, contents)
}

fn export_all(autogen_root: &Path) -> std::io::Result<()> {
    for target in EXPORT_TARGETS {
        let path = (target.export)(target.name, autogen_root)?;
        println!("wrote {} to {}", target.name, path.display());
    }

    let (path, contents) = generated_ragu_root(autogen_root);
    fs::write(&path, contents)?;
    println!("wrote Ragu to {}", path.display());

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

fn check_all(autogen_root: &Path) -> std::io::Result<bool> {
    let mut mismatches = 0;

    for target in EXPORT_TARGETS {
        let (path, expected) = (target.generated_file)(target.name, autogen_root);
        check_file(target.name, path, expected, &mut mismatches)?;
    }

    let (path, expected) = generated_ragu_root(autogen_root);
    check_file("Ragu", path, expected, &mut mismatches)?;

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

    let result = match cli.command {
        Command::Export => export_all(&cli.autogen_root).map(|_| ExitCode::SUCCESS),
        Command::Check => check_all(&cli.autogen_root).map(|ok| {
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }),
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}
