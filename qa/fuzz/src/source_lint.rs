//! No-execution source linting for Ragu circuit and gadget code.
//!
//! This QA module parses Rust with [`syn`]. It does not typecheck or execute
//! the inspected code. The rules deliberately target high-signal
//! trust-boundary mistakes that ordinary `unused_must_use` checking can be
//! told to ignore.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use proc_macro2::Span;
use syn::{
    Attribute, BinOp, Block, Expr, ExprCall, ExprClosure, ExprForLoop, ExprIf, ExprMatch,
    ExprMethodCall, ExprWhile, FnArg, GenericParam, Generics, ImplItem, ItemFn, ItemImpl, Pat,
    Signature, Stmt, TraitItem, Type, WherePredicate,
    spanned::Spanned,
    visit::{self, Visit},
};

/// Stable identifier and severity for a source-lint rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    /// A fallible driver or gadget operation is discarded without handling
    /// its error.
    IgnoredDriverResult,
    /// A witness-assignment closure mutates state captured from outside it.
    AssignmentClosureSideEffect,
    /// Witness-observable state controls code that emits constraints.
    WitnessDependentShape,
    /// A driver-produced value is deliberately discarded.
    DiscardedConstraintValue,
    /// Conditional arms emit different syntactic driver-operation shapes.
    BranchShapeDivergence,
    /// A QA-local baseline entry no longer matches its exact finding.
    StaleBaseline,
}

impl Rule {
    /// Stable diagnostic code suitable for the QA-local baseline.
    pub const fn code(self) -> &'static str {
        match self {
            Self::IgnoredDriverResult => "RAGU001",
            Self::AssignmentClosureSideEffect => "RAGU002",
            Self::WitnessDependentShape => "RAGU003",
            Self::DiscardedConstraintValue => "RAGU004",
            Self::BranchShapeDivergence => "RAGU005",
            Self::StaleBaseline => "RAGU006",
        }
    }

    /// Whether this rule is a high-confidence error rather than a review
    /// advisory.
    pub const fn is_error(self) -> bool {
        matches!(
            self,
            Self::IgnoredDriverResult
                | Self::AssignmentClosureSideEffect
                | Self::WitnessDependentShape
                | Self::StaleBaseline
        )
    }

    fn from_code(code: &str) -> Option<Self> {
        match code {
            "RAGU001" => Some(Self::IgnoredDriverResult),
            "RAGU002" => Some(Self::AssignmentClosureSideEffect),
            "RAGU003" => Some(Self::WitnessDependentShape),
            "RAGU004" => Some(Self::DiscardedConstraintValue),
            "RAGU005" => Some(Self::BranchShapeDivergence),
            "RAGU006" => Some(Self::StaleBaseline),
            _ => None,
        }
    }
}

/// One source-level finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// Rule that produced the finding.
    pub rule: Rule,
    /// One-based source line.
    pub line: usize,
    /// One-based source column.
    pub column: usize,
    /// Human-readable explanation.
    pub message: String,
}

impl Diagnostic {
    fn new(rule: Rule, span: Span, message: impl Into<String>) -> Self {
        let start = span.start();
        Self {
            rule,
            line: start.line,
            column: start.column + 1,
            message: message.into(),
        }
    }

    fn at(rule: Rule, line: usize, column: usize, message: impl Into<String>) -> Self {
        Self {
            rule,
            line,
            column,
            message: message.into(),
        }
    }
}

/// Parses and analyzes one Rust source file without typechecking or executing it.
pub fn analyze_source(source: &str) -> syn::Result<Vec<Diagnostic>> {
    let file = syn::parse_file(source)?;
    let mut analyzer = SourceAnalyzer {
        diagnostics: Vec::new(),
    };
    analyzer.visit_file(&file);
    analyzer
        .diagnostics
        .sort_by_key(|diagnostic| (diagnostic.line, diagnostic.column, diagnostic.rule.code()));
    Ok(analyzer.diagnostics)
}

/// One diagnostic paired with its repository-relative source path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocatedDiagnostic {
    /// Path relative to the scanned repository root.
    pub path: PathBuf,
    /// Source-level finding.
    pub diagnostic: Diagnostic,
}

/// Result of scanning the production Rust source tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanReport {
    /// Number of Rust files parsed.
    pub files_scanned: usize,
    /// Findings not covered by a reviewed QA-local advisory baseline.
    pub diagnostics: Vec<LocatedDiagnostic>,
}

impl ScanReport {
    /// Number of unsuppressed error-level findings.
    pub fn errors(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|finding| finding.diagnostic.rule.is_error())
            .count()
    }

    /// Number of unsuppressed advisory findings.
    pub fn advisories(&self) -> usize {
        self.diagnostics.len() - self.errors()
    }
}

#[derive(Clone, Debug)]
struct BaselineEntry {
    baseline_line: usize,
    rule: Rule,
    path: PathBuf,
    target_line: usize,
    rationale: String,
    used: bool,
}

/// Scans production sources without compiling or executing the inspected code.
///
/// `requested` paths are relative to `root`; an empty list scans every
/// `crates/*/src` tree plus a root `src` tree when present. `baseline` is also
/// relative to `root` unless absolute. The baseline may suppress only
/// advisory rules, and every entry must match exactly or becomes `RAGU006`.
pub fn scan_sources(
    root: &Path,
    requested: &[PathBuf],
    baseline: Option<&Path>,
) -> Result<ScanReport, String> {
    let full_scan = requested.is_empty();
    let root = root
        .canonicalize()
        .map_err(|error| format!("failed to resolve {}: {error}", root.display()))?;
    let roots = if requested.is_empty() {
        default_roots(&root)?
    } else {
        requested.iter().map(|path| root.join(path)).collect()
    };

    let mut files = Vec::new();
    for path in roots {
        collect_rust_files(&path, &mut files)?;
    }
    files.sort();
    files.dedup();
    if files.is_empty() {
        return Err("no Rust source files found".to_owned());
    }

    let baseline_path = baseline.map(|path| {
        if path.is_absolute() {
            path.to_owned()
        } else {
            root.join(path)
        }
    });
    let mut entries = if let Some(path) = &baseline_path {
        let source = fs::read_to_string(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        parse_baseline(&source)?
    } else {
        Vec::new()
    };

    let mut diagnostics = Vec::new();
    for path in &files {
        let source = fs::read_to_string(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let relative = path.strip_prefix(&root).unwrap_or(path).to_owned();
        let findings = analyze_source(&source)
            .map_err(|error| format!("failed to parse {}: {error}", path.display()))?;
        for diagnostic in findings {
            if let Some(entry) = entries.iter_mut().find(|entry| {
                !entry.used
                    && entry.rule == diagnostic.rule
                    && entry.path == relative
                    && entry.target_line == diagnostic.line
            }) {
                entry.used = true;
            } else {
                diagnostics.push(LocatedDiagnostic {
                    path: relative.clone(),
                    diagnostic,
                });
            }
        }
    }

    if let Some(path) = baseline_path {
        let displayed = path.strip_prefix(&root).unwrap_or(&path).to_owned();
        let scanned_paths: BTreeSet<_> = files
            .iter()
            .map(|file| file.strip_prefix(&root).unwrap_or(file).to_owned())
            .collect();
        for entry in entries
            .into_iter()
            .filter(|entry| !entry.used && (full_scan || scanned_paths.contains(&entry.path)))
        {
            diagnostics.push(LocatedDiagnostic {
                path: displayed.clone(),
                diagnostic: Diagnostic::at(
                    Rule::StaleBaseline,
                    entry.baseline_line,
                    1,
                    format!(
                        "baseline entry for {} {}:{} is stale ({})",
                        entry.rule.code(),
                        entry.path.display(),
                        entry.target_line,
                        entry.rationale,
                    ),
                ),
            });
        }
    }

    diagnostics.sort_by(|left, right| {
        (&left.path, left.diagnostic.line, left.diagnostic.column).cmp(&(
            &right.path,
            right.diagnostic.line,
            right.diagnostic.column,
        ))
    });
    Ok(ScanReport {
        files_scanned: files.len(),
        diagnostics,
    })
}

fn parse_baseline(source: &str) -> Result<Vec<BaselineEntry>, String> {
    let mut entries = Vec::new();
    let mut keys = BTreeSet::new();
    for (index, raw) in source.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split('|').map(str::trim).collect();
        if fields.len() != 4 {
            return Err(format!(
                "baseline line {} must be RULE|PATH|LINE|RATIONALE",
                index + 1,
            ));
        }
        let rule = Rule::from_code(fields[0]).ok_or_else(|| {
            format!(
                "baseline line {} names unknown rule {}",
                index + 1,
                fields[0]
            )
        })?;
        if rule.is_error() {
            return Err(format!(
                "baseline line {} cannot suppress error-level {}",
                index + 1,
                rule.code(),
            ));
        }
        let path = PathBuf::from(fields[1]);
        if path.is_absolute() || fields[1].is_empty() {
            return Err(format!(
                "baseline line {} must use a nonempty repository-relative path",
                index + 1,
            ));
        }
        let target_line = fields[2]
            .parse::<usize>()
            .map_err(|_| format!("baseline line {} has an invalid source line", index + 1))?;
        if target_line == 0 || fields[3].is_empty() {
            return Err(format!(
                "baseline line {} requires a positive line and a rationale",
                index + 1,
            ));
        }
        let key = (rule, path.clone(), target_line);
        if !keys.insert(key) {
            return Err(format!("baseline line {} duplicates an entry", index + 1));
        }
        entries.push(BaselineEntry {
            baseline_line: index + 1,
            rule,
            path,
            target_line,
            rationale: fields[3].to_owned(),
            used: false,
        });
    }
    Ok(entries)
}

fn default_roots(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut roots = Vec::new();
    let root_source = root.join("src");
    if root_source.is_dir() {
        roots.push(root_source);
    }
    let crates = root.join("crates");
    let entries = fs::read_dir(&crates)
        .map_err(|error| format!("failed to read {}: {error}", crates.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let source = entry.path().join("src");
        if source.is_dir() {
            roots.push(source);
        }
    }
    Ok(roots)
}

fn collect_rust_files(path: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    if path.is_file() {
        if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path.to_owned());
        }
        return Ok(());
    }
    if !path.is_dir() || skip_directory(path) {
        return Ok(());
    }
    let entries = fs::read_dir(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        collect_rust_files(&entry.path(), output)?;
    }
    Ok(())
}

fn skip_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                ".git" | ".claude" | "benches" | "examples" | "target" | "tests"
            )
        })
}

struct SourceAnalyzer {
    diagnostics: Vec<Diagnostic>,
}

impl SourceAnalyzer {
    fn analyze_function(
        &mut self,
        signature: &Signature,
        block: &Block,
        inherited: &BTreeSet<String>,
    ) {
        let mut driver_types = inherited.clone();
        driver_types.extend(driver_type_parameters(&signature.generics));
        let driver_variables = driver_variables(signature, &driver_types);
        if driver_types.is_empty() && driver_variables.is_empty() {
            return;
        }

        let mut closure_pass = AssignmentClosurePass {
            diagnostics: &mut self.diagnostics,
            captured_mutations: BTreeSet::new(),
        };
        closure_pass.visit_block(block);

        // Associated constructors such as `D::just` can run witness closures
        // and return fallible driver-managed values even in helpers that do not
        // take a driver value directly. Keep analyzing those operations; shape
        // rules naturally remain quiet when there is no driver variable.
        let use_counts = expression_identifier_counts(block);
        let witness_variables = witness_tainted_variables(signature, block);
        let mut body_pass = FunctionBodyPass {
            driver_types: &driver_types,
            driver_variables: &driver_variables,
            captured_mutations: &closure_pass.captured_mutations,
            witness_variables: &witness_variables,
            use_counts: &use_counts,
            diagnostics: &mut self.diagnostics,
        };
        body_pass.visit_block(block);
    }
}

impl<'ast> Visit<'ast> for SourceAnalyzer {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !is_test_only(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if !is_test_only(&item.attrs) {
            self.analyze_function(&item.sig, &item.block, &BTreeSet::new());
            visit::visit_block(self, &item.block);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if is_test_only(&item.attrs) {
            return;
        }
        let inherited = driver_type_parameters(&item.generics);
        for impl_item in &item.items {
            if let ImplItem::Fn(function) = impl_item
                && !is_test_only(&function.attrs)
            {
                self.analyze_function(&function.sig, &function.block, &inherited);
                visit::visit_block(self, &function.block);
            }
        }
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if is_test_only(&item.attrs) {
            return;
        }
        let inherited = driver_type_parameters(&item.generics);
        for trait_item in &item.items {
            if let TraitItem::Fn(function) = trait_item
                && !is_test_only(&function.attrs)
                && let Some(block) = &function.default
            {
                self.analyze_function(&function.sig, block, &inherited);
                visit::visit_block(self, block);
            }
        }
    }
}

fn is_test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("test")
            || (attribute.path().is_ident("cfg")
                && attribute
                    .parse_args::<syn::Meta>()
                    .is_ok_and(|meta| cfg_requires_test(&meta)))
    })
}

fn cfg_requires_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            use syn::parse::Parser;

            let parser = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
            let Ok(items) = parser.parse2(list.tokens.clone()) else {
                return false;
            };
            if list.path.is_ident("all") {
                items.iter().any(cfg_requires_test)
            } else {
                !items.is_empty() && items.iter().all(cfg_requires_test)
            }
        }
        syn::Meta::List(_) | syn::Meta::NameValue(_) => false,
    }
}

fn driver_type_parameters(generics: &Generics) -> BTreeSet<String> {
    let mut types = BTreeSet::new();
    for parameter in &generics.params {
        if let GenericParam::Type(parameter) = parameter
            && bounds_contain_driver(&parameter.bounds)
        {
            types.insert(parameter.ident.to_string());
        }
    }
    if let Some(where_clause) = &generics.where_clause {
        for predicate in &where_clause.predicates {
            if let WherePredicate::Type(predicate) = predicate
                && bounds_contain_driver(&predicate.bounds)
                && let Type::Path(path) = &predicate.bounded_ty
                && path.qself.is_none()
                && path.path.segments.len() == 1
            {
                types.insert(path.path.segments[0].ident.to_string());
            }
        }
    }
    types
}

fn bounds_contain_driver(
    bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::token::Plus>,
) -> bool {
    bounds.iter().any(|bound| {
        let syn::TypeParamBound::Trait(bound) = bound else {
            return false;
        };
        bound
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Driver")
    })
}

fn driver_variables(signature: &Signature, driver_types: &BTreeSet<String>) -> BTreeSet<String> {
    let mut variables = BTreeSet::new();
    for argument in &signature.inputs {
        let FnArg::Typed(argument) = argument else {
            continue;
        };
        if type_is_driver_reference(&argument.ty, driver_types) {
            collect_pattern_bindings(&argument.pat, &mut variables);
        }
    }
    variables
}

fn type_is_driver_reference(ty: &Type, driver_types: &BTreeSet<String>) -> bool {
    let mut ty = ty;
    loop {
        ty = match ty {
            Type::Reference(reference) => reference.elem.as_ref(),
            Type::Group(group) => group.elem.as_ref(),
            Type::Paren(paren) => paren.elem.as_ref(),
            _ => break,
        };
    }
    match ty {
        Type::Path(path) if path.qself.is_none() && path.path.segments.len() == 1 => {
            driver_types.contains(&path.path.segments[0].ident.to_string())
        }
        Type::ImplTrait(ty) => bounds_contain_driver(&ty.bounds),
        Type::TraitObject(ty) => bounds_contain_driver(&ty.bounds),
        _ => false,
    }
}

fn type_mentions_path_segment(ty: &Type, target: &str) -> bool {
    struct Finder<'a> {
        target: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_path_segment(&mut self, segment: &'ast syn::PathSegment) {
            self.found |= segment.ident == self.target;
            if !self.found {
                visit::visit_path_segment(self, segment);
            }
        }
    }
    let mut finder = Finder {
        target,
        found: false,
    };
    finder.visit_type(ty);
    finder.found
}

fn witness_tainted_variables(signature: &Signature, block: &Block) -> BTreeSet<String> {
    let mut tainted = BTreeSet::new();
    for argument in &signature.inputs {
        let FnArg::Typed(argument) = argument else {
            continue;
        };
        if type_mentions_path_segment(&argument.ty, "DriverValue") {
            collect_pattern_bindings(&argument.pat, &mut tainted);
        }
    }

    loop {
        let before = tainted.len();
        let mut pass = WitnessLocalPass {
            tainted: &tainted,
            additions: BTreeSet::new(),
        };
        pass.visit_block(block);
        tainted.extend(pass.additions);
        if tainted.len() == before {
            return tainted;
        }
    }
}

struct WitnessLocalPass<'a> {
    tainted: &'a BTreeSet<String>,
    additions: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for WitnessLocalPass<'_> {
    fn visit_item(&mut self, _: &'ast syn::Item) {
        // Nested functions and other item bodies have their own bindings and
        // are analyzed independently by `SourceAnalyzer`.
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(initializer) = &local.init
            && (expression_mentions_any_identifier(&initializer.expr, self.tainted)
                || expression_contains_witness_constructor(&initializer.expr))
        {
            collect_pattern_bindings(&local.pat, &mut self.additions);
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {
        // Closure-local values do not flow into structural control unless the
        // closure mutates a capture, which RAGU002 tracks separately.
    }
}

fn expression_contains_witness_constructor(expression: &Expr) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_item(&mut self, _: &'ast syn::Item) {}

        fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
            self.found |= called_name(&expression.func).is_some_and(|name| {
                matches!(
                    name.as_str(),
                    "just" | "maybe_just" | "maybe_try_just" | "try_just"
                )
            });
            if !self.found {
                visit::visit_expr_call(self, expression);
            }
        }

        fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
    }
    let mut finder = Finder { found: false };
    finder.visit_expr(expression);
    finder.found
}

struct AssignmentClosurePass<'a> {
    diagnostics: &'a mut Vec<Diagnostic>,
    captured_mutations: BTreeSet<String>,
}

impl AssignmentClosurePass<'_> {
    fn inspect_call<'ast>(&mut self, name: &str, expressions: impl Iterator<Item = &'ast Expr>) {
        if !is_assignment_source(name) {
            return;
        }
        for expression in expressions {
            if let Expr::Closure(closure) = expression {
                self.inspect_closure(closure);
            }
        }
    }

    fn inspect_closure(&mut self, closure: &ExprClosure) {
        let mut locals = BTreeSet::new();
        for input in &closure.inputs {
            collect_pattern_bindings(input, &mut locals);
        }
        let mut local_pass = ClosureLocalPass {
            bindings: &mut locals,
        };
        local_pass.visit_expr(&closure.body);

        let mut mutation_pass = ClosureMutationPass {
            locals: &locals,
            mutations: Vec::new(),
        };
        mutation_pass.visit_expr(&closure.body);
        for (name, span) in mutation_pass.mutations {
            self.captured_mutations.insert(name.clone());
            self.diagnostics.push(Diagnostic::new(
                Rule::AssignmentClosureSideEffect,
                span,
                format!(
                    "witness-assignment closure mutates captured `{name}`; source structure can observe witness execution"
                ),
            ));
        }
    }
}

impl<'ast> Visit<'ast> for AssignmentClosurePass<'_> {
    fn visit_item(&mut self, _: &'ast syn::Item) {
        // Do not cross into a nested function's capture boundary.
    }

    fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
        self.inspect_call(&expression.method.to_string(), expression.args.iter());
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
        if let Some(name) = called_name(&expression.func) {
            self.inspect_call(&name, expression.args.iter());
        }
        visit::visit_expr_call(self, expression);
    }
}

fn is_assignment_source(name: &str) -> bool {
    matches!(
        name,
        "alloc"
            | "alloc_square"
            | "alloc_with_advice"
            | "assign_extra"
            | "gate"
            | "just"
            | "maybe_just"
            | "maybe_try_just"
            | "mul"
            | "try_just"
    )
}

struct ClosureLocalPass<'a> {
    bindings: &'a mut BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ClosureLocalPass<'_> {
    fn visit_item(&mut self, _: &'ast syn::Item) {}

    fn visit_local(&mut self, local: &'ast syn::Local) {
        collect_pattern_bindings(&local.pat, self.bindings);
        visit::visit_local(self, local);
    }

    fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {
        // A nested closure has its own capture boundary.
    }
}

struct ClosureMutationPass<'a> {
    locals: &'a BTreeSet<String>,
    mutations: Vec<(String, Span)>,
}

impl ClosureMutationPass<'_> {
    fn record(&mut self, expression: &Expr) {
        if let Some((name, span)) = root_identifier(expression)
            && !self.locals.contains(&name)
        {
            self.mutations.push((name, span));
        }
    }
}

impl<'ast> Visit<'ast> for ClosureMutationPass<'_> {
    fn visit_item(&mut self, _: &'ast syn::Item) {}

    fn visit_expr_assign(&mut self, expression: &'ast syn::ExprAssign) {
        self.record(&expression.left);
        visit::visit_expr_assign(self, expression);
    }

    fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
        if matches!(
            expression.op,
            BinOp::AddAssign(_)
                | BinOp::SubAssign(_)
                | BinOp::MulAssign(_)
                | BinOp::DivAssign(_)
                | BinOp::RemAssign(_)
                | BinOp::BitXorAssign(_)
                | BinOp::BitAndAssign(_)
                | BinOp::BitOrAssign(_)
                | BinOp::ShlAssign(_)
                | BinOp::ShrAssign(_)
        ) {
            self.record(&expression.left);
        }
        visit::visit_expr_binary(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
        let name = expression.method.to_string();
        if matches!(
            name.as_str(),
            "borrow_mut"
                | "clear"
                | "extend"
                | "get_mut"
                | "insert"
                | "push"
                | "remove"
                | "replace"
                | "set"
                | "store"
                | "swap"
        ) || name.starts_with("fetch_")
        {
            self.record(&expression.receiver);
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {
        // A nested closure has its own capture boundary.
    }
}

struct FunctionBodyPass<'a> {
    driver_types: &'a BTreeSet<String>,
    driver_variables: &'a BTreeSet<String>,
    captured_mutations: &'a BTreeSet<String>,
    witness_variables: &'a BTreeSet<String>,
    use_counts: &'a BTreeMap<String, usize>,
    diagnostics: &'a mut Vec<Diagnostic>,
}

impl FunctionBodyPass<'_> {
    fn driver_operation(&self, expression: &Expr) -> Option<String> {
        top_level_driver_operation(expression, self.driver_variables)
            .or_else(|| top_level_driver_type_operation(expression, self.driver_types))
    }

    fn inspect_condition<'ast>(
        &mut self,
        condition: &Expr,
        arms: impl IntoIterator<Item = &'ast Expr>,
        span: Span,
        additionally_witness_observable: bool,
    ) {
        let arms: Vec<_> = arms.into_iter().collect();
        let shapes: Vec<_> = arms
            .iter()
            .map(|arm| driver_operation_shape(arm, self.driver_variables))
            .collect();
        if shapes.iter().all(Vec::is_empty) {
            return;
        }

        if additionally_witness_observable
            || is_witness_observable(condition, self.captured_mutations, self.witness_variables)
        {
            self.diagnostics.push(Diagnostic::new(
                Rule::WitnessDependentShape,
                span,
                "witness-observable condition controls driver/gadget operations",
            ));
        }
        if shapes.windows(2).any(|pair| pair[0] != pair[1]) {
            self.diagnostics.push(Diagnostic::new(
                Rule::BranchShapeDivergence,
                span,
                format!("conditional driver-operation shapes differ: {shapes:?}"),
            ));
        }
    }

    fn inspect_early_exit<'ast>(
        &mut self,
        condition: &Expr,
        arms: impl IntoIterator<Item = &'ast Expr>,
        continuation: &[Stmt],
        span: Span,
        additionally_witness_observable: bool,
    ) {
        if driver_operation_shape_block(
            &Block {
                brace_token: Default::default(),
                stmts: continuation.to_vec(),
            },
            self.driver_variables,
        )
        .is_empty()
        {
            return;
        }

        let arms: Vec<_> = arms.into_iter().collect();
        if arms
            .iter()
            .any(|arm| !driver_operation_shape(arm, self.driver_variables).is_empty())
        {
            // The ordinary arm comparison already reports witness control when
            // an arm itself emits constraints. This helper covers the missing
            // case where an otherwise-empty arm exits before later emissions.
            return;
        }
        let exits: Vec<_> = arms
            .iter()
            .map(|arm| expression_must_diverge(arm))
            .collect();
        if exits.iter().all(|exit| *exit) || exits.iter().all(|exit| !*exit) {
            return;
        }

        if additionally_witness_observable
            || is_witness_observable(condition, self.captured_mutations, self.witness_variables)
        {
            self.diagnostics.push(Diagnostic::new(
                Rule::WitnessDependentShape,
                span,
                "witness-observable branch can exit before later driver/gadget operations",
            ));
        }
        self.diagnostics.push(Diagnostic::new(
            Rule::BranchShapeDivergence,
            span,
            "conditional arm can exit before later driver/gadget operations",
        ));
    }
}

impl<'ast> Visit<'ast> for FunctionBodyPass<'_> {
    fn visit_item(&mut self, _: &'ast syn::Item) {
        // `SourceAnalyzer` visits nested functions separately with their own
        // driver parameters, taint set, and use counts.
    }

    fn visit_block(&mut self, block: &'ast Block) {
        for (index, statement) in block.stmts.iter().enumerate() {
            if let Stmt::Expr(expression, _) = statement {
                match peel_expression(expression) {
                    Expr::If(expression) => {
                        let then_arm = Expr::Block(syn::ExprBlock {
                            attrs: Vec::new(),
                            label: None,
                            block: expression.then_branch.clone(),
                        });
                        let empty_else = Expr::Tuple(syn::ExprTuple {
                            attrs: Vec::new(),
                            paren_token: Default::default(),
                            elems: Default::default(),
                        });
                        let else_arm = expression
                            .else_branch
                            .as_ref()
                            .map(|(_, expression)| expression.as_ref())
                            .unwrap_or(&empty_else);
                        self.inspect_early_exit(
                            &expression.cond,
                            [&then_arm, else_arm],
                            &block.stmts[index + 1..],
                            expression.if_token.span,
                            false,
                        );
                    }
                    Expr::Match(expression) => {
                        let witness_dependent_guard = expression.arms.iter().any(|arm| {
                            arm.guard.as_ref().is_some_and(|(_, guard)| {
                                is_witness_observable(
                                    guard,
                                    self.captured_mutations,
                                    self.witness_variables,
                                )
                            })
                        });
                        self.inspect_early_exit(
                            &expression.expr,
                            expression.arms.iter().map(|arm| arm.body.as_ref()),
                            &block.stmts[index + 1..],
                            expression.match_token.span,
                            witness_dependent_guard,
                        );
                    }
                    _ => {}
                }
            }
            if let Stmt::Local(local) = statement
                && let Some(initializer) = &local.init
                && let Some((_, diverge)) = &initializer.diverge
            {
                // A let-else chooses between its diverging arm and the rest of
                // the enclosing block. Comparing only the local statement
                // would miss the common `else { return }` case where all
                // constraint emission lives in that continuation.
                let continuation = Expr::Block(syn::ExprBlock {
                    attrs: Vec::new(),
                    label: None,
                    block: Block {
                        brace_token: Default::default(),
                        stmts: block.stmts[index + 1..].to_vec(),
                    },
                });
                self.inspect_condition(
                    &initializer.expr,
                    [&continuation, diverge.as_ref()],
                    local.let_token.span,
                    false,
                );
            }
            self.visit_stmt(statement);
        }
    }

    fn visit_stmt(&mut self, statement: &'ast Stmt) {
        match statement {
            Stmt::Local(local) => {
                let Some(initializer) = &local.init else {
                    visit::visit_stmt(self, statement);
                    return;
                };
                if let Some(operation) = self.driver_operation(&initializer.expr) {
                    let mut bindings = BTreeSet::new();
                    collect_pattern_bindings(&local.pat, &mut bindings);
                    let unused_underscore_bindings: Vec<_> = bindings
                        .into_iter()
                        .filter(|binding| {
                            binding.starts_with('_')
                                && self.use_counts.get(binding).copied().unwrap_or(0) == 0
                        })
                        .collect();
                    let contains_wildcard = pattern_contains_wildcard(&local.pat);
                    if contains_wildcard || !unused_underscore_bindings.is_empty() {
                        let (rule, message) = if is_fallible_operation(&operation)
                            && !explicitly_handles_result(&initializer.expr)
                        {
                            (
                                Rule::IgnoredDriverResult,
                                format!(
                                    "fallible `{operation}` result is discarded without `?`, matching, or explicit handling"
                                ),
                            )
                        } else {
                            let discarded = if contains_wildcard {
                                "wildcard pattern".to_owned()
                            } else {
                                format!("binding(s) {}", unused_underscore_bindings.join(", "))
                            };
                            (
                                Rule::DiscardedConstraintValue,
                                format!(
                                    "value produced by `{operation}` is explicitly discarded by {discarded}"
                                ),
                            )
                        };
                        self.diagnostics
                            .push(Diagnostic::new(rule, local.pat.span(), message));
                    }
                }
            }
            Stmt::Expr(expression, Some(_)) => {
                if let Some(operation) = self.driver_operation(expression) {
                    if is_fallible_operation(&operation) && !explicitly_handles_result(expression) {
                        self.diagnostics.push(Diagnostic::new(
                            Rule::IgnoredDriverResult,
                            expression.span(),
                            format!(
                                "fallible `{operation}` result is ignored without `?`, matching, or explicit handling"
                            ),
                        ));
                    } else if produces_constraint_value(&operation) {
                        self.diagnostics.push(Diagnostic::new(
                            Rule::DiscardedConstraintValue,
                            expression.span(),
                            format!("value produced by `{operation}` is explicitly discarded"),
                        ));
                    }
                }
            }
            _ => {}
        }
        visit::visit_stmt(self, statement);
    }

    fn visit_expr_if(&mut self, expression: &'ast ExprIf) {
        let then_arm = Expr::Block(syn::ExprBlock {
            attrs: Vec::new(),
            label: None,
            block: expression.then_branch.clone(),
        });
        let empty_else = Expr::Tuple(syn::ExprTuple {
            attrs: Vec::new(),
            paren_token: Default::default(),
            elems: Default::default(),
        });
        let else_arm = expression
            .else_branch
            .as_ref()
            .map(|(_, expression)| expression.as_ref())
            .unwrap_or(&empty_else);
        self.inspect_condition(
            &expression.cond,
            [&then_arm, else_arm],
            expression.if_token.span,
            false,
        );
        visit::visit_expr_if(self, expression);
    }

    fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
        if matches!(expression.op, BinOp::And(_) | BinOp::Or(_)) {
            let skipped_arm = Expr::Tuple(syn::ExprTuple {
                attrs: Vec::new(),
                paren_token: Default::default(),
                elems: Default::default(),
            });
            self.inspect_condition(
                &expression.left,
                [expression.right.as_ref(), &skipped_arm],
                expression.op.span(),
                false,
            );
        }
        visit::visit_expr_binary(self, expression);
    }

    fn visit_expr_match(&mut self, expression: &'ast ExprMatch) {
        let witness_dependent_guard = expression.arms.iter().any(|arm| {
            arm.guard.as_ref().is_some_and(|(_, guard)| {
                is_witness_observable(guard, self.captured_mutations, self.witness_variables)
            })
        });
        self.inspect_condition(
            &expression.expr,
            expression.arms.iter().map(|arm| arm.body.as_ref()),
            expression.match_token.span,
            witness_dependent_guard,
        );
        visit::visit_expr_match(self, expression);
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast ExprForLoop) {
        self.inspect_repetition(
            &expression.expr,
            &expression.body,
            expression.for_token.span,
        );
        visit::visit_expr_for_loop(self, expression);
    }

    fn visit_expr_while(&mut self, expression: &'ast ExprWhile) {
        self.inspect_repetition(
            &expression.cond,
            &expression.body,
            expression.while_token.span,
        );
        visit::visit_expr_while(self, expression);
    }
}

impl FunctionBodyPass<'_> {
    fn inspect_repetition(&mut self, source: &Expr, body: &Block, span: Span) {
        if driver_operation_shape_block(body, self.driver_variables).is_empty() {
            return;
        }
        if is_witness_observable(source, self.captured_mutations, self.witness_variables) {
            self.diagnostics.push(Diagnostic::new(
                Rule::WitnessDependentShape,
                span,
                "witness-observable loop bound controls driver/gadget operations",
            ));
        }
    }
}

fn explicitly_handles_result(expression: &Expr) -> bool {
    match peel_expression(expression) {
        Expr::Try(_) | Expr::Match(_) => true,
        Expr::MethodCall(call) => matches!(
            call.method.to_string().as_str(),
            "expect"
                | "expect_err"
                | "is_err"
                | "is_ok"
                | "ok"
                | "unwrap"
                | "unwrap_err"
                | "unwrap_or"
                | "unwrap_or_else"
        ),
        _ => false,
    }
}

fn peel_expression(mut expression: &Expr) -> &Expr {
    loop {
        expression = match expression {
            Expr::Group(group) => &group.expr,
            Expr::Paren(paren) => &paren.expr,
            _ => return expression,
        };
    }
}

fn expression_must_diverge(expression: &Expr) -> bool {
    match peel_expression(expression) {
        Expr::Break(_) | Expr::Continue(_) | Expr::Return(_) => true,
        Expr::Block(expression) => block_must_diverge(&expression.block),
        Expr::If(expression) => {
            block_must_diverge(&expression.then_branch)
                && expression
                    .else_branch
                    .as_ref()
                    .is_some_and(|(_, expression)| expression_must_diverge(expression))
        }
        Expr::Match(expression) => {
            !expression.arms.is_empty()
                && expression
                    .arms
                    .iter()
                    .all(|arm| expression_must_diverge(&arm.body))
        }
        _ => false,
    }
}

fn block_must_diverge(block: &Block) -> bool {
    block.stmts.last().is_some_and(|statement| match statement {
        Stmt::Expr(expression, _) => expression_must_diverge(expression),
        Stmt::Local(_) | Stmt::Item(_) | Stmt::Macro(_) => false,
    })
}

fn top_level_driver_operation(
    expression: &Expr,
    driver_variables: &BTreeSet<String>,
) -> Option<String> {
    match peel_expression(expression) {
        Expr::Try(expression) => top_level_driver_operation(&expression.expr, driver_variables),
        Expr::MethodCall(call) if method_call_uses_driver(call, driver_variables) => {
            Some(call.method.to_string())
        }
        Expr::Call(call)
            if called_name(&call.func)
                .is_some_and(|name| matches!(name.as_str(), "drop" | "forget"))
                && call.args.len() == 1 =>
        {
            top_level_driver_operation(&call.args[0], driver_variables)
        }
        Expr::Call(call)
            if call
                .args
                .iter()
                .any(|argument| expression_is_driver_argument(argument, driver_variables)) =>
        {
            called_name(&call.func)
        }
        Expr::MethodCall(call) => top_level_driver_operation(&call.receiver, driver_variables),
        _ => None,
    }
}

fn top_level_driver_type_operation(
    expression: &Expr,
    driver_types: &BTreeSet<String>,
) -> Option<String> {
    match peel_expression(expression) {
        Expr::Try(expression) => top_level_driver_type_operation(&expression.expr, driver_types),
        Expr::Call(call)
            if called_name(&call.func)
                .is_some_and(|name| matches!(name.as_str(), "drop" | "forget"))
                && call.args.len() == 1 =>
        {
            top_level_driver_type_operation(&call.args[0], driver_types)
        }
        Expr::Call(call) if call.args.len() == 1 => {
            let Expr::Path(function) = peel_expression(&call.func) else {
                return None;
            };
            let first = function.path.segments.first()?.ident.to_string();
            let name = function.path.segments.last()?.ident.to_string();
            (driver_types.contains(&first) && is_assignment_source(&name)).then_some(name)
        }
        Expr::MethodCall(call) => top_level_driver_type_operation(&call.receiver, driver_types),
        _ => None,
    }
}

fn method_call_uses_driver(call: &ExprMethodCall, driver_variables: &BTreeSet<String>) -> bool {
    expression_is_driver_argument(&call.receiver, driver_variables)
        || call
            .args
            .iter()
            .any(|argument| expression_is_driver_argument(argument, driver_variables))
}

fn expression_is_driver_argument(expression: &Expr, driver_variables: &BTreeSet<String>) -> bool {
    root_identifier(expression)
        .is_some_and(|(identifier, _)| driver_variables.contains(&identifier))
}

fn is_fallible_operation(name: &str) -> bool {
    name == "alloc"
        || name.starts_with("alloc_")
        || name == "assign_extra"
        || name == "divide"
        || name == "fold"
        || name == "gate"
        || name == "invert"
        || name.starts_with("invert_")
        || name == "mul"
        || name == "maybe_try_just"
        || name == "receive"
        || name == "routine"
        || name == "square"
        || name == "try_just"
        || name.starts_with("enforce")
}

fn produces_constraint_value(name: &str) -> bool {
    matches!(
        name,
        "add"
            | "alloc"
            | "assign_extra"
            | "divide"
            | "fold"
            | "gate"
            | "invert"
            | "mul"
            | "receive"
            | "routine"
            | "square"
    ) || name.starts_with("alloc_")
        || name.starts_with("invert_")
}

fn driver_operation_shape(expression: &Expr, driver_variables: &BTreeSet<String>) -> Vec<String> {
    struct ShapePass<'a> {
        drivers: &'a BTreeSet<String>,
        operations: Vec<String>,
    }
    impl<'ast> Visit<'ast> for ShapePass<'_> {
        fn visit_item(&mut self, _: &'ast syn::Item) {}

        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            if method_call_uses_driver(call, self.drivers) {
                self.operations.push(call.method.to_string());
            }
            visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_call(&mut self, call: &'ast ExprCall) {
            if call
                .args
                .iter()
                .any(|argument| expression_is_driver_argument(argument, self.drivers))
                && let Some(name) = called_name(&call.func)
            {
                self.operations.push(name);
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut pass = ShapePass {
        drivers: driver_variables,
        operations: Vec::new(),
    };
    pass.visit_expr(expression);
    pass.operations
}

fn driver_operation_shape_block(block: &Block, driver_variables: &BTreeSet<String>) -> Vec<String> {
    let wrapper = Expr::Block(syn::ExprBlock {
        attrs: Vec::new(),
        label: None,
        block: block.clone(),
    });
    driver_operation_shape(&wrapper, driver_variables)
}

fn is_witness_observable(
    expression: &Expr,
    captured_mutations: &BTreeSet<String>,
    witness_variables: &BTreeSet<String>,
) -> bool {
    struct WitnessPass<'a> {
        captures: &'a BTreeSet<String>,
        witnesses: &'a BTreeSet<String>,
        found: bool,
    }
    impl<'ast> Visit<'ast> for WitnessPass<'_> {
        fn visit_item(&mut self, _: &'ast syn::Item) {}

        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            if expression.qself.is_none() && expression.path.segments.len() == 1 {
                let identifier = expression.path.segments[0].ident.to_string();
                self.found |=
                    self.captures.contains(&identifier) || self.witnesses.contains(&identifier);
            }
        }
    }
    let mut pass = WitnessPass {
        captures: captured_mutations,
        witnesses: witness_variables,
        found: false,
    };
    pass.visit_expr(expression);
    pass.found
}

fn expression_identifier_counts(block: &Block) -> BTreeMap<String, usize> {
    struct CountPass {
        counts: BTreeMap<String, usize>,
    }
    impl<'ast> Visit<'ast> for CountPass {
        fn visit_item(&mut self, _: &'ast syn::Item) {}

        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            if expression.qself.is_none() && expression.path.segments.len() == 1 {
                *self
                    .counts
                    .entry(expression.path.segments[0].ident.to_string())
                    .or_default() += 1;
            }
            visit::visit_expr_path(self, expression);
        }
    }
    let mut pass = CountPass {
        counts: BTreeMap::new(),
    };
    pass.visit_block(block);
    pass.counts
}

fn expression_mentions_any_identifier(expression: &Expr, identifiers: &BTreeSet<String>) -> bool {
    struct Finder<'a> {
        identifiers: &'a BTreeSet<String>,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_item(&mut self, _: &'ast syn::Item) {}

        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            if expression.qself.is_none() && expression.path.segments.len() == 1 {
                self.found |= self
                    .identifiers
                    .contains(&expression.path.segments[0].ident.to_string());
            }
            if !self.found {
                visit::visit_expr_path(self, expression);
            }
        }
    }
    let mut finder = Finder {
        identifiers,
        found: false,
    };
    finder.visit_expr(expression);
    finder.found
}

fn called_name(expression: &Expr) -> Option<String> {
    let Expr::Path(path) = peel_expression(expression) else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn root_identifier(expression: &Expr) -> Option<(String, Span)> {
    match peel_expression(expression) {
        Expr::Path(path) if path.qself.is_none() && path.path.segments.len() == 1 => {
            let ident = &path.path.segments[0].ident;
            Some((ident.to_string(), ident.span()))
        }
        Expr::Field(field) => root_identifier(&field.base),
        Expr::Reference(reference) => root_identifier(&reference.expr),
        Expr::Unary(unary) => root_identifier(&unary.expr),
        Expr::Index(index) => root_identifier(&index.expr),
        _ => None,
    }
}

fn collect_pattern_bindings(pattern: &Pat, output: &mut BTreeSet<String>) {
    struct PatternPass<'a> {
        output: &'a mut BTreeSet<String>,
    }
    impl<'ast> Visit<'ast> for PatternPass<'_> {
        fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
            self.output.insert(pattern.ident.to_string());
            visit::visit_pat_ident(self, pattern);
        }
    }
    PatternPass { output }.visit_pat(pattern);
}

fn pattern_contains_wildcard(pattern: &Pat) -> bool {
    struct WildcardPass {
        found: bool,
    }
    impl<'ast> Visit<'ast> for WildcardPass {
        fn visit_pat_wild(&mut self, _: &'ast syn::PatWild) {
            self.found = true;
        }
    }
    let mut pass = WildcardPass { found: false };
    pass.visit_pat(pattern);
    pass.found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(source: &str) -> Vec<&'static str> {
        analyze_source(source)
            .unwrap()
            .iter()
            .map(|diagnostic| diagnostic.rule.code())
            .collect()
    }

    #[test]
    fn rejects_swallowed_driver_error() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                let _ = dr.mul(|| Err(Error::InvalidWitness("swallowed".into())));
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU001"]);
    }

    #[test]
    fn recognizes_impl_trait_driver_parameter() {
        let source = r#"
            fn witness<'dr>(dr: &mut impl Driver<'dr>) -> Result<()> {
                let _ = dr.mul(|| Err(Error::InvalidWitness("swallowed".into())));
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU001"]);
    }

    #[test]
    fn analyzes_nested_function_once_in_its_own_scope() {
        let source = r#"
            fn outer<'dr, D: Driver<'dr>>(_dr: &mut D) {
                fn inner<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                    let _ignored = dr.mul(|| {
                        Err(Error::InvalidWitness("swallowed".into()))
                    });
                    Ok(())
                }
            }
        "#;
        assert_eq!(codes(source), ["RAGU001"]);
    }

    #[test]
    fn accepts_propagated_driver_error() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                let _ = dr.mul(|| Err(Error::InvalidWitness("propagated".into())))?;
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU004"]);
    }

    #[test]
    fn underscore_binding_cannot_hide_a_fallible_result() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                let _ignored = dr.mul(|| Err(Error::InvalidWitness("swallowed".into())));
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU001"]);
    }

    #[test]
    fn associated_witness_error_cannot_be_discarded() {
        let source = r#"
            fn helper<'dr, D: Driver<'dr>>() -> Result<()> {
                let _ignored = D::maybe_try_just(|| {
                    Err(Error::InvalidWitness("swallowed".into()))
                });
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU001"]);
    }

    #[test]
    fn warns_about_partially_discarded_driver_output() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                let (_, right, product) = dr.mul(|| {
                    Ok((Coeff::One, Coeff::One, Coeff::One))
                })?;
                dr.enforce_equal(&right, &product)?;
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU004"]);
    }

    #[test]
    fn warns_about_driver_output_discarded_as_a_statement() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                dr.mul(|| Ok((Coeff::One, Coeff::One, Coeff::One)))?;
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU004"]);
    }

    #[test]
    fn rejects_chained_mapping_of_swallowed_result() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                let _ = dr
                    .mul(|| Err(Error::InvalidWitness("swallowed".into())))
                    .map(|_| ());
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU001"]);
    }

    #[test]
    fn rejects_explicit_drop_of_fallible_result() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                drop(dr.mul(|| Err(Error::InvalidWitness("swallowed".into()))));
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU001"]);
    }

    #[test]
    fn rejects_forgetting_a_fallible_result() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                core::mem::forget(dr.mul(|| {
                    Err(Error::InvalidWitness("swallowed".into()))
                }));
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU001"]);
    }

    #[test]
    fn rejects_assignment_closure_side_effect_and_branch() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                let ran = Cell::new(false);
                let value = dr.mul(|| {
                    ran.set(true);
                    Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero))
                })?;
                if ran.get() {
                    dr.enforce_zero(|lc| lc.add(&value.0))?;
                }
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU002", "RAGU003", "RAGU005"]);
    }

    #[test]
    fn rejects_maybe_just_closure_side_effect_and_branch() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                let ran = Cell::new(false);
                let value = D::maybe_just(|| {
                    ran.set(true);
                    F::ONE
                });
                drop(value);
                if ran.get() {
                    dr.enforce_zero(|lc| lc)?;
                }
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU002", "RAGU003", "RAGU005"]);
    }

    #[test]
    fn rejects_assignment_side_effect_without_a_driver_argument() {
        let source = r#"
            fn helper<'dr, D: Driver<'dr>>() {
                let mut ran = false;
                let value = D::just(|| {
                    ran = true;
                    F::ONE
                });
                drop(value);
            }
        "#;
        assert_eq!(codes(source), ["RAGU002"]);
    }

    #[test]
    fn warns_when_branches_emit_different_shapes() {
        let source = r#"
            fn gadget<'dr, D: Driver<'dr>>(dr: &mut D, choice: bool) -> Result<()> {
                if choice {
                    dr.enforce_zero(|lc| lc)?;
                }
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU005"]);
    }

    #[test]
    fn rejects_driver_value_controlled_shape() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(
                dr: &mut D,
                witness: DriverValue<D, bool>,
            ) -> Result<()> {
                if witness.into_option().unwrap_or(false) {
                    dr.enforce_zero(|lc| lc)?;
                }
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU003", "RAGU005"]);
    }

    #[test]
    fn rejects_driver_value_controlled_short_circuit() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(
                dr: &mut D,
                witness: DriverValue<D, bool>,
            ) -> Result<()> {
                let _ran = witness.into_option().unwrap_or(false) && {
                    dr.enforce_zero(|lc| lc)?;
                    true
                };
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU003", "RAGU005"]);
    }

    #[test]
    fn rejects_driver_value_controlled_match_guard() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(
                dr: &mut D,
                witness: DriverValue<D, bool>,
            ) -> Result<()> {
                match () {
                    _ if witness.into_option().unwrap_or(false) => {
                        dr.enforce_zero(|lc| lc)?;
                    }
                    _ => {}
                }
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU003", "RAGU005"]);
    }

    #[test]
    fn rejects_driver_value_controlled_let_else() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(
                dr: &mut D,
                witness: DriverValue<D, Option<F>>,
            ) -> Result<()> {
                let Some(_) = witness.into_option().flatten() else {
                    return Ok(());
                };
                dr.enforce_zero(|lc| lc)?;
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU003", "RAGU005"]);
    }

    #[test]
    fn rejects_driver_value_controlled_early_return() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(
                dr: &mut D,
                witness: DriverValue<D, bool>,
            ) -> Result<()> {
                if witness.into_option().unwrap_or(false) {
                    return Ok(());
                }
                dr.enforce_zero(|lc| lc)?;
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU003", "RAGU005"]);
    }

    #[test]
    fn does_not_taint_ordinary_option_state() {
        let source = r#"
            fn gadget<'dr, D: Driver<'dr>>(dr: &mut D, value: Option<bool>) -> Result<()> {
                if value.take().unwrap_or(false) {
                    dr.enforce_zero(|lc| lc)?;
                }
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU005"]);
    }

    #[test]
    fn allows_mutating_state_local_to_assignment_closure() {
        let source = r#"
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                let value = dr.mul(|| {
                    let local = Cell::new(false);
                    local.set(true);
                    Ok((Coeff::One, Coeff::One, Coeff::One))
                })?;
                dr.enforce_equal(&value.0, &value.2)?;
                Ok(())
            }
        "#;
        assert!(codes(source).is_empty());
    }

    #[test]
    fn skips_cfg_test_modules() {
        let source = r#"
            #[cfg(test)]
            mod tests {
                fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                    let _ = dr.mul(|| Err(Error::InvalidWitness("fixture".into())));
                    Ok(())
                }
            }
        "#;
        assert!(codes(source).is_empty());
    }

    #[test]
    fn does_not_skip_non_test_cfg_expressions() {
        let source = r#"
            #[cfg(not(test))]
            fn witness<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                let _ = dr.mul(|| Err(Error::InvalidWitness("production".into())));
                Ok(())
            }

            #[cfg(any(test, feature = "production"))]
            fn second<'dr, D: Driver<'dr>>(dr: &mut D) -> Result<()> {
                let _ = dr.routine(BadRoutine, ()) ;
                Ok(())
            }
        "#;
        assert_eq!(codes(source), ["RAGU001", "RAGU001"]);
    }

    #[test]
    fn qa_baseline_cannot_suppress_errors() {
        let error = parse_baseline(
            "RAGU001|crates/ragu_core/src/example.rs|10|error suppression is forbidden",
        )
        .unwrap_err();
        assert!(error.contains("cannot suppress error-level RAGU001"));
    }

    #[test]
    fn production_sources_match_reviewed_qa_baseline() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let baseline = Path::new("qa/fuzz/source-lint-baseline.txt");
        let report = scan_sources(&root, &[], Some(baseline)).unwrap();
        assert_eq!(
            (report.errors(), report.advisories()),
            (0, 0),
            "production source lint found unreviewed or stale findings: {report:#?}",
        );
        assert!(
            report.diagnostics.is_empty(),
            "production source lint found unreviewed or stale findings: {report:#?}",
        );
        assert!(report.files_scanned > 100);
    }
}
