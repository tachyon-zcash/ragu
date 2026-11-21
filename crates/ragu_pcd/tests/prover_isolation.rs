//! Keeps prover code out of the code soundness depends on.
//!
//! A proof's soundness rests on the rest of the crate: the recursion's
//! definitions and circuits, the deciders, and the definitions they share.
//! Prover code only constructs proofs, so a soundness review can set it aside,
//! provided nothing else reaches into it. This test resolves every path that
//! code outside the prover files names and fails if one leads into prover code
//! (see [`is_prover`]). Test-only code and the fuzzing surface are exempt, and
//! the public re-exports of prover items are listed in [`ALLOWED`].
//!
//! It checks paths, not calls: an inherent method on `Application` that a
//! prover file defines can be called from anywhere, so verifier code keeps to
//! the methods its own files define.

use std::{collections::BTreeSet, fs, path::Path};

/// Whether the module or item at `path`, relative to the crate root, is prover
/// code.
fn is_prover(path: &[String]) -> bool {
    let path: Vec<&str> = path.iter().map(String::as_str).collect();
    match path.as_slice() {
        ["fuse", ..] | ["multicore", ..] | ["proof", "builder", ..] => true,
        // Prover items re-exported from shared modules.
        ["proof", "ProofBuilder"]
        | ["ipa", "create_proof"]
        | ["profile", "Decompressed" | "Decompression"] => true,
        _ => path.contains(&"prover"),
    }
}

/// Whether the file at `file`, relative to `src/`, is prover code.
fn is_prover_file(file: &str) -> bool {
    file.starts_with("fuse/")
        || file == "multicore.rs"
        || file == "proof/builder.rs"
        || file.ends_with("/prover.rs")
}

/// Whether the file at `file`, relative to `src/`, is test-only code. Inline
/// `#[cfg(test)]` items are skipped wherever they appear.
fn is_test_file(file: &str) -> bool {
    file.starts_with("fuzzing/") || file.ends_with("/tests.rs")
}

/// The prover paths that code outside the prover files may name, and why.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "proof/mod.rs",
        "proof::builder::ProofBuilder",
        "re-exports the builder for the fuse",
    ),
    (
        "ipa/mod.rs",
        "ipa::prover::create_proof",
        "the argument's public API",
    ),
    (
        "profile/mod.rs",
        "decompress::prover::Decompressed",
        "public under `unstable-aggregator`",
    ),
    (
        "profile/mod.rs",
        "decompress::prover::Decompression",
        "public under `unstable-aggregator`",
    ),
    (
        "decompress/aggregator.rs",
        "decompress::prover::Decompressed",
        "the aggregator profile's public types",
    ),
    (
        "decompress/aggregator.rs",
        "decompress::prover::Decompression",
        "the aggregator profile's public types",
    ),
    (
        "recursion/native/online.rs",
        "proof::ProofBuilder",
        "holds the fuse's native online batch phases",
    ),
    (
        "recursion/native/online.rs",
        "profile::online::prover::State",
        "holds the fuse's native online batch phases",
    ),
    (
        "recursion/nested/online.rs",
        "proof::ProofBuilder",
        "holds the fuse's nested online batch phases",
    ),
    (
        "recursion/nested/online.rs",
        "profile::online::prover::State",
        "holds the fuse's nested online batch phases",
    ),
];

#[test]
fn code_outside_the_prover_does_not_reach_into_it() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect(&src, &src, &mut files);

    let mut found = BTreeSet::new();
    let mut violations = Vec::new();
    for file in &files {
        if is_prover_file(file) || is_test_file(file) {
            continue;
        }
        let source = fs::read_to_string(src.join(file)).expect("readable source");
        for (line, path) in prover_paths(file, &source) {
            let joined = path.join("::");
            if ALLOWED
                .iter()
                .any(|(f, p, _)| *f == file.as_str() && *p == joined)
            {
                found.insert((file.clone(), joined));
            } else {
                violations.push(format!("src/{file}:{line}: {joined}"));
            }
        }
    }

    let stale: Vec<_> = ALLOWED
        .iter()
        .filter(|(f, p, _)| !found.contains(&(f.to_string(), p.to_string())))
        .map(|(f, p, _)| format!("src/{f}: {p}"))
        .collect();

    assert!(
        violations.is_empty(),
        "code outside the prover reaches into prover code; move the code that \
         needs it into the prover, or move the item it needs out:\n{}",
        violations.join("\n")
    );
    assert!(
        stale.is_empty(),
        "allowed prover paths that are no longer named; remove them from \
         `ALLOWED`:\n{}",
        stale.join("\n")
    );
}

#[test]
fn prover_paths_resolve_relative_and_grouped_imports() {
    let source = "
        use crate::{fuse::Orchestrator, recursion::native};
        use super::{prover::{Witness, reduce as r}, verifier};
        #[cfg(test)]
        mod tests {
            use crate::fuse::Test;
        }
        fn f() {
            let s = \"crate::fuse::Ignored\"; // crate::fuse::Ignored
            crate::multicore::par_join(|| (), || ());
            fuse::local();
        }
    ";
    let paths: Vec<_> = prover_paths("compress/verifier.rs", source)
        .into_iter()
        .map(|(line, path)| (line, path.join("::")))
        .collect();
    assert_eq!(
        paths,
        [
            (2, "fuse::Orchestrator".to_string()),
            (3, "compress::prover::Witness".to_string()),
            (3, "compress::prover::reduce".to_string()),
            (10, "multicore::par_join".to_string()),
        ]
    );
}

/// The `.rs` files under `dir`, relative to `root`.
fn collect(root: &Path, dir: &Path, files: &mut Vec<String>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("readable directory")
        .map(|entry| entry.expect("readable entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(root, &path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let relative = path.strip_prefix(root).expect("under the root");
            files.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// The module path of the file at `file`, relative to `src/`.
fn module_of(file: &str) -> Vec<String> {
    let mut segments: Vec<String> = file
        .trim_end_matches(".rs")
        .split('/')
        .map(String::from)
        .collect();
    if matches!(segments.last().map(String::as_str), Some("mod" | "lib")) {
        segments.pop();
    }
    segments
}

/// The prover paths `source` names, with the line each starts on.
fn prover_paths(file: &str, source: &str) -> Vec<(usize, Vec<String>)> {
    let module = module_of(file);
    let tokens = without_test_items(tokenize(source));
    let mut paths = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let (line, token) = &tokens[i];
        if token == "use" {
            i += 1;
            let mut trees = Vec::new();
            use_tree(&tokens, &mut i, Vec::new(), &mut trees);
            paths.extend(trees.into_iter().map(|path| (*line, path)));
            continue;
        }
        if is_ident(token) && (i == 0 || tokens[i - 1].1 != "::") {
            let mut path = vec![token.clone()];
            let mut j = i + 1;
            while j + 1 < tokens.len() && tokens[j].1 == "::" && is_ident(&tokens[j + 1].1) {
                path.push(tokens[j + 1].1.clone());
                j += 2;
            }
            if path.len() > 1 {
                paths.push((*line, path));
            }
            i = j;
            continue;
        }
        i += 1;
    }
    paths
        .into_iter()
        .filter_map(|(line, path)| resolve(&module, &path).map(|path| (line, path)))
        .filter(|(_, path)| is_prover(path))
        .collect()
}

/// Flattens the use tree at `tokens[*i]` under `prefix` into `out`.
fn use_tree(
    tokens: &[(usize, String)],
    i: &mut usize,
    prefix: Vec<String>,
    out: &mut Vec<Vec<String>>,
) {
    let mut path = prefix;
    while *i < tokens.len() {
        let token = tokens[*i].1.as_str();
        match token {
            "{" => {
                *i += 1;
                while *i < tokens.len() && tokens[*i].1 != "}" {
                    use_tree(tokens, i, path.clone(), out);
                    if *i < tokens.len() && tokens[*i].1 == "," {
                        *i += 1;
                    }
                }
                *i += 1;
                return;
            }
            "*" => {
                *i += 1;
                out.push(path);
                return;
            }
            "::" => *i += 1,
            _ if is_ident(token) => {
                *i += 1;
                if token != "self" || path.is_empty() {
                    path.push(token.to_string());
                }
                if *i < tokens.len() && tokens[*i].1 == "::" {
                    continue;
                }
                if *i + 1 < tokens.len() && tokens[*i].1 == "as" {
                    *i += 2;
                }
                out.push(path);
                return;
            }
            _ => return,
        }
    }
}

/// The crate-relative path `path` names from `module`, or `None` when it names
/// something outside the crate or a local item.
fn resolve(module: &[String], path: &[String]) -> Option<Vec<String>> {
    let mut base = module.to_vec();
    let mut rest = path;
    match path.first()?.as_str() {
        "crate" => {
            base.clear();
            rest = &path[1..];
        }
        "self" => rest = &path[1..],
        "super" => {
            while rest.first().map(String::as_str) == Some("super") {
                base.pop()?;
                rest = &rest[1..];
            }
        }
        // A child module of the current one, as these names are not crates.
        "fuse" | "prover" | "multicore" | "builder" => {}
        _ => return None,
    }
    base.extend(rest.iter().cloned());
    Some(base)
}

fn is_ident(token: &str) -> bool {
    token
        .chars()
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_')
}

/// Drops each item marked `#[cfg(test)]` or `#[cfg(all(test, ..))]`: the
/// attributes, then the item up to its `;` or `,`, its closing brace, or the
/// end of the scope it sits in.
fn without_test_items(tokens: Vec<(usize, String)>) -> Vec<(usize, String)> {
    let mut out = Vec::with_capacity(tokens.len());
    let mut i = 0;
    while i < tokens.len() {
        if is_test_attribute(&tokens, i) {
            while i < tokens.len() && tokens[i].1 == "#" {
                i = skip_attribute(&tokens, i);
            }
            let mut depth = 0usize;
            while i < tokens.len() {
                match tokens[i].1.as_str() {
                    "{" | "(" | "[" => depth += 1,
                    "}" | ")" | "]" => {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                        if depth == 0 && tokens[i].1 == "}" {
                            i += 1;
                            break;
                        }
                    }
                    ";" | "," if depth == 0 => {
                        i += 1;
                        break;
                    }
                    _ => {}
                }
                i += 1;
            }
            continue;
        }
        out.push(tokens[i].clone());
        i += 1;
    }
    out
}

/// Whether `tokens[i]` begins `#[cfg(test)]` or `#[cfg(all(test, ..))]`.
fn is_test_attribute(tokens: &[(usize, String)], i: usize) -> bool {
    let text: Vec<&str> = tokens[i..]
        .iter()
        .take(7)
        .map(|(_, token)| token.as_str())
        .collect();
    matches!(
        text.as_slice(),
        ["#", "[", "cfg", "(", "test", ")", ..] | ["#", "[", "cfg", "(", "all", "(", "test"]
    )
}

/// The index past the attribute at `tokens[i]`.
fn skip_attribute(tokens: &[(usize, String)], mut i: usize) -> usize {
    i += 1;
    let mut depth = 0usize;
    while i < tokens.len() {
        match tokens[i].1.as_str() {
            "[" => depth += 1,
            "]" => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    i
}

/// Splits `source` into identifiers, `::` and single punctuation characters,
/// each with its line, dropping comments and the contents of string and
/// character literals.
fn tokenize(source: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            _ if c.is_whitespace() => i += 1,
            '/' if next == Some('/') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if next == Some('*') => {
                let mut depth = 0usize;
                while i < chars.len() {
                    if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                    } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        line += usize::from(chars[i] == '\n');
                        i += 1;
                    }
                }
            }
            '"' => {
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    line += usize::from(chars[i] == '\n');
                    i += if chars[i] == '\\' { 2 } else { 1 };
                }
                i += 1;
            }
            'r' if matches!(next, Some('"' | '#')) && raw_string_end(&chars, i).is_some() => {
                let end = raw_string_end(&chars, i).expect("checked");
                line += chars[i..end].iter().filter(|&&c| c == '\n').count();
                i = end;
            }
            '\'' => {
                // A character literal, unlike a lifetime, closes after one
                // character or one escape.
                let close = if next == Some('\\') {
                    chars[i + 2..]
                        .iter()
                        .position(|&c| c == '\'')
                        .map(|p| i + 3 + p)
                } else if chars.get(i + 2) == Some(&'\'') {
                    Some(i + 3)
                } else {
                    None
                };
                match close {
                    Some(end) => i = end,
                    None => {
                        tokens.push((line, "'".to_string()));
                        i += 1;
                    }
                }
            }
            ':' if next == Some(':') => {
                tokens.push((line, "::".to_string()));
                i += 2;
            }
            _ if c.is_alphanumeric() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                tokens.push((line, chars[start..i].iter().collect()));
            }
            _ => {
                tokens.push((line, c.to_string()));
                i += 1;
            }
        }
    }
    tokens
}

/// The index past the raw string literal starting at `chars[i]`, if one does.
fn raw_string_end(chars: &[char], i: usize) -> Option<usize> {
    if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
        return None;
    }
    let mut j = i + 1;
    let mut hashes = 0;
    while chars.get(j) == Some(&'#') {
        hashes += 1;
        j += 1;
    }
    if chars.get(j) != Some(&'"') {
        return None;
    }
    j += 1;
    while j < chars.len() {
        if chars[j] == '"'
            && chars[j + 1..]
                .iter()
                .take(hashes)
                .filter(|&&c| c == '#')
                .count()
                == hashes
        {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
    None
}
