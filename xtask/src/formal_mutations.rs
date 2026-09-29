#![allow(clippy::too_many_lines)]

//! Mutation adequacy of the formal development: study 006's three campaigns.
//!
//! S1 applies each case of the project's semantic mutation matrix, S2 mutates
//! the comparison, Boolean, and result-position operators of the model's `def`
//! bodies, and S3 replaces each translated function's generated body with
//! `fail .panic`. A mutant is killed when `lake build Auths` fails; the first
//! error and the declaration it falls in are recorded. A first error inside
//! the mutated definition itself is a stillborn mutant, not a kill.

use crate::formal_coverage::{
    ErrorLocation, MUTATION_SCHEMA, MUTATIONS_PATH, Mutant, MutationResults, TOOL_VERSION, Tree,
    WorkTree, formal_inputs_sha256, load_mutation_results, render_json,
};
use crate::*;
use std::sync::{Arc, Mutex};

const S1_EDITS: &str = "formal/s1-mutation-edits-v1.json";
const S2_FILES: [&str; 4] = [
    "Auths/Observation.lean",
    "Auths/Composition.lean",
    "Auths/Generated/Algebra.lean",
    "Auths/Product/CeilingCount.lean",
];
const BUILD_TARGET: &str = "Auths";

/// One mutant ready to apply: a replacement of `original` by `replacement` at
/// character `offset` of `file` (relative to `formal/`).
#[derive(Clone, Debug)]
pub(crate) struct Planned {
    pub(crate) campaign: &'static str,
    pub(crate) id: String,
    pub(crate) file: String,
    pub(crate) definition: String,
    pub(crate) definition_lines: (usize, usize),
    pub(crate) operator: String,
    pub(crate) offset: usize,
    pub(crate) original: String,
    pub(crate) replacement: String,
    pub(crate) witness: Option<String>,
}

// ---------------------------------------------------------------------------
// S2: model operator sites (a port of study 006's `mutate.py`)
// ---------------------------------------------------------------------------

fn code_mask(text: &[char]) -> Vec<bool> {
    let mut mask = vec![true; text.len()];
    let starts = |index: usize, pattern: &str| {
        pattern
            .chars()
            .enumerate()
            .all(|(position, character)| text.get(index + position) == Some(&character))
    };
    let (mut index, mut depth) = (0usize, 0usize);
    while index < text.len() {
        if depth > 0 {
            if starts(index, "/-") {
                depth += 1;
                mask[index] = false;
                mask[index + 1] = false;
                index += 2;
                continue;
            }
            if starts(index, "-/") {
                depth -= 1;
                mask[index] = false;
                mask[index + 1] = false;
                index += 2;
                continue;
            }
            mask[index] = false;
            index += 1;
            continue;
        }
        if starts(index, "/-") {
            depth = 1;
            mask[index] = false;
            mask[index + 1] = false;
            index += 2;
            continue;
        }
        if starts(index, "--") {
            let end = (index..text.len())
                .find(|&position| text[position] == '\n')
                .unwrap_or(text.len());
            for flag in &mut mask[index..end] {
                *flag = false;
            }
            index = end;
            continue;
        }
        if text[index] == '"' {
            let mut end = index + 1;
            while end < text.len() && text[end] != '"' {
                end += if text[end] == '\\' { 2 } else { 1 };
            }
            for flag in &mut mask[index..(end + 1).min(text.len())] {
                *flag = false;
            }
            index = end + 1;
            continue;
        }
        index += 1;
    }
    mask
}

fn line_starts(text: &[char]) -> Vec<usize> {
    let mut starts = vec![0];
    starts.extend(
        text.iter()
            .enumerate()
            .filter(|(_, character)| **character == '\n')
            .map(|(position, _)| position + 1),
    );
    starts
}

/// `^(?:@\[[^\]]*\]\s*)*(?:(?:private|protected|noncomputable|partial|unsafe)\s+)*def\s+(\S+)`.
fn def_header(line: &str) -> Option<String> {
    let characters: Vec<char> = line.chars().collect();
    let mut index = 0;
    let skip_space = |mut index: usize| {
        while index < characters.len() && characters[index].is_whitespace() {
            index += 1;
        }
        index
    };
    loop {
        if characters.get(index) == Some(&'@') && characters.get(index + 1) == Some(&'[') {
            let mut cursor = index + 2;
            while cursor < characters.len() && characters[cursor] != ']' {
                cursor += 1;
            }
            if cursor >= characters.len() {
                return None;
            }
            index = skip_space(cursor + 1);
            continue;
        }
        break;
    }
    let word_at = |index: usize, word: &str| {
        word.chars()
            .enumerate()
            .all(|(position, character)| characters.get(index + position) == Some(&character))
    };
    loop {
        let modifier = ["private", "protected", "noncomputable", "partial", "unsafe"]
            .into_iter()
            .find(|word| {
                word_at(index, word)
                    && characters
                        .get(index + word.len())
                        .is_some_and(|character| character.is_whitespace())
            });
        match modifier {
            Some(word) => index = skip_space(index + word.len()),
            None => break,
        }
    }
    if !(word_at(index, "def")
        && characters
            .get(index + 3)
            .is_some_and(|character| character.is_whitespace()))
    {
        return None;
    }
    let start = skip_space(index + 3);
    let mut end = start;
    while end < characters.len() && !characters[end].is_whitespace() {
        end += 1;
    }
    (end > start).then(|| characters[start..end].iter().collect())
}

/// (name, start offset, end offset) of every top-level `def`.
fn definitions(text: &[char]) -> Vec<(String, usize, usize)> {
    let starts = line_starts(text);
    let source: String = text.iter().collect();
    let lines: Vec<&str> = source.split('\n').collect();
    let mut found = Vec::new();
    let mut number = 0;
    while number < lines.len() {
        let Some(name) = def_header(lines[number]) else {
            number += 1;
            continue;
        };
        let mut end = number + 1;
        while end < lines.len()
            && (lines[end].is_empty()
                || lines[end].starts_with(' ')
                || lines[end].starts_with('\t'))
        {
            end += 1;
        }
        let stop = if end < lines.len() {
            starts[end]
        } else {
            text.len()
        };
        found.push((name, starts[number], stop));
        number = end;
    }
    found
}

fn body_start(text: &[char], mask: &[bool], start: usize, end: usize) -> usize {
    let mut depth = 0i64;
    let mut index = start;
    while index < end {
        if !mask[index] {
            index += 1;
            continue;
        }
        let character = text[index];
        if "([{⟨".contains(character) {
            depth += 1;
        } else if ")]}⟩".contains(character) {
            depth -= 1;
        } else if depth == 0 {
            if character == ':' && text.get(index + 1) == Some(&'=') {
                return index + 2;
            }
            let is_where = "where"
                .chars()
                .enumerate()
                .all(|(position, expected)| text.get(index + position) == Some(&expected))
                && !text
                    .get(index + 5)
                    .is_some_and(|next| next.is_alphanumeric() || *next == '_');
            if is_where && (index == 0 || !text[index - 1].is_alphanumeric()) {
                return index + 5;
            }
            if character == '|' {
                let line_start = text[..index]
                    .iter()
                    .rposition(|character| *character == '\n')
                    .map_or(0, |position| position + 1);
                if text[line_start..index]
                    .iter()
                    .all(|character| character.is_whitespace())
                {
                    return index;
                }
            }
        }
        index += 1;
    }
    end
}

const MULTI: [&str; 14] = [
    "<;>", "<|>", "<$>", "<*>", ">>=", "<=", ">=", "<|", "|>", "=>", "->", "<-", "&&", "||",
];

fn lean_tokens(text: &[char], mask: &[bool], start: usize, end: usize) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut index = start;
    let at = |index: usize, token: &str| {
        token
            .chars()
            .enumerate()
            .all(|(position, character)| text.get(index + position) == Some(&character))
    };
    while index < end {
        if !mask[index] || text[index].is_whitespace() {
            index += 1;
            continue;
        }
        if let Some(token) = MULTI.iter().find(|token| at(index, token)) {
            found.push((index, (*token).to_owned()));
            index += token.chars().count();
            continue;
        }
        let word_start = |character: char| character.is_ascii_alphabetic() || character == '_';
        let word_continue =
            |character: char| character.is_ascii_alphanumeric() || "_'.!?".contains(character);
        let (dotted, first) = if text[index] == '.' {
            (true, index + 1)
        } else {
            (false, index)
        };
        let is_word = text
            .get(first)
            .is_some_and(|character| word_start(*character))
            && (!dotted || index == 0 || !text[index - 1].is_alphanumeric());
        if is_word {
            let mut cursor = first + 1;
            while cursor < text.len() && word_continue(text[cursor]) {
                cursor += 1;
            }
            found.push((index, text[index..cursor].iter().collect()));
            index = cursor;
        } else {
            found.push((index, text[index].to_string()));
            index += 1;
        }
    }
    found
}

fn swap(token: &str) -> Option<&'static str> {
    Some(match token {
        "≤" | "<=" => "<",
        "<" => "≤",
        "≥" | ">=" => ">",
        ">" => "≥",
        "&&" => "||",
        "||" => "&&",
        "∧" => "∨",
        "∨" => "∧",
        _ => return None,
    })
}

pub(crate) fn enumerate_s2(file: &str, source: &str) -> Vec<Planned> {
    let text: Vec<char> = source.chars().collect();
    let mask = code_mask(&text);
    let stem = Path::new(file)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("")
        .to_owned();
    let line_of = |offset: usize| {
        text[..offset]
            .iter()
            .filter(|character| **character == '\n')
            .count()
            + 1
    };
    let mut sites = Vec::new();
    for (name, start, end) in definitions(&text) {
        let body = body_start(&text, &mask, start, end);
        let first_line = line_of(start);
        let last_line = line_of(end.saturating_sub(1));
        let stream = lean_tokens(&text, &mask, body, end);
        for (position, (offset, token)) in stream.iter().enumerate() {
            let (replacement, operator) = if let Some(replacement) = swap(token) {
                (replacement.to_owned(), format!("{token}→{replacement}"))
            } else if matches!(token.as_str(), ".authorized" | ".denied")
                && position > 0
                && matches!(stream[position - 1].1.as_str(), "=>" | "then" | "else")
            {
                let replacement = if token == ".authorized" {
                    ".denied"
                } else {
                    ".authorized"
                };
                (
                    replacement.to_owned(),
                    format!("{token}→{replacement} (result position)"),
                )
            } else {
                continue;
            };
            let line = line_of(*offset);
            let line_start = text[..*offset]
                .iter()
                .rposition(|character| *character == '\n')
                .map_or(0, |position| position + 1);
            sites.push(Planned {
                campaign: "s2",
                id: format!("{stem}:{line}:{}", offset - line_start + 1),
                file: file.to_owned(),
                definition: name.clone(),
                definition_lines: (first_line, last_line),
                operator,
                offset: *offset,
                original: token.clone(),
                replacement,
                witness: None,
            });
        }
    }
    sites
}

// ---------------------------------------------------------------------------
// S3: crash mutants of the translated functions (a port of `crash_mutant.py`)
// ---------------------------------------------------------------------------

fn next_item(line: &str) -> bool {
    ["/--", "def ", "end ", "mutual", "@["]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

/// The whole-body replacement that makes `def name` fail on every input, as
/// (offset, original body, replacement) in characters, with the definition's lines.
fn crash_edit(source: &str, name: &str) -> Result<(usize, String, String, (usize, usize)), String> {
    let lines: Vec<&str> = source.split('\n').collect();
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            **line == format!("def {name}") || line.starts_with(&format!("def {name} "))
        })
        .map(|(index, _)| index)
        .collect();
    let [start] = starts.as_slice() else {
        return Err(format!(
            "expected exactly one 'def {name}', found {}",
            starts.len()
        ));
    };
    let header_end = (*start..lines.len())
        .find(|&index| {
            let trimmed = lines[index].trim_end();
            trimmed.ends_with(":=") || trimmed.ends_with(":= do")
        })
        .ok_or_else(|| format!("no ':=' after 'def {name}'"))?;
    let body_end = (header_end + 1..lines.len())
        .find(|&index| next_item(lines[index]))
        .unwrap_or(lines.len());
    let offset_of = |line: usize| -> usize {
        lines[..line]
            .iter()
            .map(|text| text.chars().count() + 1)
            .sum()
    };
    let header = lines[header_end].trim_end();
    let header = header
        .strip_suffix(":= do")
        .map_or_else(|| header.to_owned(), |head| format!("{}:=", head));
    let original: String = lines[header_end..body_end].join("\n");
    let replacement = format!("{header}\n  fail .panic\n");
    Ok((
        offset_of(header_end),
        original,
        replacement.trim_end_matches('\n').to_owned() + "\n",
        (start + 1, body_end),
    ))
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct S1Edits {
    schema: String,
    source: String,
    provenance: String,
    edits: Vec<S1Edit>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct S1Edit {
    id: String,
    file: String,
    before: String,
    after: String,
    note: String,
}

#[derive(Deserialize)]
struct Matrix {
    cases: Vec<MatrixCase>,
}

#[derive(Deserialize)]
struct MatrixCase {
    id: String,
    operator: String,
    lean_declaration: String,
}

fn top_level_declaration(line: &str) -> Option<String> {
    let mut rest = line;
    while let Some(after) = rest.strip_prefix("@[") {
        rest = after.split_once(']')?.1.trim_start();
    }
    loop {
        let trimmed = [
            "private ",
            "protected ",
            "noncomputable ",
            "partial ",
            "unsafe ",
        ]
        .iter()
        .find_map(|modifier| rest.strip_prefix(modifier));
        match trimmed {
            Some(after) => rest = after.trim_start(),
            None => break,
        }
    }
    for keyword in [
        "def",
        "theorem",
        "lemma",
        "instance",
        "abbrev",
        "structure",
        "inductive",
        "example",
        "class",
    ] {
        if let Some(after) = rest.strip_prefix(keyword)
            && (after.is_empty() || after.starts_with(char::is_whitespace))
        {
            let name = after.split_whitespace().next().unwrap_or(keyword);
            return Some(name.trim_end_matches(':').to_owned());
        }
    }
    None
}

/// First and last line, and name, of the top-level declaration holding `line`.
fn declaration_around(source: &str, line: usize) -> (usize, usize, String) {
    let lines: Vec<&str> = source.split('\n').collect();
    let mut first = line.min(lines.len()).max(1);
    let mut name = String::new();
    while first >= 1 {
        if let Some(found) = top_level_declaration(lines[first - 1]) {
            name = found;
            break;
        }
        first -= 1;
    }
    let first = first.max(1);
    let mut last = line;
    while last < lines.len() && top_level_declaration(lines[last]).is_none() {
        last += 1;
    }
    (first, last, name)
}

fn plan_s1(root: &Path) -> Result<Vec<Planned>, String> {
    let edits: S1Edits = serde_json::from_str(
        &fs::read_to_string(root.join(S1_EDITS))
            .map_err(|error| format!("could not read {S1_EDITS}: {error}"))?,
    )
    .map_err(|error| format!("invalid {S1_EDITS}: {error}"))?;
    if edits.schema != "auths-proof-s1-mutation-edits/v1" || edits.provenance.trim().is_empty() {
        return Err(format!("unsupported {S1_EDITS}"));
    }
    let matrix: Matrix = serde_json::from_str(
        &fs::read_to_string(root.join(&edits.source)).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("invalid {}: {error}", edits.source))?;
    let matrix_ids: Vec<&str> = matrix.cases.iter().map(|case| case.id.as_str()).collect();
    let edit_ids: Vec<&str> = edits.edits.iter().map(|edit| edit.id.as_str()).collect();
    if matrix_ids != edit_ids {
        return Err(format!(
            "{S1_EDITS} must give one edit per matrix case, in order"
        ));
    }
    let mut planned = Vec::new();
    for (edit, case) in edits.edits.iter().zip(&matrix.cases) {
        if edit.note.trim().is_empty() {
            return Err(format!("S1 edit {} has no note", edit.id));
        }
        let relative = edit
            .file
            .strip_prefix("formal/")
            .ok_or_else(|| format!("S1 edit {} is outside formal/", edit.id))?;
        let source =
            fs::read_to_string(root.join(&edit.file)).map_err(|error| error.to_string())?;
        if source.matches(&edit.before).count() != 1 {
            return Err(format!(
                "S1 edit {}: the edited text must occur exactly once in {}",
                edit.id, edit.file
            ));
        }
        let byte_offset = source.find(&edit.before).unwrap_or(0);
        let offset = source[..byte_offset].chars().count();
        let line = source[..byte_offset].matches('\n').count() + 1;
        let (first, last, name) = declaration_around(&source, line);
        planned.push(Planned {
            campaign: "s1",
            id: edit.id.clone(),
            file: relative.to_owned(),
            definition: name,
            definition_lines: (first, last),
            operator: case.operator.clone(),
            offset,
            original: edit.before.clone(),
            replacement: edit.after.clone(),
            witness: Some(case.lean_declaration.clone()),
        });
    }
    Ok(planned)
}

fn plan_s2(root: &Path) -> Result<Vec<Planned>, String> {
    let mut planned = Vec::new();
    for file in S2_FILES {
        let source = fs::read_to_string(root.join("formal").join(file))
            .map_err(|error| format!("could not read formal/{file}: {error}"))?;
        planned.extend(enumerate_s2(file, &source));
    }
    Ok(planned)
}

fn plan_s3(root: &Path) -> Result<Vec<Planned>, String> {
    let tree = WorkTree::new(root.to_path_buf());
    let translated = formal_coverage::translated_functions(&tree)?;
    let mut planned = Vec::new();
    for item in translated {
        let relative = item
            .funs_path
            .strip_prefix("formal/")
            .ok_or("translation outside formal/")?
            .to_owned();
        let source = tree.read(&item.funs_path)?;
        let name = item
            .lean_name
            .strip_prefix(&format!("{}.", item.crate_name))
            .unwrap_or(&item.lean_name)
            .to_owned();
        let (offset, original, replacement, lines) =
            crash_edit(&source, &name).map_err(|error| format!("{}: {error}", item.funs_path))?;
        planned.push(Planned {
            campaign: "s3",
            id: item.rust_name.clone(),
            file: relative,
            definition: name,
            definition_lines: lines,
            operator: "body → fail .panic".to_owned(),
            offset,
            original,
            replacement,
            witness: None,
        });
    }
    Ok(planned)
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

fn apply(text: &str, planned: &Planned) -> Result<String, String> {
    let characters: Vec<char> = text.chars().collect();
    let original: Vec<char> = planned.original.chars().collect();
    let end = planned.offset + original.len();
    if end > characters.len() || characters[planned.offset..end] != original[..] {
        return Err(format!(
            "{}: formal/{} does not hold the original text at its offset",
            planned.id, planned.file
        ));
    }
    let mut mutated: String = characters[..planned.offset].iter().collect();
    mutated.push_str(&planned.replacement);
    mutated.extend(&characters[end..]);
    Ok(mutated)
}

fn first_error(output: &str) -> Option<(String, usize, usize)> {
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("error: ") else {
            continue;
        };
        let mut rest = rest;
        while let Some(stripped) = rest.strip_prefix("./") {
            rest = stripped;
        }
        let mut parts = rest.splitn(4, ':');
        let (Some(file), Some(line_text), Some(column_text)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if !Path::new(file)
            .extension()
            .is_some_and(|extension| extension == "lean")
            || file.contains(char::is_whitespace)
        {
            continue;
        }
        if let (Ok(line), Ok(column)) = (line_text.parse(), column_text.parse()) {
            return Some((file.to_owned(), line, column));
        }
    }
    None
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let status = if cfg!(target_os = "macos") {
        Command::new("cp")
            .args(["-c", "-R"])
            .arg(source)
            .arg(destination)
            .status()
    } else {
        Command::new("cp")
            .args(["-R", "--reflink=auto"])
            .arg(source)
            .arg(destination)
            .status()
    }
    .map_err(|error| format!("could not copy {}: {error}", source.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("copying {} failed", source.display()))
    }
}

/// A private copy of `formal/` whose build outputs start from the built
/// original and whose Lake packages are shared read-only.
fn prepare_worker(formal: &Path, directory: &Path) -> Result<PathBuf, String> {
    let worker = directory.join("formal");
    fs::create_dir_all(&worker).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(formal).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.file_name() == ".lake" {
            continue;
        }
        copy_tree(&entry.path(), &worker.join(entry.file_name()))?;
    }
    fs::create_dir_all(worker.join(".lake")).map_err(|error| error.to_string())?;
    copy_tree(&formal.join(".lake/build"), &worker.join(".lake/build"))?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(formal.join(".lake/packages"), worker.join(".lake/packages"))
        .map_err(|error| format!("could not link Lake packages: {error}"))?;
    Ok(worker)
}

fn run_one(worker: &Path, planned: &Planned) -> Result<Mutant, String> {
    let path = worker.join(&planned.file);
    let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
    let mutated = apply(&original, planned)?;
    fs::write(&path, &mutated).map_err(|error| error.to_string())?;
    let output = Command::new("lake")
        .args(["build", BUILD_TARGET])
        .current_dir(worker)
        .output();
    fs::write(&path, &original).map_err(|error| error.to_string())?;
    let output = output.map_err(|error| format!("could not run lake: {error}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut mutant = Mutant {
        id: planned.id.clone(),
        file: format!("formal/{}", planned.file),
        definition: planned.definition.clone(),
        operator: planned.operator.clone(),
        outcome: "survived".to_owned(),
        first_error: None,
        caught: None,
    };
    if output.status.success() {
        return Ok(mutant);
    }
    let (file, line, column) = first_error(&text).ok_or_else(|| {
        format!(
            "{} {}: lake failed without a Lean error location:\n{}",
            planned.campaign,
            planned.id,
            text.lines()
                .rev()
                .take(20)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        )
    })?;
    let error_source = if file == planned.file {
        mutated.clone()
    } else {
        fs::read_to_string(worker.join(&file)).unwrap_or_default()
    };
    let (_, _, declaration) = declaration_around(&error_source, line);
    let stillborn = file == planned.file
        && (planned.definition_lines.0..=planned.definition_lines.1).contains(&line);
    mutant.outcome = if stillborn { "stillborn" } else { "killed" }.to_owned();
    if let Some(witness) = &planned.witness
        && !stillborn
    {
        let short = witness.rsplit('.').next().unwrap_or(witness);
        let at_witness = file == "Auths/Rich/Mutations.lean" && declaration == short;
        mutant.caught = Some(if at_witness { "witness" } else { "elsewhere" }.to_owned());
    }
    mutant.first_error = Some(ErrorLocation {
        file: format!("formal/{file}"),
        line,
        column,
        declaration,
    });
    Ok(mutant)
}

fn run_campaign(root: &Path, planned: Vec<Planned>, jobs: usize) -> Result<Vec<Mutant>, String> {
    let formal = root.join("formal");
    command_in("lake", &["build", BUILD_TARGET], &formal, None)?;
    let scratch = tempfile::Builder::new()
        .prefix("auths-formal-mutations-")
        .tempdir()
        .map_err(|error| format!("could not create a mutation workspace: {error}"))?;
    let total = planned.len();
    let queue = Arc::new(Mutex::new(
        planned.into_iter().enumerate().collect::<Vec<_>>(),
    ));
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut workers = Vec::new();
    for index in 0..jobs.max(1) {
        let worker = prepare_worker(&formal, &scratch.path().join(format!("worker-{index}")))?;
        let queue = Arc::clone(&queue);
        let results = Arc::clone(&results);
        workers.push(std::thread::spawn(move || -> Result<(), String> {
            loop {
                let next = queue.lock().map_err(|_| "mutation queue poisoned")?.pop();
                let Some((position, planned)) = next else {
                    return Ok(());
                };
                let mutant = run_one(&worker, &planned)?;
                println!(
                    "{} {:>4}/{total} {:<10} {}",
                    planned.campaign.to_uppercase(),
                    position + 1,
                    mutant.outcome,
                    mutant.id
                );
                results
                    .lock()
                    .map_err(|_| "mutation results poisoned")?
                    .push((position, mutant));
            }
        }));
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| "a mutation worker panicked".to_owned())??;
    }
    let mut results = Arc::try_unwrap(results)
        .map_err(|_| "mutation results still shared")?
        .into_inner()
        .map_err(|_| "mutation results poisoned")?;
    results.sort_by_key(|(position, _)| *position);
    Ok(results.into_iter().map(|(_, mutant)| mutant).collect())
}

/// Checks that committed results are for the current formal sources and that
/// every survivor is explained. Release gates call this; pull requests do not.
pub(crate) fn check_release_ready(root: &Path) -> Result<(), String> {
    let results = load_mutation_results(root)?.ok_or_else(|| {
        format!("{MUTATIONS_PATH} is absent; run `cargo xtask formal mutations all --update`")
    })?;
    let current = formal_inputs_sha256(root)?;
    for campaign in ["s1", "s2", "s3"] {
        let entry = results
            .campaigns
            .get(campaign)
            .ok_or_else(|| format!("{MUTATIONS_PATH} has no {campaign} results"))?;
        if entry.formal_inputs_sha256 != current {
            return Err(format!(
                "{MUTATIONS_PATH} {campaign} results predate the current formal sources; run `cargo xtask formal mutations all --update`"
            ));
        }
        for mutant in &entry.mutants {
            if mutant.outcome == "survived"
                && results
                    .explanations
                    .get(&format!("{campaign}:{}", mutant.id))
                    .is_none_or(|text| text.trim().is_empty())
            {
                return Err(format!(
                    "{campaign} mutant {} survived without a fix or an explanation in {MUTATIONS_PATH}",
                    mutant.id
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn formal_mutations(arguments: &[String]) -> Result<(), String> {
    let root = root();
    let mut campaigns: Vec<&'static str> = Vec::new();
    let mut update = false;
    let mut jobs = 2usize;
    let mut only: Option<String> = None;
    let mut output: Option<PathBuf> = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "s1" => campaigns.push("s1"),
            "s2" => campaigns.push("s2"),
            "s3" => campaigns.push("s3"),
            "all" => campaigns.extend(["s1", "s2", "s3"]),
            "--update" => update = true,
            "--check" => return check_release_ready(&root),
            "--jobs" => {
                index += 1;
                jobs = arguments
                    .get(index)
                    .and_then(|value| value.parse().ok())
                    .ok_or("--jobs needs a positive number")?;
            }
            "--output" => {
                index += 1;
                output = Some(PathBuf::from(
                    arguments.get(index).ok_or("--output needs a path")?,
                ));
            }
            "--only" => {
                index += 1;
                only = Some(
                    arguments
                        .get(index)
                        .ok_or("--only needs a mutant id")?
                        .clone(),
                );
            }
            other => {
                return Err(format!(
                    "unknown formal mutations argument {other}; expected s1, s2, s3, all, --update, --check, --output <path>, --jobs <n>, or --only <id>"
                ));
            }
        }
        index += 1;
    }
    if campaigns.is_empty() {
        return Err("name a campaign: s1, s2, s3, or all".to_owned());
    }
    if only.is_some() && update {
        return Err(
            "--only runs a single mutant and cannot update the committed results".to_owned(),
        );
    }
    let formal_inputs = formal_inputs_sha256(&root)?;
    let mut results = load_mutation_results(&root)?.unwrap_or_else(|| MutationResults {
        schema: MUTATION_SCHEMA.to_owned(),
        tool_version: TOOL_VERSION.to_owned(),
        campaigns: BTreeMap::new(),
        explanations: BTreeMap::new(),
    });
    let mut differences = Vec::new();
    for campaign in campaigns {
        let mut planned = match campaign {
            "s1" => plan_s1(&root)?,
            "s2" => plan_s2(&root)?,
            _ => plan_s3(&root)?,
        };
        if let Some(id) = &only {
            planned.retain(|mutant| &mutant.id == id);
        }
        println!("{}: {} mutants", campaign.to_uppercase(), planned.len());
        let mutants = run_campaign(&root, planned, jobs)?;
        for mutant in &mutants {
            if mutant.outcome == "survived"
                && !results
                    .explanations
                    .contains_key(&format!("{campaign}:{}", mutant.id))
            {
                println!(
                    "UNEXPLAINED SURVIVOR {campaign}:{} in {}",
                    mutant.id, mutant.definition
                );
            }
        }
        if only.is_none() {
            if let Some(committed) = results.campaigns.get(campaign) {
                let outcome = |mutants: &[Mutant]| {
                    mutants
                        .iter()
                        .map(|mutant| (mutant.id.clone(), mutant.outcome.clone()))
                        .collect::<Vec<_>>()
                };
                if outcome(&committed.mutants) != outcome(&mutants) {
                    differences.push(campaign);
                }
            } else {
                differences.push(campaign);
            }
            results.campaigns.insert(
                campaign.to_owned(),
                formal_coverage::Campaign {
                    formal_inputs_sha256: formal_inputs.clone(),
                    mutants,
                },
            );
        }
    }
    let mut unexplained = Vec::new();
    for (campaign, entry) in &results.campaigns {
        for mutant in &entry.mutants {
            if mutant.outcome == "survived"
                && !results
                    .explanations
                    .contains_key(&format!("{campaign}:{}", mutant.id))
            {
                unexplained.push(format!("{campaign}:{}", mutant.id));
            }
        }
    }
    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        fs::write(
            &path,
            render_json(&serde_json::to_value(&results).map_err(|error| error.to_string())?)?,
        )
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        println!("Wrote {}", path.display());
        if !unexplained.is_empty() {
            return Err(format!(
                "survivors without a fix or an explanation: {unexplained:?}"
            ));
        }
        return Ok(());
    }
    if update {
        results.tool_version = TOOL_VERSION.to_owned();
        fs::write(
            root.join(MUTATIONS_PATH),
            render_json(&serde_json::to_value(&results).map_err(|error| error.to_string())?)?,
        )
        .map_err(|error| format!("could not write {MUTATIONS_PATH}: {error}"))?;
        println!("Updated {MUTATIONS_PATH}");
    } else if !differences.is_empty() {
        return Err(format!(
            "mutation outcomes differ from {MUTATIONS_PATH} for {differences:?}; review and run with --update"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_s2_survivor_site_is_enumerated_at_its_study_id() {
        let source =
            fs::read_to_string(root().join("formal/Auths/Composition.lean")).expect("source");
        let sites = enumerate_s2("Auths/Composition.lean", &source);
        let site = sites
            .iter()
            .find(|site| site.id == "Composition:21:16")
            .expect("Composition:21:16 is still an S2 site");
        assert_eq!(site.definition, "thresholdTwo");
        assert_eq!(site.original, ".authorized");
        assert_eq!(site.replacement, ".denied");
    }

    #[test]
    fn crash_edits_replace_exactly_one_generated_body() {
        let source = "/-- [a::f]: x -/\ndef f (x : U8) : Result U8 := do\n  let y ← x + 1\n  ok y\n\n/-- [a::g]: y -/\ndef g : Result U8 := ok 0\n";
        let (offset, original, replacement, lines) = crash_edit(source, "f").expect("edit");
        assert_eq!(lines, (2, 5));
        assert!(original.starts_with("def f (x : U8) : Result U8 := do"));
        assert_eq!(
            replacement,
            "def f (x : U8) : Result U8 :=\n  fail .panic\n"
        );
        assert_eq!(offset, source.find("def f").expect("def"));
    }

    #[test]
    fn first_error_reads_lake_locations() {
        let output = "✖ [4/4] Building Auths.Composition\nerror: Auths/Composition.lean:55:0: Not a definitional equality\nerror: build failed\n";
        assert_eq!(
            first_error(output),
            Some(("Auths/Composition.lean".to_owned(), 55, 0))
        );
    }
}
