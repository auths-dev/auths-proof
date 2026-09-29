#![allow(clippy::too_many_lines)]

//! Proof coverage of the decision path.
//!
//! The scanner and the metrics are a port of study 006's reference scanner
//! (`analysis/proof_coverage.py` in auths-research), with its definitions
//! unchanged: what a function is, when it is translated, refined directly, or
//! in the refined closure (trait-instance records included), the two weights,
//! and the five scopes. `reproduces_the_study_at_its_pinned_commit` holds the
//! port to byte-identical output on the vendored inputs of the study's commit.

use crate::*;
use std::cell::RefCell;
use std::io::Read as _;

pub(crate) const TOOL_VERSION: &str = "1";
pub(crate) const PIN: &str = "8bf2970c68ef01302a70b52861ecc256cf1bb06a";
const QUALIFICATION: &str = "formal/qualification/aeneas/qualification.toml";
pub(crate) const SCOPE_PATH: &str = "formal/coverage-scope-v1.toml";
pub(crate) const KINDS_PATH: &str = "formal/theorem-kinds-v1.toml";
pub(crate) const CHECK_SITE_MAP_PATH: &str = "formal/check-site-functions-v1.toml";
pub(crate) const AUDIT_PATH: &str = "formal/lean-assurance-audit-v1.json";
pub(crate) const MUTATIONS_PATH: &str = "formal/model-mutations-v1.json";
pub(crate) const OUTPUT_JSON: &str = "formal/proof-coverage-v1.json";
pub(crate) const OUTPUT_TSV: &str = "formal/proof-coverage-functions-v1.tsv";
pub(crate) const DOCUMENT: &str = "docs/assurance/PROOF_COVERAGE.md";
pub(crate) const PIN_FIXTURE: &str = "formal/coverage/pin-8bf2970c.tar.zst";
pub(crate) const PIN_FIXTURE_MANIFEST: &str = "formal/coverage/pin-8bf2970c.sha256";

// ---------------------------------------------------------------------------
// Input trees
// ---------------------------------------------------------------------------

/// Read access to one revision's files. Every read is recorded, so the output
/// can name the digest of each input it used.
pub(crate) trait Tree {
    fn read_bytes(&self, path: &str) -> Result<Vec<u8>, String>;
    fn list_files(&self, directory: &str) -> Result<Vec<String>, String>;
    fn reads(&self) -> &RefCell<BTreeMap<String, String>>;

    fn read(&self, path: &str) -> Result<String, String> {
        let bytes = self.read_bytes(path)?;
        self.reads()
            .borrow_mut()
            .insert(path.to_owned(), hex::encode(Sha256::digest(&bytes)));
        String::from_utf8(bytes).map_err(|error| format!("{path} is not UTF-8: {error}"))
    }
}

pub(crate) struct WorkTree {
    root: PathBuf,
    reads: RefCell<BTreeMap<String, String>>,
}

impl WorkTree {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self {
            root,
            reads: RefCell::new(BTreeMap::new()),
        }
    }
}

impl Tree for WorkTree {
    fn read_bytes(&self, path: &str) -> Result<Vec<u8>, String> {
        fs::read(self.root.join(path)).map_err(|error| format!("could not read {path}: {error}"))
    }

    fn list_files(&self, directory: &str) -> Result<Vec<String>, String> {
        let mut found = Vec::new();
        let mut pending = vec![self.root.join(directory)];
        while let Some(current) = pending.pop() {
            let Ok(entries) = fs::read_dir(&current) else {
                continue;
            };
            for entry in entries {
                let entry = entry.map_err(|error| error.to_string())?;
                let path = entry.path();
                let kind = entry.file_type().map_err(|error| error.to_string())?;
                if kind.is_dir() {
                    pending.push(path);
                } else if kind.is_file() {
                    let relative = path
                        .strip_prefix(&self.root)
                        .map_err(|error| error.to_string())?;
                    let text = relative
                        .to_str()
                        .ok_or_else(|| format!("non-UTF-8 path {}", relative.display()))?;
                    found.push(text.replace('\\', "/"));
                }
            }
        }
        found.sort();
        Ok(found)
    }

    fn reads(&self) -> &RefCell<BTreeMap<String, String>> {
        &self.reads
    }
}

/// The vendored inputs of a pinned commit, read from a tar.zst archive.
pub(crate) struct ArchiveTree {
    files: BTreeMap<String, Vec<u8>>,
    reads: RefCell<BTreeMap<String, String>>,
}

impl ArchiveTree {
    pub(crate) fn open(
        archive: &Path,
        manifest: &Path,
    ) -> Result<(Self, BTreeMap<String, Vec<u8>>), String> {
        let compressed = fs::read(archive)
            .map_err(|error| format!("could not read {}: {error}", archive.display()))?;
        let decompressed = zstd::decode_all(compressed.as_slice())
            .map_err(|error| format!("could not decompress {}: {error}", archive.display()))?;
        let mut entries = tar::Archive::new(decompressed.as_slice());
        let mut all = BTreeMap::new();
        for entry in entries
            .entries()
            .map_err(|error| format!("invalid fixture archive: {error}"))?
        {
            let mut entry = entry.map_err(|error| format!("invalid fixture entry: {error}"))?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry
                .path()
                .map_err(|error| error.to_string())?
                .to_str()
                .ok_or("non-UTF-8 fixture path")?
                .to_owned();
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            all.insert(path, bytes);
        }
        let listed = fs::read_to_string(manifest)
            .map_err(|error| format!("could not read {}: {error}", manifest.display()))?;
        let mut expected = BTreeMap::new();
        for line in listed.lines().filter(|line| !line.trim().is_empty()) {
            let (digest, path) = line
                .split_once("  ")
                .ok_or_else(|| format!("malformed fixture manifest line: {line}"))?;
            expected.insert(path.to_owned(), digest.to_owned());
        }
        let actual: BTreeMap<String, String> = all
            .iter()
            .map(|(path, bytes)| (path.clone(), hex::encode(Sha256::digest(bytes))))
            .collect();
        if actual != expected {
            return Err("the pin fixture archive does not match its sha256 manifest".to_owned());
        }
        let mut inputs = BTreeMap::new();
        let mut rest = BTreeMap::new();
        for (path, bytes) in all {
            if let Some(stripped) = path.strip_prefix("inputs/") {
                inputs.insert(stripped.to_owned(), bytes);
            } else {
                rest.insert(path, bytes);
            }
        }
        Ok((
            Self {
                files: inputs,
                reads: RefCell::new(BTreeMap::new()),
            },
            rest,
        ))
    }
}

impl Tree for ArchiveTree {
    fn read_bytes(&self, path: &str) -> Result<Vec<u8>, String> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| format!("the pin fixture does not hold {path}"))
    }

    fn list_files(&self, directory: &str) -> Result<Vec<String>, String> {
        let prefix = format!("{}/", directory.trim_end_matches('/'));
        Ok(self
            .files
            .keys()
            .filter(|path| path.starts_with(&prefix))
            .cloned()
            .collect())
    }

    fn reads(&self) -> &RefCell<BTreeMap<String, String>> {
        &self.reads
    }
}

// ---------------------------------------------------------------------------
// Rust scanning
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Ident,
    Punct,
    Literal,
    Lifetime,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    text: String,
    line: usize,
    end_line: usize,
}

fn text_of(source: &[char], start: usize, end: usize) -> String {
    let end = end.min(source.len());
    if start >= end {
        return String::new();
    }
    source[start..end].iter().collect()
}

fn starts_with(source: &[char], index: usize, pattern: &str) -> bool {
    pattern
        .chars()
        .enumerate()
        .all(|(offset, expected)| source.get(index + offset) == Some(&expected))
}

fn find_from(source: &[char], index: usize, pattern: &str) -> Option<usize> {
    (index..source.len()).find(|&position| starts_with(source, position, pattern))
}

fn is_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// `(?:b|c)?r(#*)"` at `index`: the number of hashes and the index after the quote.
fn raw_string_open(source: &[char], index: usize) -> Option<(usize, usize)> {
    let mut cursor = index;
    if matches!(source.get(cursor), Some('b' | 'c')) && source.get(cursor + 1) == Some(&'r') {
        cursor += 1;
    }
    if source.get(cursor) != Some(&'r') {
        return None;
    }
    cursor += 1;
    let mut hashes = 0;
    while source.get(cursor) == Some(&'#') {
        hashes += 1;
        cursor += 1;
    }
    (source.get(cursor) == Some(&'"')).then_some((hashes, cursor + 1))
}

fn count_newlines(text: &str) -> usize {
    text.matches('\n').count()
}

/// A minimal Rust lexer: identifiers, punctuation, literals; drops comments.
fn tokenize(text: &str) -> Vec<Token> {
    let source: Vec<char> = text.chars().collect();
    let length = source.len();
    let mut tokens = Vec::new();
    let (mut index, mut line) = (0usize, 1usize);
    while index < length {
        let character = source[index];
        if character == '\n' {
            line += 1;
            index += 1;
            continue;
        }
        if character.is_whitespace() {
            index += 1;
            continue;
        }
        if starts_with(&source, index, "//") {
            index = find_from(&source, index, "\n").unwrap_or(length);
            continue;
        }
        if starts_with(&source, index, "/*") {
            let mut depth = 1;
            index += 2;
            while index < length && depth > 0 {
                if starts_with(&source, index, "/*") {
                    depth += 1;
                    index += 2;
                } else if starts_with(&source, index, "*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    if source[index] == '\n' {
                        line += 1;
                    }
                    index += 1;
                }
            }
            continue;
        }
        if let Some((hashes, after)) = raw_string_open(&source, index) {
            let terminator = format!("\"{}", "#".repeat(hashes));
            let close = find_from(&source, after, &terminator)
                .map_or(length, |close| close + terminator.chars().count());
            let literal = text_of(&source, index, close);
            let newlines = count_newlines(&literal);
            tokens.push(Token {
                kind: TokenKind::Literal,
                text: literal,
                line,
                end_line: line + newlines,
            });
            line += newlines;
            index = close;
            continue;
        }
        if character == '"'
            || (matches!(character, 'b' | 'c') && source.get(index + 1) == Some(&'"'))
        {
            let start = index + if character == '"' { 1 } else { 2 };
            let mut cursor = start;
            while cursor < length && source[cursor] != '"' {
                cursor += if source[cursor] == '\\' { 2 } else { 1 };
            }
            let literal = text_of(&source, index, cursor + 1);
            let newlines = count_newlines(&literal);
            tokens.push(Token {
                kind: TokenKind::Literal,
                text: literal,
                line,
                end_line: line + newlines,
            });
            line += newlines;
            index = cursor + 1;
            continue;
        }
        if character == '\'' || (character == 'b' && source.get(index + 1) == Some(&'\'')) {
            let quote = if character == '\'' { index } else { index + 1 };
            if source.get(quote + 1) == Some(&'\\') {
                let mut cursor = quote + 3;
                while cursor < length && source[cursor] != '\'' {
                    cursor += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Literal,
                    text: text_of(&source, index, cursor + 1),
                    line,
                    end_line: line,
                });
                index = cursor + 1;
                continue;
            }
            if quote + 2 < length && source[quote + 2] == '\'' {
                tokens.push(Token {
                    kind: TokenKind::Literal,
                    text: text_of(&source, index, quote + 3),
                    line,
                    end_line: line,
                });
                index = quote + 3;
                continue;
            }
            let mut cursor = quote + 1;
            while cursor < length && is_word(source[cursor]) {
                cursor += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Lifetime,
                text: text_of(&source, index, cursor),
                line,
                end_line: line,
            });
            index = cursor;
            continue;
        }
        if character.is_alphabetic() || character == '_' {
            let mut cursor = index;
            if starts_with(&source, index, "r#") {
                cursor += 2;
            }
            while cursor < length && is_word(source[cursor]) {
                cursor += 1;
            }
            let word = text_of(&source, index, cursor);
            tokens.push(Token {
                kind: TokenKind::Ident,
                text: word.strip_prefix("r#").unwrap_or(&word).to_owned(),
                line,
                end_line: line,
            });
            index = cursor;
            continue;
        }
        if character.is_numeric() {
            let mut cursor = index;
            while cursor < length && is_word(source[cursor]) {
                cursor += 1;
            }
            if cursor + 1 < length && source[cursor] == '.' && source[cursor + 1].is_numeric() {
                cursor += 1;
                while cursor < length && is_word(source[cursor]) {
                    cursor += 1;
                }
            }
            tokens.push(Token {
                kind: TokenKind::Literal,
                text: text_of(&source, index, cursor),
                line,
                end_line: line,
            });
            index = cursor;
            continue;
        }
        tokens.push(Token {
            kind: TokenKind::Punct,
            text: character.to_string(),
            line,
            end_line: line,
        });
        index += 1;
    }
    tokens
}

#[derive(Clone, Debug)]
pub(crate) struct RustFunction {
    pub(crate) file: String,
    pub(crate) qualified: String,
    pub(crate) begin_line: usize,
    pub(crate) end_line: usize,
    pub(crate) code_lines: usize,
    pub(crate) in_macro: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameKind {
    Item,
    Function,
    Block,
    Macro,
}

struct Frame {
    kind: FrameKind,
    name: String,
    test: bool,
}

#[derive(Default)]
pub(crate) struct ScanResult {
    pub(crate) functions: Vec<RustFunction>,
    pub(crate) test_functions: usize,
    pub(crate) test_module_files: Vec<String>,
    pub(crate) code_line_set: BTreeSet<usize>,
}

fn matching_close(tokens: &[Token], open_index: usize) -> usize {
    let opener = tokens[open_index].text.as_str();
    let closer = match opener {
        "{" => "}",
        "(" => ")",
        _ => "]",
    };
    let mut depth = 0i64;
    for (cursor, token) in tokens.iter().enumerate().skip(open_index) {
        if token.kind != TokenKind::Punct {
            continue;
        }
        if token.text == opener {
            depth += 1;
        } else if token.text == closer {
            depth -= 1;
            if depth == 0 {
                return cursor;
            }
        }
    }
    tokens.len() - 1
}

pub(crate) fn attribute_marks_test(words: &[String]) -> bool {
    let Some(first) = words.first() else {
        return false;
    };
    if first == "cfg" {
        return !words.iter().any(|word| word == "not")
            && words
                .iter()
                .any(|word| matches!(word.as_str(), "test" | "kani" | "fuzzing"));
    }
    if matches!(
        first.as_str(),
        "cfg_attr" | "allow" | "expect" | "deny" | "warn" | "doc" | "must_use"
    ) {
        return false;
    }
    let last = words.last().map_or("", String::as_str);
    matches!(last, "test" | "proof" | "proptest") || first == "kani"
}

const FN_QUALIFIERS: [&str; 6] = ["pub", "const", "async", "unsafe", "extern", "default"];
const ITEM_KEYWORDS: [&str; 6] = ["struct", "enum", "union", "use", "type", "static"];

fn qualifier_start(tokens: &[Token], fn_index: usize) -> usize {
    let mut begin = tokens[fn_index].line;
    let mut cursor = fn_index as isize - 1;
    while cursor >= 0 {
        let position = cursor as usize;
        let token = &tokens[position];
        if token.kind == TokenKind::Ident && FN_QUALIFIERS.contains(&token.text.as_str()) {
            begin = token.line;
            cursor -= 1;
            continue;
        }
        if token.kind == TokenKind::Literal && position > 0 && tokens[position - 1].text == "extern"
        {
            cursor -= 1;
            continue;
        }
        if token.text == ")" {
            let mut depth = 0i64;
            let mut probe = cursor;
            while probe >= 0 {
                let text = tokens[probe as usize].text.as_str();
                if text == ")" {
                    depth += 1;
                } else if text == "(" {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                probe -= 1;
            }
            if probe > 0 && tokens[probe as usize - 1].text == "pub" {
                begin = tokens[probe as usize - 1].line;
                cursor = probe - 2;
                continue;
            }
        }
        break;
    }
    begin
}

fn impl_label(tokens: &[Token], start: usize, stop: usize) -> String {
    let mut words: Vec<&str> = tokens[start..stop]
        .iter()
        .filter(|token| token.kind == TokenKind::Ident)
        .map(|token| token.text.as_str())
        .collect();
    if let Some(position) = words.iter().position(|word| *word == "for") {
        words = words.split_off(position + 1);
    }
    words
        .into_iter()
        .find(|word| !matches!(*word, "impl" | "where" | "dyn" | "mut" | "const"))
        .unwrap_or("impl")
        .to_owned()
}

fn parent_directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

pub(crate) fn scan_rust(path: &str, source: &str) -> ScanResult {
    let tokens = tokenize(source);
    let mut result = ScanResult::default();
    for token in &tokens {
        result.code_line_set.extend(token.line..=token.end_line);
    }
    let mut stack = vec![Frame {
        kind: FrameKind::Item,
        name: String::new(),
        test: false,
    }];
    let mut pending: Vec<Vec<String>> = Vec::new();
    let mut index = 0usize;
    let enclosing_test = |stack: &[Frame]| stack.iter().any(|frame| frame.test);
    let in_macro = |stack: &[Frame]| stack.iter().any(|frame| frame.kind == FrameKind::Macro);
    let qualified = |stack: &[Frame], name: &str| {
        let mut parts: Vec<&str> = stack
            .iter()
            .filter(|frame| frame.kind == FrameKind::Item && !frame.name.is_empty())
            .map(|frame| frame.name.as_str())
            .collect();
        parts.push(name);
        parts.join("::")
    };

    while index < tokens.len() {
        let token = &tokens[index];
        let text = token.text.as_str();
        let following = tokens.get(index + 1).map_or("", |next| next.text.as_str());
        if token.kind == TokenKind::Punct && text == "#" && matches!(following, "[" | "!") {
            let inner = following == "!";
            let open_index = if inner { index + 2 } else { index + 1 };
            if open_index >= tokens.len() || tokens[open_index].text != "[" {
                index += 1;
                continue;
            }
            let close = matching_close(&tokens, open_index);
            let words: Vec<String> = tokens[open_index + 1..close]
                .iter()
                .filter(|token| token.kind == TokenKind::Ident)
                .map(|token| token.text.clone())
                .collect();
            if inner {
                if attribute_marks_test(&words)
                    && let Some(top) = stack.last_mut()
                {
                    top.test = true;
                }
            } else {
                pending.push(words);
            }
            index = close + 1;
            continue;
        }
        if token.kind == TokenKind::Ident && text == "macro_rules" && following == "!" {
            let mut cursor = index + 2;
            while cursor < tokens.len() && !matches!(tokens[cursor].text.as_str(), "{" | "(" | "[")
            {
                cursor += 1;
            }
            if cursor < tokens.len() {
                let test = enclosing_test(&stack);
                stack.push(Frame {
                    kind: FrameKind::Macro,
                    name: String::new(),
                    test,
                });
            }
            pending.clear();
            index = cursor + 1;
            continue;
        }
        if token.kind == TokenKind::Ident && text == "fn" && index + 1 < tokens.len() {
            let name_token = &tokens[index + 1];
            if name_token.kind != TokenKind::Ident {
                index += 1;
                continue;
            }
            let is_test =
                enclosing_test(&stack) || pending.iter().any(|words| attribute_marks_test(words));
            pending.clear();
            let (mut cursor, mut depth) = (index + 2, 0i64);
            let mut body = None;
            while cursor < tokens.len() {
                let current = &tokens[cursor];
                if current.kind == TokenKind::Punct && matches!(current.text.as_str(), "(" | "[") {
                    depth += 1;
                } else if current.kind == TokenKind::Punct
                    && matches!(current.text.as_str(), ")" | "]")
                {
                    depth -= 1;
                } else if depth == 0 && current.text == "{" {
                    body = Some(cursor);
                    break;
                } else if depth == 0 && current.text == ";" {
                    break;
                }
                cursor += 1;
            }
            let Some(body) = body else {
                index = cursor + 1;
                continue;
            };
            let end = matching_close(&tokens, body);
            if is_test {
                result.test_functions += 1;
            } else {
                result.functions.push(RustFunction {
                    file: path.to_owned(),
                    qualified: qualified(&stack, &name_token.text),
                    begin_line: qualifier_start(&tokens, index),
                    end_line: tokens[end].line,
                    code_lines: 0,
                    in_macro: in_macro(&stack),
                });
            }
            stack.push(Frame {
                kind: FrameKind::Function,
                name: name_token.text.clone(),
                test: is_test,
            });
            index = body + 1;
            continue;
        }
        if token.kind == TokenKind::Ident && matches!(text, "mod" | "impl" | "trait") {
            if text == "impl"
                && index > 0
                && matches!(tokens[index - 1].text.as_str(), "(" | "," | "<" | "&" | ">")
            {
                index += 1;
                continue;
            }
            let is_test =
                enclosing_test(&stack) || pending.iter().any(|words| attribute_marks_test(words));
            pending.clear();
            let mut cursor = index + 1;
            while cursor < tokens.len() && !matches!(tokens[cursor].text.as_str(), "{" | ";") {
                cursor += 1;
            }
            if cursor >= tokens.len() {
                break;
            }
            if tokens[cursor].text == ";" {
                if text == "mod" && is_test {
                    let parent = parent_directory(path);
                    let module = &tokens[index + 1].text;
                    let join = |tail: &str| {
                        if parent.is_empty() {
                            tail.to_owned()
                        } else {
                            format!("{parent}/{tail}")
                        }
                    };
                    result.test_module_files.push(join(&format!("{module}.rs")));
                    result
                        .test_module_files
                        .push(join(&format!("{module}/mod.rs")));
                }
                index = cursor + 1;
                continue;
            }
            let label = if text == "impl" {
                impl_label(&tokens, index + 1, cursor)
            } else {
                tokens[index + 1].text.clone()
            };
            stack.push(Frame {
                kind: FrameKind::Item,
                name: label,
                test: is_test,
            });
            index = cursor + 1;
            continue;
        }
        if token.kind == TokenKind::Punct && text == "{" {
            let test = enclosing_test(&stack);
            stack.push(Frame {
                kind: FrameKind::Block,
                name: String::new(),
                test,
            });
            pending.clear();
        } else if token.kind == TokenKind::Punct && text == "}" {
            if stack.len() > 1 {
                stack.pop();
            }
            pending.clear();
        } else if (token.kind == TokenKind::Punct && text == ";")
            || (token.kind == TokenKind::Ident && ITEM_KEYWORDS.contains(&text))
        {
            pending.clear();
        }
        index += 1;
    }

    for function in &mut result.functions {
        function.code_lines = (function.begin_line..=function.end_line)
            .filter(|number| result.code_line_set.contains(number))
            .count();
    }
    result
}

// ---------------------------------------------------------------------------
// Lean text matching (the reference scanner's three regular expressions)
// ---------------------------------------------------------------------------

fn lean_ident_start(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '_'
}

fn lean_ident_continue(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '\'' | '!' | '?')
}

/// `findall` of `[A-Za-z_][A-Za-z0-9_'!?]*(?:\.[A-Za-z_][A-Za-z0-9_'!?]*)*`.
fn lean_identifiers(text: &str) -> Vec<String> {
    let source: Vec<char> = text.chars().collect();
    let mut found = Vec::new();
    let mut index = 0;
    while index < source.len() {
        if !lean_ident_start(source[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < source.len() && lean_ident_continue(source[index]) {
            index += 1;
        }
        while index + 1 < source.len()
            && source[index] == '.'
            && lean_ident_start(source[index + 1])
        {
            index += 2;
            while index < source.len() && lean_ident_continue(source[index]) {
                index += 1;
            }
        }
        found.push(text_of(&source, start, index));
    }
    found
}

fn python_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// `finditer` of `/--\s*\[(?P<name>.+?)\]:` as (start, name) pairs.
fn lean_doc_rust_names(source: &[char]) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut index = 0;
    while index < source.len() {
        if !starts_with(source, index, "/--") {
            index += 1;
            continue;
        }
        let mut cursor = index + 3;
        while cursor < source.len() && python_space(source[cursor]) {
            cursor += 1;
        }
        if source.get(cursor) != Some(&'[') {
            index += 1;
            continue;
        }
        let name_start = cursor + 1;
        let mut probe = name_start;
        let mut matched = None;
        while probe < source.len() && source[probe] != '\n' {
            if probe > name_start && starts_with(source, probe, "]:") {
                matched = Some(probe);
                break;
            }
            probe += 1;
        }
        if let Some(end) = matched {
            found.push((index, text_of(source, name_start, end)));
            index = end + 2;
        } else {
            index += 1;
        }
    }
    found
}

/// `search` of `^(?:noncomputable\s+|partial\s+|private\s+)*def\s+(?P<name>\S+)` with
/// multiline anchors, returning the offset just past the name.
fn lean_def_end(block: &[char]) -> Option<usize> {
    let mut line_starts = vec![0];
    line_starts.extend(
        block
            .iter()
            .enumerate()
            .filter(|(_, character)| **character == '\n')
            .map(|(position, _)| position + 1),
    );
    let keyword_then_space = |position: usize, keyword: &str| -> Option<usize> {
        if !starts_with(block, position, keyword) {
            return None;
        }
        let mut cursor = position + keyword.chars().count();
        let start = cursor;
        while cursor < block.len() && python_space(block[cursor]) {
            cursor += 1;
        }
        (cursor > start).then_some(cursor)
    };
    for start in line_starts {
        let mut position = start;
        loop {
            let next = ["noncomputable", "partial", "private"]
                .iter()
                .find_map(|keyword| keyword_then_space(position, keyword));
            match next {
                Some(after) => position = after,
                None => break,
            }
        }
        let Some(after) = keyword_then_space(position, "def") else {
            continue;
        };
        let mut end = after;
        while end < block.len() && !python_space(block[end]) {
            end += 1;
        }
        if end > after {
            return Some(end);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Scope definition, translation inventory, and closure
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeDefinition {
    schema: String,
    pub(crate) verifier_crate: String,
    pub(crate) decision_kernel_crates: Vec<String>,
    pub(crate) translated_crates: Vec<String>,
    pub(crate) excluded_roles: Vec<String>,
    pub(crate) nontrivial_code_lines: usize,
    pub(crate) every_file_listed: bool,
    #[serde(default)]
    pub(crate) components: Vec<Component>,
    pub(crate) files: BTreeMap<String, String>,
}

impl ScopeDefinition {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let scope: Self =
            toml::from_str(text).map_err(|error| format!("invalid coverage scope: {error}"))?;
        if scope.schema != "auths-proof-coverage-scope/v1" {
            return Err(format!(
                "unsupported coverage scope schema {}",
                scope.schema
            ));
        }
        const ROLES: [&str; 7] = [
            "decision",
            "decoding",
            "crypto",
            "interface",
            "explanation",
            "storage",
            "test-support",
        ];
        for (path, role) in &scope.files {
            if !ROLES.contains(&role.as_str()) {
                return Err(format!(
                    "coverage scope gives {path} the unknown role {role}"
                ));
            }
        }
        Ok(scope)
    }

    fn role(&self, path: &str) -> &str {
        self.files.get(path).map_or("decision", String::as_str)
    }

    fn excluded(&self, role: &str) -> bool {
        self.excluded_roles.iter().any(|excluded| excluded == role)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Translated {
    pub(crate) crate_name: String,
    pub(crate) rust_name: String,
    pub(crate) lean_name: String,
    pub(crate) file: String,
    pub(crate) begin_line: usize,
    pub(crate) end_line: usize,
    pub(crate) kind: &'static str,
    pub(crate) funs_path: String,
}

#[derive(Deserialize)]
struct QualificationTranslations {
    translations: Vec<QualificationTranslation>,
}

#[derive(Deserialize)]
struct QualificationTranslation {
    translation_json: String,
    local_functions: usize,
}

type Translations = (Vec<Translated>, Vec<(String, String)>);

fn load_translations(tree: &dyn Tree) -> Result<Translations, String> {
    let qualification: QualificationTranslations = toml::from_str(&tree.read(QUALIFICATION)?)
        .map_err(|error| format!("invalid {QUALIFICATION}: {error}"))?;
    let mut translated = Vec::new();
    let mut funs_files: Vec<(String, String)> = Vec::new();
    for entry in &qualification.translations {
        let document: Value = serde_json::from_str(&tree.read(&entry.translation_json)?)
            .map_err(|error| format!("invalid {}: {error}", entry.translation_json))?;
        let crate_name = document["crate"]
            .as_str()
            .ok_or_else(|| format!("{} names no crate", entry.translation_json))?
            .to_owned();
        let funs_path = format!("{}/Funs.lean", parent_directory(&entry.translation_json));
        if let Some(existing) = funs_files.iter_mut().find(|(name, _)| *name == crate_name) {
            existing.1.clone_from(&funs_path);
        } else {
            funs_files.push((crate_name.clone(), funs_path.clone()));
        }
        let local: Vec<&Value> = document["functions"]
            .as_array()
            .ok_or_else(|| format!("{} lists no functions", entry.translation_json))?
            .iter()
            .filter(|item| item["is_local"].as_bool() == Some(true))
            .collect();
        if local.len() != entry.local_functions {
            return Err(format!(
                "{crate_name}: inventory says {}, json {}",
                entry.local_functions,
                local.len()
            ));
        }
        for item in local {
            let lean_name = item["lean_name"]
                .as_str()
                .ok_or("translation without lean_name")?;
            let rust_name = item["rust_name"]
                .as_str()
                .ok_or("translation without rust_name")?;
            let source = &item["source"];
            let file = source["file"].as_str().ok_or("translation without file")?;
            let begin_line = usize::try_from(source["begin_line"].as_u64().ok_or("no begin_line")?)
                .map_err(|error| error.to_string())?;
            let end_line = usize::try_from(source["end_line"].as_u64().ok_or("no end_line")?)
                .map_err(|error| error.to_string())?;
            let pieces: Vec<&str> = lean_name.rsplitn(3, '.').collect();
            let second_last = if pieces.len() >= 2 { pieces[1] } else { "" };
            let kind = if second_last.contains("_loop") || lean_name.ends_with("_loop") {
                "loop"
            } else if begin_line == end_line
                && tree
                    .read(file)?
                    .lines()
                    .nth(begin_line.saturating_sub(1))
                    .is_some_and(|line| line.contains("#[derive("))
            {
                "derived"
            } else {
                "function"
            };
            translated.push(Translated {
                crate_name: crate_name.clone(),
                rust_name: rust_name.to_owned(),
                lean_name: lean_name.to_owned(),
                file: file.to_owned(),
                begin_line,
                end_line,
                kind,
                funs_path: funs_path.clone(),
            });
        }
    }
    Ok((translated, funs_files))
}

/// The hand-written functions Aeneas translates, in inventory order.
pub(crate) fn translated_functions(tree: &dyn Tree) -> Result<Vec<Translated>, String> {
    Ok(load_translations(tree)?
        .0
        .into_iter()
        .filter(|item| item.kind == "function")
        .collect())
}

/// Every translated Lean name (loop helpers included) mapped to its function's name.
fn owner_of(translated: &[Translated]) -> BTreeMap<String, String> {
    let mut function_by_rust: BTreeMap<&str, &str> = BTreeMap::new();
    for item in translated.iter().filter(|item| item.kind != "loop") {
        function_by_rust.insert(&item.rust_name, &item.lean_name);
    }
    translated
        .iter()
        .filter_map(|item| {
            function_by_rust
                .get(item.rust_name.as_str())
                .map(|owner| (item.lean_name.clone(), (*owner).to_owned()))
        })
        .collect()
}

fn resolve(candidate: &str, known: &BTreeSet<String>, instances: bool) -> Vec<String> {
    if known.contains(candidate) {
        return vec![candidate.to_owned()];
    }
    if instances && candidate.contains(".Insts.") {
        let prefix = format!("{candidate}.");
        return known
            .iter()
            .filter(|name| name.starts_with(&prefix))
            .cloned()
            .collect();
    }
    Vec::new()
}

fn lean_call_graph(
    tree: &dyn Tree,
    translated: &[Translated],
    funs_files: &[(String, String)],
    instances: bool,
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let owners = owner_of(translated);
    let mut by_rust: BTreeMap<&str, String> = BTreeMap::new();
    for item in translated {
        if let Some(owner) = owners.get(&item.lean_name) {
            by_rust.insert(&item.rust_name, owner.clone());
        }
    }
    let known: BTreeSet<String> = owners.keys().cloned().collect();
    let crates: BTreeSet<&str> = translated
        .iter()
        .map(|item| item.crate_name.as_str())
        .collect();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (crate_name, funs_path) in funs_files {
        let text: Vec<char> = tree.read(funs_path)?.chars().collect();
        let docs = lean_doc_rust_names(&text);
        for (position, (start, name)) in docs.iter().enumerate() {
            let stop = docs.get(position + 1).map_or(text.len(), |next| next.0);
            let block = &text[*start..stop];
            let Some(definition_end) = lean_def_end(block) else {
                continue;
            };
            let Some(owner) = by_rust.get(name.as_str()) else {
                continue;
            };
            let body = text_of(block, definition_end, block.len());
            for identifier in lean_identifiers(&body) {
                let head = identifier.split('.').next().unwrap_or("");
                let candidate = if crates.contains(head) {
                    identifier.clone()
                } else {
                    format!("{crate_name}.{identifier}")
                };
                for callee in resolve(&candidate, &known, instances) {
                    let callee_owner = &owners[&callee];
                    if callee_owner != owner {
                        edges
                            .entry(owner.clone())
                            .or_default()
                            .insert(callee_owner.clone());
                    }
                }
            }
        }
    }
    Ok(edges)
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct AuditDeclaration {
    pub(crate) name: String,
    pub(crate) statement: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Audit {
    pub(crate) declarations: Vec<AuditDeclaration>,
}

/// Each translated function's Lean name mapped to the theorems whose statement names it,
/// in first-mention order.
fn statement_mentions(
    audit: &Audit,
    translated: &[Translated],
    instances: bool,
) -> Vec<(String, Vec<String>)> {
    let owners = owner_of(translated);
    let known: BTreeSet<String> = owners.keys().cloned().collect();
    let crates: BTreeSet<&str> = translated
        .iter()
        .map(|item| item.crate_name.as_str())
        .collect();
    let mut mentions: Vec<(String, Vec<String>)> = Vec::new();
    for declaration in &audit.declarations {
        let mut found = BTreeSet::new();
        for identifier in lean_identifiers(&declaration.statement) {
            let parts: Vec<&str> = identifier.split('.').collect();
            for offset in 0..parts.len() {
                if crates.contains(parts[offset]) {
                    for name in resolve(&parts[offset..].join("."), &known, instances) {
                        found.insert(owners[&name].clone());
                    }
                }
            }
        }
        for name in found {
            if let Some(entry) = mentions.iter_mut().find(|(owner, _)| *owner == name) {
                entry.1.push(declaration.name.clone());
            } else {
                mentions.push((name, vec![declaration.name.clone()]));
            }
        }
    }
    mentions
}

fn closure(
    seeds: &BTreeSet<String>,
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut reached = seeds.clone();
    let mut pending: Vec<String> = seeds.iter().cloned().collect();
    while let Some(current) = pending.pop() {
        for callee in edges.get(&current).into_iter().flatten() {
            if reached.insert(callee.clone()) {
                pending.push(callee.clone());
            }
        }
    }
    reached
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub(crate) struct Status {
    pub(crate) lean_name: String,
    pub(crate) refined_direct: bool,
    pub(crate) refined_closure: bool,
    pub(crate) theorems: Vec<String>,
}

pub(crate) struct Measurement {
    pub(crate) scope: ScopeDefinition,
    pub(crate) verifier_closure: Vec<String>,
    pub(crate) translated_crates: Vec<String>,
    pub(crate) files: BTreeMap<String, String>,
    pub(crate) scans: BTreeMap<String, ScanResult>,
    pub(crate) test_files: BTreeSet<String>,
    pub(crate) functions: Vec<RustFunction>,
    pub(crate) translated: Vec<Translated>,
    pub(crate) mentions: Vec<(String, Vec<String>)>,
    pub(crate) direct: BTreeSet<String>,
    pub(crate) reached: BTreeSet<String>,
    pub(crate) reached_without_instances: BTreeSet<String>,
    pub(crate) edges: BTreeMap<String, BTreeSet<String>>,
    pub(crate) validation: Vec<Value>,
    pub(crate) status: BTreeMap<(String, usize), Status>,
    pub(crate) audit_sha256: String,
}

fn workspace_members(tree: &dyn Tree) -> Result<BTreeMap<String, String>, String> {
    let root: toml::Value = toml::from_str(&tree.read("Cargo.toml")?)
        .map_err(|error| format!("invalid Cargo.toml: {error}"))?;
    let mut members = BTreeMap::new();
    if let Some(dependencies) = root
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        for (name, specification) in dependencies {
            if let Some(path) = specification.get("path").and_then(toml::Value::as_str) {
                members.insert(name.clone(), path.to_owned());
            }
        }
    }
    Ok(members)
}

fn dependency_closure(tree: &dyn Tree, start: &str) -> Result<Vec<String>, String> {
    let members = workspace_members(tree)?;
    let mut pending = vec![start.to_owned()];
    let mut seen = BTreeSet::new();
    while let Some(crate_path) = pending.pop() {
        if !seen.insert(crate_path.clone()) {
            continue;
        }
        let manifest: toml::Value =
            toml::from_str(&tree.read(&format!("{crate_path}/Cargo.toml"))?)
                .map_err(|error| format!("invalid {crate_path}/Cargo.toml: {error}"))?;
        if let Some(dependencies) = manifest.get("dependencies").and_then(toml::Value::as_table) {
            for name in dependencies.keys() {
                if let Some(path) = members.get(name) {
                    pending.push(path.clone());
                }
            }
        }
    }
    Ok(seen.into_iter().collect())
}

fn crate_sources(tree: &dyn Tree, crate_path: &str) -> Result<Vec<String>, String> {
    Ok(tree
        .list_files(&format!("{crate_path}/src"))?
        .into_iter()
        .filter(|path| {
            Path::new(path)
                .extension()
                .is_some_and(|extension| extension == "rs")
                && !path.contains("/src/bin/")
        })
        .collect())
}

pub(crate) fn measure(
    tree: &dyn Tree,
    scope: ScopeDefinition,
    audit_text: &str,
) -> Result<Measurement, String> {
    let audit: Audit = serde_json::from_str(audit_text)
        .map_err(|error| format!("invalid Lean assurance audit: {error}"))?;
    let verifier_closure = dependency_closure(tree, &scope.verifier_crate)?;
    let (translated, funs_files) = load_translations(tree)?;
    let qualified_crates: BTreeSet<String> = translated
        .iter()
        .filter_map(|item| {
            item.file
                .split_once("/src/")
                .map(|(crate_path, _)| crate_path.to_owned())
        })
        .collect();
    let translated_crates = scope.translated_crates.clone();
    if qualified_crates != translated_crates.iter().cloned().collect::<BTreeSet<_>>() {
        return Err(format!(
            "the coverage scope's translated crates {translated_crates:?} differ from the crates qualification.toml translates {qualified_crates:?}"
        ));
    }
    let scoped_crates: BTreeSet<String> = verifier_closure
        .iter()
        .chain(&translated_crates)
        .chain(&scope.decision_kernel_crates)
        .cloned()
        .collect();
    let mut files = BTreeMap::new();
    let mut file_order = Vec::new();
    for crate_path in &scoped_crates {
        for path in crate_sources(tree, crate_path)? {
            file_order.push(path.clone());
            files.insert(path, crate_path.clone());
        }
    }
    let mut scans = BTreeMap::new();
    for path in &file_order {
        scans.insert(path.clone(), scan_rust(path, &tree.read(path)?));
    }
    let test_files: BTreeSet<String> = scans
        .values()
        .flat_map(|scan| scan.test_module_files.iter().cloned())
        .collect();
    let functions: Vec<RustFunction> = file_order
        .iter()
        .filter(|path| !test_files.contains(*path) && scope.role(path) != "test-support")
        .flat_map(|path| scans[path].functions.iter().cloned())
        .collect();

    let edges = lean_call_graph(tree, &translated, &funs_files, true)?;
    let mentions = statement_mentions(&audit, &translated, true);
    let direct: BTreeSet<String> = mentions.iter().map(|(name, _)| name.clone()).collect();
    let reached = closure(&direct, &edges);
    let edges_without = lean_call_graph(tree, &translated, &funs_files, false)?;
    let direct_without: BTreeSet<String> = statement_mentions(&audit, &translated, false)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let reached_without_instances = closure(&direct_without, &edges_without);

    let mut by_span: BTreeMap<(String, usize), &RustFunction> = BTreeMap::new();
    for function in &functions {
        by_span.insert((function.file.clone(), function.begin_line), function);
    }
    let mut validation = Vec::new();
    let mut status = BTreeMap::new();
    for item in translated.iter().filter(|item| item.kind == "function") {
        let found = by_span.get(&(item.file.clone(), item.begin_line));
        let outcome = match found {
            None => "not-found",
            Some(function) if function.end_line != item.end_line => "end-line-differs",
            Some(_) => "matched",
        };
        validation.push(json!({
            "rust_name": item.rust_name,
            "file": item.file,
            "charon_span": [item.begin_line, item.end_line],
            "scanner_span": found.map(|function| json!([function.begin_line, function.end_line])),
            "outcome": outcome,
        }));
        if let Some(function) = found {
            status.insert(
                (function.file.clone(), function.begin_line),
                Status {
                    lean_name: item.lean_name.clone(),
                    refined_direct: direct.contains(&item.lean_name),
                    refined_closure: reached.contains(&item.lean_name),
                    theorems: mentions
                        .iter()
                        .find(|(name, _)| *name == item.lean_name)
                        .map(|(_, theorems)| theorems.clone())
                        .unwrap_or_default(),
                },
            );
        }
    }
    let audit_sha256 = hex::encode(Sha256::digest(audit_text.as_bytes()));
    Ok(Measurement {
        scope,
        verifier_closure,
        translated_crates,
        files,
        scans,
        test_files,
        functions,
        translated,
        mentions,
        direct,
        reached,
        reached_without_instances,
        edges,
        validation,
        status,
        audit_sha256,
    })
}

pub(crate) fn ratio(numerator: usize, denominator: usize) -> Value {
    if denominator == 0 {
        return Value::Null;
    }
    #[allow(clippy::cast_precision_loss)]
    let value = numerator as f64 / denominator as f64;
    let rounded: f64 = format!("{value:.4}").parse().unwrap_or(value);
    serde_json::Number::from_f64(rounded).map_or(Value::Null, Value::Number)
}

pub(crate) const SCOPES: [&str; 4] = [
    "decision",
    "verifier-core",
    "translated-crates",
    "verifier-closure",
];

impl Measurement {
    pub(crate) fn role(&self, path: &str) -> &str {
        self.scope.role(path)
    }

    pub(crate) fn in_scope(&self, function: &RustFunction, scope: &str) -> bool {
        let crate_path = &self.files[&function.file];
        let role = self.role(&function.file);
        let in_closure = self.verifier_closure.contains(crate_path);
        match scope {
            "verifier-closure" => in_closure,
            "translated-crates" => self.translated_crates.contains(crate_path),
            "verifier-core" => in_closure && !self.scope.excluded(role),
            _ => {
                (in_closure || self.scope.decision_kernel_crates.contains(crate_path))
                    && !self.scope.excluded(role)
            }
        }
    }

    pub(crate) fn status_of(&self, function: &RustFunction) -> Option<&Status> {
        self.status
            .get(&(function.file.clone(), function.begin_line))
    }

    /// The five-variant metric table, with an optional restriction of the
    /// members and an optional replacement for the refined-closure set.
    pub(crate) fn metric(
        &self,
        scope: &str,
        minimum: usize,
        include: &dyn Fn(&RustFunction) -> bool,
        closure_set: Option<&BTreeSet<String>>,
    ) -> Value {
        let members: Vec<&RustFunction> = self
            .functions
            .iter()
            .filter(|function| {
                self.in_scope(function, scope)
                    && function.code_lines >= minimum
                    && include(function)
            })
            .collect();
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        let mut lines: BTreeMap<&str, BTreeSet<(String, usize)>> = BTreeMap::new();
        let mut code: BTreeMap<&str, BTreeSet<(String, usize)>> = BTreeMap::new();
        for function in &members {
            let span: Vec<usize> = (function.begin_line..=function.end_line).collect();
            let code_set = &self.scans[&function.file].code_line_set;
            let mut levels = vec!["all"];
            if let Some(info) = self.status_of(function) {
                levels.push("translated");
                if info.refined_direct {
                    levels.push("direct");
                }
                let in_closure =
                    closure_set.map_or(info.refined_closure, |set| set.contains(&info.lean_name));
                if in_closure {
                    levels.push("closure");
                }
            }
            for level in levels {
                let span_entry = lines.entry(level).or_default();
                let code_entry = code.entry(level).or_default();
                for number in &span {
                    span_entry.insert((function.file.clone(), *number));
                    if code_set.contains(number) {
                        code_entry.insert((function.file.clone(), *number));
                    }
                }
                if level != "all" {
                    *counts.entry(level).or_default() += 1;
                }
            }
        }
        let size = |map: &BTreeMap<&str, BTreeSet<(String, usize)>>, level: &str| {
            map.get(level).map_or(0, BTreeSet::len)
        };
        let mut by_level = serde_json::Map::new();
        for level in ["translated", "direct", "closure"] {
            let count = counts.get(level).copied().unwrap_or(0);
            by_level.insert(
                level.to_owned(),
                json!({
                    "functions": count,
                    "function_share": ratio(count, members.len()),
                    "span_lines": size(&lines, level),
                    "span_line_share": ratio(size(&lines, level), size(&lines, "all")),
                    "code_lines": size(&code, level),
                    "code_line_share": ratio(size(&code, level), size(&code, "all")),
                }),
            );
        }
        json!({
            "scope": scope,
            "minimum_code_lines": minimum,
            "functions": members.len(),
            "span_lines": size(&lines, "all"),
            "code_lines": size(&code, "all"),
            "by_level": Value::Object(by_level),
        })
    }

    pub(crate) fn metrics(&self) -> Value {
        let mut metrics = serde_json::Map::new();
        for scope in SCOPES {
            metrics.insert(scope.to_owned(), self.metric(scope, 0, &|_| true, None));
        }
        metrics.insert(
            "decision-nontrivial".to_owned(),
            self.metric(
                "decision",
                self.scope.nontrivial_code_lines,
                &|_| true,
                None,
            ),
        );
        Value::Object(metrics)
    }

    fn translation_kinds(&self) -> Vec<(&'static str, usize)> {
        let mut kinds: Vec<(&'static str, usize)> = Vec::new();
        for item in &self.translated {
            if let Some(entry) = kinds.iter_mut().find(|(kind, _)| *kind == item.kind) {
                entry.1 += 1;
            } else {
                kinds.push((item.kind, 1));
            }
        }
        kinds
    }

    fn per_crate(&self) -> Value {
        let mut per_crate = serde_json::Map::new();
        let scoped: BTreeSet<&String> = self.files.values().collect();
        for crate_path in scoped {
            let members: Vec<&RustFunction> = self
                .functions
                .iter()
                .filter(|function| {
                    &self.files[&function.file] == crate_path
                        && !self.scope.excluded(self.role(&function.file))
                })
                .collect();
            let infos: Vec<Option<&Status>> = members
                .iter()
                .map(|function| self.status_of(function))
                .collect();
            per_crate.insert(
                crate_path.clone(),
                json!({
                    "decision_functions": members.len(),
                    "decision_code_lines": members.iter().map(|function| function.code_lines).sum::<usize>(),
                    "translated": infos.iter().filter(|info| info.is_some()).count(),
                    "refined_closure": infos.iter().filter(|info| info.is_some_and(|info| info.refined_closure)).count(),
                    "refined_closure_code_lines": members
                        .iter()
                        .zip(&infos)
                        .filter(|(_, info)| info.is_some_and(|info| info.refined_closure))
                        .map(|(function, _)| function.code_lines)
                        .sum::<usize>(),
                }),
            );
        }
        Value::Object(per_crate)
    }

    /// The reference scanner's `proof_coverage.json`, byte for byte.
    pub(crate) fn study_json(&self) -> Value {
        let outcomes = {
            let mut outcomes: Vec<(String, usize)> = Vec::new();
            for row in &self.validation {
                let outcome = row["outcome"].as_str().unwrap_or("").to_owned();
                if let Some(entry) = outcomes.iter_mut().find(|(name, _)| *name == outcome) {
                    entry.1 += 1;
                } else {
                    outcomes.push((outcome, 1));
                }
            }
            outcomes
        };
        let mut per_file = serde_json::Map::new();
        for path in self.files.keys() {
            let members: Vec<&RustFunction> = self
                .functions
                .iter()
                .filter(|function| &function.file == path)
                .collect();
            per_file.insert(
                path.clone(),
                json!({
                    "functions": members.len(),
                    "translated": members.iter().filter(|function| self.status_of(function).is_some()).count(),
                    "test_functions": self.scans[path].test_functions,
                }),
            );
        }
        let theorems: BTreeSet<&String> = self
            .mentions
            .iter()
            .flat_map(|(_, theorems)| theorems)
            .collect();
        let derived: Vec<String> = {
            let mut names: Vec<String> = self
                .translated
                .iter()
                .filter(|item| item.kind == "derived" && self.direct.contains(&item.lean_name))
                .map(|item| item.rust_name.clone())
                .collect();
            names.sort();
            names
        };
        let mut excluded_roles: Vec<&String> = self.scope.excluded_roles.iter().collect();
        excluded_roles.sort();
        json!({
            "pilot": true,
            "auths_proof_commit": PIN,
            "audit_sha256": self.audit_sha256,
            "definitions": {
                "function": "hand-written fn item with a body, outside test/kani code, in src/",
                "translated": "local Aeneas translation.json function with the same file and span",
                "refined_direct": "translated and named in the statement of an audited theorem",
                "refined_closure": "refined_direct plus translated callees in the generated Lean",
                "excluded_roles": excluded_roles,
            },
            "verifier_dependency_closure": self.verifier_closure,
            "translated_crates": self.translated_crates,
            "product_kernel_crates": self.scope.decision_kernel_crates,
            "file_roles": self.files.keys().map(|path| (path.clone(), Value::from(self.role(path)))).collect::<serde_json::Map<_, _>>(),
            "excluded_test_module_files": self.test_files.iter().filter(|path| self.files.contains_key(*path)).collect::<Vec<_>>(),
            "translation_inventory": {
                "aeneas_local_definitions": self.translated.len(),
                "by_kind": self.translation_kinds().into_iter().map(|(kind, count)| (kind.to_owned(), Value::from(count))).collect::<serde_json::Map<_, _>>(),
                "derived_trait_methods_refined_direct": derived,
                "refined_direct": self.direct.len(),
                "refined_closure": self.reached.len(),
                "theorems_naming_translated_functions": theorems.len(),
            },
            "scanner_validation": {
                "translated_functions": self.validation.len(),
                "outcomes": outcomes.iter().map(|(name, count)| (name.clone(), Value::from(*count))).collect::<serde_json::Map<_, _>>(),
                "unmatched": self.validation.iter().filter(|row| row["outcome"] != "matched").cloned().collect::<Vec<_>>(),
            },
            "metrics": self.metrics(),
            "per_crate_decision": self.per_crate(),
            "per_file": Value::Object(per_file),
        })
    }

    pub(crate) fn sorted_functions(&self) -> Vec<&RustFunction> {
        let mut functions: Vec<&RustFunction> = self.functions.iter().collect();
        functions.sort_by(|left, right| {
            (&left.file, left.begin_line).cmp(&(&right.file, right.begin_line))
        });
        functions
    }

    /// The reference scanner's `proof_coverage_functions.tsv`, byte for byte.
    pub(crate) fn study_tsv(&self) -> String {
        let mut output = String::new();
        write_tsv_row(
            &mut output,
            &[
                "file",
                "begin_line",
                "end_line",
                "code_lines",
                "function",
                "crate",
                "role",
                "translated",
                "refined_direct",
                "refined_closure",
                "theorems",
            ]
            .map(str::to_owned),
        );
        for function in self.sorted_functions() {
            let info = self.status_of(function);
            write_tsv_row(
                &mut output,
                &[
                    function.file.clone(),
                    function.begin_line.to_string(),
                    function.end_line.to_string(),
                    function.code_lines.to_string(),
                    function.qualified.clone(),
                    self.files[&function.file].clone(),
                    self.role(&function.file).to_owned(),
                    u8::from(info.is_some()).to_string(),
                    u8::from(info.is_some_and(|info| info.refined_direct)).to_string(),
                    u8::from(info.is_some_and(|info| info.refined_closure)).to_string(),
                    info.map_or(0, |info| info.theorems.len()).to_string(),
                ],
            );
        }
        output
    }
}

pub(crate) fn write_tsv_row(output: &mut String, fields: &[String]) {
    let rendered: Vec<String> = fields
        .iter()
        .map(|field| {
            if field.contains(['\t', '"', '\n', '\r']) {
                format!("\"{}\"", field.replace('"', "\"\""))
            } else {
                field.clone()
            }
        })
        .collect();
    output.push_str(&rendered.join("\t"));
    output.push('\n');
}

// ---------------------------------------------------------------------------
// JSON rendering compatible with Python's `json.dumps(value, indent=n)`
// ---------------------------------------------------------------------------

pub(crate) fn python_json(value: &Value, indent: usize) -> String {
    let mut output = String::new();
    render_python_json(value, indent, 0, &mut output);
    output
}

fn render_python_json(value: &Value, indent: usize, depth: usize, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(flag) => output.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => {
            if let Some(float) = number.as_f64().filter(|_| number.is_f64()) {
                if float.fract() == 0.0 && float.abs() < 1e16 {
                    let _ = write!(output, "{float:.1}");
                } else {
                    let _ = write!(output, "{float}");
                }
            } else {
                output.push_str(&number.to_string());
            }
        }
        Value::String(text) => render_python_string(text, output),
        Value::Array(items) => {
            if items.is_empty() {
                output.push_str("[]");
                return;
            }
            output.push('[');
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    output.push(',');
                }
                output.push('\n');
                output.push_str(&" ".repeat(indent * (depth + 1)));
                render_python_json(item, indent, depth + 1, output);
            }
            output.push('\n');
            output.push_str(&" ".repeat(indent * depth));
            output.push(']');
        }
        Value::Object(entries) => {
            if entries.is_empty() {
                output.push_str("{}");
                return;
            }
            output.push('{');
            for (position, (key, item)) in entries.iter().enumerate() {
                if position > 0 {
                    output.push(',');
                }
                output.push('\n');
                output.push_str(&" ".repeat(indent * (depth + 1)));
                render_python_string(key, output);
                output.push_str(": ");
                render_python_json(item, indent, depth + 1, output);
            }
            output.push('\n');
            output.push_str(&" ".repeat(indent * depth));
            output.push('}');
        }
    }
}

fn render_python_string(text: &str, output: &mut String) {
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{8}' => output.push_str("\\b"),
            '\u{c}' => output.push_str("\\f"),
            character if character.is_ascii() && !character.is_ascii_control() => {
                output.push(character);
            }
            character => {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    let _ = write!(output, "\\u{unit:04x}");
                }
            }
        }
    }
    output.push('"');
}

// ---------------------------------------------------------------------------
// Second parser (syn): an independent reading of the same function spans
// ---------------------------------------------------------------------------

struct SpanVisitor {
    test_depth: Vec<bool>,
    spans: Vec<(usize, usize, bool)>,
}

fn attribute_words(attribute: &syn::Attribute) -> Vec<String> {
    fn collect(stream: proc_macro2::TokenStream, words: &mut Vec<String>) {
        for tree in stream {
            match tree {
                proc_macro2::TokenTree::Ident(ident) => words.push(ident.to_string()),
                proc_macro2::TokenTree::Group(group) => collect(group.stream(), words),
                _ => {}
            }
        }
    }
    let mut words = Vec::new();
    let path = match &attribute.meta {
        syn::Meta::Path(path) => path,
        syn::Meta::List(list) => &list.path,
        syn::Meta::NameValue(pair) => &pair.path,
    };
    words.extend(
        path.segments
            .iter()
            .map(|segment| segment.ident.to_string()),
    );
    if let syn::Meta::List(list) = &attribute.meta {
        collect(list.tokens.clone(), &mut words);
    }
    words
        .into_iter()
        .map(|word| word.strip_prefix("r#").map_or(word.clone(), str::to_owned))
        .collect()
}

fn attributes_mark_test(attributes: &[syn::Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute_marks_test(&attribute_words(attribute)))
}

impl SpanVisitor {
    fn testing(&self) -> bool {
        self.test_depth.iter().any(|flag| *flag)
    }

    fn record(
        &mut self,
        attributes: &[syn::Attribute],
        starts: &[Option<proc_macro2::Span>],
        block: &syn::Block,
    ) {
        let test = self.testing() || attributes_mark_test(attributes);
        let begin = starts
            .iter()
            .flatten()
            .map(|span| span.start().line)
            .min()
            .unwrap_or(0);
        let end = block.brace_token.span.close().end().line;
        self.spans.push((begin, end, test));
    }
}

fn signature_starts(
    visibility: Option<&syn::Visibility>,
    signature: &syn::Signature,
    defaultness: Option<proc_macro2::Span>,
) -> Vec<Option<proc_macro2::Span>> {
    vec![
        visibility.and_then(|visibility| match visibility {
            syn::Visibility::Inherited => None,
            syn::Visibility::Public(token) => Some(token.span),
            syn::Visibility::Restricted(restricted) => Some(restricted.pub_token.span),
        }),
        defaultness,
        signature.constness.as_ref().map(|token| token.span),
        signature.asyncness.as_ref().map(|token| token.span),
        signature.unsafety.as_ref().map(|token| token.span),
        signature.abi.as_ref().map(|abi| abi.extern_token.span),
        Some(signature.fn_token.span),
    ]
}

impl<'ast> syn::visit::Visit<'ast> for SpanVisitor {
    fn visit_file(&mut self, file: &'ast syn::File) {
        self.test_depth.push(attributes_mark_test(&file.attrs));
        syn::visit::visit_file(self, file);
        self.test_depth.pop();
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        self.test_depth.push(attributes_mark_test(&item.attrs));
        syn::visit::visit_item_mod(self, item);
        self.test_depth.pop();
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        self.test_depth.push(attributes_mark_test(&item.attrs));
        syn::visit::visit_item_impl(self, item);
        self.test_depth.pop();
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        self.test_depth.push(attributes_mark_test(&item.attrs));
        syn::visit::visit_item_trait(self, item);
        self.test_depth.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let starts = signature_starts(Some(&item.vis), &item.sig, None);
        self.record(&item.attrs, &starts, &item.block);
        self.test_depth.push(attributes_mark_test(&item.attrs));
        syn::visit::visit_item_fn(self, item);
        self.test_depth.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        let starts = signature_starts(
            Some(&item.vis),
            &item.sig,
            item.defaultness.as_ref().map(|token| token.span),
        );
        self.record(&item.attrs, &starts, &item.block);
        self.test_depth.push(attributes_mark_test(&item.attrs));
        syn::visit::visit_impl_item_fn(self, item);
        self.test_depth.pop();
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if let Some(block) = &item.default {
            let starts = signature_starts(None, &item.sig, None);
            self.record(&item.attrs, &starts, block);
        }
        self.test_depth.push(attributes_mark_test(&item.attrs));
        syn::visit::visit_trait_item_fn(self, item);
        self.test_depth.pop();
    }
}

/// Non-test function spans `(first line, last line)` as syn reads them. A
/// function written inside a `macro_rules!` body is a token tree to syn and has
/// no span here.
pub(crate) fn syn_function_spans(source: &str) -> Result<BTreeSet<(usize, usize)>, String> {
    let file = syn::parse_file(source).map_err(|error| error.to_string())?;
    let mut visitor = SpanVisitor {
        test_depth: Vec::new(),
        spans: Vec::new(),
    };
    syn::visit::Visit::visit_file(&mut visitor, &file);
    Ok(visitor
        .spans
        .into_iter()
        .filter(|(_, _, test)| !test)
        .map(|(begin, end, _)| (begin, end))
        .collect())
}

pub(crate) struct SecondParser {
    pub(crate) agreements: usize,
    pub(crate) compared: usize,
    pub(crate) files: usize,
    pub(crate) disagreements: Vec<Value>,
    pub(crate) parser_only: Vec<Value>,
    pub(crate) agreeing: BTreeSet<(String, usize)>,
}

pub(crate) fn second_parser(
    measurement: &Measurement,
    tree: &dyn Tree,
) -> Result<SecondParser, String> {
    let decision: Vec<&RustFunction> = measurement
        .sorted_functions()
        .into_iter()
        .filter(|function| measurement.in_scope(function, "decision"))
        .collect();
    let files: BTreeSet<&String> = decision.iter().map(|function| &function.file).collect();
    let mut spans = BTreeMap::new();
    for file in &files {
        spans.insert((*file).clone(), syn_function_spans(&tree.read(file)?)?);
    }
    let mut agreeing = BTreeSet::new();
    let mut disagreements = Vec::new();
    for function in &decision {
        if spans[&function.file].contains(&(function.begin_line, function.end_line)) {
            agreeing.insert((function.file.clone(), function.begin_line));
        } else {
            disagreements.push(json!({
                "file": function.file,
                "function": function.qualified,
                "scanner_span": [function.begin_line, function.end_line],
                "reason": if function.in_macro {
                    "inside a macro_rules! body (syn parses it as a token tree)"
                } else {
                    "no syn function with this span"
                },
            }));
        }
    }
    let scanned: BTreeSet<(String, usize, usize)> = decision
        .iter()
        .map(|function| {
            (
                function.file.clone(),
                function.begin_line,
                function.end_line,
            )
        })
        .collect();
    let mut parser_only = Vec::new();
    for (file, found) in &spans {
        for (begin, end) in found {
            if !scanned.contains(&(file.clone(), *begin, *end)) {
                parser_only.push(json!({"file": file, "span": [begin, end]}));
            }
        }
    }
    Ok(SecondParser {
        agreements: agreeing.len(),
        compared: decision.len(),
        files: files.len(),
        disagreements,
        parser_only,
        agreeing,
    })
}

// ---------------------------------------------------------------------------
// Product inputs: theorem kinds, the check-site map, mutation results
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TheoremKinds {
    schema: String,
    pub(crate) kinds: BTreeMap<String, String>,
}

pub(crate) const KINDS: [&str; 4] = ["exact", "verdict-exact", "partial", "case"];

impl TheoremKinds {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let kinds: Self =
            toml::from_str(text).map_err(|error| format!("invalid theorem kinds: {error}"))?;
        if kinds.schema != "auths-proof-theorem-kinds/v1" {
            return Err(format!("unsupported theorem-kinds schema {}", kinds.schema));
        }
        for (theorem, kind) in &kinds.kinds {
            if !KINDS.contains(&kind.as_str()) {
                return Err(format!("theorem {theorem} has the unknown kind {kind}"));
            }
        }
        Ok(kinds)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FunctionRef {
    pub(crate) file: String,
    pub(crate) function: String,
    #[serde(default)]
    pub(crate) begin_line: Option<usize>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckSiteEntry {
    pub(crate) site: String,
    pub(crate) refusal: FunctionRef,
    #[serde(default)]
    pub(crate) guard: Option<FunctionRef>,
    #[serde(default)]
    pub(crate) also: Vec<FunctionRef>,
    pub(crate) stage: String,
    #[serde(default)]
    pub(crate) note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckSiteMap {
    schema: String,
    pub(crate) sites: Vec<CheckSiteEntry>,
}

impl CheckSiteEntry {
    pub(crate) fn functions(&self) -> Vec<&FunctionRef> {
        std::iter::once(&self.refusal)
            .chain(self.guard.iter())
            .chain(self.also.iter())
            .collect()
    }
}

pub(crate) fn load_check_site_map(text: &str) -> Result<CheckSiteMap, String> {
    let map: CheckSiteMap =
        toml::from_str(text).map_err(|error| format!("invalid check-site map: {error}"))?;
    if map.schema != "auths-proof-check-site-functions/v1" {
        return Err(format!("unsupported check-site map schema {}", map.schema));
    }
    let expected: Vec<&str> = auths_testkit::check_sites::CHECK_SITES
        .iter()
        .map(|site| site.site)
        .collect();
    let mapped: Vec<&str> = map.sites.iter().map(|entry| entry.site.as_str()).collect();
    if mapped != expected {
        let missing: Vec<&&str> = expected
            .iter()
            .filter(|site| !mapped.contains(site))
            .collect();
        let extra: Vec<&&str> = mapped
            .iter()
            .filter(|site| !expected.contains(site))
            .collect();
        return Err(format!(
            "{CHECK_SITE_MAP_PATH} must map every CHECK_SITES entry once, in evaluation order; missing {missing:?}, unknown {extra:?}"
        ));
    }
    for entry in &map.sites {
        if entry.stage.trim().is_empty() {
            return Err(format!("check site {} names no covering stage", entry.site));
        }
    }
    Ok(map)
}

/// The scanned function a map entry names; exactly one must match.
pub(crate) fn resolve_function<'a>(
    functions: &'a [RustFunction],
    reference: &FunctionRef,
) -> Result<&'a RustFunction, String> {
    let matches: Vec<&RustFunction> = functions
        .iter()
        .filter(|function| {
            function.file == reference.file
                && function.qualified == reference.function
                && reference
                    .begin_line
                    .is_none_or(|line| line == function.begin_line)
        })
        .collect();
    match matches.as_slice() {
        [single] => Ok(single),
        [] => Err(format!(
            "the scanner finds no function {} in {}",
            reference.function, reference.file
        )),
        _ => Err(format!(
            "{} in {} is ambiguous; give begin_line",
            reference.function, reference.file
        )),
    }
}

/// Every map entry resolves to scanned functions. `cargo xtask spec-sync` runs this.
pub(crate) fn validate_check_site_map(root: &Path) -> Result<usize, String> {
    let tree = WorkTree::new(root.to_path_buf());
    let map = load_check_site_map(&tree.read(CHECK_SITE_MAP_PATH)?)?;
    let scope = ScopeDefinition::parse(&tree.read(SCOPE_PATH)?)?;
    let verifier_closure = dependency_closure(&tree, &scope.verifier_crate)?;
    let crates: BTreeSet<String> = verifier_closure
        .into_iter()
        .chain(scope.translated_crates.iter().cloned())
        .chain(scope.decision_kernel_crates.iter().cloned())
        .collect();
    let mut functions = Vec::new();
    for crate_path in &crates {
        for path in crate_sources(&tree, crate_path)? {
            functions.extend(scan_rust(&path, &tree.read(&path)?).functions);
        }
    }
    for entry in &map.sites {
        for reference in entry.functions() {
            resolve_function(&functions, reference)
                .map_err(|error| format!("check site {}: {error}", entry.site))?;
        }
    }
    Ok(map.sites.len())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErrorLocation {
    pub(crate) file: String,
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) declaration: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mutant {
    pub(crate) id: String,
    pub(crate) file: String,
    pub(crate) definition: String,
    pub(crate) operator: String,
    pub(crate) outcome: String,
    pub(crate) first_error: Option<ErrorLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) caught: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Campaign {
    pub(crate) formal_inputs_sha256: String,
    pub(crate) mutants: Vec<Mutant>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MutationResults {
    pub(crate) schema: String,
    pub(crate) tool_version: String,
    pub(crate) campaigns: BTreeMap<String, Campaign>,
    pub(crate) explanations: BTreeMap<String, String>,
}

pub(crate) const MUTATION_SCHEMA: &str = "auths-proof-model-mutations/v1";

pub(crate) fn load_mutation_results(root: &Path) -> Result<Option<MutationResults>, String> {
    let path = root.join(MUTATIONS_PATH);
    if !path.is_file() {
        return Ok(None);
    }
    let results: MutationResults = serde_json::from_slice(
        &fs::read(&path).map_err(|error| format!("could not read {MUTATIONS_PATH}: {error}"))?,
    )
    .map_err(|error| format!("invalid {MUTATIONS_PATH}: {error}"))?;
    if results.schema != MUTATION_SCHEMA {
        return Err(format!(
            "unsupported mutation results schema {}",
            results.schema
        ));
    }
    Ok(Some(results))
}

/// The digest of everything a mutation campaign builds: the Lean sources, the
/// generated translation, the project's matrix, and the Lean project files.
pub(crate) fn formal_inputs_sha256(root: &Path) -> Result<String, String> {
    let tree = WorkTree::new(root.to_path_buf());
    let mut paths: Vec<String> = tree
        .list_files("formal/Auths")?
        .into_iter()
        .chain(tree.list_files("formal/qualification")?)
        .filter(|path| {
            Path::new(path)
                .extension()
                .is_some_and(|extension| extension == "lean")
        })
        .collect();
    paths.extend(
        [
            "formal/Auths.lean",
            "formal/qualification.lean",
            "formal/lakefile.toml",
            "formal/lake-manifest.json",
            "formal/lean-toolchain",
            "formal/refinement-mutations-v1.json",
        ]
        .map(str::to_owned),
    );
    paths.sort();
    paths.dedup();
    let mut digest = Sha256::new();
    for path in &paths {
        digest.update(path.as_bytes());
        digest.update([0]);
        digest.update(Sha256::digest(tree.read_bytes(path)?));
    }
    Ok(hex::encode(digest.finalize()))
}

// ---------------------------------------------------------------------------
// The published measurement
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Component {
    pub(crate) name: String,
    pub(crate) crates: Vec<String>,
}

pub(crate) struct Published {
    pub(crate) json: Value,
    pub(crate) tsv: String,
    pub(crate) document: String,
}

fn percent(numerator: usize, denominator: usize) -> String {
    if denominator == 0 {
        return "n/a".to_owned();
    }
    #[allow(clippy::cast_precision_loss)]
    let value = numerator as f64 * 100.0 / denominator as f64;
    format!("{value:.1}%")
}

fn level(metric: &Value, level: &str, weight: &str) -> usize {
    usize::try_from(metric["by_level"][level][weight].as_u64().unwrap_or(0)).unwrap_or(0)
}

fn total(metric: &Value, weight: &str) -> usize {
    usize::try_from(metric[weight].as_u64().unwrap_or(0)).unwrap_or(0)
}

pub(crate) fn publish(root: &Path) -> Result<Published, String> {
    let tree = WorkTree::new(root.to_path_buf());
    let scope_text = tree.read(SCOPE_PATH)?;
    let scope = ScopeDefinition::parse(&scope_text)?;
    let audit_text = tree.read(AUDIT_PATH)?;
    let measurement = measure(&tree, scope, &audit_text)?;
    if !measurement.scope.every_file_listed {
        return Err(format!("{SCOPE_PATH} must give every scoped file a role"));
    }
    let unlisted: Vec<&String> = measurement
        .files
        .keys()
        .filter(|path| !measurement.scope.files.contains_key(*path))
        .collect();
    let stale: Vec<&String> = measurement
        .scope
        .files
        .keys()
        .filter(|path| !measurement.files.contains_key(*path))
        .collect();
    if !unlisted.is_empty() || !stale.is_empty() {
        return Err(format!(
            "{SCOPE_PATH} must give exactly the scoped files a role: unlisted {unlisted:?}, stale {stale:?}"
        ));
    }
    let unmatched: Vec<&Value> = measurement
        .validation
        .iter()
        .filter(|row| row["outcome"] != "matched")
        .collect();
    if !unmatched.is_empty() {
        return Err(format!(
            "the scanner does not find every translated function at Charon's span: {unmatched:?}"
        ));
    }
    let second = second_parser(&measurement, &tree)?;

    let kinds = TheoremKinds::parse(&tree.read(KINDS_PATH)?)?;
    let naming: BTreeSet<String> = measurement
        .mentions
        .iter()
        .flat_map(|(_, theorems)| theorems.iter().cloned())
        .collect();
    let unclassified: Vec<&String> = naming
        .iter()
        .filter(|theorem| !kinds.kinds.contains_key(*theorem))
        .collect();
    let stale_kinds: Vec<&String> = kinds
        .kinds
        .keys()
        .filter(|theorem| !naming.contains(*theorem))
        .collect();
    if !unclassified.is_empty() || !stale_kinds.is_empty() {
        return Err(format!(
            "{KINDS_PATH} must classify exactly the audited theorems that name translated functions: unclassified {unclassified:?}, not naming one {stale_kinds:?}"
        ));
    }
    let restricted = |accepted: &[&str]| {
        let seeds: BTreeSet<String> = measurement
            .mentions
            .iter()
            .filter(|(_, theorems)| {
                theorems
                    .iter()
                    .any(|theorem| accepted.contains(&kinds.kinds[theorem].as_str()))
            })
            .map(|(name, _)| name.clone())
            .collect();
        closure(&seeds, &measurement.edges)
    };
    let exact_or_verdict = restricted(&["exact", "verdict-exact"]);
    let exact_only = restricted(&["exact"]);
    let all = |_: &RustFunction| true;
    let decision = measurement.metric("decision", 0, &all, None);
    let decision_exact_or_verdict =
        measurement.metric("decision", 0, &all, Some(&exact_or_verdict));
    let decision_exact = measurement.metric("decision", 0, &all, Some(&exact_only));
    let decision_without_macros =
        measurement.metric("decision", 0, &|function| !function.in_macro, None);
    let decision_without_instances = measurement.metric(
        "decision",
        0,
        &all,
        Some(&measurement.reached_without_instances),
    );

    let map = load_check_site_map(&tree.read(CHECK_SITE_MAP_PATH)?)?;
    let codes: BTreeMap<&str, &str> = auths_testkit::check_sites::CHECK_SITES
        .iter()
        .map(|site| (site.site, site.code))
        .collect();
    let mut site_rows = Vec::new();
    let mut covered_sites = 0usize;
    for entry in &map.sites {
        let mut functions = Vec::new();
        let mut covered = true;
        for (role, reference) in std::iter::once(("refusal", &entry.refusal))
            .chain(entry.guard.iter().map(|guard| ("guard", guard)))
            .chain(entry.also.iter().map(|also| ("also", also)))
        {
            let function = resolve_function(&measurement.functions, reference)
                .map_err(|error| format!("check site {}: {error}", entry.site))?;
            let in_closure = measurement
                .status_of(function)
                .is_some_and(|info| info.refined_closure);
            covered &= in_closure;
            functions.push(json!({
                "role": role,
                "file": function.file,
                "function": function.qualified,
                "begin_line": function.begin_line,
                "refined_closure": in_closure,
            }));
        }
        if !covered && entry.stage == "covered" {
            return Err(format!(
                "check site {} is no longer covered; give it a covering stage in {CHECK_SITE_MAP_PATH}",
                entry.site
            ));
        }
        covered_sites += usize::from(covered);
        site_rows.push(json!({
            "site": entry.site,
            "code": codes.get(entry.site.as_str()).copied().unwrap_or(""),
            "covered": covered,
            "stage": if covered { "covered".to_owned() } else { entry.stage.clone() },
            "note": entry.note,
            "functions": functions,
        }));
    }

    let mut outside = Vec::new();
    for item in measurement
        .translated
        .iter()
        .filter(|item| item.kind == "function")
    {
        let function = measurement
            .functions
            .iter()
            .find(|function| function.file == item.file && function.begin_line == item.begin_line);
        let in_closure = measurement.reached.contains(&item.lean_name);
        if !in_closure {
            outside.push(json!({
                "rust_name": item.rust_name,
                "lean_name": item.lean_name,
                "file": item.file,
                "span": [item.begin_line, item.end_line],
                "decision_scope": function.is_some_and(|function| measurement.in_scope(function, "decision")),
            }));
        }
    }

    let mutations = load_mutation_results(root)?;
    let formal_inputs = formal_inputs_sha256(root)?;
    let mutation_summary = mutations.as_ref().map(|results| {
        let campaigns: serde_json::Map<String, Value> = results
            .campaigns
            .iter()
            .map(|(name, campaign)| {
                let mutants = &campaign.mutants;
                let count = |outcome: &str| mutants.iter().filter(|mutant| mutant.outcome == outcome).count();
                let survivors: Vec<Value> = mutants
                    .iter()
                    .filter(|mutant| mutant.outcome == "survived")
                    .map(|mutant| {
                        json!({
                            "id": mutant.id,
                            "definition": mutant.definition,
                            "operator": mutant.operator,
                            "explanation": results.explanations.get(&format!("{name}:{}", mutant.id)),
                        })
                    })
                    .collect();
                let stillborn: Vec<Value> = mutants
                    .iter()
                    .filter(|mutant| mutant.outcome == "stillborn")
                    .map(|mutant| json!({"id": mutant.id, "definition": mutant.definition, "operator": mutant.operator}))
                    .collect();
                let elsewhere = mutants
                    .iter()
                    .filter(|mutant| mutant.caught.as_deref() == Some("elsewhere"))
                    .count();
                (
                    name.clone(),
                    json!({
                        "formal_inputs_sha256": campaign.formal_inputs_sha256,
                        "fresh": campaign.formal_inputs_sha256 == formal_inputs,
                        "mutants": mutants.len(),
                        "killed": count("killed"),
                        "killed_elsewhere": elsewhere,
                        "survived": count("survived"),
                        "stillborn": count("stillborn"),
                        "survivors": survivors,
                        "stillborn_mutants": stillborn,
                    }),
                )
            })
            .collect();
        let fresh = results
            .campaigns
            .values()
            .all(|campaign| campaign.formal_inputs_sha256 == formal_inputs);
        json!({
            "results": MUTATIONS_PATH,
            "current_formal_inputs_sha256": formal_inputs,
            "fresh": fresh,
            "campaigns": Value::Object(campaigns),
        })
    });

    let uncovered_components: Vec<String> = measurement
        .scope
        .components
        .iter()
        .filter(|component| {
            component.crates.is_empty()
                || measurement.functions.iter().any(|function| {
                    component
                        .crates
                        .contains(&measurement.files[&function.file])
                        && measurement.in_scope(function, "verifier-closure")
                        && !measurement
                            .status_of(function)
                            .is_some_and(|info| info.refined_closure)
                })
        })
        .map(|component| component.name.clone())
        .collect();

    let inputs: serde_json::Map<String, Value> = tree
        .reads()
        .borrow()
        .iter()
        .map(|(path, digest)| (path.clone(), Value::from(format!("sha256:{digest}"))))
        .collect();
    let mut inputs_digest = Sha256::new();
    for (path, digest) in &inputs {
        inputs_digest.update(path.as_bytes());
        inputs_digest.update([0]);
        inputs_digest.update(digest.as_str().unwrap_or("").as_bytes());
        inputs_digest.update([0xff]);
    }
    let lean_toolchain = fs::read_to_string(root.join("formal/lean-toolchain"))
        .map_err(|error| format!("could not read formal/lean-toolchain: {error}"))?;
    let toolchain_lock = sha256_file(&root.join("formal/translation-toolchain.lock"))?;
    let scope_digest = hex::encode(Sha256::digest(scope_text.as_bytes()));

    let claim = json!({
        "decision_functions": total(&decision, "functions"),
        "decision_closure_functions": level(&decision, "closure", "functions"),
        "decision_code_lines": total(&decision, "code_lines"),
        "decision_closure_code_lines": level(&decision, "closure", "code_lines"),
        "check_sites": map.sites.len(),
        "covered_check_sites": covered_sites,
        "uncovered_components": uncovered_components,
    });
    let json = json!({
        "schema": "auths-proof-proof-coverage/v1",
        "tool": {"command": "cargo xtask formal coverage", "version": TOOL_VERSION},
        "revision": "the commit that contains this file",
        "reference_reproduction": {
            "commit": PIN,
            "fixture": PIN_FIXTURE,
            "fixture_manifest_sha256": sha256_file(&root.join(PIN_FIXTURE_MANIFEST))?,
            "result": "byte-identical to study 006's proof_coverage.json and proof_coverage_functions.tsv",
        },
        "toolchain": {
            "lean_toolchain": lean_toolchain.trim(),
            "translation_toolchain_lock_sha256": toolchain_lock,
        },
        "scope_definition_sha256": scope_digest,
        "inputs_sha256": hex::encode(inputs_digest.finalize()),
        "inputs": Value::Object(inputs),
        "claim": claim,
        "scope": {
            "verifier_dependency_closure": measurement.verifier_closure,
            "decision_kernel_crates": measurement.scope.decision_kernel_crates,
            "translated_crates": measurement.translated_crates,
            "excluded_roles": measurement.scope.excluded_roles,
            "non_decision_files": measurement.scope.files.iter().filter(|(_, role)| role.as_str() != "decision").map(|(path, role)| (path.clone(), Value::from(role.clone()))).collect::<serde_json::Map<_, _>>(),
        },
        "metrics": measurement.metrics(),
        "sensitivities": {
            "decision_without_macro_rules_functions": decision_without_macros,
            "decision_exact_or_verdict_exact_theorems": decision_exact_or_verdict,
            "decision_exact_theorems": decision_exact,
            "decision_without_trait_instance_records": decision_without_instances,
        },
        "per_crate_decision": measurement.per_crate(),
        "second_parser": {
            "parser": "syn 2 (full syntax tree), independent of the scanner's tokenizer",
            "decision_functions": second.compared,
            "decision_files": second.files,
            "agreements": second.agreements,
            "agreement_share": ratio(second.agreements, second.compared),
            "disagreements": second.disagreements,
            "parser_only_functions": second.parser_only,
        },
        "check_sites": {
            "total": map.sites.len(),
            "covered": covered_sites,
            "share": ratio(covered_sites, map.sites.len()),
            "sites": site_rows,
        },
        "translated_outside_closure": outside,
        "theorem_kinds": {
            "classified": kinds.kinds.iter().map(|(theorem, kind)| (theorem.clone(), Value::from(kind.clone()))).collect::<serde_json::Map<_, _>>(),
        },
        "translation_inventory": {
            "aeneas_local_definitions": measurement.translated.len(),
            "by_kind": measurement.translation_kinds().into_iter().map(|(kind, count)| (kind.to_owned(), Value::from(count))).collect::<serde_json::Map<_, _>>(),
            "refined_direct": measurement.direct.len(),
            "refined_closure": measurement.reached.len(),
            "theorems_naming_translated_functions": naming.len(),
        },
        "mutation_adequacy": mutation_summary.unwrap_or(Value::Null),
    });
    let tsv = product_tsv(&measurement, &second);
    let document = render_document(&json, &measurement);
    Ok(Published {
        json,
        tsv,
        document,
    })
}

fn product_tsv(measurement: &Measurement, second: &SecondParser) -> String {
    let mut output = String::new();
    write_tsv_row(
        &mut output,
        &[
            "file",
            "begin_line",
            "end_line",
            "code_lines",
            "function",
            "crate",
            "role",
            "decision_scope",
            "macro_rules",
            "second_parser_agrees",
            "translated",
            "refined_direct",
            "refined_closure",
            "theorems",
        ]
        .map(str::to_owned),
    );
    for function in measurement.sorted_functions() {
        let info = measurement.status_of(function);
        let decision = measurement.in_scope(function, "decision");
        write_tsv_row(
            &mut output,
            &[
                function.file.clone(),
                function.begin_line.to_string(),
                function.end_line.to_string(),
                function.code_lines.to_string(),
                function.qualified.clone(),
                measurement.files[&function.file].clone(),
                measurement.role(&function.file).to_owned(),
                u8::from(decision).to_string(),
                u8::from(function.in_macro).to_string(),
                if decision {
                    u8::from(
                        second
                            .agreeing
                            .contains(&(function.file.clone(), function.begin_line)),
                    )
                    .to_string()
                } else {
                    String::new()
                },
                u8::from(info.is_some()).to_string(),
                u8::from(info.is_some_and(|info| info.refined_direct)).to_string(),
                u8::from(info.is_some_and(|info| info.refined_closure)).to_string(),
                info.map_or(0, |info| info.theorems.len()).to_string(),
            ],
        );
    }
    output
}

// ---------------------------------------------------------------------------
// The rendered document
// ---------------------------------------------------------------------------

fn grouped(value: usize) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (position, digit) in digits.chars().enumerate() {
        if position > 0 && (digits.len() - position).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

fn count(value: &Value) -> usize {
    usize::try_from(value.as_u64().unwrap_or(0)).unwrap_or(0)
}

fn join_names(names: &[String]) -> String {
    match names {
        [] => "nothing else".to_owned(),
        [single] => single.clone(),
        [init @ .., last] => format!("{}, and {last}", init.join(", ")),
    }
}

fn render_document(json: &Value, measurement: &Measurement) -> String {
    let mut out = String::new();
    let claim = &json["claim"];
    let decision = &json["metrics"]["decision"];
    let (n, m) = (
        count(&claim["decision_closure_functions"]),
        count(&claim["decision_functions"]),
    );
    let (l, t) = (
        count(&claim["decision_closure_code_lines"]),
        count(&claim["decision_code_lines"]),
    );
    let (s, sites) = (
        count(&claim["covered_check_sites"]),
        count(&claim["check_sites"]),
    );
    let components: Vec<String> = claim["uncovered_components"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "<!-- Generated by `cargo xtask formal coverage --update` from `{OUTPUT_JSON}`. Do not edit; `cargo xtask formal` rejects drift. -->"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "# Proof coverage of the decision path");
    let _ = writeln!(out);
    let _ = writeln!(out, "## 1. Claim");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "At the commit that contains this document, {} of {} decision-scope functions ({}) and {} of {} code lines ({}) are translated to Lean and reached from audited theorem statements, and {s} of {sites} kernel check sites map only to such functions. The rest of the decision path, including {}, is tested, not proved.",
        grouped(n),
        grouped(m),
        percent(n, m),
        grouped(l),
        grouped(t),
        percent(l, t),
        join_names(&components)
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- Revision: the commit that contains this document and `{OUTPUT_JSON}`; a release binds it in its assurance evidence."
    );
    let _ = writeln!(
        out,
        "- Measurement inputs: sha256 `{}` over the {} files listed in `{OUTPUT_JSON}`.",
        json["inputs_sha256"].as_str().unwrap_or(""),
        json["inputs"].as_object().map_or(0, serde_json::Map::len)
    );
    let _ = writeln!(
        out,
        "- Tool: `cargo xtask formal coverage`, version {TOOL_VERSION}."
    );
    let _ = writeln!(
        out,
        "- Toolchain pins: `formal/lean-toolchain` = `{}`; `formal/translation-toolchain.lock` sha256 `{}`.",
        json["toolchain"]["lean_toolchain"].as_str().unwrap_or(""),
        json["toolchain"]["translation_toolchain_lock_sha256"]
            .as_str()
            .unwrap_or("")
    );
    let _ = writeln!(
        out,
        "- Role table: `{SCOPE_PATH}`, sha256 `{}`. Figures computed under a different role table are not comparable.",
        json["scope_definition_sha256"].as_str().unwrap_or("")
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## 2. Definitions and file roles");
    let _ = writeln!(out);
    let _ = writeln!(out, "These are study 006's definitions, unchanged.");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- **Function**: a hand-written `fn` item with a body under a crate's `src/`, outside test, fuzzing, and Kani code; one per definition in a `macro_rules!` body. Derive-generated methods have no hand-written body and are counted in neither numerator nor denominator."
    );
    let _ = writeln!(
        out,
        "- **Translated**: the function's file, first line, and last line equal a local function's span in an Aeneas `translation.json` that `formal/qualification/aeneas/qualification.toml` names."
    );
    let _ = writeln!(
        out,
        "- **Refined, direct**: translated, and its Lean name appears in the statement of a theorem in the audited inventory (`formal/Auths/Theorems.lean`, compiled by `Auths.AssuranceAudit`; statements in `{AUDIT_PATH}`)."
    );
    let _ = writeln!(
        out,
        "- **Refined closure**: refined-direct plus every translated function reachable from one in the generated Lean call graph, including through trait-instance records."
    );
    let _ = writeln!(
        out,
        "- **Weights**: function count, and code lines (lines of a function's span holding a non-comment token), each line counted once per scope."
    );
    let _ = writeln!(
        out,
        "- **Scopes**: `verifier-closure` is the workspace dependency closure of `{}`; `verifier-core` removes from it the files whose role is {}; `decision` (the headline) adds the kernels {} under the same exclusion; `translated-crates` is every non-test file of the translated crates; `decision-nontrivial` keeps decision-scope functions of at least {} code lines.",
        measurement.scope.verifier_crate,
        measurement.scope.excluded_roles.join(", "),
        measurement
            .scope
            .decision_kernel_crates
            .iter()
            .map(|crate_path| format!("`{crate_path}`"))
            .collect::<Vec<_>>()
            .join(" and "),
        measurement.scope.nontrivial_code_lines
    );
    let _ = writeln!(
        out,
        "- **Macro-generated identifier accessors** (functions written inside `macro_rules!` bodies) are counted as decision logic in the headline, as study 006 did; section 3 also gives the figure without them."
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Files in scoped crates with a non-decision role (every other scoped file is decision logic):"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "| File | Role |");
    let _ = writeln!(out, "| --- | --- |");
    if let Some(files) = json["scope"]["non_decision_files"].as_object() {
        for (path, role) in files {
            let _ = writeln!(out, "| `{path}` | {} |", role.as_str().unwrap_or(""));
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## 3. Scope table");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Scope | Functions | Translated | Refined directly | Refined closure | Code lines | Translated | Refined directly | Refined closure |"
    );
    let _ = writeln!(
        out,
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
    );
    if let Some(metrics) = json["metrics"].as_object() {
        for (name, metric) in metrics {
            let (functions, lines) = (total(metric, "functions"), total(metric, "code_lines"));
            let cell = |level_name: &str, weight: &str, whole: usize| {
                let value = level(metric, level_name, weight);
                format!("{} ({})", grouped(value), percent(value, whole))
            };
            let _ = writeln!(
                out,
                "| {name} | {} | {} | {} | {} | {} | {} | {} | {} |",
                grouped(functions),
                cell("translated", "functions", functions),
                cell("direct", "functions", functions),
                cell("closure", "functions", functions),
                grouped(lines),
                cell("translated", "code_lines", lines),
                cell("direct", "code_lines", lines),
                cell("closure", "code_lines", lines),
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Decision scope by crate:");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Crate | Functions | Code lines | Translated | In refined closure | Closure code lines |"
    );
    let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: | ---: |");
    if let Some(crates) = json["per_crate_decision"].as_object() {
        for (crate_path, row) in crates {
            if count(&row["decision_functions"]) == 0 {
                continue;
            }
            let in_decision = measurement.verifier_closure.contains(crate_path)
                || measurement
                    .scope
                    .decision_kernel_crates
                    .contains(crate_path);
            if !in_decision {
                continue;
            }
            let _ = writeln!(
                out,
                "| `{crate_path}` | {} | {} | {} | {} | {} |",
                grouped(count(&row["decision_functions"])),
                grouped(count(&row["decision_code_lines"])),
                count(&row["translated"]),
                count(&row["refined_closure"]),
                grouped(count(&row["refined_closure_code_lines"]))
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Per-crate code lines are summed per function, so a function nested in another counts in both; the scope table counts each line once."
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Sensitivities of the decision-scope refined-closure figure:"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "| Reading | Functions | Code lines |");
    let _ = writeln!(out, "| --- | ---: | ---: |");
    let headline = (
        level(decision, "closure", "functions"),
        total(decision, "functions"),
        level(decision, "closure", "code_lines"),
        total(decision, "code_lines"),
    );
    let _ = writeln!(
        out,
        "| Headline | {} of {} ({}) | {} of {} ({}) |",
        grouped(headline.0),
        grouped(headline.1),
        percent(headline.0, headline.1),
        grouped(headline.2),
        grouped(headline.3),
        percent(headline.2, headline.3)
    );
    for (key, label) in [
        (
            "decision_without_macro_rules_functions",
            "Without functions defined in `macro_rules!` bodies",
        ),
        (
            "decision_exact_or_verdict_exact_theorems",
            "Closure of exact and verdict-exact theorems only",
        ),
        ("decision_exact_theorems", "Closure of exact theorems only"),
        (
            "decision_without_trait_instance_records",
            "Closure without trait-instance records",
        ),
    ] {
        let metric = &json["sensitivities"][key];
        let (a, b, c, d) = (
            level(metric, "closure", "functions"),
            total(metric, "functions"),
            level(metric, "closure", "code_lines"),
            total(metric, "code_lines"),
        );
        let _ = writeln!(
            out,
            "| {label} | {} of {} ({}) | {} of {} ({}) |",
            grouped(a),
            grouped(b),
            percent(a, b),
            grouped(c),
            grouped(d),
            percent(c, d)
        );
    }
    let _ = writeln!(out);
    let second = &json["second_parser"];
    let _ = writeln!(
        out,
        "**Second parser.** {} of {} decision-scope function spans ({}) agree with an independent parse by syn over {} files. Disagreements:",
        count(&second["agreements"]),
        count(&second["decision_functions"]),
        percent(
            count(&second["agreements"]),
            count(&second["decision_functions"])
        ),
        count(&second["decision_files"])
    );
    let _ = writeln!(out);
    if let Some(rows) = second["disagreements"].as_array() {
        if rows.is_empty() {
            let _ = writeln!(out, "- none.");
        }
        for row in rows {
            let _ = writeln!(
                out,
                "- `{}` `{}` (lines {}-{}): {}.",
                row["file"].as_str().unwrap_or(""),
                row["function"].as_str().unwrap_or(""),
                row["scanner_span"][0],
                row["scanner_span"][1],
                row["reason"].as_str().unwrap_or("")
            );
        }
    }
    let parser_only = second["parser_only_functions"]
        .as_array()
        .map_or(0, Vec::len);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "syn finds {parser_only} non-test function spans in those files that the scanner does not."
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## 4. Decision-critical coverage");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "`{CHECK_SITE_MAP_PATH}` maps each of the {sites} `CHECK_SITES` entries (`core/testkit/auths-testkit/src/check_sites.rs`) to the function that constructs its refusal, the predicate its guard calls, and further deciding functions, by study 006's innermost-function rule. A site is covered when every one of those functions is in the refined closure. {s} of {sites} are covered ({}).",
        percent(s, sites)
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Site | Code | Deciding functions outside the closure | Covering stage |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    if let Some(rows) = json["check_sites"]["sites"].as_array() {
        for row in rows.iter().filter(|row| row["covered"] != true) {
            let outside: Vec<String> = row["functions"]
                .as_array()
                .map(|functions| {
                    functions
                        .iter()
                        .filter(|function| function["refined_closure"] != true)
                        .map(|function| {
                            format!(
                                "`{}` ({})",
                                function["function"].as_str().unwrap_or(""),
                                function["role"].as_str().unwrap_or("")
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "| `{}` | `{}` | {} | {} |",
                row["site"].as_str().unwrap_or(""),
                row["code"].as_str().unwrap_or(""),
                outside.join(", "),
                row["stage"].as_str().unwrap_or("")
            );
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "## 5. Translated functions outside the refined closure"
    );
    let _ = writeln!(out);
    match json["translated_outside_closure"].as_array() {
        Some(rows) if !rows.is_empty() => {
            for row in rows {
                let _ = writeln!(
                    out,
                    "- `{}` (`{}`, lines {}-{})",
                    row["rust_name"].as_str().unwrap_or(""),
                    row["file"].as_str().unwrap_or(""),
                    row["span"][0],
                    row["span"][1]
                );
            }
        }
        _ => {
            let _ = writeln!(
                out,
                "None: every function Aeneas translates is in the refined closure."
            );
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## 6. Mutation adequacy");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "`cargo xtask formal mutations` runs study 006's three campaigns: S1 applies each case of `formal/refinement-mutations-v1.json`, S2 mutates comparison, Boolean, and result-position operators in the model's `def` bodies, and S3 replaces each translated function's body with `fail .panic`. A mutant is killed when the build of the audited targets fails, and stillborn when its first error lies in the mutated definition itself. The first error (the earliest in the mutated file, else the least location among the failing modules, so that parallel builds record the same one) and its declaration are recorded; an S1 mutant whose build reports no error in its case's named witness is reported as killed elsewhere. Every survivor must be fixed or explained before a release; pull requests are not blocked."
    );
    let _ = writeln!(out);
    let mutation = &json["mutation_adequacy"];
    if mutation.is_null() {
        let _ = writeln!(out, "No campaign results are committed.");
    } else {
        if mutation["fresh"] != true {
            let _ = writeln!(
                out,
                "**Some results predate the current formal sources** (current formal inputs `{}`); re-run the stale campaigns before a release.",
                mutation["current_formal_inputs_sha256"]
                    .as_str()
                    .unwrap_or("")
            );
            let _ = writeln!(out);
        }
        let _ = writeln!(
            out,
            "| Campaign | Mutants | Killed | Of which killed elsewhere | Survived | Stillborn | Current |"
        );
        let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: | ---: | --- |");
        if let Some(campaigns) = mutation["campaigns"].as_object() {
            for (name, row) in campaigns {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} | {} | {} |",
                    name.to_uppercase(),
                    count(&row["mutants"]),
                    count(&row["killed"]),
                    count(&row["killed_elsewhere"]),
                    count(&row["survived"]),
                    count(&row["stillborn"]),
                    if row["fresh"] == true { "yes" } else { "stale" }
                );
            }
            let _ = writeln!(out);
            for (name, row) in campaigns {
                for survivor in row["survivors"].as_array().into_iter().flatten() {
                    let _ = writeln!(
                        out,
                        "- Survivor {} `{}` in `{}` ({}): {}",
                        name.to_uppercase(),
                        survivor["id"].as_str().unwrap_or(""),
                        survivor["definition"].as_str().unwrap_or(""),
                        survivor["operator"].as_str().unwrap_or(""),
                        survivor["explanation"].as_str().unwrap_or("UNEXPLAINED")
                    );
                }
                for stillborn in row["stillborn_mutants"].as_array().into_iter().flatten() {
                    let _ = writeln!(
                        out,
                        "- Stillborn {} `{}` in `{}` ({}): the mutated definition does not elaborate.",
                        name.to_uppercase(),
                        stillborn["id"].as_str().unwrap_or(""),
                        stillborn["definition"].as_str().unwrap_or(""),
                        stillborn["operator"].as_str().unwrap_or("")
                    );
                }
            }
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## 7. Theorem kinds");
    let _ = writeln!(out);
    let classified = json["theorem_kinds"]["classified"].as_object();
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for kind in classified.into_iter().flat_map(|map| map.values()) {
        *tally
            .entry(kind.as_str().unwrap_or("").to_owned())
            .or_default() += 1;
    }
    let _ = writeln!(
        out,
        "Every audited theorem whose statement names a translated function carries a kind in `{KINDS_PATH}`: exact (for every input meeting its premises the function returns exactly its specification's value), verdict-exact (the statement fixes the component of the result that decides authorization), partial (a property that does not fix the verdict, or a subclass of inputs), or case (specific inputs). Counts: {}.",
        KINDS
            .iter()
            .map(|kind| format!("{} {kind}", tally.get(*kind).copied().unwrap_or(0)))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(out);
    let metric = &json["sensitivities"]["decision_exact_or_verdict_exact_theorems"];
    let _ = writeln!(
        out,
        "Recomputed over the closure of exact and verdict-exact theorems only, the decision-scope figure is {} of {} functions ({}) and {} of {} code lines ({}).",
        grouped(level(metric, "closure", "functions")),
        grouped(total(metric, "functions")),
        percent(
            level(metric, "closure", "functions"),
            total(metric, "functions")
        ),
        grouped(level(metric, "closure", "code_lines")),
        grouped(total(metric, "code_lines")),
        percent(
            level(metric, "closure", "code_lines"),
            total(metric, "code_lines")
        )
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "The 33 theorems study 006 classified keep the kind both of its raters gave; theorems added since were classified by the agent that added them and await a second rater."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "| Theorem | Kind |");
    let _ = writeln!(out, "| --- | --- |");
    for (theorem, kind) in classified.into_iter().flatten() {
        let _ = writeln!(out, "| `{theorem}` | {} |", kind.as_str().unwrap_or(""));
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## 8. Trusted base");
    let _ = writeln!(out);
    for line in [
        "Lean's kernel and the three allowed axioms (`propext`, `Classical.choice`, `Quot.sound`); the audit rejects any theorem that depends on another axiom or on `sorryAx`.",
        "Mathlib and the Aeneas Lean library at the revisions `formal/lake-manifest.json` pins.",
        "The Charon and Aeneas translation of Rust to Lean, which is not itself verified; the theorems are about the translated Lean, not the compiled Rust.",
        "Each theorem's premises: representation validity (for example, that compared text fits the translated byte bound) and, for the extension handlers, `LawsRefine`.",
        "The generated Lean algebra and its Rust twin, linked by the shared generator and the exported vectors, not by a theorem.",
        "The audit module `Auths.AssuranceAudit` and the xtask that checks its output against `formal/assurance-manifest-v1.toml`.",
        "Everything outside the proof surface: canonical decoding, cryptography and signature suites, principal adapters, clocks, storage, networking, the staged verifier control flow, and the compiler.",
    ] {
        let _ = writeln!(out, "- {line}");
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## 9. What these figures do not mean");
    let _ = writeln!(out);
    for line in [
        "They do not mean the verifier is formally verified. Most of the decision path, including the staged control flow that decides every refusal outside the authority kernel, is outside the proofs.",
        "They do not mean Rust is proved. The theorems relate the Aeneas-translated Lean to Lean models; the translation is unverified, and the compiled Rust is not in the proof.",
        "Coverage of functions is not coverage of behaviour. A function in the refined closure is reached from some audited statement; section 7 gives how strong those statements are, and section 6 how much of each definition they constrain.",
        "Any text citing this document keeps the prohibitions of AP-SPEC-011 §13 on claims about the Rust–Lean link.",
    ] {
        let _ = writeln!(out, "- {line}");
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## 10. Reproduce");
    let _ = writeln!(out);
    let _ = writeln!(out, "```text");
    let _ = writeln!(
        out,
        "cargo xtask formal coverage            # check the committed outputs and reproduce the study at {}",
        &PIN[..8]
    );
    let _ = writeln!(
        out,
        "cargo xtask formal coverage --update   # rewrite {OUTPUT_JSON}, {OUTPUT_TSV}, and this document"
    );
    let _ = writeln!(
        out,
        "cargo xtask formal                     # Lean build, audit, and the same drift check"
    );
    let _ = writeln!(
        out,
        "cargo xtask formal mutations all       # the three mutation campaigns (hours)"
    );
    let _ = writeln!(out, "```");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "The tool is a port of study 006's reference scanner. Before any output is used it recomputes the study's figures from the vendored inputs of auths-proof commit `{}` (`{PIN_FIXTURE}`, sha256 manifest `{PIN_FIXTURE_MANIFEST}`) and requires byte-identical `proof_coverage.json` and `proof_coverage_functions.tsv`. Study 006's figures at that commit (final results; Stage 2 paper in draft): 75 of 933 decision-scope functions (8.0%) and 885 of 10,083 code lines (8.8%) in the refined closure; 93 translated, 28 refined directly; 74 of 933 functions and 882 of 10,083 code lines over exact and verdict-exact theorems only. For an independent check, run study 006's scanner (`studies/006-formal-comparison-prior-art/analysis/proof_coverage.py` in auths-research), which reads git objects only, pointed at this commit.",
        &PIN[..8]
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## Next stages");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Stage | Scope of work | Target | Status |");
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for row in [
        "| 0. Measure | This tool, a baseline, the theorems that kill the S2 survivor, and this document | The tool reproduces the pin exactly; the S2 survivor is killed; the baseline is published | Done |",
        "| 1. Refine what is translated | Refinement theorems for every translated but unrefined function | No translated function outside the refined closure; S3 kills every crash mutant | Done (section 5) |",
        "| 2. Decision-critical pure predicates | The registry handlers, the composition evaluator with a Lean plan evaluator, the composition floors, the status decision, and the resource, budget, and shared-action checks, extracted as pure functions under AP-SPEC-061's rules | Every deciding check study 006 found at F0 that is a pure predicate reaches F3; AP-SPEC-001 §6.3's plan theorems are proved; every `composition.*` and `branch.*` check site whose guard is a pure predicate maps to closure functions | Next (P2, 2 to 4 months; overlaps AP-SPEC-061) |",
        "| 3. Control flow | AP-SPEC-061 phase 3: the staged verifier as extractable per-stage slices | Every check site of the proved configuration maps to closure functions; every refusal site is in the closure; every study class's minimum F-level is at least F2 | Next (P2, with stage 2) |",
        "| 4. Publish | This document, regenerated for every release | A published document per release, bound to the release's revision | Each release |",
    ] {
        let _ = writeln!(out, "{row}");
    }
    out
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Recomputes study 006's outputs from the vendored inputs of its pinned
/// commit and requires them byte for byte, with the second parser's and the
/// restricted closures' figures.
pub(crate) fn reproduce_pin(root: &Path) -> Result<Value, String> {
    let (tree, reference) =
        ArchiveTree::open(&root.join(PIN_FIXTURE), &root.join(PIN_FIXTURE_MANIFEST))?;
    let scope = ScopeDefinition::parse(&tree.read("coverage-scope.toml")?)?;
    let audit = tree.read("lean-assurance-audit.json")?;
    let measurement = measure(&tree, scope, &audit)?;
    let reference_text = |name: &str| {
        reference
            .get(name)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .ok_or_else(|| format!("the pin fixture holds no {name}"))
    };
    if format!("{}\n", python_json(&measurement.study_json(), 2))
        != reference_text("reference/proof_coverage.json")?
    {
        return Err(format!(
            "the coverage tool does not reproduce study 006's proof_coverage.json at {PIN}"
        ));
    }
    if measurement.study_tsv() != reference_text("reference/proof_coverage_functions.tsv")? {
        return Err(format!(
            "the coverage tool does not reproduce study 006's function inventory at {PIN}"
        ));
    }
    let second = second_parser(&measurement, &tree)?;
    let study_second: Value =
        serde_json::from_str(&reference_text("reference/coverage_second_parser.json")?)
            .map_err(|error| error.to_string())?;
    let expected: BTreeSet<(String, String)> = study_second["disagreements"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            (
                row["file"].as_str().unwrap_or("").to_owned(),
                row["function"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    let found: BTreeSet<(String, String)> = second
        .disagreements
        .iter()
        .map(|row| {
            (
                row["file"].as_str().unwrap_or("").to_owned(),
                row["function"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    if second.agreements != count(&study_second["agreements"]) || found != expected {
        return Err(format!(
            "the second parser does not reproduce study 006's agreement at {PIN}: {} of {}, disagreements {found:?}",
            second.agreements, second.compared
        ));
    }
    let kinds = TheoremKinds::parse(&tree.read("theorem-kinds.toml")?)?;
    let seeds: BTreeSet<String> = measurement
        .mentions
        .iter()
        .filter(|(_, theorems)| {
            theorems.iter().any(|theorem| {
                matches!(
                    kinds.kinds.get(theorem).map(String::as_str),
                    Some("exact" | "verdict-exact")
                )
            })
        })
        .map(|(name, _)| name.clone())
        .collect();
    let restricted = closure(&seeds, &measurement.edges);
    let exact = measurement.metric("decision", 0, &|_| true, Some(&restricted));
    let study: Value = serde_json::from_str(&reference_text("reference/coverage.json")?)
        .map_err(|error| error.to_string())?;
    let study_exact = &study["R4_theorem_kinds"]["numerator_exact_or_verdict_exact"]["decision"];
    if level(&exact, "closure", "functions") != count(&study_exact["refined_functions"])
        || level(&exact, "closure", "code_lines") != count(&study_exact["refined_code_lines"])
    {
        return Err(
            "the exact and verdict-exact closure does not reproduce study 006's R4 figure"
                .to_owned(),
        );
    }
    let without = measurement
        .translated
        .iter()
        .filter(|item| {
            item.kind == "function"
                && measurement
                    .reached_without_instances
                    .contains(&item.lean_name)
        })
        .count();
    if without != count(&study["instance_only_reach"]["closure_functions_without_instance_records"])
    {
        return Err(
            "the closure without trait-instance records does not reproduce study 006's figure"
                .to_owned(),
        );
    }
    Ok(json!({
        "decision_functions": total(&measurement.metric("decision", 0, &|_| true, None), "functions"),
        "second_parser_agreements": second.agreements,
        "exact_or_verdict_exact_functions": level(&exact, "closure", "functions"),
        "closure_without_instance_records": without,
    }))
}

fn synchronize_output(
    path: &Path,
    expected: &str,
    update: bool,
    label: &str,
) -> Result<(), String> {
    if update {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
        return fs::write(path, expected)
            .map_err(|error| format!("could not write {}: {error}", path.display()));
    }
    let actual = fs::read_to_string(path).unwrap_or_default();
    if actual != expected {
        return Err(format!(
            "{label} ({}) drifted from a fresh measurement; run `cargo xtask formal coverage --update`",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn render_json(value: &Value) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map(|text| format!("{text}\n"))
        .map_err(|error| error.to_string())
}

/// Checks (or rewrites) the committed coverage outputs against a fresh run.
pub(crate) fn synchronize_coverage(root: &Path, update: bool) -> Result<Published, String> {
    reproduce_pin(root)?;
    let published = publish(root)?;
    synchronize_output(
        &root.join(OUTPUT_JSON),
        &render_json(&published.json)?,
        update,
        "proof coverage measurement",
    )?;
    synchronize_output(
        &root.join(OUTPUT_TSV),
        &published.tsv,
        update,
        "proof coverage function inventory",
    )?;
    if let Some(parent) = root.join(DOCUMENT).parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    synchronize_output(
        &root.join(DOCUMENT),
        &published.document,
        update,
        "proof coverage document",
    )?;
    synchronize_readme(root, &published.json, update)?;
    Ok(published)
}

const README: &str = "README.md";
const README_BEGIN: &str = "<!-- proof-coverage:begin -->";
const README_END: &str = "<!-- proof-coverage:end -->";

/// The README's coverage sentence, from the same figures as the document.
fn readme_sentence(json: &Value) -> String {
    let claim = &json["claim"];
    let (n, m) = (
        count(&claim["decision_closure_functions"]),
        count(&claim["decision_functions"]),
    );
    let (l, t) = (
        count(&claim["decision_closure_code_lines"]),
        count(&claim["decision_code_lines"]),
    );
    let (s, sites) = (
        count(&claim["covered_check_sites"]),
        count(&claim["check_sites"]),
    );
    let components: Vec<String> = claim["uncovered_components"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let sentence = format!(
        "{} of {} decision-scope functions ({}) and {} of {} code lines ({}) are translated to Lean and reached from audited theorem statements, and {s} of {sites} kernel check sites map only to such functions. The rest of the decision path, including {}, is tested, not proved. For K-of-N approval the proofs cover the threshold count function and the two-input helper, not the plan evaluator or the distinct-actor floor. Figures, method, and what they do not mean: [`{DOCUMENT}`]({DOCUMENT}).",
        grouped(n),
        grouped(m),
        percent(n, m),
        grouped(l),
        grouped(t),
        percent(l, t),
        join_names(&components)
    );
    let mut lines = vec![String::new()];
    for word in sentence.split(' ') {
        let current = lines.last().map_or(0, String::len);
        if current > 0 && current + 1 + word.len() > 78 {
            lines.push(String::new());
        }
        if let Some(line) = lines.last_mut() {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    let body: Vec<String> = lines.into_iter().map(|line| format!("  {line}")).collect();
    format!("\n{}\n  ", body.join("\n"))
}

fn synchronize_readme(root: &Path, json: &Value, update: bool) -> Result<(), String> {
    let path = root.join(README);
    let text =
        fs::read_to_string(&path).map_err(|error| format!("could not read {README}: {error}"))?;
    let (Some(begin), Some(end)) = (text.find(README_BEGIN), text.find(README_END)) else {
        return Err(format!("{README} has no proof-coverage markers"));
    };
    let expected = format!(
        "{}{README_BEGIN}{}{}",
        &text[..begin],
        readme_sentence(json),
        &text[end..]
    );
    if expected == text {
        return Ok(());
    }
    if update {
        return fs::write(&path, expected)
            .map_err(|error| format!("could not write {README}: {error}"));
    }
    Err(format!(
        "{README}'s proof-coverage sentence drifted from a fresh measurement; run `cargo xtask formal coverage --update`"
    ))
}

pub(crate) fn formal_coverage(update: bool) -> Result<(), String> {
    let root = root();
    let published = synchronize_coverage(&root, update)?;
    let claim = &published.json["claim"];
    println!(
        "Study 006 reproduction:     PASS (byte-identical at {})",
        &PIN[..8]
    );
    println!(
        "Proof coverage:             {} of {} decision-scope functions, {} of {} code lines, {} of {} check sites",
        claim["decision_closure_functions"],
        claim["decision_functions"],
        claim["decision_closure_code_lines"],
        claim["decision_code_lines"],
        claim["covered_check_sites"],
        claim["check_sites"]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin_measurement() -> (Measurement, BTreeMap<String, Vec<u8>>) {
        let (tree, reference) = ArchiveTree::open(
            &root().join(PIN_FIXTURE),
            &root().join(PIN_FIXTURE_MANIFEST),
        )
        .expect("pin fixture");
        let scope = ScopeDefinition::parse(&tree.read("coverage-scope.toml").expect("scope"))
            .expect("valid scope");
        let audit = tree.read("lean-assurance-audit.json").expect("audit");
        (
            measure(&tree, scope, &audit).expect("measurement"),
            reference,
        )
    }

    #[test]
    fn reproduces_the_study_at_its_pinned_commit() {
        let (measurement, reference) = pin_measurement();
        let json = format!("{}\n", python_json(&measurement.study_json(), 2));
        let expected = String::from_utf8(reference["reference/proof_coverage.json"].clone())
            .expect("reference JSON");
        assert_eq!(json, expected);
        let tsv = measurement.study_tsv();
        let expected =
            String::from_utf8(reference["reference/proof_coverage_functions.tsv"].clone())
                .expect("reference TSV");
        assert_eq!(tsv, expected);
    }

    #[test]
    fn second_parser_and_restricted_closures_reproduce_the_study() {
        let figures = reproduce_pin(&root()).expect("pin reproduction");
        assert_eq!(figures["decision_functions"], 933);
        assert_eq!(figures["second_parser_agreements"], 916);
        assert_eq!(figures["exact_or_verdict_exact_functions"], 74);
        assert_eq!(figures["closure_without_instance_records"], 73);
    }

    #[test]
    fn the_same_tree_gives_the_same_bytes() {
        let first = publish(&root()).expect("first measurement");
        let second = publish(&root()).expect("second measurement");
        assert_eq!(
            render_json(&first.json).expect("json"),
            render_json(&second.json).expect("json")
        );
        assert_eq!(first.tsv, second.tsv);
        assert_eq!(first.document, second.document);
    }

    #[test]
    fn the_check_site_map_must_name_every_site_and_real_functions() {
        let text = fs::read_to_string(root().join(CHECK_SITE_MAP_PATH)).expect("map");
        load_check_site_map(&text).expect("committed map is complete");
        let first_site = auths_testkit::check_sites::CHECK_SITES[0].site;
        let without_first = text.replacen(
            &format!("site = \"{first_site}\""),
            "site = \"decode.unknown\"",
            1,
        );
        let error = load_check_site_map(&without_first).expect_err("a missing site fails");
        assert!(error.contains(first_site), "{error}");
        let functions = vec![RustFunction {
            file: "core/crates/auths-verifier/src/lib.rs".to_owned(),
            qualified: "verify_branch".to_owned(),
            begin_line: 1,
            end_line: 2,
            code_lines: 2,
            in_macro: false,
        }];
        let absent = FunctionRef {
            file: "core/crates/auths-verifier/src/lib.rs".to_owned(),
            function: "no_such_function".to_owned(),
            begin_line: None,
        };
        assert!(resolve_function(&functions, &absent).is_err());
    }
}
