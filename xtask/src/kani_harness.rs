//! Static check that every Kani harness exercises its own crate.
//!
//! A harness proves something about shipping code only if it calls shipping
//! code. [`lint_harness_calls`] rejects a harness whose body, together with
//! the harness-local helpers it calls, never calls a function its crate
//! defines outside test and Kani builds. Only calls that source text resolves
//! count: a bare call of a module-level function, or a path call whose first
//! segment is `crate`, `super`, `self`, `Self` or a type, trait or module the
//! crate defines. Method-call syntax does not count, because resolving a
//! receiver's type needs the compiler; a harness that exercises a method names
//! it by path, as in `Type::method(value)`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    ops::Range,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Ident(String),
    Punct(char),
    Literal,
    Lifetime,
}

/// A lexed source file: its tokens without comments, each token's line, and
/// the closing index of every `(`, `[` and `{`.
struct Lexed {
    tokens: Vec<Token>,
    lines: Vec<usize>,
    closing: Vec<Option<usize>>,
}

fn lex(source: &str) -> Result<Lexed, String> {
    let characters: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut lines = Vec::new();
    let mut line = 1;
    let mut index = 0;
    while let Some(&character) = characters.get(index) {
        let start_line = line;
        if character == '\n' {
            line += 1;
            index += 1;
            continue;
        }
        if character.is_whitespace() {
            index += 1;
            continue;
        }
        if character == '/' && characters.get(index + 1) == Some(&'/') {
            while characters.get(index).is_some_and(|&next| next != '\n') {
                index += 1;
            }
            continue;
        }
        if character == '/' && characters.get(index + 1) == Some(&'*') {
            index = skip_block_comment(&characters, index, &mut line)?;
            continue;
        }
        let token = if character.is_alphabetic() || character == '_' {
            let start = index;
            while characters
                .get(index)
                .is_some_and(|&next| next.is_alphanumeric() || next == '_')
            {
                index += 1;
            }
            let word: String = characters[start..index].iter().collect();
            match (word.as_str(), characters.get(index)) {
                ("r" | "br" | "cr", Some('"' | '#')) => {
                    let (end, token) = raw_literal_or_identifier(&characters, index, &mut line)?;
                    index = end;
                    token
                }
                ("b" | "c", Some('"')) | ("b", Some('\'')) => {
                    index = skip_quoted(&characters, index, &mut line)?;
                    Token::Literal
                }
                _ => Token::Ident(word),
            }
        } else if character.is_ascii_digit() {
            while let Some(&next) = characters.get(index) {
                let fraction =
                    next == '.' && characters.get(index + 1).is_some_and(char::is_ascii_digit);
                if next.is_alphanumeric() || next == '_' || fraction {
                    index += 1;
                } else {
                    break;
                }
            }
            Token::Literal
        } else if character == '"' {
            index = skip_quoted(&characters, index, &mut line)?;
            Token::Literal
        } else if character == '\'' {
            if characters.get(index + 1) == Some(&'\\') {
                index = skip_quoted(&characters, index, &mut line)?;
                Token::Literal
            } else if characters.get(index + 2) == Some(&'\'') {
                index += 3;
                Token::Literal
            } else {
                index += 1;
                while characters
                    .get(index)
                    .is_some_and(|&next| next.is_alphanumeric() || next == '_')
                {
                    index += 1;
                }
                Token::Lifetime
            }
        } else {
            index += 1;
            Token::Punct(character)
        };
        tokens.push(token);
        lines.push(start_line);
    }
    let closing = match_delimiters(&tokens, &lines)?;
    Ok(Lexed {
        tokens,
        lines,
        closing,
    })
}

/// From `/*` at `start`, returns the index after the matching `*/`; block
/// comments nest.
fn skip_block_comment(
    characters: &[char],
    start: usize,
    line: &mut usize,
) -> Result<usize, String> {
    let mut depth = 0_usize;
    let mut index = start;
    loop {
        match (characters.get(index), characters.get(index + 1)) {
            (Some('/'), Some('*')) => {
                depth += 1;
                index += 2;
            }
            (Some('*'), Some('/')) => {
                depth -= 1;
                index += 2;
                if depth == 0 {
                    return Ok(index);
                }
            }
            (Some('\n'), _) => {
                *line += 1;
                index += 1;
            }
            (Some(_), _) => index += 1,
            (None, _) => return Err(format!("unterminated block comment at line {line}")),
        }
    }
}

/// From the opening quote at `start`, returns the index after the closing
/// quote of the same kind.
fn skip_quoted(characters: &[char], start: usize, line: &mut usize) -> Result<usize, String> {
    let quote = characters[start];
    let mut index = start + 1;
    while let Some(&character) = characters.get(index) {
        match character {
            '\\' => {
                if characters.get(index + 1) == Some(&'\n') {
                    *line += 1;
                }
                index += 2;
            }
            '\n' => {
                *line += 1;
                index += 1;
            }
            _ if character == quote => return Ok(index + 1),
            _ => index += 1,
        }
    }
    Err(format!("unterminated literal at line {line}"))
}

/// Handles what follows an `r`, `br` or `cr` prefix at `start`: a raw string
/// such as `r#"…"#`, or a raw identifier such as `r#type`.
fn raw_literal_or_identifier(
    characters: &[char],
    start: usize,
    line: &mut usize,
) -> Result<(usize, Token), String> {
    let mut index = start;
    let mut hashes = 0_usize;
    while characters.get(index) == Some(&'#') {
        hashes += 1;
        index += 1;
    }
    if characters.get(index) != Some(&'"') {
        let identifier_start = index;
        while characters
            .get(index)
            .is_some_and(|&next| next.is_alphanumeric() || next == '_')
        {
            index += 1;
        }
        return Ok((
            index,
            Token::Ident(characters[identifier_start..index].iter().collect()),
        ));
    }
    index += 1;
    loop {
        match characters.get(index) {
            None => return Err(format!("unterminated raw string at line {line}")),
            Some('\n') => {
                *line += 1;
                index += 1;
            }
            Some('"')
                if (1..=hashes).all(|offset| characters.get(index + offset) == Some(&'#')) =>
            {
                return Ok((index + 1 + hashes, Token::Literal));
            }
            Some(_) => index += 1,
        }
    }
}

fn match_delimiters(tokens: &[Token], lines: &[usize]) -> Result<Vec<Option<usize>>, String> {
    let mut closing = vec![None; tokens.len()];
    let mut open: Vec<(usize, char)> = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Punct(delimiter @ ('(' | '[' | '{')) => open.push((index, *delimiter)),
            Token::Punct(delimiter @ (')' | ']' | '}')) => {
                let expected = match delimiter {
                    ')' => '(',
                    ']' => '[',
                    _ => '{',
                };
                match open.pop() {
                    Some((opening, found)) if found == expected => closing[opening] = Some(index),
                    _ => return Err(format!("unbalanced `{delimiter}` at line {}", lines[index])),
                }
            }
            _ => {}
        }
    }
    match open.pop() {
        Some((index, delimiter)) => Err(format!("unclosed `{delimiter}` at line {}", lines[index])),
        None => Ok(closing),
    }
}

/// One `#[kani::proof]` function.
struct HarnessSite {
    name: String,
    line: usize,
    /// Inline module path, joined with `::`, that declares the harness.
    module: String,
    body: Range<usize>,
}

/// Items one file contributes to its crate.
#[derive(Default)]
struct FileItems {
    free_functions: BTreeSet<String>,
    associated_functions: BTreeSet<String>,
    namespaces: BTreeSet<String>,
    harnesses: Vec<HarnessSite>,
    /// Functions that exist only in test or Kani builds, by inline module.
    helpers: BTreeMap<String, BTreeMap<String, Range<usize>>>,
    /// File modules declared under a test or Kani configuration, as inline
    /// module paths ending in the declared name.
    excluded_modules: Vec<Vec<String>>,
}

#[derive(Clone)]
struct Scope {
    excluded: bool,
    associated: bool,
    module: Vec<String>,
}

struct Scanner<'a> {
    lexed: &'a Lexed,
    items: FileItems,
}

impl Scanner<'_> {
    fn token(&self, index: usize) -> Option<&Token> {
        self.lexed.tokens.get(index)
    }

    fn ident(&self, index: usize) -> Option<&str> {
        match self.token(index) {
            Some(Token::Ident(name)) => Some(name),
            _ => None,
        }
    }

    fn punct(&self, index: usize, expected: char) -> bool {
        self.token(index) == Some(&Token::Punct(expected))
    }

    fn line(&self, index: usize) -> usize {
        self.lexed.lines.get(index).copied().unwrap_or(0)
    }

    fn closing(&self, open: usize) -> Result<usize, String> {
        self.lexed
            .closing
            .get(open)
            .copied()
            .flatten()
            .ok_or_else(|| format!("unmatched delimiter at line {}", self.line(open)))
    }

    fn attribute(&self, range: &Range<usize>) -> &[Token] {
        &self.lexed.tokens[range.clone()]
    }

    /// `#[cfg(…)]` whose predicate names `test` or `kani` and negates nothing.
    fn cfg_excludes(&self, range: &Range<usize>) -> bool {
        let tokens = self.attribute(range);
        let named = |wanted: &[&str]| {
            tokens
                .iter()
                .any(|token| matches!(token, Token::Ident(name) if wanted.contains(&name.as_str())))
        };
        matches!(tokens.first(), Some(Token::Ident(name)) if name == "cfg")
            && named(&["test", "kani"])
            && !named(&["not"])
    }

    /// `#[test]`, or a path attribute ending in `test` such as `#[tokio::test]`.
    fn is_test_attribute(&self, range: &Range<usize>) -> bool {
        let tokens = self.attribute(range);
        let path = &tokens[..tokens
            .iter()
            .position(|token| token == &Token::Punct('('))
            .unwrap_or(tokens.len())];
        matches!(path.last(), Some(Token::Ident(name)) if name == "test")
            && path
                .iter()
                .all(|token| matches!(token, Token::Ident(_) | Token::Punct(':')))
    }

    /// `#[kani::proof]`, the attribute the harness inventory counts.
    fn is_kani_proof(&self, range: &Range<usize>) -> bool {
        matches!(
            self.attribute(range),
            [Token::Ident(tool), Token::Punct(':'), Token::Punct(':'), Token::Ident(name)]
                if tool == "kani" && name == "proof"
        )
    }

    fn scan_items(&mut self, start: usize, end: usize, scope: &Scope) -> Result<(), String> {
        let mut scope = scope.clone();
        let mut attributes: Vec<Range<usize>> = Vec::new();
        let mut index = start;
        while index < end {
            if self.punct(index, '#') {
                let inner = self.punct(index + 1, '!');
                let open = index + 1 + usize::from(inner);
                if !self.punct(open, '[') {
                    index += 1;
                    continue;
                }
                let close = self.closing(open)?;
                let range = open + 1..close;
                if !inner {
                    attributes.push(range);
                } else if self.cfg_excludes(&range) {
                    scope.excluded = true;
                }
                index = close + 1;
                continue;
            }
            let next = self.scan_item(index, &scope, &attributes)?;
            index = next.max(index + 1);
            attributes.clear();
        }
        Ok(())
    }

    fn scan_item(
        &mut self,
        start: usize,
        scope: &Scope,
        attributes: &[Range<usize>],
    ) -> Result<usize, String> {
        let mut index = start;
        loop {
            match self.ident(index) {
                Some("pub") => {
                    index += 1;
                    if self.punct(index, '(') {
                        index = self.closing(index)? + 1;
                    }
                }
                Some("unsafe" | "async" | "default") => index += 1,
                Some("extern") => {
                    index += 1;
                    if self.token(index) == Some(&Token::Literal) {
                        index += 1;
                    }
                }
                Some("const")
                    if matches!(
                        self.ident(index + 1),
                        Some("fn" | "unsafe" | "async" | "extern")
                    ) =>
                {
                    index += 1;
                }
                _ => break,
            }
        }
        let excluded = scope.excluded
            || attributes
                .iter()
                .any(|range| self.cfg_excludes(range) || self.is_test_attribute(range));
        let keyword = self.ident(index).map(str::to_owned);
        match keyword.as_deref() {
            Some("fn") => self.scan_function(index, scope, excluded, attributes),
            Some("mod") => self.scan_module(index, scope, excluded, attributes),
            Some(keyword @ ("impl" | "trait")) => {
                if keyword == "trait"
                    && !excluded
                    && let Some(name) = self.ident(index + 1).map(str::to_owned)
                {
                    self.items.namespaces.insert(name);
                }
                let mut cursor = index + 1;
                loop {
                    match self.token(cursor) {
                        None => {
                            return Err(format!(
                                "{keyword} at line {} has no body",
                                self.line(index)
                            ));
                        }
                        Some(Token::Punct('(' | '[')) => cursor = self.closing(cursor)? + 1,
                        Some(Token::Punct('{')) => break,
                        Some(Token::Punct(';')) => return Ok(cursor + 1),
                        Some(_) => cursor += 1,
                    }
                }
                let close = self.closing(cursor)?;
                self.scan_items(
                    cursor + 1,
                    close,
                    &Scope {
                        excluded,
                        associated: true,
                        module: scope.module.clone(),
                    },
                )?;
                Ok(close + 1)
            }
            Some(kind @ ("struct" | "enum" | "union" | "type")) => {
                if !excluded && let Some(name) = self.ident(index + 1).map(str::to_owned) {
                    self.items.namespaces.insert(name);
                }
                self.skip_item(index, kind != "type")
            }
            _ => {
                let brace_terminated = self.ident(index) == Some("macro_rules")
                    || self.punct(index + 1, '!')
                    || self.punct(index, '{');
                self.skip_item(index, brace_terminated)
            }
        }
    }

    fn scan_function(
        &mut self,
        keyword: usize,
        scope: &Scope,
        excluded: bool,
        attributes: &[Range<usize>],
    ) -> Result<usize, String> {
        let name = self
            .ident(keyword + 1)
            .ok_or_else(|| format!("fn without a name at line {}", self.line(keyword)))?
            .to_owned();
        let mut index = keyword + 2;
        let body = loop {
            match self.token(index) {
                None => return Err(format!("fn {name} has neither a body nor `;`")),
                Some(Token::Punct('(' | '[')) => index = self.closing(index)? + 1,
                Some(Token::Punct('{')) => break Some(index),
                Some(Token::Punct(';')) => break None,
                Some(_) => index += 1,
            }
        };
        let Some(open) = body else {
            if !excluded {
                self.insert_production(name, scope);
            }
            return Ok(index + 1);
        };
        let close = self.closing(open)?;
        let module = scope.module.join("::");
        if attributes.iter().any(|range| self.is_kani_proof(range)) {
            self.items.harnesses.push(HarnessSite {
                name,
                line: self.line(keyword),
                module,
                body: open + 1..close,
            });
        } else if excluded {
            self.items
                .helpers
                .entry(module)
                .or_default()
                .insert(name, open + 1..close);
        } else {
            self.insert_production(name, scope);
        }
        Ok(close + 1)
    }

    fn insert_production(&mut self, name: String, scope: &Scope) {
        if scope.associated {
            self.items.associated_functions.insert(name);
        } else {
            self.items.free_functions.insert(name);
        }
    }

    fn scan_module(
        &mut self,
        keyword: usize,
        scope: &Scope,
        excluded: bool,
        attributes: &[Range<usize>],
    ) -> Result<usize, String> {
        let name = self
            .ident(keyword + 1)
            .ok_or_else(|| format!("mod without a name at line {}", self.line(keyword)))?
            .to_owned();
        let mut module = scope.module.clone();
        module.push(name.clone());
        if self.punct(keyword + 2, ';') {
            if excluded {
                if attributes.iter().any(|range| {
                    matches!(self.attribute(range).first(), Some(Token::Ident(first)) if first == "path")
                }) {
                    return Err(format!(
                        "test or Kani module {name} at line {} uses #[path], which this lint cannot resolve",
                        self.line(keyword)
                    ));
                }
                self.items.excluded_modules.push(module);
            } else {
                self.items.namespaces.insert(name);
            }
            return Ok(keyword + 3);
        }
        if !self.punct(keyword + 2, '{') {
            return Err(format!(
                "malformed mod {name} at line {}",
                self.line(keyword)
            ));
        }
        let close = self.closing(keyword + 2)?;
        if !excluded {
            self.items.namespaces.insert(name);
        }
        self.scan_items(
            keyword + 3,
            close,
            &Scope {
                excluded,
                associated: false,
                module,
            },
        )?;
        Ok(close + 1)
    }

    /// Skips an item this lint does not model; `brace_terminated` items end at
    /// their first top-level brace group.
    fn skip_item(&self, start: usize, brace_terminated: bool) -> Result<usize, String> {
        let mut index = start;
        while let Some(token) = self.token(index) {
            match token {
                Token::Punct(';') => return Ok(index + 1),
                Token::Punct('}') => return Ok(index),
                Token::Punct('(' | '[') => index = self.closing(index)? + 1,
                Token::Punct('{') => {
                    index = self.closing(index)? + 1;
                    if brace_terminated {
                        return Ok(index + usize::from(self.punct(index, ';')));
                    }
                }
                _ => index += 1,
            }
        }
        Ok(index)
    }
}

fn scan_file(lexed: &Lexed, excluded: bool) -> Result<FileItems, String> {
    let mut scanner = Scanner {
        lexed,
        items: FileItems::default(),
    };
    scanner.scan_items(
        0,
        lexed.tokens.len(),
        &Scope {
            excluded,
            associated: false,
            module: Vec::new(),
        },
    )?;
    Ok(scanner.items)
}

/// A call a harness makes, as far as source text resolves it.
#[derive(Debug, Eq, PartialEq)]
enum Call {
    Bare(String),
    Path { first: String, last: String },
}

const NOT_CALLEES: [&str; 12] = [
    "if", "while", "match", "return", "for", "in", "fn", "move", "as", "else", "let", "where",
];

fn calls(tokens: &[Token], body: Range<usize>) -> Vec<Call> {
    let mut found = Vec::new();
    for open in body.clone() {
        if tokens[open] != Token::Punct('(') || open == body.start {
            continue;
        }
        let mut callee = open - 1;
        if tokens[callee] == Token::Punct('>') {
            // `name::<T>(…)`: step back over the turbofish.
            let mut depth = 0_usize;
            let mut cursor = callee;
            let opening = loop {
                match tokens[cursor] {
                    Token::Punct('>') => depth += 1,
                    Token::Punct('<') => {
                        depth -= 1;
                        if depth == 0 {
                            break Some(cursor);
                        }
                    }
                    _ => {}
                }
                if cursor == body.start {
                    break None;
                }
                cursor -= 1;
            };
            match opening {
                Some(opening)
                    if opening >= body.start + 3
                        && tokens[opening - 1] == Token::Punct(':')
                        && tokens[opening - 2] == Token::Punct(':') =>
                {
                    callee = opening - 3;
                }
                _ => continue,
            }
        }
        let Token::Ident(name) = &tokens[callee] else {
            continue;
        };
        if NOT_CALLEES.contains(&name.as_str())
            || (callee > body.start && tokens[callee - 1] == Token::Punct('.'))
        {
            continue;
        }
        let mut first = name.clone();
        let mut segments = 1_usize;
        let mut cursor = callee;
        while cursor >= body.start + 3
            && tokens[cursor - 1] == Token::Punct(':')
            && tokens[cursor - 2] == Token::Punct(':')
        {
            segments += 1;
            match &tokens[cursor - 3] {
                Token::Ident(segment) => {
                    first.clone_from(segment);
                    cursor -= 3;
                }
                _ => {
                    // A qualified path such as `<T as Trait>::f` or
                    // `Vec::<u8>::new` does not resolve from text.
                    first = "<qualified>".to_owned();
                    break;
                }
            }
        }
        found.push(if segments == 1 {
            Call::Bare(name.clone())
        } else {
            Call::Path {
                first,
                last: name.clone(),
            }
        });
    }
    found
}

/// Every source file of one package, and the production items its crate
/// declares.
struct CrateScan {
    files: Vec<(PathBuf, Lexed, FileItems)>,
    free_functions: BTreeSet<String>,
    associated_functions: BTreeSet<String>,
    namespaces: BTreeSet<String>,
}

/// The directory a file's child modules live in.
fn module_directory(path: &Path) -> PathBuf {
    let parent = path.parent().map_or_else(PathBuf::new, Path::to_path_buf);
    match path.file_name().and_then(|name| name.to_str()) {
        Some("lib.rs" | "main.rs" | "mod.rs") => parent,
        _ => path
            .file_stem()
            .map_or_else(|| parent.clone(), |stem| parent.join(stem)),
    }
}

fn scan_sources(source_root: &Path, sources: Vec<(PathBuf, String)>) -> Result<CrateScan, String> {
    let mut lexed_files = Vec::with_capacity(sources.len());
    for (path, source) in sources {
        let lexed = lex(&source).map_err(|error| format!("{}: {error}", path.display()))?;
        lexed_files.push((path, lexed));
    }
    // Files declared under `#[cfg(test)]` or `#[cfg(kani)]`, and their
    // subtrees, are not production code.
    let mut excluded_paths = Vec::new();
    for (path, lexed) in &lexed_files {
        let items =
            scan_file(lexed, false).map_err(|error| format!("{}: {error}", path.display()))?;
        for module in items.excluded_modules {
            let mut base = module_directory(path);
            let Some((name, inline)) = module.split_last() else {
                continue;
            };
            for segment in inline {
                base.push(segment);
            }
            excluded_paths.push(base.join(format!("{name}.rs")));
            excluded_paths.push(base.join(name));
        }
    }
    let library = source_root.join("src");
    let binaries = library.join("bin");
    let mut scan = CrateScan {
        files: Vec::new(),
        free_functions: BTreeSet::new(),
        associated_functions: BTreeSet::new(),
        namespaces: BTreeSet::new(),
    };
    for (path, lexed) in lexed_files {
        let excluded = !path.starts_with(&library)
            || path.starts_with(&binaries)
            || excluded_paths
                .iter()
                .any(|excluded| path.starts_with(excluded));
        let items =
            scan_file(&lexed, excluded).map_err(|error| format!("{}: {error}", path.display()))?;
        scan.free_functions
            .extend(items.free_functions.iter().cloned());
        scan.associated_functions
            .extend(items.associated_functions.iter().cloned());
        scan.namespaces.extend(items.namespaces.iter().cloned());
        scan.files.push((path, lexed, items));
    }
    Ok(scan)
}

fn scan_crate(source_root: &Path) -> Result<CrateScan, String> {
    let mut paths = Vec::new();
    collect_sources(source_root, &mut paths)?;
    paths.sort();
    let mut sources = Vec::with_capacity(paths.len());
    for path in paths {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        sources.push((path, source));
    }
    scan_sources(source_root, sources)
}

fn collect_sources(directory: &Path, found: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("could not read {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("could not read a directory entry: {error}"))?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "target" {
            continue;
        }
        if path.is_dir() {
            collect_sources(&path, found)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
    Ok(())
}

impl CrateScan {
    fn harness_count(&self) -> usize {
        self.files
            .iter()
            .map(|(_, _, items)| items.harnesses.len())
            .sum()
    }

    /// Harnesses that reach no production function, as `(file, line, name)`.
    fn vacuous_harnesses(&self) -> Vec<(PathBuf, usize, String)> {
        let mut vacuous = Vec::new();
        for (path, lexed, items) in &self.files {
            for harness in &items.harnesses {
                if !self.reaches_production(lexed, items, harness) {
                    vacuous.push((path.clone(), harness.line, harness.name.clone()));
                }
            }
        }
        vacuous
    }

    fn reaches_production(&self, lexed: &Lexed, items: &FileItems, harness: &HarnessSite) -> bool {
        let helpers = items.helpers.get(&harness.module);
        let helper = |name: &str| helpers.and_then(|helpers| helpers.get(name));
        let mut pending = vec![harness.body.clone()];
        let mut visited = BTreeSet::new();
        while let Some(body) = pending.pop() {
            for call in calls(&lexed.tokens, body) {
                let (local, production) = match &call {
                    Call::Bare(name) => (helper(name), self.free_functions.contains(name)),
                    Call::Path { first, last } => (
                        helper(last).filter(|_| first == "self"),
                        (matches!(first.as_str(), "crate" | "super" | "self" | "Self")
                            || self.namespaces.contains(first))
                            && (self.free_functions.contains(last)
                                || self.associated_functions.contains(last)),
                    ),
                };
                if let Some(body) = local {
                    let name = match &call {
                        Call::Bare(name) | Call::Path { last: name, .. } => name.clone(),
                    };
                    if visited.insert(name) {
                        pending.push(body.clone());
                    }
                } else if production {
                    return true;
                }
            }
        }
        false
    }
}

/// Names of the harnesses declared in the files of `source_root` that define
/// the production function `entry_point`, so a citation names a harness
/// beside that function rather than anywhere in its crate.
///
/// # Errors
///
/// Reports a source file the scanner cannot parse.
pub(crate) fn harnesses_beside(
    source_root: &Path,
    entry_point: &str,
) -> Result<BTreeSet<String>, String> {
    let scan = scan_crate(source_root)?;
    Ok(scan
        .files
        .iter()
        .filter(|(_, _, items)| items.free_functions.contains(entry_point))
        .flat_map(|(_, _, items)| items.harnesses.iter().map(|harness| harness.name.clone()))
        .collect())
}

/// Checks every harness in `packages`, given as `(package, source root)`,
/// and returns how many harnesses it checked.
///
/// # Errors
///
/// Names each harness that calls no production function of its own crate,
/// or reports a source file the lint cannot parse.
pub(crate) fn lint_harness_calls(packages: &[(&str, PathBuf)]) -> Result<usize, String> {
    let mut checked = 0;
    let mut vacuous = Vec::new();
    for (package, source_root) in packages {
        let scan = scan_crate(source_root)?;
        checked += scan.harness_count();
        vacuous.extend(
            scan.vacuous_harnesses()
                .into_iter()
                .map(|(path, line, name)| format!("{}:{line} {name} ({package})", path.display())),
        );
    }
    if vacuous.is_empty() {
        Ok(checked)
    } else {
        Err(format!(
            "Kani harnesses call no non-test function of their own crate, so no change to the \
             code they name can fail them; call the production function each one verifies \
             (a free function, or `Type::method(value)`): {}",
            vacuous.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The attribute is assembled so that no line of this file declares a
    /// harness to the line-based harness inventory.
    const PROOF: &str = concat!("#[kani", "::proof]");

    fn scan(files: &[(&str, &str)]) -> CrateScan {
        let root = Path::new("/fixture");
        scan_sources(
            root,
            files
                .iter()
                .map(|(path, source)| (root.join(path), source.replace("@proof", PROOF)))
                .collect(),
        )
        .expect("fixture crate parses")
    }

    fn vacuous_names(scan: &CrateScan) -> Vec<String> {
        scan.vacuous_harnesses()
            .into_iter()
            .map(|(_, _, name)| name)
            .collect()
    }

    const LIBRARY: &str = r#"
pub struct Meter {
    used: u64,
}

impl Meter {
    pub const fn remaining(&self, limit: u64) -> Option<u64> {
        limit.checked_sub(self.used)
    }
}

/// Mentions checked_total(value) only in documentation.
pub fn checked_total(left: u64, right: u64) -> Option<u64> {
    left.checked_add(right)
}

pub fn widen<T: Into<u128>>(value: T) -> u128 {
    value.into()
}

pub mod ledger {
    pub fn settle(value: u64) -> u64 {
        value
    }
}

#[cfg(test)]
mod tests {
    pub fn test_only(value: u64) -> u64 {
        value
    }
}

#[cfg(test)]
fn module_test_helper() {}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn arbitrary() -> u64 {
        kani::any()
    }

    fn checks(value: u64) {
        assert!(checked_total(value, 0) == Some(value));
    }

    @proof
    fn local_arithmetic_only() {
        let value: u64 = kani::any();
        // checked_total(value, 1)
        let _ = "checked_total(value, 1)";
        assert!(value.checked_add(0) == Some(value));
    }

    @proof
    fn method_syntax_only() {
        let meter = Meter { used: arbitrary() };
        assert!(meter.remaining(u64::MAX).is_some());
    }

    @proof
    fn test_helpers_only() {
        assert_eq!(tests::test_only(1), 1);
        module_test_helper();
    }

    @proof
    fn bare_call() {
        assert!(checked_total(arbitrary(), 0).is_some());
    }

    @proof
    fn path_call() {
        assert_eq!(super::ledger::settle(1), 1);
    }

    @proof
    fn associated_function_by_path() {
        let meter = Meter { used: 0 };
        assert!(Meter::remaining(&meter, 1).is_some());
    }

    @proof
    fn through_a_local_helper() {
        checks(arbitrary());
    }

    @proof
    fn turbofish_call() {
        assert!(widen::<u64>(arbitrary()) <= u128::from(u64::MAX));
    }
}
"#;

    #[test]
    fn harnesses_must_call_production_code_of_their_crate() {
        let scan = scan(&[("src/lib.rs", LIBRARY)]);
        assert_eq!(scan.harness_count(), 8);
        assert_eq!(
            vacuous_names(&scan),
            [
                "local_arithmetic_only",
                "method_syntax_only",
                "test_helpers_only"
            ]
        );
    }

    #[test]
    fn a_file_module_under_a_test_configuration_is_not_production() {
        let library = "#[cfg(test)]\nmod support;\n#[cfg(kani)]\nmod proofs {\n    use super::*;\n    @proof\n    fn uses_support() {\n        assert!(support::helper(1) == 1);\n        assert!(helper(1) == 1);\n    }\n}\n";
        let support = "pub fn helper(value: u64) -> u64 {\n    value\n}\n";
        let excluded = scan(&[("src/lib.rs", library), ("src/support.rs", support)]);
        assert_eq!(vacuous_names(&excluded), ["uses_support"]);

        let production = library.replacen("#[cfg(test)]\nmod support;", "pub mod support;", 1);
        let included = scan(&[("src/lib.rs", &production), ("src/support.rs", support)]);
        assert!(vacuous_names(&included).is_empty());
    }

    #[test]
    fn lexing_drops_comments_and_literals_but_keeps_lifetimes_apart() {
        let source = "/* outer /* nested */ call(1) */ fn keep<'a>(x: &'a str) -> char {\n    let _ = r##\"quote \"# // not a comment\"##;\n    let _ = b'\\'';\n    let _ = \"line\\\n continued\";\n    'x'\n}\n";
        let lexed = lex(source).expect("lexes");
        let identifiers = lexed
            .tokens
            .iter()
            .filter_map(|token| match token {
                Token::Ident(name) => Some(name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            identifiers,
            [
                "fn", "keep", "x", "str", "char", "let", "_", "let", "_", "let", "_"
            ]
        );
        assert_eq!(
            lexed
                .tokens
                .iter()
                .filter(|token| **token == Token::Lifetime)
                .count(),
            2
        );
        assert!(lex("fn broken() { (").is_err());
        assert!(lex("let text = \"unterminated;").is_err());
    }

    #[test]
    fn calls_resolve_bare_path_and_turbofish_but_not_methods() {
        let lexed =
            lex("{ a(1); b::c(2); d::<u8>(3); x.e(4); f!(5); if (g) {} Some(6); <T as U>::h(7); }")
                .expect("lexes");
        let body = 1..lexed.tokens.len() - 1;
        assert_eq!(
            calls(&lexed.tokens, body),
            [
                Call::Bare("a".to_owned()),
                Call::Path {
                    first: "b".to_owned(),
                    last: "c".to_owned()
                },
                Call::Bare("d".to_owned()),
                Call::Bare("Some".to_owned()),
                Call::Path {
                    first: "<qualified>".to_owned(),
                    last: "h".to_owned()
                },
            ]
        );
    }
}
