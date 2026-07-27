use crate::explanation::{ExplanationError, ExplanationReport};

/// Renders bounded terminal-safe operator text.
///
/// # Errors
///
/// Returns an error when the requested terminal width is outside 40..=240.
pub fn render_text(report: &ExplanationReport, width: usize) -> Result<String, ExplanationError> {
    if !(40..=240).contains(&width) {
        return Err(ExplanationError::Encoding(
            "terminal width must be in 40..=240".to_owned(),
        ));
    }
    let mut output = format!(
        "AUTHS DECISION  {} · {}\nStage           {}\nExplanation     {}\n\nWhy\n",
        report.decision.to_ascii_uppercase(),
        report.code,
        report.stage,
        report.explanation_id
    );
    for fact in &report.facts {
        let marker = match fact.result.as_str() {
            "satisfied" => "✓",
            "unavailable" => "?",
            "not-evaluated" => "·",
            _ => "✗",
        };
        let line = format!(
            "  {marker} {} [{} · {}]\n",
            escape_terminal(&fact.kind),
            fact.result,
            fact.contribution
        );
        output.push_str(&line.chars().take(width).collect::<String>());
    }
    if !report.remediation.is_empty() {
        output.push_str("\nPossible remediation\n");
        for hint in &report.remediation {
            output.push_str("  ");
            output.push_str(&escape_terminal(hint));
            output.push('\n');
        }
    }
    Ok(output)
}

fn escape_terminal(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}
