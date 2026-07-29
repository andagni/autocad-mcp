#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub path: String,
    pub line: usize,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckReport {
    pub diagnostics: Vec<Diagnostic>,
}

impl CheckReport {
    pub fn errors(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|diag| diag.severity == Severity::Error)
            .count()
    }

    pub fn warnings(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|diag| diag.severity == Severity::Warning)
            .count()
    }
}

pub fn check_source(src: &str, path: &str) -> CheckReport {
    let mut report = CheckReport::default();
    let mut emit = |severity: Severity, line: usize, msg: &str| {
        report.diagnostics.push(Diagnostic {
            path: path.to_string(),
            line,
            severity,
            message: msg.to_string(),
        });
    };

    // ── 1. Paren balance ──────────────────────────────────────────────────────
    {
        let mut depth: i32 = 0;
        let mut line = 1usize;
        let mut in_string = false;
        let mut in_line_comment = false;
        let chars: Vec<char> = src.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let ch = chars[i];

            if ch == '\n' {
                line += 1;
                in_line_comment = false;
                i += 1;
                continue;
            }
            if in_line_comment {
                i += 1;
                continue;
            }
            if ch == ';' && !in_string {
                in_line_comment = true;
                i += 1;
                continue;
            }
            if ch == '"' && !in_line_comment {
                if in_string {
                    // count preceding backslashes to handle \"
                    let mut bs = 0;
                    let mut j = i as isize - 1;
                    while j >= 0 && chars[j as usize] == '\\' {
                        bs += 1;
                        j -= 1;
                    }
                    if bs % 2 == 0 {
                        in_string = false;
                    }
                } else {
                    in_string = true;
                }
                i += 1;
                continue;
            }
            if in_string {
                i += 1;
                continue;
            }

            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth < 0 {
                        emit(
                            Severity::Error,
                            line,
                            "unmatched `)` — more closing than opening parens",
                        );
                        depth = 0;
                    }
                }
                _ => {}
            }
            i += 1;
        }

        if depth > 0 {
            emit(
                Severity::Error,
                line_count(src),
                &format!("{depth} unclosed `(` at end of file"),
            );
        }
    }

    // ── 2. Closed validator policy ────────────────────────────────────────────
    // These diagnostics are the implementation authority. The shipped failure
    // guide describes the same checks; neither file is generated from the other.
    let pitfalls: &[(&str, &str)] = &[
        (
            "(let ",
            "CL `let` is not an AutoLISP form; declare defun locals after `/` and assign with setq",
        ),
        (
            "(let*",
            "CL `let*` is not an AutoLISP form; declare defun locals after `/` and assign with setq",
        ),
        (
            "(loop ",
            "CL `loop` is unavailable; select an AutoLISP iterator such as while, repeat, foreach, or mapcar",
        ),
        (
            "(dotimes ",
            "CL `dotimes` is unavailable; use repeat for a fixed count",
        ),
        (
            "(dolist ",
            "CL `dolist` is unavailable; use foreach to traverse a list",
        ),
        (
            "(format ",
            "CL `format` is unavailable; compose text with AutoLISP string and conversion functions",
        ),
        (
            "(defmacro ",
            "CL `defmacro` is not part of the supported AutoLISP surface",
        ),
        (
            "&optional",
            "user AutoLISP defuns do not accept `&optional`; define an explicit fixed parameter list",
        ),
        (
            "&rest",
            "user AutoLISP defuns do not accept `&rest`; pass a list when arity must vary",
        ),
        (
            "&key",
            "user AutoLISP defuns do not accept Common Lisp `&key` parameters",
        ),
        (
            "(incf ",
            "CL `incf` is unavailable; update the binding explicitly with setq",
        ),
        (
            "(decf ",
            "CL `decf` is unavailable; update the binding explicitly with setq",
        ),
        (
            "(push ",
            "CL `push` is unavailable; prepend with cons and store the returned list",
        ),
        (
            "(getint ",
            "getint accepts only -32768 through 32767; choose another validated input path for a wider range",
        ),
    ];

    for (line_no, line_text) in src.lines().enumerate() {
        let line_no = line_no + 1;
        // skip comment lines
        let trimmed = line_text.trim_start();
        if trimmed.starts_with(';') {
            continue;
        }
        let lower = line_text.to_lowercase();

        for (pat, msg) in pitfalls {
            if lower.contains(&pat.to_lowercase()) {
                emit(Severity::Warning, line_no, msg);
            }
        }

        // command string missing _.  prefix: (command "ALPHA... but not already _. prefixed
        if let Some(idx) = lower.find("(command \"") {
            let after = &line_text[idx + 10..];
            let first = after.chars().next();
            match first {
                Some(c) if c.is_ascii_alphabetic() => {
                    emit(
                        Severity::Warning,
                        line_no,
                        "prefix standard command strings with `_.` so language translation and redefinitions are handled deliberately",
                    );
                }
                _ => {}
            }
        }
    }

    // ── 3. Command convention checks ─────────────────────────────────────────
    let has_cmd_defun = src.to_lowercase().contains("(defun c:");
    let has_princ_exit = src.contains("(princ)");

    if has_cmd_defun && !has_princ_exit {
        emit(
            Severity::Warning,
            1,
            "c: command has no no-argument `(princ)` exit; suppress incidental return-value output explicitly",
        );
    }

    report
}

fn line_count(s: &str) -> usize {
    s.lines().count().max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_unclosed_paren_as_error() {
        let report = check_source("(defun c:X ()\n  (princ)\n", "commands/X.lsp");
        assert_eq!(report.errors(), 1);
        assert_eq!(report.warnings(), 0);
        assert_eq!(report.diagnostics[0].severity, Severity::Error);
        assert!(report.diagnostics[0].message.contains("unclosed `(`"));
    }

    #[test]
    fn reports_common_lisp_let_as_warning() {
        let report = check_source("(let ((x 1)) x)\n", "commands/X.lsp");
        assert_eq!(report.errors(), 0);
        assert_eq!(report.warnings(), 1);
        assert_eq!(report.diagnostics[0].severity, Severity::Warning);
        assert!(report.diagnostics[0].message.contains("CL `let`"));
    }
}
