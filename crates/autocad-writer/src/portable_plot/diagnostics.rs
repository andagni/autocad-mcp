use std::collections::BTreeMap;

use super::PortablePlotError;

/// The fidelity disposition of one visible source semantic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FidelityDisposition {
    Exact,
    ToleranceBounded,
    Substituted,
    Omitted,
    Unsupported,
    Invalid,
}

/// Total result classification after applying all semantic dispositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlotCompleteness {
    Complete,
    Partial,
    Rejected,
}

/// A normalized drawing handle suitable for diagnostics and aggregate receipts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceHandle(String);

impl SourceHandle {
    pub fn new(value: impl AsRef<str>) -> Result<Self, PortablePlotError> {
        let normalized = value.as_ref().trim().to_ascii_uppercase();
        if normalized.is_empty()
            || normalized.len() > 32
            || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(PortablePlotError::new(
                "source_handle_invalid",
                "source handles must be non-empty hexadecimal values no longer than 32 digits",
            ));
        }
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One stable, content-safe fidelity diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlotDiagnostic {
    code: String,
    source_type: String,
    source_handle: Option<SourceHandle>,
    disposition: FidelityDisposition,
    message: String,
}

impl PlotDiagnostic {
    pub fn new(
        code: impl Into<String>,
        source_type: impl Into<String>,
        source_handle: Option<SourceHandle>,
        disposition: FidelityDisposition,
        message: impl Into<String>,
    ) -> Result<Self, PortablePlotError> {
        let code = code.into();
        let source_type = source_type.into();
        let message = message.into();
        if !valid_stable_token(&code) {
            return Err(PortablePlotError::new(
                "diagnostic_code_invalid",
                "diagnostic codes must use lowercase ASCII letters, digits, and underscores",
            ));
        }
        if !valid_source_type(&source_type) {
            return Err(PortablePlotError::new(
                "diagnostic_source_type_invalid",
                "diagnostic source types must use printable ASCII without path separators",
            ));
        }
        if message.is_empty() || message.len() > 512 || message.contains(['\r', '\n']) {
            return Err(PortablePlotError::new(
                "diagnostic_message_invalid",
                "diagnostic messages must be one non-empty line no longer than 512 bytes",
            ));
        }
        Ok(Self {
            code,
            source_type,
            source_handle,
            disposition,
            message,
        })
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn source_type(&self) -> &str {
        &self.source_type
    }

    pub fn source_handle(&self) -> Option<&SourceHandle> {
        self.source_handle.as_ref()
    }

    pub fn disposition(&self) -> FidelityDisposition {
        self.disposition
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

fn valid_stable_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_source_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_graphic()
                && !matches!(byte, b'/' | b'\\' | b':' | b'<' | b'>' | b'|' | b'"')
        })
}

/// Exact counts for one source entity family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DispositionCounts {
    pub exact: usize,
    pub tolerance_bounded: usize,
    pub substituted: usize,
    pub omitted: usize,
    pub unsupported: usize,
    pub invalid: usize,
}

impl DispositionCounts {
    fn increment(&mut self, disposition: FidelityDisposition) -> Result<(), PortablePlotError> {
        let value = match disposition {
            FidelityDisposition::Exact => &mut self.exact,
            FidelityDisposition::ToleranceBounded => &mut self.tolerance_bounded,
            FidelityDisposition::Substituted => &mut self.substituted,
            FidelityDisposition::Omitted => &mut self.omitted,
            FidelityDisposition::Unsupported => &mut self.unsupported,
            FidelityDisposition::Invalid => &mut self.invalid,
        };
        *value = value.checked_add(1).ok_or_else(|| {
            PortablePlotError::new(
                "diagnostic_count_overflow",
                "fidelity diagnostic accounting overflowed",
            )
        })?;
        Ok(())
    }

    pub fn total(self) -> usize {
        self.exact
            .saturating_add(self.tolerance_bounded)
            .saturating_add(self.substituted)
            .saturating_add(self.omitted)
            .saturating_add(self.unsupported)
            .saturating_add(self.invalid)
    }

    pub fn completeness(self) -> PlotCompleteness {
        if self.unsupported > 0 || self.invalid > 0 {
            PlotCompleteness::Rejected
        } else if self.substituted > 0 || self.omitted > 0 {
            PlotCompleteness::Partial
        } else {
            PlotCompleteness::Complete
        }
    }
}

/// The maximum observed error for one named approximation tolerance.
#[derive(Debug, Clone, PartialEq)]
pub struct ToleranceUse {
    name: String,
    maximum_error_points: f64,
}

impl ToleranceUse {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn maximum_error_points(&self) -> f64 {
        self.maximum_error_points
    }
}

/// Bounded, deterministic diagnostic aggregation for one compilation.
#[derive(Debug)]
pub struct DiagnosticLedger {
    representative_limit: usize,
    representatives: Vec<PlotDiagnostic>,
    diagnostic_counts: BTreeMap<String, usize>,
    source_counts: BTreeMap<String, DispositionCounts>,
    tolerances: BTreeMap<String, f64>,
    totals: DispositionCounts,
}

impl DiagnosticLedger {
    pub fn new(representative_limit: usize) -> Self {
        Self {
            representative_limit,
            representatives: Vec::new(),
            diagnostic_counts: BTreeMap::new(),
            source_counts: BTreeMap::new(),
            tolerances: BTreeMap::new(),
            totals: DispositionCounts::default(),
        }
    }

    pub fn record(&mut self, diagnostic: PlotDiagnostic) -> Result<(), PortablePlotError> {
        self.record_source(diagnostic.source_type(), diagnostic.disposition())?;
        let count = self
            .diagnostic_counts
            .entry(diagnostic.code().to_owned())
            .or_default();
        *count = count.checked_add(1).ok_or_else(|| {
            PortablePlotError::new(
                "diagnostic_count_overflow",
                "fidelity diagnostic accounting overflowed",
            )
        })?;
        if self.representatives.len() < self.representative_limit {
            self.representatives.push(diagnostic);
        }
        Ok(())
    }

    pub fn record_source(
        &mut self,
        source_type: impl AsRef<str>,
        disposition: FidelityDisposition,
    ) -> Result<(), PortablePlotError> {
        let source_type = source_type.as_ref();
        if !valid_source_type(source_type) {
            return Err(PortablePlotError::new(
                "diagnostic_source_type_invalid",
                "diagnostic source types must use printable ASCII without path separators",
            ));
        }
        self.source_counts
            .entry(source_type.to_owned())
            .or_default()
            .increment(disposition)?;
        self.totals.increment(disposition)
    }

    pub fn record_tolerance(
        &mut self,
        name: impl Into<String>,
        error_points: f64,
    ) -> Result<(), PortablePlotError> {
        let name = name.into();
        if !valid_stable_token(&name) {
            return Err(PortablePlotError::new(
                "tolerance_name_invalid",
                "tolerance names must use lowercase ASCII letters, digits, and underscores",
            ));
        }
        if !error_points.is_finite() || error_points < 0.0 {
            return Err(PortablePlotError::new(
                "tolerance_value_invalid",
                "tolerance observations must be finite and non-negative",
            ));
        }
        self.tolerances
            .entry(name)
            .and_modify(|maximum| *maximum = maximum.max(error_points))
            .or_insert(error_points);
        Ok(())
    }

    pub fn finish(mut self) -> FidelitySummary {
        self.representatives.sort_by(|left, right| {
            (
                left.code(),
                left.source_type(),
                left.source_handle().map(SourceHandle::as_str),
                left.disposition(),
                left.message(),
            )
                .cmp(&(
                    right.code(),
                    right.source_type(),
                    right.source_handle().map(SourceHandle::as_str),
                    right.disposition(),
                    right.message(),
                ))
        });
        self.representatives.dedup();
        FidelitySummary {
            completeness: self.totals.completeness(),
            totals: self.totals,
            diagnostic_counts: self.diagnostic_counts,
            source_counts: self.source_counts,
            representative_diagnostics: self.representatives,
            tolerances: self
                .tolerances
                .into_iter()
                .map(|(name, maximum_error_points)| ToleranceUse {
                    name,
                    maximum_error_points,
                })
                .collect(),
        }
    }
}

/// Final immutable fidelity accounting.
#[derive(Debug, Clone, PartialEq)]
pub struct FidelitySummary {
    completeness: PlotCompleteness,
    totals: DispositionCounts,
    diagnostic_counts: BTreeMap<String, usize>,
    source_counts: BTreeMap<String, DispositionCounts>,
    representative_diagnostics: Vec<PlotDiagnostic>,
    tolerances: Vec<ToleranceUse>,
}

impl FidelitySummary {
    pub fn completeness(&self) -> PlotCompleteness {
        self.completeness
    }

    pub fn totals(&self) -> DispositionCounts {
        self.totals
    }

    pub fn diagnostic_counts(&self) -> &BTreeMap<String, usize> {
        &self.diagnostic_counts
    }

    pub fn source_counts(&self) -> &BTreeMap<String, DispositionCounts> {
        &self.source_counts
    }

    pub fn representative_diagnostics(&self) -> &[PlotDiagnostic] {
        &self.representative_diagnostics
    }

    pub fn tolerances(&self) -> &[ToleranceUse] {
        &self.tolerances
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostic(code: &str, source: &str, disposition: FidelityDisposition) -> PlotDiagnostic {
        PlotDiagnostic::new(
            code,
            source,
            Some(SourceHandle::new("a0").unwrap()),
            disposition,
            "stable aggregate-safe message",
        )
        .unwrap()
    }

    #[test]
    fn handles_are_normalized_and_reject_non_hex_values() {
        assert_eq!(SourceHandle::new(" 00af ").unwrap().as_str(), "00AF");
        assert_eq!(
            SourceHandle::new("../private.dwg").unwrap_err().code(),
            "source_handle_invalid"
        );
    }

    #[test]
    fn result_classification_has_total_rejection_precedence() {
        let mut counts = DispositionCounts::default();
        counts.increment(FidelityDisposition::Exact).unwrap();
        assert_eq!(counts.completeness(), PlotCompleteness::Complete);
        counts.increment(FidelityDisposition::Omitted).unwrap();
        assert_eq!(counts.completeness(), PlotCompleteness::Partial);
        counts.increment(FidelityDisposition::Unsupported).unwrap();
        assert_eq!(counts.completeness(), PlotCompleteness::Rejected);
    }

    #[test]
    fn representative_diagnostics_are_bounded_and_deterministic() {
        let mut ledger = DiagnosticLedger::new(2);
        ledger
            .record(diagnostic(
                "z_code",
                "LINE",
                FidelityDisposition::ToleranceBounded,
            ))
            .unwrap();
        ledger
            .record(diagnostic(
                "a_code",
                "ARC",
                FidelityDisposition::Substituted,
            ))
            .unwrap();
        ledger
            .record(diagnostic(
                "unrepresented",
                "TEXT",
                FidelityDisposition::Unsupported,
            ))
            .unwrap();
        let summary = ledger.finish();
        assert_eq!(summary.representative_diagnostics().len(), 2);
        assert_eq!(summary.representative_diagnostics()[0].code(), "a_code");
        assert_eq!(summary.diagnostic_counts()["unrepresented"], 1);
        assert_eq!(summary.completeness(), PlotCompleteness::Rejected);
    }

    #[test]
    fn tolerance_accounting_retains_only_the_maximum() {
        let mut ledger = DiagnosticLedger::new(0);
        ledger.record_tolerance("curve_flattening", 0.01).unwrap();
        ledger.record_tolerance("curve_flattening", 0.002).unwrap();
        ledger.record_tolerance("curve_flattening", 0.02).unwrap();
        let summary = ledger.finish();
        assert_eq!(summary.tolerances().len(), 1);
        assert_eq!(summary.tolerances()[0].maximum_error_points(), 0.02);
    }

    #[test]
    fn content_or_path_shaped_diagnostic_fields_are_rejected() {
        assert_eq!(
            PlotDiagnostic::new(
                "Bad-Code",
                "LINE",
                None,
                FidelityDisposition::Invalid,
                "message",
            )
            .unwrap_err()
            .code(),
            "diagnostic_code_invalid"
        );
        assert_eq!(
            PlotDiagnostic::new(
                "stable_code",
                "/private/drawing",
                None,
                FidelityDisposition::Invalid,
                "message",
            )
            .unwrap_err()
            .code(),
            "diagnostic_source_type_invalid"
        );
    }
}
