//! Normalize Trivy's pb/v3 ASCII progress when stderr is not a terminal.
//! pb/v3 writes each default bar without a separator to a pipe. Preserve other
//! diagnostics and bound incomplete candidates without adding a protocol.

const CANDIDATE_BYTES: usize = 16 * 1024;

#[derive(Default)]
pub(super) struct ProgressText {
    pending: Vec<u8>,
    last_progress: Option<String>,
}

impl ProgressText {
    pub(super) fn feed(&mut self, bytes: &[u8], eof: bool) -> Vec<u8> {
        let mut output = Vec::new();
        for &byte in bytes {
            if self.pending.is_empty() && !byte.is_ascii_digit() {
                self.normal(&[byte], &mut output);
                continue;
            }
            self.pending.push(byte);
            if self.pending.ends_with(b" p/s") {
                let pending = std::mem::take(&mut self.pending);
                if let Some(progress) = compact_bar(&pending) {
                    if self.last_progress.as_ref() != Some(&progress) {
                        output.push(b'\r');
                        output.extend_from_slice(progress.as_bytes());
                        self.last_progress = Some(progress);
                    }
                } else {
                    self.normal(&pending, &mut output);
                }
            } else if matches!(byte, b'\r' | b'\n') || self.pending.len() == CANDIDATE_BYTES {
                let pending = std::mem::take(&mut self.pending);
                self.normal(&pending, &mut output);
            }
        }
        if eof {
            let pending = std::mem::take(&mut self.pending);
            self.normal(&pending, &mut output);
        }
        output
    }

    fn normal(&mut self, bytes: &[u8], output: &mut Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        if self.last_progress.take().is_some() {
            output.push(b'\n');
        }
        output.extend_from_slice(bytes);
    }
}

fn compact_bar(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let (counts, rest) = text.split_once(" [")?;
    let (current, total) = counts.split_once(" / ")?;
    current.parse::<u64>().ok()?;
    total.parse::<u64>().ok()?;
    let (bar, rest) = rest.split_once("] ")?;
    if !bar.bytes().all(|c| matches!(c, b'-' | b'_' | b'>')) {
        return None;
    }
    let mut fields = rest.split_whitespace();
    let percent = fields.next()?;
    let value = percent.strip_suffix('%')?;
    if !value.bytes().all(|c| c.is_ascii_digit() || c == b'.') || value.parse::<f64>().is_err() {
        return None;
    }
    let speed = fields.next()?;
    if speed != "?" && speed.parse::<u64>().is_err() {
        return None;
    }
    if fields.next()? != "p/s" || fields.next().is_some() {
        return None;
    }
    // Counts and percentages come from Trivy, not an estimate by the adapter.
    Some(format!("Trivy progress: {counts} ({percent}) {speed} p/s"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undelimited_pb_bars_become_compact_redraws_at_any_chunk_boundary() {
        let first = format!("2 / 81 [-->{}] 2.47% ? p/s", "_".repeat(6000));
        let next = format!("8 / 81 [---->{}] 9.88% 1 p/s", "_".repeat(3000));
        let bytes =
            format!("INFO scanning\n{first}{first}{next}2026-09-13 FATAL example failure\n");
        for width in [1, 2, 3, 7, 64, 4096, 16384] {
            let mut normalizer = ProgressText::default();
            let mut out = Vec::new();
            for chunk in bytes.as_bytes().chunks(width) {
                out.extend(normalizer.feed(chunk, false));
            }
            out.extend(normalizer.feed(&[], true));
            assert_eq!(
                String::from_utf8(out).unwrap(),
                "INFO scanning\n\rTrivy progress: 2 / 81 (2.47%) ? p/s\rTrivy progress: 8 / 81 (9.88%) 1 p/s\n2026-09-13 FATAL example failure\n",
                "chunk width {width}"
            );
        }
    }

    #[test]
    fn normal_diagnostics_and_incomplete_or_unknown_bars_are_preserved() {
        for input in [
            b"2026-09-13 INFO scan started\nplain message\n".as_slice(),
            b"2 / 81 [invalid bar] 2.47% ? p/s\n",
            b"2 / 81 [--->____] incomplete",
            b"INFO unicode \xc3\xa9\r\n",
        ] {
            let mut normalizer = ProgressText::default();
            let mut out = Vec::new();
            for byte in input {
                out.extend(normalizer.feed(&[*byte], false));
            }
            out.extend(normalizer.feed(&[], true));
            assert_eq!(out, input);
        }
        let mut normalizer = ProgressText::default();
        let bytes = format!("2 / 81 [{}", "_".repeat(CANDIDATE_BYTES * 3));
        let mut output = normalizer.feed(bytes.as_bytes(), false);
        assert!(normalizer.pending.len() < CANDIDATE_BYTES);
        output.extend(normalizer.feed(&[], true));
        assert_eq!(output, bytes.as_bytes());
    }
}
