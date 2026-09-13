//! Optional plain-text activity on stderr. Stdout remains the final JSON report.

use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(super) struct Progress {
    stop: Sender<()>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl Progress {
    pub(super) fn start(duration: u64, connections: u32, rate: u32) -> Self {
        let (stop, receiver) = mpsc::channel();
        let task = std::thread::spawn(move || {
            duration_activity(io::stderr(), receiver, duration, connections, rate)
        });
        Self {
            stop,
            task: Some(task),
        }
    }

    pub(super) fn finish(mut self) -> io::Result<()> {
        let _ = self.stop.send(());
        self.task
            .take()
            .unwrap()
            .join()
            .map_err(|_| io::Error::other("oha activity thread panicked"))?
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

fn duration_activity(
    mut writer: impl Write,
    stop: Receiver<()>,
    duration: u64,
    connections: u32,
    rate: u32,
) -> io::Result<()> {
    let start = Instant::now();
    writeln!(
        writer,
        "Starting oha: {duration}s planned, {connections} connections, rate limit {rate} requests/s (configured, not measured)"
    )?;
    writer.flush()?;
    // The manifest allows at most five minutes of load and a six-minute job.
    // Keep output bounded even when invoked directly with a longer duration.
    for _ in 0..360 {
        match stop.recv_timeout(Duration::from_secs(1)) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {
                writeln!(
                    writer,
                    "{}",
                    duration_message(start.elapsed().as_secs(), duration)
                )?;
                writer.flush()?;
            }
        }
    }
    writeln!(
        writer,
        "oha activity limit reached; still waiting for the process to exit"
    )?;
    writer.flush()
}

fn duration_message(elapsed: u64, planned: u64) -> String {
    if elapsed < planned {
        format!("oha running: {elapsed}s elapsed / {planned}s planned")
    } else {
        format!(
            "oha still running: {elapsed}s elapsed; planned {planned}s reached, waiting for final results"
        )
    }
}

/// Keep and relay a bounded diagnostic prefix, but always drain the child pipe.
/// A write failure must not leave oha blocked on a full stderr pipe.
pub(super) fn relay_stderr(
    mut reader: impl Read,
    mut writer: impl Write,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut truncated = false;
    let mut write_error = None;
    let mut chunk = [0; 8192];
    loop {
        let n = match reader.read(&mut chunk) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            break;
        }
        let keep = n.min(limit.saturating_sub(captured.len()));
        captured.extend_from_slice(&chunk[..keep]);
        if write_error.is_none() {
            let result = (|| {
                writer.write_all(&chunk[..keep])?;
                if keep < n && !truncated {
                    writer.write_all(b"\n[oha diagnostics truncated; benchmark continues]\n")?;
                    truncated = true;
                }
                writer.flush()
            })();
            if let Err(error) = result {
                write_error = Some(error);
            }
        }
    }
    match write_error {
        Some(error) => Err(error),
        None => Ok(captured),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_does_not_claim_measured_requests_or_completion() {
        assert_eq!(
            duration_message(2, 10),
            "oha running: 2s elapsed / 10s planned"
        );
        assert_eq!(
            duration_message(12, 10),
            "oha still running: 12s elapsed; planned 10s reached, waiting for final results"
        );
        let (tx, rx) = mpsc::channel();
        tx.send(()).unwrap();
        let mut output = Vec::new();
        duration_activity(&mut output, rx, 10, 20, 100).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Starting oha: 10s planned, 20 connections, rate limit 100 requests/s (configured, not measured)\n"
        );
    }

    #[test]
    fn diagnostics_are_bounded_and_drained_after_the_relay_limit() {
        let mut input = io::Cursor::new(vec![b'x'; 100_000]);
        let mut output = Vec::new();
        assert_eq!(
            relay_stderr(&mut input, &mut output, 1024).unwrap().len(),
            1024
        );
        assert_eq!(input.position(), 100_000);
        assert!(output.len() < 1100);
        assert_eq!(
            String::from_utf8(output)
                .unwrap()
                .matches("truncated")
                .count(),
            1
        );
    }

    #[test]
    fn diagnostic_read_and_write_errors_propagate_without_stopping_the_drain() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("read failed"))
            }
        }
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("write failed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            relay_stderr(Broken, Vec::new(), 10)
                .unwrap_err()
                .to_string(),
            "read failed"
        );
        let mut input = io::Cursor::new(vec![0; 100_000]);
        assert_eq!(
            relay_stderr(&mut input, Broken, 10)
                .unwrap_err()
                .to_string(),
            "write failed"
        );
        assert_eq!(input.position(), 100_000);
    }
}
