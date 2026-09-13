//! Forward bounded child diagnostics without blocking stdout report parsing.

use std::io::{self, Read, Write};

pub(super) fn relay(
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
                    writer.write_all(b"\n[Popeye diagnostics truncated; scan continues]\n")?;
                    truncated = true;
                }
                writer.flush()
            })();
            write_error = result.err();
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
    fn relay_is_bounded_and_drains_even_when_the_writer_fails() {
        let mut reader = io::Cursor::new(vec![b'x'; 100_000]);
        let mut output = Vec::new();
        assert_eq!(relay(&mut reader, &mut output, 1024).unwrap().len(), 1024);
        assert_eq!(reader.position(), 100_000);
        assert!(output.len() < 1100);
        assert_eq!(
            String::from_utf8(output)
                .unwrap()
                .matches("truncated")
                .count(),
            1
        );
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("write failed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        reader.set_position(0);
        assert_eq!(
            relay(&mut reader, Broken, 1024).unwrap_err().to_string(),
            "write failed"
        );
        assert_eq!(reader.position(), 100_000);
    }

    #[test]
    fn relay_propagates_read_failures() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("read failed"))
            }
        }
        assert_eq!(
            relay(Broken, Vec::new(), 1024).unwrap_err().to_string(),
            "read failed"
        );
    }
}
