//! Keeps what a spawned `hearth serve` process writes to stdout and stderr, so
//! a failing test can print the server's own log.
//!
//! A first `POST /admin/bootstrap` to a newly spawned dev server sometimes took
//! 2–10 s in CI instead of about 0.35 s, and the tests that time out at 5 s or
//! 10 s failed with no clue where the time went. Each stream is read to its end
//! on a background thread; reading also keeps the pipe from filling, which
//! would block the server on its own log writes.
//!
//! Included with `#[path = "support/server_output.rs"] mod server_output;`.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read};
use std::sync::{Arc, Mutex};

/// The lines a spawned server wrote, in the order the reader threads saw them.
#[derive(Clone, Default)]
pub struct ServerOutput {
    lines: Arc<Mutex<Vec<String>>>,
}

impl ServerOutput {
    /// Reads `stream` to its end on a background thread and keeps each line.
    pub fn capture(&self, stream: impl Read + Send + 'static) {
        self.capture_with(stream, |_| {});
    }

    /// Like [`Self::capture`], and also calls `on_line` with each line as it
    /// arrives.
    pub fn capture_with(
        &self,
        stream: impl Read + Send + 'static,
        mut on_line: impl FnMut(&str) + Send + 'static,
    ) {
        let lines = Arc::clone(&self.lines);
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                on_line(&line);
                lines.lock().expect("server output lock").push(line);
            }
        });
    }

    /// The last `n` lines kept so far, one per line, for a failure message.
    pub fn tail(&self, n: usize) -> String {
        let lines = self.lines.lock().expect("server output lock");
        lines[lines.len().saturating_sub(n)..].join("\n")
    }
}
