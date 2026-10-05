// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! Quote-aware comment detection for the CLI.
//!
//! hornet's AST does not keep comments, so writing a parsed file back out
//! drops them. The CLI uses this scanner to refuse in-place rewrites that
//! would silently delete comments, and to warn when printed output omits them.

use std::ops::Range;

/// Length of the two-byte comment markers `//`, `/*` and `*/`.
const TWO_BYTE_MARKER: usize = 2;

/// Which comment syntax the source uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentSyntax {
    /// `named.conf`: `#` and `//` to end of line, `/* ... */` blocks.
    NamedConf,
    /// RFC 1035 zone file: `;` to end of line.
    ZoneFile,
}

/// The comments found in a source text, as byte ranges.
#[derive(Debug)]
pub struct Comments<'a> {
    src: &'a str,
    spans: Vec<Range<usize>>,
}

impl<'a> Comments<'a> {
    /// Scans `src` for comments. Markers inside double-quoted strings (with
    /// `\` escapes) are data, not comments. An unterminated block comment runs
    /// to the end of the input.
    pub fn scan(src: &'a str, syntax: CommentSyntax) -> Self {
        let bytes = src.as_bytes();
        let mut spans = Vec::new();
        let mut in_quote = false;
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if in_quote {
                match b {
                    b'\\' => i += 1,
                    b'"' => in_quote = false,
                    _ => {}
                }
                i += 1;
                continue;
            }
            if b == b'"' {
                in_quote = true;
                i += 1;
                continue;
            }
            let Some(end) = comment_end(bytes, i, syntax) else {
                i += 1;
                continue;
            };
            spans.push(i..end);
            i = end;
        }
        Self { src, spans }
    }

    /// Whether the source contains at least one comment.
    pub fn any(&self) -> bool {
        !self.spans.is_empty()
    }

    /// The source with every comment removed. A line that held a comment has
    /// its trailing whitespace trimmed, and is dropped entirely when nothing
    /// but whitespace remains. Lines without comments are kept verbatim.
    pub fn stripped(&self) -> String {
        let mut out = String::with_capacity(self.src.len());
        let mut start = 0;
        for line in self.src.split_inclusive('\n') {
            let end = start + line.len();
            let content_end = end - usize::from(line.ends_with('\n'));
            self.push_line(&mut out, start..content_end, &line[content_end - start..]);
            start = end;
        }
        out
    }

    fn push_line(&self, out: &mut String, line: Range<usize>, newline: &str) {
        let touching: Vec<&Range<usize>> = self
            .spans
            .iter()
            .filter(|s| s.start < line.end.max(line.start + 1) && s.end > line.start)
            .collect();
        if touching.is_empty() {
            out.push_str(&self.src[line]);
            out.push_str(newline);
            return;
        }
        let mut kept = String::new();
        let mut pos = line.start;
        for span in touching {
            if span.start > pos {
                kept.push_str(&self.src[pos..span.start]);
            }
            pos = pos.max(span.end);
        }
        if pos < line.end {
            kept.push_str(&self.src[pos..line.end]);
        }
        let kept = kept.trim_end();
        if kept.trim_start().is_empty() {
            return;
        }
        out.push_str(kept);
        out.push_str(newline);
    }
}

/// If a comment starts at `i`, returns the byte offset just past its end.
fn comment_end(bytes: &[u8], i: usize, syntax: CommentSyntax) -> Option<usize> {
    let line_end = || {
        bytes[i..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |p| i + p)
    };
    let next = bytes.get(i + 1).copied();
    match (syntax, bytes[i], next) {
        (CommentSyntax::ZoneFile, b';', _)
        | (CommentSyntax::NamedConf, b'#', _)
        | (CommentSyntax::NamedConf, b'/', Some(b'/')) => Some(line_end()),
        (CommentSyntax::NamedConf, b'/', Some(b'*')) => {
            let body = i + TWO_BYTE_MARKER;
            Some(
                bytes[body..]
                    .windows(TWO_BYTE_MARKER)
                    .position(|w| w == b"*/")
                    .map_or(bytes.len(), |p| body + p + TWO_BYTE_MARKER),
            )
        }
        _ => None,
    }
}

#[cfg(test)]
mod comments_tests;
