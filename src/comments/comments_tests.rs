// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::super::{CommentSyntax, Comments};

    fn named(src: &str) -> Comments<'_> {
        Comments::scan(src, CommentSyntax::NamedConf)
    }

    fn zone(src: &str) -> Comments<'_> {
        Comments::scan(src, CommentSyntax::ZoneFile)
    }

    // ── detection: named.conf ────────────────────────────────────────────────

    #[test]
    fn test_named_conf_without_comments_is_clean() {
        assert!(!named("options { directory \"/var/named\"; };\n").any());
    }

    #[test]
    fn test_named_conf_hash_comment_detected() {
        assert!(named("# header\noptions { };\n").any());
    }

    #[test]
    fn test_named_conf_double_slash_comment_detected() {
        assert!(named("options { }; // trailing\n").any());
    }

    #[test]
    fn test_named_conf_block_comment_detected() {
        assert!(named("/* block */ options { };\n").any());
    }

    #[test]
    fn test_named_conf_markers_inside_quotes_are_not_comments() {
        let src = "zone \"a#b//c/*d*/\" { file \"/x#y\"; };\n";
        assert!(!named(src).any());
    }

    #[test]
    fn test_named_conf_escaped_quote_does_not_end_string() {
        // The `#` is still inside the string after the escaped quote.
        assert!(!named("key \"a\\\"#b\" { };\n").any());
    }

    #[test]
    fn test_named_conf_lone_slash_is_not_a_comment() {
        assert!(!named("acl a { 10.0.0.0/8; };\n").any());
    }

    #[test]
    fn test_named_conf_unterminated_block_comment_runs_to_end() {
        let c = named("options { };\n/* never closed\n");
        assert!(c.any());
        assert_eq!(c.stripped(), "options { };\n");
    }

    // ── detection: zone files ────────────────────────────────────────────────

    #[test]
    fn test_zone_semicolon_comment_detected() {
        assert!(zone("@ IN A 192.0.2.1 ; web\n").any());
    }

    #[test]
    fn test_zone_semicolon_inside_txt_quotes_is_not_a_comment() {
        let src = "@ IN TXT \"v=DKIM1; k=rsa; p=abc\"\n";
        assert!(!zone(src).any());
    }

    #[test]
    fn test_zone_hash_and_slashes_are_not_comments() {
        assert!(!zone("@ IN TXT \"x\"\nhost IN A 192.0.2.1 #x //y\n").any());
    }

    // ── stripping ────────────────────────────────────────────────────────────

    #[test]
    fn test_strip_drops_comment_only_lines() {
        let src = "# header\noptions { };\n// another\n";
        assert_eq!(named(src).stripped(), "options { };\n");
    }

    #[test]
    fn test_strip_trims_whitespace_before_trailing_comment() {
        let src = "options { };   # note\n";
        assert_eq!(named(src).stripped(), "options { };\n");
    }

    #[test]
    fn test_strip_removes_multi_line_block_comment() {
        let src = "/*\n * licence\n */\noptions { };\n";
        assert_eq!(named(src).stripped(), "options { };\n");
    }

    #[test]
    fn test_strip_keeps_code_after_inline_block_comment() {
        let src = "/* a */options { };\n";
        assert_eq!(named(src).stripped(), "options { };\n");
    }

    #[test]
    fn test_strip_keeps_code_after_multi_line_block_comment_ends() {
        let src = "acl a { any; }; /* starts\nends */ options { };\n";
        assert_eq!(named(src).stripped(), "acl a { any; };\n options { };\n");
    }

    #[test]
    fn test_strip_keeps_blank_lines_that_had_no_comment() {
        let src = "acl a { any; };\n\noptions { }; # x\n";
        assert_eq!(named(src).stripped(), "acl a { any; };\n\noptions { };\n");
    }

    #[test]
    fn test_strip_keeps_quoted_markers() {
        let src = "zone \"a#b\" { }; # real\n";
        assert_eq!(named(src).stripped(), "zone \"a#b\" { };\n");
    }

    #[test]
    fn test_strip_without_comments_is_identity() {
        let src = "options { };\nzone \"x\" { };";
        assert_eq!(named(src).stripped(), src);
    }

    #[test]
    fn test_strip_zone_comments() {
        let src = "; origin\n@ IN A 192.0.2.1 ; web\n";
        assert_eq!(zone(src).stripped(), "@ IN A 192.0.2.1\n");
    }
}
