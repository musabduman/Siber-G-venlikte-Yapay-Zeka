"""
Text Normalizer for Tier 1 Pre-Filter.
Applies iterative multi-pass de-obfuscation:
1. URL decoding (up to 3 passes for nested / double encoding)
2. HTML entity decoding (&lt;, &#x3C;, etc.)
3. Unicode & hex escape sequence decoding (\\u003c, \\x27, etc.)
4. SQL comment stripping and keyword defragmentation (UN/**/ION -> UNION)
5. Whitespace collapsing and case folding
"""

import html
import re
import urllib.parse


def _strip_sql_comments(text: str) -> str:
    """
    Strips inline SQL comments (/*...*/ and /*!...*/) by merging adjacent fragments
    so obfuscated keywords like 'UN/**/ION' or 'SEL/*!*/ECT' rejoin into 'UNION' and 'SELECT'.
    """
    # Pattern for C-style / MySQL-style comments
    comment_pattern = re.compile(r"/\*.*?\*/", re.DOTALL)
    # If the comment is flanked by alphanumeric chars on both sides, remove it entirely without space
    # Example: 'UN/**/ION' -> 'UNION'
    def _replacer(m):
        start = m.start()
        end = m.end()
        before_char = text[start - 1] if start > 0 else ""
        after_char = text[end] if end < len(text) else ""
        if before_char.isalnum() and after_char.isalnum():
            return ""
        return " "

    return comment_pattern.sub(_replacer, text)


def _decode_escapes(text: str) -> str:
    """Decodes unicode escapes (\\uXXXX) and hex escapes (\\xXX)."""
    # 1. Unicode escapes: \\u003c or \u003c
    def _sub_unicode(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    text = re.sub(r"(?:\\u|%5cu)([0-9a-fA-F]{4})", _sub_unicode, text)

    # 2. Hex escapes: \\x3c or \x3c
    def _sub_hex(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    text = re.sub(r"(?:\\x|%5cx)([0-9a-fA-F]{2})", _sub_hex, text)
    return text


def normalize_log_text(raw_text: str, max_passes: int = 3) -> str:
    """
    Normalizes raw log text through up to max_passes of de-obfuscation.
    Returns normalized, canonical lowercase text.
    """
    if not raw_text:
        return ""

    current = raw_text

    for _ in range(max_passes):
        prev = current

        # 1. URL decoding
        try:
            decoded_url = urllib.parse.unquote_plus(current)
            if decoded_url != current:
                current = decoded_url
        except Exception:
            pass

        # 2. HTML entity decoding
        try:
            decoded_html = html.unescape(current)
            if decoded_html != current:
                current = decoded_html
        except Exception:
            pass

        # 3. Unicode and hex escape decoding
        current = _decode_escapes(current)

        # 4. SQL comment defragmentation
        current = _strip_sql_comments(current)

        # If no transformations happened in this pass, break early
        if current == prev:
            break

    # 5. Whitespace normalization (tab, newline, multi-space -> single space)
    current = re.sub(r"\s+", " ", current).strip()

    # 6. Lowercase conversion
    return current.lower()
