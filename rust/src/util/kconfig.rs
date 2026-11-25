// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! One option line of a Linux kernel configuration.

/// The most bytes before a newline that can set an option.
pub(crate) const LINE_MAX: usize = 8191;

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn trim(mut text: &[u8]) -> &[u8] {
    while text.first().is_some_and(|c| is_space(*c)) {
        text = &text[1..];
    }
    while text.last().is_some_and(|c| is_space(*c)) {
        text = &text[..text.len() - 1];
    }
    text
}

/// Return the name and value of a CONFIG_ option, or none for another line.
/// An unset comment gives "n"; one pair of enclosing double quotes is
/// removed from an assigned value.
pub(crate) fn line(text: &[u8]) -> Option<(&[u8], &[u8])> {
    if text.contains(&0) {
        return None;
    }
    let text = trim(text);
    let (key, value) = if let Some(rest) = text.strip_prefix(b"# CONFIG_") {
        const NOT_SET: &[u8] = b" is not set";
        let at = rest.windows(NOT_SET.len()).position(|w| w == NOT_SET)?;
        if at + NOT_SET.len() != rest.len() {
            return None;
        }
        (&text[2..2 + b"CONFIG_".len() + at], &b"n"[..])
    } else {
        let eq = text.iter().position(|&c| c == b'=')?;
        let key = trim(&text[..eq]);
        let value = trim(&text[eq + 1..]);
        let value = value
            .strip_prefix(b"\"")
            .and_then(|value| value.strip_suffix(b"\""))
            .unwrap_or(value);
        (key, value)
    };
    (key.starts_with(b"CONFIG_") && key.len() > b"CONFIG_".len()).then_some((key, value))
}

#[cfg(test)]
mod tests {
    use super::line;

    #[test]
    fn option_values_and_unset_comments() {
        assert_eq!(
            line(b"CONFIG_BPF_LSM=y"),
            Some((&b"CONFIG_BPF_LSM"[..], &b"y"[..]))
        );
        assert_eq!(
            line(b"CONFIG_INITRAMFS_SOURCE="),
            Some((&b"CONFIG_INITRAMFS_SOURCE"[..], &b""[..]))
        );
        assert_eq!(
            line(b"CONFIG_LSM=\"lockdown,bpf\""),
            Some((&b"CONFIG_LSM"[..], &b"lockdown,bpf"[..]))
        );
        assert_eq!(
            line(b"CONFIG_LOCALVERSION=\""),
            Some((&b"CONFIG_LOCALVERSION"[..], &b"\""[..]))
        );
        assert_eq!(
            line(b"\t# CONFIG_MODULES is not set \r"),
            Some((&b"CONFIG_MODULES"[..], &b"n"[..]))
        );
        assert_eq!(
            line(b" CONFIG_A = y \r"),
            Some((&b"CONFIG_A"[..], &b"y"[..]))
        );
    }

    #[test]
    fn unrelated_or_ambiguous_lines_set_nothing() {
        for text in [
            &b""[..],
            b" \t\r",
            b"# CONFIG_A=y",
            b"# CONFIG_A is not set at all",
            b"# CONFIG_ is not set",
            b"CONFIG_A",
            b"CONFIG_=y",
            b"A=y",
            b"=y",
            b"CONFIG_A=y\0CONFIG_B=n",
        ] {
            assert_eq!(line(text), None, "{text:?}");
        }
    }
}
