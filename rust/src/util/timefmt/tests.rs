// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::text::cstr;

#[test]
#[cfg_attr(miri, ignore = "iso8601 calls libc gmtime_r and strftime")]
fn iso8601_is_utc_to_the_second() {
    let mut out = [b'X'; 32];

    assert_eq!(iso8601(0, &mut out[..21]), 0);
    assert_eq!(cstr(&out), b"1970-01-01T00:00:00Z");
    assert_eq!(iso8601(1_700_000_000, &mut out), 0);
    assert_eq!(cstr(&out), b"2023-11-14T22:13:20Z");
}

#[test]
#[cfg_attr(miri, ignore = "iso8601 calls libc gmtime_r and strftime")]
fn iso8601_clears_output_on_failure() {
    let mut out = [b'X'; 32];
    out[31] = 0;

    assert_eq!(iso8601(0, &mut out[..20]), -EINVAL);
    assert_eq!(cstr(&out), b"");
    out.fill(b'X');
    out[31] = 0;
    assert_eq!(iso8601(1_i64 << 62, &mut out), -EINVAL);
    assert_eq!(cstr(&out), b"");
}

#[test]
fn duration_uses_the_largest_whole_unit() {
    for (seconds, expected) in [
        (0, &b"0s"[..]),
        (59, b"59s"),
        (60, b"1m"),
        (3599, b"59m"),
        (3600, b"1h"),
        (86399, b"23h"),
        (86400, b"1d"),
        (86400 * 400, b"400d"),
        (-1, b"?"),
    ] {
        let mut out = [0u8; 16];
        assert_eq!(format_duration(seconds, &mut out), 0);
        assert_eq!(cstr(&out), expected);
    }
}

#[test]
fn duration_clears_output_when_it_does_not_fit() {
    let mut out = [b'X'; 8];
    out[7] = 0;

    assert_eq!(format_duration(3599, &mut out[..3]), -E2BIG);
    assert_eq!(cstr(&out), b"");
    out.fill(b'X');
    out[7] = 0;
    assert_eq!(format_duration(-1, &mut out[..1]), -E2BIG);
    assert_eq!(cstr(&out), b"");
}
