// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::text::find;

#[test]
#[cfg_attr(miri, ignore = "strerrorname_np reads an errno name from libc")]
fn a_refusal_is_one_document() {
    let mut report = OpReport::new(c"upatch_load");
    report.phase = c"parse";
    report.err = EINVAL;
    report.category = Some(c"parser_rejected");
    report.path = Some(c"a.upatch".to_owned());
    report.name = Some(c"a".to_owned());
    for (dst, &byte) in report.message.iter_mut().zip(b"unsafe upatch name") {
        *dst = byte as c_char;
    }

    let doc = encode(&report, b"7.4.0").unwrap();
    assert_eq!(
        doc.as_bytes(),
        concat!(
            r#"{"schema":1,"result":"failed","op":"upatch_load","#,
            r#""phase":"parse","errno":22,"errno_name":"EINVAL","#,
            r#""category":"parser_rejected","message":"unsafe upatch name","#,
            r#""verifier_log":"","loader_return":0,"upatch":{"path":"a.upatch","#,
            r#""name":"a","payload_sha256":""},"kernel":{"release":"7.4.0"},"tpm":null}"#,
        )
        .as_bytes()
    );
}

#[test]
fn text_that_is_not_utf8_is_written() {
    let mut report = OpReport::new(c"upatch_load");
    report.phase = c"payload_load";
    report.category = Some(c"verifier_rejected");
    report.path = Some(c"caf\xe9.upatch".to_owned());
    report.name = Some(c"\xff".to_owned());
    report.set_log(b"return na\xefve; @ caf\xe9.bpf.c:7\n");

    let doc = encode(&report, b"7.4.0-\xfe").unwrap();
    for field in [
        &br#""verifier_log":"return na\ufffdve; @ caf\ufffd.bpf.c:7\n""#[..],
        br#""path":"caf\ufffd.upatch""#,
        br#""name":"\ufffd""#,
        br#""kernel":{"release":"7.4.0-\ufffd"}"#,
    ] {
        assert!(find(doc.as_bytes(), field).is_some());
    }
}
