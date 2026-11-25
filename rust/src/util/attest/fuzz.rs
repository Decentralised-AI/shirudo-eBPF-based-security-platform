// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-attest: evidence verified against a nonce, made a credential
//! challenge of with presented keys trusted, and read as a challenge.

use super::{AttestChallengePolicy, AttestExpect, Report, challenge_make, challenge_read, verify};
use core::ffi::{CStr, c_int};
use std::sync::OnceLock;

use crate::builtin::attest::cmd_attest;
use crate::fuzzing::{StdoutCapture, fuzz_target, input_file};
use crate::util::json::{Visit, walk};

const NONCE: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const REPORT_MAX: usize = 4096;

fuzz_target!(shirudo_fuzz_attest, shirudo_fuzz_attest_init, |data| {
    let pol = AttestChallengePolicy {
        trust_presented: true,
        ..AttestChallengePolicy::default()
    };
    let expect = AttestExpect {
        nonce: NONCE.to_vec(),
        allow_runtime_events: true,
        ..AttestExpect::default()
    };
    let _ = verify(data, &expect, &mut Report::new(REPORT_MAX));
    let _ = challenge_make(data, &pol, &mut Report::new(REPORT_MAX));
    if let Some(input) = input_file(data) {
        let _ = challenge_read(&input.path);
    }
});

/// The CLI report is checked in both forms against the same evidence.
/// A malformed document may print a partial text report and no JSON.
#[derive(Default)]
struct Verdict {
    status: c_int,
    checks: usize,
    verdict: Option<&'static [u8]>,
    in_result: bool,
    in_verdict: bool,
}

fn text_verdict(output: &[u8], status: c_int) -> Verdict {
    let mut result = Verdict {
        status,
        ..Verdict::default()
    };
    for line in output.split(|&c| c == b'\n') {
        if line.len() > 8
            && [b"  OK    ", b"  FAIL  ", b"  NOTE  "]
                .iter()
                .any(|mark| line.starts_with(*mark))
        {
            result.checks += 1;
        } else if line == b"verdict: ok" {
            result.verdict = Some(b"ok");
        } else if line == b"verdict: fail" {
            result.verdict = Some(b"fail");
        }
    }
    result
}

impl Visit for Verdict {
    fn open(&mut self, _array: bool) -> Result<(), c_int> {
        Ok(())
    }
    fn close(&mut self, _array: bool) -> Result<(), c_int> {
        Ok(())
    }
    fn key(&mut self, key: &CStr) -> Result<(), c_int> {
        self.in_result = key.to_bytes() == b"result";
        self.in_verdict = key.to_bytes() == b"verdict";
        Ok(())
    }
    fn string(&mut self, value: &CStr) -> Result<(), c_int> {
        if self.in_result {
            self.checks += 1;
        }
        if self.in_verdict {
            self.verdict = Some(match value.to_bytes() {
                b"ok" => b"ok",
                b"fail" => b"fail",
                _ => b"?",
            });
        }
        self.in_result = false;
        self.in_verdict = false;
        Ok(())
    }
    fn number(&mut self, _text: &[u8], _integer: bool) -> Result<(), c_int> {
        Ok(())
    }
    fn literal(&mut self, _value: c_int) -> Result<(), c_int> {
        Ok(())
    }
}

fn json_verdict(output: &[u8], status: c_int) -> Verdict {
    let mut result = Verdict {
        status,
        ..Verdict::default()
    };
    if !output.is_empty() {
        let document = output.strip_suffix(b"\n").expect("JSON without line feed");
        assert!(walk(document, &mut result).is_ok());
    }
    result
}

static CAPTURE: OnceLock<StdoutCapture> = OnceLock::new();
const NONCE_HEX: &CStr = c"0102030405060708090a0b0c0d0e0f10";

fuzz_target!(
    shirudo_fuzz_attest_report,
    shirudo_fuzz_attest_report_init,
    |data| {
        let Some(input) = input_file(data) else {
            return;
        };
        let capture = CAPTURE.get_or_init(StdoutCapture::new);
        let args = [
            c"attest",
            c"verify",
            c"--evidence",
            input.path.as_c_str(),
            c"--nonce",
            NONCE_HEX,
            c"--allow-runtime-events",
        ];
        let status = cmd_attest(&args);
        let text = text_verdict(&capture.take(), status);
        let args_json = [
            c"attest",
            c"verify",
            c"--evidence",
            input.path.as_c_str(),
            c"--nonce",
            NONCE_HEX,
            c"--allow-runtime-events",
            c"--json",
        ];
        let status = cmd_attest(&args_json);
        let json = json_verdict(&capture.take(), status);
        assert_eq!(text.status, json.status);
        if text.verdict.is_none() {
            assert!(json.verdict.is_none() && json.checks == 0);
        } else {
            assert_eq!(text.checks, json.checks);
            assert_eq!(text.verdict, json.verdict);
        }
    },
    || {
        let _ = CAPTURE.get_or_init(StdoutCapture::new);
    }
);
