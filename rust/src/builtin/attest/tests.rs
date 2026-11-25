// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

#[test]
fn config_nvpcr_name_selects_the_nv_index_and_excludes_a_pcr() {
    let option = CString::new(format!("--expect-config-nvpcr={}", "ab".repeat(NAME_LEN))).unwrap();
    let mut expect = AttestExpect::default();
    let args = [c"attest", c"verify", option.as_c_str()];

    assert_eq!(verify_against(&args, &mut expect), Err(EXIT_USAGE));
    assert_eq!(expect.config_pcr, Some(CONFIG_NVPCR_INDEX));
    assert_eq!(expect.config_nvpcr_name, Some([0xab; NAME_LEN]));

    let mut expect = AttestExpect::default();
    let args = [
        c"attest",
        c"verify",
        c"--expect-config-pcr=15",
        option.as_c_str(),
    ];
    assert_eq!(verify_against(&args, &mut expect), Err(EXIT_USAGE));

    let mut expect = AttestExpect::default();
    let args = [c"attest", c"verify", c"--expect-config-nvpcr=ab"];
    assert_eq!(verify_against(&args, &mut expect), Err(EXIT_USAGE));
}
