// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The local security conditions `shirudo status` shows:
//! one condition for each guarantee, and the
//! verdict and reason that sum them up.

use core::ffi::{CStr, c_char, c_int};

use crate::errno::{EBADMSG, EINPROGRESS, EKEYREJECTED, ENOENT, ESTALE, EXDEV};
use crate::sys::libc::{printf, snprintf, strerror};
use crate::text::strscpy;

/// Facts used to explain the local security verdict. The `*_seen`
/// flags distinguish a missing field from one carrying zero.
#[derive(Default)]
pub struct ConditionsInput<'a> {
    pub(crate) reachable: bool,
    pub(crate) parsed: bool,
    pub(crate) unreach: Option<&'a CStr>,
    pub(crate) lsm_attached: c_int,
    pub(crate) keyring_present: c_int,
    pub(crate) keyring_serial: i64,
    pub(crate) keyring_serial_pinned: i64,
    pub(crate) keyring_serial_matches: c_int,
    pub(crate) ksp_seen: c_int,
    pub(crate) ksm_seen: c_int,
    pub(crate) bpf_unfrozen: c_int,
    pub(crate) dmv_present: c_int,
    pub(crate) dmv_serial: i64,
    pub(crate) dmv_serial_pinned: i64,
    pub(crate) dmv_serial_matches: c_int,
    pub(crate) dmvp_seen: c_int,
    pub(crate) dmvm_seen: c_int,
    pub(crate) dmv_unfrozen: c_int,
    pub(crate) dmv_key_missing: c_int,
    pub(crate) tpm_reachable: c_int,
    pub(crate) chain_seen: c_int,
    pub(crate) chain_matches: c_int,
    pub(crate) cm_seen: c_int,
    pub(crate) nv_index: Option<&'a CStr>,
    pub(crate) config_seen: c_int,
    pub(crate) config_state: c_int,
    pub(crate) config_root: Option<&'a CStr>,
    pub(crate) pins_rc: c_int,
    pub(crate) pins_unmeasured: c_int,
    pub(crate) pins_detail: Option<&'a CStr>,
    /// Loaded XDP upatches whose archive changed, and their names.
    pub(crate) xdp_tampered: c_int,
    pub(crate) xdp_tampered_detail: Option<&'a CStr>,
    /// Loaded upatches missing a link or their archive, and their names.
    pub(crate) links_lost: c_int,
    pub(crate) links_lost_detail: Option<&'a CStr>,
    /// -errno of a link or archive check that could not run.
    pub(crate) checks_rc: c_int,
    /// Selected devices an XDP upatch does not run on: upatch, device and
    /// why.
    pub(crate) xdp_uncovered: c_int,
    pub(crate) xdp_uncovered_detail: Option<&'a CStr>,
    /// -errno when that could not be checked.
    pub(crate) xdp_coverage_rc: c_int,
}

/// One row in the status display. Names and status labels are static.
#[derive(Clone, Copy)]
pub struct Condition {
    pub(crate) kind: &'static CStr,
    pub(crate) status: &'static CStr,
    pub(crate) detail: [u8; 192],
}

impl Condition {
    pub(crate) const fn empty() -> Self {
        Self {
            kind: c"",
            status: c"",
            detail: [0; 192],
        }
    }
}

/// `CONDITIONS_MAX`: the conditions there are.
pub(crate) const CONDITIONS_MAX: usize = 7;

const OK: &CStr = c"OK";
const WARN: &CStr = c"WARN";
const ALERT: &CStr = c"ALERT";

/// The status and the detail of a condition, the detail as snprintf()
/// prints the format and its arguments. A list of names can outgrow the
/// detail, and its start still says the most, so a detail too long is cut
/// and ends in "..."; one that does not print is "?".
macro_rules! set_detail {
    ($c:expr, $status:expr, $fmt:expr $(, $arg:expr)* $(,)?) => {{
        let c: &mut Condition = $c;
        let mut full = [0u8; 1024];

        c.status = $status;
        // SAFETY: the room of the buffer, and a format whose conversions
        // take the arguments given, in their C types.
        let n = unsafe { snprintf(full.as_mut_ptr().cast(), full.len(), $fmt.as_ptr() $(, $arg)*) };

        cut_detail(c, (n >= 0 && (n as usize) < full.len()).then(|| crate::text::cstr(&full)));
    }};
}

fn cut_detail(c: &mut Condition, full: Option<&[u8]>) {
    let Some(full) = full else {
        let _ = strscpy(&mut c.detail, b"?");
        return;
    };
    if strscpy(&mut c.detail, full).is_err() {
        let end = c.detail.len();
        c.detail[end - 4..].copy_from_slice(b"...\0");
    }
}

/// What an absent string field shows in a condition detail.
fn or_unknown(s: Option<&CStr>) -> *const c_char {
    s.unwrap_or(c"?").as_ptr()
}

fn config_untrusted(i: &ConditionsInput<'_>) -> bool {
    i.config_seen != 0 && i.config_state != 0 && i.config_state != -EINPROGRESS
}

fn config_untrusted_detail(state: c_int) -> &'static CStr {
    if state == -ESTALE {
        c"the config activation record does not belong to this TPM boot"
    } else if state == -EKEYREJECTED {
        c"the mounted config does not match the selected root"
    } else {
        c"the config PCR, activation records and mounted config disagree"
    }
}

fn keyring_tampered(i: &ConditionsInput<'_>) -> bool {
    (i.ksp_seen != 0 && i.keyring_present == 0)
        || (i.ksm_seen != 0 && i.keyring_serial_matches == 0)
        || (i.dmvp_seen != 0 && i.dmv_present == 0)
        || (i.dmvm_seen != 0 && i.dmv_serial_matches == 0)
        || i.bpf_unfrozen != 0
        || i.dmv_unfrozen != 0
        || i.dmv_key_missing != 0
}

/// "" for one link, "s" for more.
fn plural(n: c_int) -> *const c_char {
    if n == 1 { c"".as_ptr() } else { c"s".as_ptr() }
}

fn keyring_condition(i: &ConditionsInput<'_>, c: &mut Condition) {
    c.kind = c"KeyringSealed";
    if i.keyring_present == 0 && i.ksp_seen != 0 {
        set_detail!(
            c,
            ALERT,
            c"pinned serial %lld, the .bpf keyring is gone",
            i.keyring_serial_pinned
        );
    } else if i.keyring_present == 0 {
        set_detail!(c, WARN, c".bpf keyring absent before init");
    } else if i.ksm_seen != 0 && i.keyring_serial_matches == 0 {
        set_detail!(
            c,
            ALERT,
            c"pinned serial %lld, live serial %lld: swapped",
            i.keyring_serial_pinned,
            i.keyring_serial,
        );
    } else if i.bpf_unfrozen != 0 {
        set_detail!(
            c,
            ALERT,
            c"the BPF keyring holds %d link%s init did not freeze",
            i.bpf_unfrozen,
            plural(i.bpf_unfrozen),
        );
    } else if i.dmvp_seen != 0 && i.dmv_present == 0 {
        set_detail!(
            c,
            ALERT,
            c"dm-verity pinned serial %lld, the dm-verity keyring is gone",
            i.dmv_serial_pinned,
        );
    } else if i.dmvm_seen != 0 && i.dmv_serial_matches == 0 {
        set_detail!(
            c,
            ALERT,
            c"dm-verity pinned serial %lld, live serial %lld: swapped",
            i.dmv_serial_pinned,
            i.dmv_serial,
        );
    } else if i.dmv_unfrozen != 0 {
        set_detail!(
            c,
            ALERT,
            c"the dm-verity keyring holds %d link%s init did not freeze",
            i.dmv_unfrozen,
            plural(i.dmv_unfrozen),
        );
    } else if i.dmv_key_missing != 0 {
        set_detail!(
            c,
            ALERT,
            c"a config key init froze is gone from the dm-verity keyring"
        );
    } else if i.ksp_seen != 0 && i.dmvp_seen != 0 {
        set_detail!(
            c,
            OK,
            c"bpf serial %lld, dm-verity serial %lld, pins match",
            i.keyring_serial,
            i.dmv_serial,
        );
    } else {
        let pin = if i.ksp_seen != 0 {
            c"pin matches"
        } else {
            c"no pin recorded"
        };

        set_detail!(
            c,
            OK,
            c"bpf serial %lld, %s",
            i.keyring_serial,
            pin.as_ptr()
        );
    }
}

/// A condition whose detail is fixed text.
fn set_fixed(c: &mut Condition, status: &'static CStr, detail: &CStr) {
    c.status = status;
    let _ = strscpy(&mut c.detail, detail.to_bytes());
}

/// The conditions, as many as `out` holds, in their order: LsmAttached,
/// KeyringSealed, ChainIntact, UpatchesMeasured, TpmMeasured,
/// ConfigActive and XdpCovered; returns how many it wrote.
pub(crate) fn conditions(i: &ConditionsInput<'_>, out: &mut [Condition]) -> usize {
    let n = out.len().min(CONDITIONS_MAX);
    let mut it = out[..n].iter_mut();

    if let Some(c) = it.next() {
        c.kind = c"LsmAttached";
        if i.lsm_attached != 0 {
            set_fixed(c, OK, c"lsm/bpf link present and pinned");
        } else {
            set_fixed(c, ALERT, c"lsm/bpf link absent, enforcement off");
        }
    }
    if let Some(c) = it.next() {
        keyring_condition(i, c);
    }
    if let Some(c) = it.next() {
        c.kind = c"ChainIntact";
        if i.chain_seen == 0 {
            let detail = if i.tpm_reachable != 0 {
                c"no register bound this boot (init incomplete)"
            } else {
                c"no TPM answered, no register to replay"
            };

            set_fixed(c, WARN, detail);
        } else if i.cm_seen != 0 && i.chain_matches != 0 {
            set_fixed(c, OK, c"live register equals the eventlog replay");
        } else if i.cm_seen != 0 {
            set_fixed(c, ALERT, c"live register differs from the eventlog replay");
        } else {
            set_fixed(c, WARN, c"chain present, replay not evaluated");
        }
    }
    if let Some(c) = it.next() {
        c.kind = c"UpatchesMeasured";
        if i.xdp_tampered != 0 {
            set_detail!(
                c,
                ALERT,
                c"%d XDP archives differ from the loaded payload: %s",
                i.xdp_tampered,
                or_unknown(i.xdp_tampered_detail),
            );
        } else if i.links_lost != 0 {
            set_detail!(
                c,
                ALERT,
                c"%d upatches are missing a link or their archive: %s",
                i.links_lost,
                or_unknown(i.links_lost_detail),
            );
        } else if i.pins_rc == -ENOENT {
            set_detail!(c, WARN, c"no record of this boot to check the pins against");
        } else if i.pins_rc == -EBADMSG {
            set_detail!(
                c,
                ALERT,
                c"this boot's records do not fold to the measurement register"
            );
        } else if i.pins_rc != 0 {
            // SAFETY: a call that takes no pointer.
            let reason = unsafe { strerror(-i.pins_rc) };

            set_detail!(c, WARN, c"pins not checked against the records: %s", reason);
        } else if i.pins_unmeasured != 0 {
            set_detail!(
                c,
                ALERT,
                c"%d pinned or archived without a record of this boot: %s",
                i.pins_unmeasured,
                or_unknown(i.pins_detail),
            );
        } else if i.checks_rc != 0 {
            // SAFETY: a call that takes no pointer.
            let reason = unsafe { strerror(-i.checks_rc) };

            set_detail!(c, WARN, c"links or archives not checked: %s", reason);
        } else {
            set_detail!(
                c,
                OK,
                c"every pinned or archived upatch is in this boot's records"
            );
        }
    }
    if let Some(c) = it.next() {
        c.kind = c"TpmMeasured";
        if i.chain_seen != 0 {
            set_detail!(c, OK, c"NV index %s readable", or_unknown(i.nv_index));
        } else if i.tpm_reachable != 0 {
            set_detail!(
                c,
                WARN,
                c"NV index %s not bound this boot",
                or_unknown(i.nv_index)
            );
        } else {
            set_fixed(c, WARN, c"no TPM answered");
        }
    }
    if let Some(c) = it.next() {
        let root = or_unknown(i.config_root);

        c.kind = c"ConfigActive";
        if i.config_seen == 0 {
            set_fixed(c, WARN, c"no config activation state before init");
        } else if i.config_state == -EINPROGRESS {
            set_detail!(
                c,
                WARN,
                c"the activation of config %.12s.. is pending until the next reboot",
                root,
            );
        } else if config_untrusted(i) {
            set_fixed(c, ALERT, config_untrusted_detail(i.config_state));
        } else {
            set_detail!(c, OK, c"config %.12s.. is active", root);
        }
    }
    if let Some(c) = it.next() {
        c.kind = c"XdpCovered";
        if i.xdp_uncovered != 0 {
            set_detail!(
                c,
                WARN,
                c"%d selected devices run without their XDP upatch: %s",
                i.xdp_uncovered,
                or_unknown(i.xdp_uncovered_detail),
            );
        } else if i.xdp_coverage_rc == -EXDEV {
            set_fixed(
                c,
                WARN,
                c"XDP coverage not checked: not in the initial network namespace",
            );
        } else if i.xdp_coverage_rc != 0 {
            // SAFETY: a call that takes no pointer.
            let reason = unsafe { strerror(-i.xdp_coverage_rc) };

            set_detail!(c, WARN, c"XDP coverage not checked: %s", reason);
        } else {
            set_fixed(c, OK, c"every device an XDP upatch selects runs it");
        }
    }
    n
}

/// The conditions as the table `shirudo status` prints.
pub(crate) fn conditions_print(conds: &[Condition]) {
    let row = c"  %-18s %-7s %s\n";

    // SAFETY: formats of C strings, and the conditions' strings.
    unsafe {
        printf(c"Conditions:\n".as_ptr());
        printf(
            row.as_ptr(),
            c"TYPE".as_ptr(),
            c"STATUS".as_ptr(),
            c"DETAIL".as_ptr(),
        );
        for c in conds {
            printf(
                row.as_ptr(),
                c.kind.as_ptr(),
                c.status.as_ptr(),
                c.detail.as_ptr(),
            );
        }
    }
}

/// The verdict in one word, from worst to best: unreachable,
/// unparseable, tampered, lsm-off, init-pending, reboot-pending,
/// degraded, ok.
pub(crate) fn status_verdict(i: &ConditionsInput<'_>) -> &'static CStr {
    if !i.reachable {
        c"unreachable"
    } else if !i.parsed {
        c"unparseable"
    } else if (i.cm_seen != 0 && i.chain_matches == 0)
        || i.pins_unmeasured != 0
        || i.pins_rc == -EBADMSG
        || i.xdp_tampered != 0
        || i.links_lost != 0
        || keyring_tampered(i)
        || config_untrusted(i)
    {
        c"tampered"
    } else if i.lsm_attached == 0 {
        c"lsm-off"
    } else if i.keyring_present == 0 {
        c"init-pending"
    } else if i.config_seen != 0 && i.config_state == -EINPROGRESS {
        c"reboot-pending"
    } else if i.chain_seen == 0 || i.xdp_uncovered != 0 {
        c"degraded"
    } else {
        c"ok"
    }
}

/// The reason for the verdict. Borrowing the caller's text keeps the
/// full message when it exceeds the old fixed output buffer.
pub(crate) fn status_reason<'a>(i: &ConditionsInput<'a>) -> &'a CStr {
    match status_verdict(i).to_bytes() {
        b"unreachable" => i.unreach.unwrap_or(c""),
        b"unparseable" => c"status JSON unparseable",
        b"tampered" => {
            if i.cm_seen != 0 && i.chain_matches == 0 {
                c"live register differs from the eventlog replay"
            } else if i.xdp_tampered != 0 {
                c"the archive of a loaded XDP upatch differs from what was loaded"
            } else if i.links_lost != 0 {
                c"a loaded upatch is missing a link or its archive"
            } else if i.pins_unmeasured != 0 {
                c"a upatch is pinned or archived without a record of this boot"
            } else if i.pins_rc == -EBADMSG {
                c"this boot's records do not fold to the measurement register"
            } else if config_untrusted(i) {
                c"the selected config cannot be verified against its records"
            } else if i.ksp_seen != 0 && i.keyring_present == 0 {
                c"the keyring init froze is gone"
            } else if i.ksm_seen != 0 && i.keyring_serial_matches == 0 {
                c"keyring serial swap detected"
            } else if i.dmvp_seen != 0 && i.dmv_present == 0 {
                c"the dm-verity keyring init froze is gone"
            } else if i.dmvm_seen != 0 && i.dmv_serial_matches == 0 {
                c"dm-verity keyring serial swap detected"
            } else if i.bpf_unfrozen != 0 || i.dmv_unfrozen != 0 {
                c"a keyring holds a link init did not freeze"
            } else {
                c"the config key init froze is gone"
            }
        }
        b"lsm-off" => c"LSM not attached, enforcement off",
        b"init-pending" => c".bpf keyring absent before init",
        b"reboot-pending" => c"a config activation is pending until the next reboot",
        b"degraded" if i.chain_seen != 0 => c"a device an XDP upatch selects does not run it",
        b"degraded" if i.tpm_reachable != 0 => c"no register bound this boot",
        b"degraded" => c"no TPM answered",
        _ => c"",
    }
}

#[cfg(test)]
mod tests;
