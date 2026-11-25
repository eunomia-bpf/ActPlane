// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! Host support probe for the unprivileged backend (`actplane doctor`,
//! `compile --explain`). Probing needs no privileges.

use crate::plan::{LANDLOCK_ABI_SCOPE, LANDLOCK_ABI_TCP, LANDLOCK_ABI_WRITE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSupport {
    /// Landlock ABI version reported by the kernel; 0 when unavailable.
    pub landlock_abi: i32,
    /// Why Landlock is unavailable, when it is.
    pub landlock_error: Option<String>,
    /// seccomp filter mode can be installed.
    pub seccomp_filter: bool,
    /// `/proc/sys/kernel/seccomp/actions_avail`, when readable.
    pub seccomp_actions: Option<String>,
    /// `NoNewPrivs` of the current process, when readable.
    pub no_new_privs: Option<bool>,
    /// The seccomp filter knows this CPU architecture.
    pub seccomp_arch_supported: bool,
}

impl HostSupport {
    /// One line per capability, for `doctor` and `compile --explain`.
    pub fn landlock_summary(&self) -> String {
        if self.landlock_abi <= 0 {
            return format!(
                "unavailable ({}); only the seccomp hardening and seccomp network denial apply",
                self.landlock_error.as_deref().unwrap_or("unknown reason")
            );
        }
        let mut features = vec!["filesystem"];
        if self.landlock_abi >= LANDLOCK_ABI_WRITE {
            features.push("truncate");
        }
        if self.landlock_abi >= LANDLOCK_ABI_TCP {
            features.push("TCP connect/bind");
        }
        if self.landlock_abi >= LANDLOCK_ABI_SCOPE {
            features.push("signal and abstract-unix scoping");
        }
        let mut line = format!("ABI {} ({})", self.landlock_abi, features.join(", "));
        if self.landlock_abi < LANDLOCK_ABI_WRITE {
            line.push_str(&format!(
                "; write confinement needs ABI {LANDLOCK_ABI_WRITE} (Linux 6.2)"
            ));
        } else if self.landlock_abi < LANDLOCK_ABI_SCOPE {
            line.push_str(&format!(
                "; signal and abstract-unix scoping need ABI {LANDLOCK_ABI_SCOPE} (Linux 6.12)"
            ));
        }
        line
    }

    pub fn seccomp_summary(&self) -> String {
        if !self.seccomp_arch_supported {
            return "the static filter does not support this CPU architecture (x86_64 and aarch64 only)".into();
        }
        if !self.seccomp_filter {
            return "filter mode unavailable (kernel without CONFIG_SECCOMP_FILTER)".into();
        }
        match &self.seccomp_actions {
            Some(actions) => format!("filter mode available (actions: {})", actions.trim()),
            None => "filter mode available".into(),
        }
    }

    pub fn no_new_privs_summary(&self) -> String {
        match self.no_new_privs {
            Some(true) => "already set on this process; the launcher sets it on the launched process before exec".into(),
            Some(false) => "settable; the launcher sets it on the launched process before exec".into(),
            None => "unknown (cannot read /proc/self/status); the launcher sets it before exec".into(),
        }
    }
}

#[cfg(target_os = "linux")]
pub fn probe() -> HostSupport {
    let (landlock_abi, landlock_error) = match crate::linux::landlock_abi() {
        Ok(abi) => (abi, None),
        Err(e) => (0, Some(e)),
    };
    let status = std::fs::read_to_string("/proc/self/status").ok();
    let field = |name: &str| -> Option<String> {
        status.as_deref().and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix(name))
                .map(|v| v.trim().to_string())
        })
    };
    let no_new_privs = field("NoNewPrivs:").map(|v| v == "1");
    // PR_GET_SECCOMP fails with EINVAL when the kernel lacks seccomp.
    let zero: libc::c_ulong = 0;
    let seccomp_mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, zero, zero, zero, zero) };
    let seccomp_actions = std::fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail").ok();
    let seccomp_filter = seccomp_mode >= 0
        && seccomp_actions
            .as_deref()
            .is_none_or(|a| a.split_whitespace().any(|w| w == "errno"));
    HostSupport {
        landlock_abi,
        landlock_error,
        seccomp_filter,
        seccomp_actions,
        no_new_privs,
        seccomp_arch_supported: crate::seccomp::Arch::native().is_some(),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn probe() -> HostSupport {
    HostSupport {
        landlock_abi: 0,
        landlock_error: Some("Landlock and seccomp are Linux interfaces".into()),
        seccomp_filter: false,
        seccomp_actions: None,
        no_new_privs: None,
        seccomp_arch_supported: crate::seccomp::Arch::native().is_some(),
    }
}
