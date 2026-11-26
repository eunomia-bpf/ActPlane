// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! Unprivileged ActPlane enforcement backend.
//!
//! The default backend loads the eBPF engine and needs root (or CAP_BPF,
//! CAP_PERFMON and CAP_SYS_ADMIN) plus a kernel booted with `lsm=bpf`. This
//! crate is the static tier of the second backend described in
//! `docs/design/unprivileged-backend.md`: it takes the same parsed policy,
//! decides which clauses map exactly onto Landlock allow-lists and seccomp
//! filters, and applies them in the launched child right before `execve`
//! (`no_new_privs`, `landlock_restrict_self`, seccomp). No privilege is
//! needed. A policy with any clause that does not map exactly is refused.
//!
//! The crate does not depend on the eBPF engine.

pub mod host;
pub mod plan;
pub mod report;
pub mod seccomp;

#[cfg(target_os = "linux")]
mod linux;

pub use host::{HostSupport, probe};
pub use plan::{Allowed, Analysis, ClauseReport, ClauseStatus, FsClass, SandboxSpec, analyze};

/// Error preparing or applying the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxError(String);

impl SandboxError {
    pub fn new(message: impl Into<String>) -> Self {
        SandboxError(message.into())
    }
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SandboxError {}

/// A sandbox prepared in the launcher, ready to apply to children.
#[derive(Debug, Clone)]
pub struct Sandbox {
    #[cfg(target_os = "linux")]
    inner: std::sync::Arc<linux::Prepared>,
}

/// Build the Landlock rulesets and seccomp program for `spec`. Fails when
/// the host cannot enforce every constraint.
pub fn prepare(spec: &SandboxSpec) -> Result<Sandbox, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        Ok(Sandbox {
            inner: std::sync::Arc::new(linux::prepare(spec)?),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = spec;
        Err(SandboxError::new(
            "the unprivileged backend uses Landlock and seccomp, which are Linux interfaces",
        ))
    }
}

impl Sandbox {
    /// What the sandbox applies, one line per item.
    pub fn summary(&self) -> Vec<String> {
        #[cfg(target_os = "linux")]
        {
            self.inner.applied().lines()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Vec::new()
        }
    }

    /// Restrict the calling process. Only call this in a child between
    /// `fork` and `execve` (or in a process that will only `execve`).
    pub fn apply_in_child(&self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.inner.apply_in_child()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "unprivileged backend is Linux-only",
            ))
        }
    }

    /// Apply the sandbox in `cmd`'s child right before `execve`.
    #[cfg(target_os = "linux")]
    pub fn install(&self, cmd: &mut std::process::Command) {
        self.inner.install(cmd);
    }

    /// Run `argv` under the sandbox and wait for it. With `drop_to`, the
    /// child first switches to that (uid, gid), as sudo-launched `run` does.
    pub fn run(
        &self,
        argv: &[String],
        drop_to: Option<(u32, u32)>,
    ) -> std::io::Result<std::process::ExitStatus> {
        #[cfg(target_os = "linux")]
        {
            linux::run(argv, std::sync::Arc::clone(&self.inner), drop_to)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (argv, drop_to);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "unprivileged backend is Linux-only",
            ))
        }
    }
}
