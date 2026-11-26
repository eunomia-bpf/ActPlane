// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! Linux application of a [`SandboxSpec`]: Landlock rulesets and the seccomp
//! filter are built in the launcher, and only async-signal-safe system calls
//! run in the child between `fork` and `execve`.

use crate::SandboxError;
use crate::plan::{
    Allowed, FsClass, LANDLOCK_ABI_SCOPE, LANDLOCK_ABI_TCP, SandboxSpec, class_region,
    exec_write_conflict,
};
use crate::seccomp::{self, Arch, FilterOptions};
use landlock::{
    AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, Scope, make_bitflags,
};
use std::collections::BTreeSet;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

/// Landlock allows 16 stacked layers per process, shared with any sandbox the
/// launcher already runs in; the static tier keeps well below that.
const MAX_LAYERS: usize = 8;

/// Character devices that stay writable and readable under file rules. The
/// bpf-lsm backend's file rules cover regular files and directories only, so
/// these keep the two backends aligned for the common device nodes.
const DEVICE_FILES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/ptmx",
];
const DEVICE_DIRS: &[&str] = &["/dev/pts"];

/// Kernel Landlock ABI, or why Landlock is unavailable.
pub fn landlock_abi() -> Result<i32, String> {
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if v >= 0 {
        return Ok(v as i32);
    }
    let err = std::io::Error::last_os_error();
    Err(match err.raw_os_error() {
        Some(libc::ENOSYS) => "the kernel is built without Landlock".into(),
        Some(libc::EOPNOTSUPP) => {
            "Landlock is built in but not enabled at boot (add `landlock` to the lsm= list)".into()
        }
        _ => format!("landlock_create_ruleset: {err}"),
    })
}

fn class_rights(class: FsClass, dir: bool) -> BitFlags<AccessFs> {
    match (class, dir) {
        (FsClass::Write, true) => make_bitflags!(AccessFs::{
            WriteFile | Truncate | RemoveFile | RemoveDir | MakeReg | MakeDir | MakeSym
                | MakeChar | MakeBlock | MakeSock | MakeFifo | Refer
        }),
        (FsClass::Write, false) => make_bitflags!(AccessFs::{WriteFile | Truncate}),
        (FsClass::Read, true) => make_bitflags!(AccessFs::{ReadFile | ReadDir}),
        (FsClass::Read, false) => make_bitflags!(AccessFs::{ReadFile}),
        (FsClass::Execute, _) => make_bitflags!(AccessFs::{Execute}),
    }
}

fn device_rights(class: FsClass) -> Option<BitFlags<AccessFs>> {
    match class {
        FsClass::Write => Some(make_bitflags!(AccessFs::{WriteFile | Truncate})),
        FsClass::Read => Some(make_bitflags!(AccessFs::{ReadFile})),
        FsClass::Execute => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Root {
    Nothing,
    Dir(PathBuf),
    File(PathBuf),
}

impl Root {
    fn describe(&self) -> String {
        match self {
            Root::Nothing => "nowhere".into(),
            Root::Dir(p) => format!("beneath {}", p.display()),
            Root::File(p) => format!("on {}", p.display()),
        }
    }

    fn as_allowed(&self) -> Allowed {
        match self {
            Root::Nothing => Allowed::Nothing,
            Root::Dir(p) => Allowed::Beneath(p.clone()),
            Root::File(p) => Allowed::File(p.clone()),
        }
    }
}

#[derive(Debug, Clone)]
struct Group {
    root: Root,
    classes: BTreeSet<FsClass>,
}

fn resolve(
    allowed: &Allowed,
    class: FsClass,
    rule: &str,
    clause: usize,
) -> Result<Root, SandboxError> {
    let what = |p: &Path| {
        format!(
            "rule {rule} clause {clause} allows {} {}",
            class.name(),
            p.display()
        )
    };
    match allowed {
        Allowed::Nothing => Ok(Root::Nothing),
        Allowed::Beneath(p) => {
            let meta = std::fs::metadata(p).map_err(|e| {
                SandboxError::new(format!("{}, which cannot be opened: {e}", what(p)))
            })?;
            if !meta.is_dir() {
                return Err(SandboxError::new(format!(
                    "{}/**, but {} is not a directory",
                    what(p),
                    p.display()
                )));
            }
            Ok(Root::Dir(canonical(p)?))
        }
        Allowed::File(p) => {
            let meta = std::fs::metadata(p).map_err(|e| {
                SandboxError::new(format!("{}, which cannot be opened: {e}", what(p)))
            })?;
            if meta.is_dir() {
                return Err(SandboxError::new(format!(
                    "{}, which is a directory; an exact target names one path, so use \"{}/**\" to allow the hierarchy",
                    what(p),
                    p.display()
                )));
            }
            Ok(Root::File(canonical(p)?))
        }
    }
}

fn canonical(p: &Path) -> Result<PathBuf, SandboxError> {
    std::fs::canonicalize(p)
        .map_err(|e| SandboxError::new(format!("cannot resolve {}: {e}", p.display())))
}

/// Merge constraints that share a root, then pack groups into as few
/// Landlock layers as possible. Inside one layer each access class is
/// handled by one group only, so a layer never widens a constraint: an access
/// of class C is allowed by the layer only where C's group allows it.
fn pack(groups: Vec<Group>) -> Vec<Vec<Group>> {
    let mut layers: Vec<Vec<Group>> = Vec::new();
    for g in groups {
        let slot = layers.iter_mut().find(|layer| {
            layer
                .iter()
                .all(|other| other.classes.is_disjoint(&g.classes))
        });
        match slot {
            Some(layer) => layer.push(g),
            None => layers.push(vec![g]),
        }
    }
    layers
}

/// What [`prepare`] arranged, for the launch summary.
#[derive(Debug, Clone, Default)]
pub struct Applied {
    pub landlock_abi: i32,
    pub layers: Vec<String>,
    pub network: Option<String>,
    pub scoping: String,
    pub seccomp: Vec<String>,
    pub notes: Vec<String>,
}

impl Applied {
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec!["no_new_privs is set before exec".to_string()];
        if self.landlock_abi > 0 {
            out.push(format!("Landlock ABI {}", self.landlock_abi));
        } else {
            out.push("Landlock unavailable".into());
        }
        for (i, layer) in self.layers.iter().enumerate() {
            out.push(format!("Landlock layer {}: {layer}", i + 1));
        }
        if let Some(net) = &self.network {
            out.push(format!("network: {net}"));
        }
        out.push(format!("scoping: {}", self.scoping));
        for s in &self.seccomp {
            out.push(format!("seccomp: {s}"));
        }
        out.extend(self.notes.iter().cloned());
        out
    }
}

/// A sandbox ready to be applied in a child process.
pub struct Prepared {
    rulesets: Vec<OwnedFd>,
    filter: Vec<libc::sock_filter>,
    applied: Applied,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("rulesets", &self.rulesets.len())
            .field("filter_len", &self.filter.len())
            .field("applied", &self.applied)
            .finish()
    }
}

/// Build the Landlock rulesets and the seccomp program for `spec` in the
/// launcher. Fails closed: any requirement the kernel cannot meet is an
/// error, never a silently weaker sandbox.
pub fn prepare(spec: &SandboxSpec) -> Result<Prepared, SandboxError> {
    let arch = Arch::native().ok_or_else(|| {
        SandboxError::new(
            "the unprivileged backend's seccomp filter supports x86_64 and aarch64 only",
        )
    })?;
    let (abi, landlock_error) = match landlock_abi() {
        Ok(abi) => (abi, None),
        Err(e) => (0, Some(e)),
    };
    let need = spec.landlock_min_abi();
    if need > abi {
        let classes: Vec<&str> = spec.classes().into_iter().map(FsClass::name).collect();
        return Err(SandboxError::new(format!(
            "this policy confines {} access with Landlock, which needs ABI {need} or newer; {}",
            classes.join("/"),
            match &landlock_error {
                Some(e) => format!("Landlock is unavailable: {e}"),
                None => format!("the kernel reports ABI {abi}"),
            }
        )));
    }

    // Resolve allowed roots and re-check the exec/write separation on real
    // paths (symlinks resolved).
    let mut resolved: Vec<(FsClass, Root)> = Vec::new();
    for c in &spec.fs {
        resolved.push((c.class, resolve(&c.allowed, c.class, &c.rule, c.clause)?));
    }
    let write_region = class_region(
        resolved
            .iter()
            .filter(|(class, _)| *class == FsClass::Write)
            .map(|(_, r)| r.as_allowed())
            .collect::<Vec<_>>()
            .iter(),
    );
    exec_write_conflict(
        resolved
            .iter()
            .filter(|(class, _)| *class == FsClass::Execute)
            .map(|(_, r)| (r.as_allowed(), String::new())),
        write_region,
    )
    .map_err(SandboxError::new)?;

    let mut groups: Vec<Group> = Vec::new();
    for (class, root) in resolved {
        match groups.iter_mut().find(|g| g.root == root) {
            Some(g) => {
                g.classes.insert(class);
            }
            None => groups.push(Group {
                root,
                classes: BTreeSet::from([class]),
            }),
        }
    }
    let mut layers = pack(groups);

    let landlock_tcp = spec.deny_network && abi >= LANDLOCK_ABI_TCP;
    let scoping = abi >= LANDLOCK_ABI_SCOPE;
    if layers.is_empty() && (landlock_tcp || scoping) {
        layers.push(Vec::new());
    }
    if layers.len() > MAX_LAYERS {
        return Err(SandboxError::new(format!(
            "this policy needs {} Landlock layers; the unprivileged backend stacks at most {MAX_LAYERS}",
            layers.len()
        )));
    }

    let mut applied = Applied {
        landlock_abi: abi,
        ..Applied::default()
    };
    let mut rulesets = Vec::new();
    for (idx, layer) in layers.iter().enumerate() {
        let (fd, description) = build_layer(layer, idx == 0 && landlock_tcp, idx == 0 && scoping)?;
        rulesets.push(fd);
        applied.layers.push(description);
    }

    let opts = FilterOptions {
        deny_network: spec.deny_network,
        landlock_tcp,
    };
    if spec.deny_network {
        applied.network = Some(if landlock_tcp {
            "Landlock refuses TCP connect and bind on every port; seccomp refuses other IPv4/IPv6 sockets".into()
        } else {
            format!(
                "seccomp refuses every IPv4/IPv6 socket (Landlock TCP control needs ABI {LANDLOCK_ABI_TCP})"
            )
        });
    }
    applied.scoping = if scoping {
        "Landlock scopes signals and abstract Unix sockets to the sandbox".into()
    } else {
        format!(
            "unavailable (needs Landlock ABI {LANDLOCK_ABI_SCOPE}); Landlock still blocks ptrace across the sandbox boundary when a layer is applied"
        )
    };
    applied.seccomp = seccomp::describe(opts);
    let filter = seccomp::build(arch, opts)
        .into_iter()
        .map(|i| libc::sock_filter {
            code: i.code,
            jt: i.jt,
            jf: i.jf,
            k: i.k,
        })
        .collect();
    Ok(Prepared {
        rulesets,
        filter,
        applied,
    })
}

fn landlock_err(e: impl std::fmt::Display) -> SandboxError {
    SandboxError::new(format!("Landlock: {e}"))
}

fn build_layer(
    groups: &[Group],
    tcp: bool,
    scope: bool,
) -> Result<(OwnedFd, String), SandboxError> {
    let mut handled = BitFlags::<AccessFs>::empty();
    for g in groups {
        for class in &g.classes {
            handled |= class_rights(*class, true);
        }
    }
    let mut ruleset = Ruleset::default().set_compatibility(CompatLevel::HardRequirement);
    if !handled.is_empty() {
        ruleset = ruleset.handle_access(handled).map_err(landlock_err)?;
    }
    if tcp {
        ruleset = ruleset
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
            .map_err(landlock_err)?;
    }
    if scope {
        ruleset = ruleset
            .scope(Scope::AbstractUnixSocket | Scope::Signal)
            .map_err(landlock_err)?;
    }
    let mut created = ruleset.create().map_err(landlock_err)?;
    let mut parts = Vec::new();
    let mut classes_here = BTreeSet::new();
    for g in groups {
        classes_here.extend(g.classes.iter().copied());
        let names: Vec<&str> = g.classes.iter().map(|c| c.name()).collect();
        parts.push(format!("{} allowed {}", names.join("+"), g.root.describe()));
        let (path, dir) = match &g.root {
            Root::Nothing => continue,
            Root::Dir(p) => (p, true),
            Root::File(p) => (p, false),
        };
        let mut rights = BitFlags::<AccessFs>::empty();
        for class in &g.classes {
            rights |= class_rights(*class, dir);
        }
        let fd = PathFd::new(path).map_err(landlock_err)?;
        created = created
            .add_rule(PathBeneath::new(fd, rights))
            .map_err(landlock_err)?;
    }
    let mut devices = Vec::new();
    for class in &classes_here {
        let Some(rights) = device_rights(*class) else {
            continue;
        };
        for dev in DEVICE_FILES {
            let ok = std::fs::metadata(dev).is_ok_and(|m| m.file_type().is_char_device());
            if ok {
                let fd = PathFd::new(dev).map_err(landlock_err)?;
                created = created
                    .add_rule(PathBeneath::new(fd, rights))
                    .map_err(landlock_err)?;
                devices.push(*dev);
            }
        }
        for dir in DEVICE_DIRS {
            if std::fs::metadata(dir).is_ok_and(|m| m.is_dir()) {
                let fd = PathFd::new(dir).map_err(landlock_err)?;
                created = created
                    .add_rule(PathBeneath::new(fd, rights))
                    .map_err(landlock_err)?;
                devices.push(*dir);
            }
        }
    }
    if !devices.is_empty() {
        devices.sort();
        devices.dedup();
        parts.push(format!("device nodes kept: {}", devices.join(" ")));
    }
    if tcp {
        parts.push("TCP connect/bind refused".into());
    }
    if scope {
        parts.push("signal + abstract Unix socket scoping".into());
    }
    let fd: Option<OwnedFd> = created.into();
    let fd = fd.ok_or_else(|| SandboxError::new("Landlock did not create a ruleset"))?;
    Ok((fd, parts.join("; ")))
}

impl Prepared {
    pub fn applied(&self) -> &Applied {
        &self.applied
    }

    /// Restrict the calling process: `no_new_privs`, every Landlock layer,
    /// then the seccomp filter. Uses only raw system calls on memory prepared
    /// by [`prepare`], so it is safe between `fork` and `execve`.
    pub fn apply_in_child(&self) -> std::io::Result<()> {
        unsafe {
            // prctl is variadic and the kernel reads unsigned long arguments.
            let one: libc::c_ulong = 1;
            let zero: libc::c_ulong = 0;
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for fd in &self.rulesets {
                if libc::syscall(libc::SYS_landlock_restrict_self, fd.as_raw_fd(), 0u32) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            let prog = libc::sock_fprog {
                len: self.filter.len() as libc::c_ushort,
                filter: self.filter.as_ptr() as *mut libc::sock_filter,
            };
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &prog as *const libc::sock_fprog as libc::c_ulong,
                zero,
                zero,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Apply the sandbox in `cmd`'s child right before `execve`.
    pub fn install(self: &Arc<Self>, cmd: &mut Command) {
        let prepared = Arc::clone(self);
        // SAFETY: apply_in_child performs only async-signal-safe system calls
        // on data allocated before fork.
        unsafe {
            cmd.pre_exec(move || prepared.apply_in_child());
        }
    }
}

/// Run `argv` under `prepared`, optionally switching to `drop_to` (uid, gid)
/// first, and wait for it.
pub fn run(
    argv: &[String],
    prepared: Arc<Prepared>,
    drop_to: Option<(u32, u32)>,
) -> std::io::Result<std::process::ExitStatus> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty command"))?;
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some((uid, gid)) = drop_to {
        // SAFETY: setgid/setuid are async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    prepared.install(&mut cmd);
    cmd.status()
}
