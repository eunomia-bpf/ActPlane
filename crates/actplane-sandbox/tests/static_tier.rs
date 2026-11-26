// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! Unprivileged integration tests for the static tier. Each test launches
//! children under a real Landlock + seccomp sandbox; none needs root.
//!
//! A child is this test binary re-executed with `ACTPLANE_SANDBOX_PROBE`
//! set: the `probe_entry` test performs one operation and exits with a code
//! that names the outcome. File-system tests skip with a message when the
//! kernel has no Landlock, unless `ACTPLANE_REQUIRE_LANDLOCK` is set (CI sets
//! it, so a missing Landlock fails CI instead of skipping silently).
#![cfg(target_os = "linux")]

use actplane_sandbox::plan::{FsConstraint, LANDLOCK_ABI_SCOPE, LANDLOCK_ABI_WRITE};
use actplane_sandbox::{Allowed, FsClass, Sandbox, SandboxSpec, prepare, probe};
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;

const PROBE: &str = "ACTPLANE_SANDBOX_PROBE";
const PROBE_ARG: &str = "ACTPLANE_SANDBOX_PROBE_ARG";

const OK: i32 = 0;
const EACCES: i32 = 10;
const EPERM: i32 = 11;
const OTHER: i32 = 12;

fn code_for(err: &std::io::Error) -> i32 {
    match err.raw_os_error() {
        Some(libc::EACCES) => EACCES,
        Some(libc::EPERM) => EPERM,
        _ => {
            eprintln!("probe error: {err}");
            OTHER
        }
    }
}

fn last_os_error_code() -> i32 {
    code_for(&std::io::Error::last_os_error())
}

/// Entry point of probe children; a no-op in the normal test run.
#[test]
fn probe_entry() {
    let Ok(action) = std::env::var(PROBE) else {
        return;
    };
    let arg = std::env::var(PROBE_ARG).unwrap_or_default();
    let code = match action.as_str() {
        "write" => match std::fs::write(&arg, b"probe") {
            Ok(()) => OK,
            Err(e) => code_for(&e),
        },
        "connect" => match TcpStream::connect(&arg) {
            Ok(_) => OK,
            Err(e) => code_for(&e),
        },
        "bind" => match TcpListener::bind("127.0.0.1:0") {
            Ok(_) => OK,
            Err(e) => code_for(&e),
        },
        "udp" => match UdpSocket::bind("127.0.0.1:0") {
            Ok(_) => OK,
            Err(e) => code_for(&e),
        },
        "io_uring" => {
            // struct io_uring_params is 120 bytes; zeroed is a valid request.
            let mut params = [0u8; 120];
            let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
            if fd >= 0 {
                unsafe { libc::close(fd as i32) };
                OK
            } else {
                last_os_error_code()
            }
        }
        "ptrace" => {
            // PTRACE_TRACEME = 0
            let zero: libc::c_long = 0;
            let rc = unsafe { libc::syscall(libc::SYS_ptrace, zero, zero, zero, zero) };
            if rc == 0 { OK } else { last_os_error_code() }
        }
        "signal-parent" => {
            let rc = unsafe { libc::kill(libc::getppid(), libc::SIGCONT) };
            if rc == 0 { OK } else { last_os_error_code() }
        }
        "status" => {
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            let field = |name: &str| {
                status
                    .lines()
                    .find_map(|l| l.strip_prefix(name))
                    .map(|v| v.trim().to_string())
                    .unwrap_or_default()
            };
            if field("Seccomp:") == "2" && field("NoNewPrivs:") == "1" {
                OK
            } else {
                eprintln!(
                    "Seccomp={} NoNewPrivs={}",
                    field("Seccomp:"),
                    field("NoNewPrivs:")
                );
                OTHER
            }
        }
        other => panic!("unknown probe action {other}"),
    };
    std::process::exit(code);
}

/// Run one probe action in a child, under `sandbox` when given.
fn run_probe(sandbox: Option<&Sandbox>, action: &str, arg: &str) -> i32 {
    let exe = std::env::current_exe().expect("test binary path");
    let mut cmd = Command::new(exe);
    cmd.args([
        "probe_entry",
        "--exact",
        "--nocapture",
        "--test-threads",
        "1",
        "-q",
    ])
    .env(PROBE, action)
    .env(PROBE_ARG, arg);
    if let Some(sandbox) = sandbox {
        sandbox.install(&mut cmd);
    }
    let out = cmd.output().expect("spawn probe child");
    let code = out.status.code().unwrap_or(-1);
    if code != OK {
        eprintln!(
            "probe {action} {arg} -> {code}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    code
}

fn landlock_or_skip(test: &str, min_abi: i32) -> bool {
    let host = probe();
    if host.landlock_abi >= min_abi {
        eprintln!("{test}: running with Landlock ABI {}", host.landlock_abi);
        return true;
    }
    let msg = format!(
        "{test}: Landlock ABI {} is below the required {min_abi} ({})",
        host.landlock_abi,
        host.landlock_error.as_deref().unwrap_or("kernel too old")
    );
    if std::env::var_os("ACTPLANE_REQUIRE_LANDLOCK").is_some() {
        panic!("{msg}; ACTPLANE_REQUIRE_LANDLOCK is set, so this is a failure");
    }
    eprintln!("SKIP {msg}");
    false
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let path =
            std::env::temp_dir().join(format!("actplane-sandbox-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn join(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_confined_to(dir: &Path) -> SandboxSpec {
    SandboxSpec {
        fs: vec![FsConstraint {
            class: FsClass::Write,
            allowed: Allowed::Beneath(dir.to_path_buf()),
            rule: "confine".into(),
            clause: 1,
        }],
        deny_network: false,
    }
}

#[test]
fn write_outside_allowed_dir_is_denied_and_inside_succeeds() {
    if !landlock_or_skip("write confinement", LANDLOCK_ABI_WRITE) {
        return;
    }
    let allowed = TempDir::new("write-allowed");
    let outside = TempDir::new("write-outside");
    let sandbox = prepare(&write_confined_to(allowed.path())).expect("prepare sandbox");
    eprintln!("applied: {:#?}", sandbox.summary());

    let inside_file = allowed.join("inside.txt");
    assert_eq!(run_probe(Some(&sandbox), "write", &inside_file), OK);
    assert_eq!(std::fs::read(&inside_file).unwrap(), b"probe");

    let outside_file = outside.join("outside.txt");
    assert_eq!(run_probe(Some(&sandbox), "write", &outside_file), EACCES);
    assert!(!Path::new(&outside_file).exists());

    // The same write succeeds without the sandbox, so the denial above is
    // the sandbox's doing.
    assert_eq!(run_probe(None, "write", &outside_file), OK);
}

#[test]
fn read_only_domain_refuses_writes_but_keeps_dev_null() {
    if !landlock_or_skip("read-only domain", LANDLOCK_ABI_WRITE) {
        return;
    }
    let dir = TempDir::new("read-only");
    let spec = SandboxSpec {
        fs: vec![FsConstraint {
            class: FsClass::Write,
            allowed: Allowed::Nothing,
            rule: "ro".into(),
            clause: 1,
        }],
        deny_network: false,
    };
    let sandbox = prepare(&spec).expect("prepare sandbox");
    assert_eq!(run_probe(Some(&sandbox), "write", &dir.join("x")), EACCES);
    assert_eq!(run_probe(Some(&sandbox), "write", "/dev/null"), OK);
}

#[test]
fn tcp_connect_and_bind_are_blocked_when_network_is_denied() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let addr = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();
    let spec = SandboxSpec {
        fs: Vec::new(),
        deny_network: true,
    };
    let sandbox = prepare(&spec).expect("prepare sandbox");
    eprintln!("applied: {:#?}", sandbox.summary());

    let code = run_probe(Some(&sandbox), "connect", &addr);
    // Landlock (ABI >= 4) refuses connect with EACCES; below ABI 4 the
    // seccomp filter refuses the socket with EPERM.
    assert!(
        code == EACCES || code == EPERM,
        "sandboxed connect returned {code}"
    );
    match listener.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        other => panic!("listener saw a connection from the sandbox: {other:?}"),
    }
    let code = run_probe(Some(&sandbox), "bind", "");
    assert!(
        code == EACCES || code == EPERM,
        "sandboxed bind returned {code}"
    );

    assert_eq!(run_probe(None, "connect", &addr), OK);
}

#[test]
fn udp_socket_is_blocked_when_network_is_denied() {
    let spec = SandboxSpec {
        fs: Vec::new(),
        deny_network: true,
    };
    let sandbox = prepare(&spec).expect("prepare sandbox");
    assert_eq!(run_probe(Some(&sandbox), "udp", ""), EPERM);

    // The always-on hardening alone keeps UDP.
    let hardening = prepare(&SandboxSpec::default()).expect("prepare hardening");
    assert_eq!(run_probe(Some(&hardening), "udp", ""), OK);
}

#[test]
fn io_uring_and_ptrace_are_blocked_by_hardening() {
    let sandbox = prepare(&SandboxSpec::default()).expect("prepare hardening");
    eprintln!("applied: {:#?}", sandbox.summary());
    assert_eq!(
        run_probe(Some(&sandbox), "status", ""),
        OK,
        "seccomp filter and no_new_privs"
    );
    assert_eq!(run_probe(Some(&sandbox), "io_uring", ""), EPERM);
    assert_eq!(run_probe(Some(&sandbox), "ptrace", ""), EPERM);
    let unsandboxed = run_probe(None, "io_uring", "");
    eprintln!(
        "io_uring_setup without the sandbox -> {unsandboxed} (0 means available on this host)"
    );
}

#[test]
fn scoping_keeps_signals_inside_the_sandbox() {
    if !landlock_or_skip("signal scoping", LANDLOCK_ABI_SCOPE) {
        return;
    }
    let sandbox = prepare(&SandboxSpec::default()).expect("prepare hardening");
    assert_eq!(run_probe(Some(&sandbox), "signal-parent", ""), EPERM);
    assert_eq!(run_probe(None, "signal-parent", ""), OK);
}

#[test]
fn exec_allow_list_refuses_programs_written_by_the_agent() {
    if !landlock_or_skip("execute allow-list", LANDLOCK_ABI_WRITE) {
        return;
    }
    let sh = Path::new("/usr/bin/sh");
    let true_bin = Path::new("/usr/bin/true");
    if !sh.exists() || !true_bin.exists() {
        eprintln!("SKIP execute allow-list: /usr/bin/sh or /usr/bin/true is missing");
        return;
    }
    let work = TempDir::new("exec-work");
    let constraint = |class, allowed| FsConstraint {
        class,
        allowed,
        rule: "exec".into(),
        clause: 1,
    };

    // An exec root inside the writable region is refused up front.
    let overlapping = SandboxSpec {
        fs: vec![
            constraint(FsClass::Write, Allowed::Beneath(work.path().to_path_buf())),
            constraint(
                FsClass::Execute,
                Allowed::Beneath(work.path().to_path_buf()),
            ),
        ],
        deny_network: false,
    };
    let err = prepare(&overlapping).expect_err("overlapping exec and write roots");
    assert!(
        err.to_string().contains("overlaps the writable region"),
        "{err}"
    );

    let spec = SandboxSpec {
        fs: vec![
            constraint(FsClass::Write, Allowed::Beneath(work.path().to_path_buf())),
            constraint(FsClass::Execute, Allowed::Beneath(PathBuf::from("/usr"))),
        ],
        deny_network: false,
    };
    let sandbox = prepare(&spec).expect("prepare sandbox");
    let run_sh = |script: &str| {
        let mut cmd = Command::new(sh);
        cmd.arg("-c").arg(script).arg("sh").arg(work.path());
        sandbox.install(&mut cmd);
        let out = cmd.output().expect("spawn sh");
        eprintln!(
            "sh -c {script:?} -> {:?} stderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        out.status.code()
    };
    assert_eq!(run_sh("/usr/bin/true"), Some(0));
    // The copy succeeds (writes are allowed in the work dir), executing it
    // does not: the shell reports 126 for a program it may not execute.
    assert_eq!(run_sh("cp /usr/bin/true \"$1/t\" && \"$1/t\""), Some(126));
    assert!(work.path().join("t").exists());
}

#[test]
fn missing_allowed_root_fails_closed() {
    if !landlock_or_skip("missing root", LANDLOCK_ABI_WRITE) {
        return;
    }
    let spec = write_confined_to(Path::new("/nonexistent/actplane-sandbox-root"));
    let err = prepare(&spec).expect_err("missing root");
    assert!(err.to_string().contains("cannot be opened"), "{err}");
}
