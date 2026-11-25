// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! Hand-written classic-BPF seccomp filter for the static tier.
//!
//! The filter is small and fixed, so it is assembled here instead of pulling
//! in a filter compiler. It is built for an explicit architecture, which lets
//! the unit tests run the same program through [`run`] on any host.

/// One classic BPF instruction (`struct sock_filter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JA: u16 = 0x05;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JGE_K: u16 = 0x35;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_RET_K: u16 = 0x06;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const EPERM: u32 = 1;

// struct seccomp_data offsets
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const fn off_arg_lo(i: u32) -> u32 {
    16 + 8 * i
}

const AF_UNIX: u32 = 1;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const AF_NETLINK: u32 = 16;
const AF_PACKET: u32 = 17;
const SOCK_STREAM: u32 = 1;
const SOCK_RAW: u32 = 3;
const SOCK_PACKET: u32 = 10;
const SOCK_TYPE_MASK: u32 = 0xf;
const IPPROTO_TCP: u32 = 6;
const MSG_FASTOPEN: u32 = 0x2000_0000;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

struct Nr {
    socket: u32,
    sendto: u32,
    sendmsg: u32,
    sendmmsg: u32,
    ptrace: u32,
    process_vm_writev: u32,
    io_uring_setup: u32,
    io_uring_enter: u32,
    io_uring_register: u32,
}

impl Arch {
    /// The architecture this binary runs on, if the filter supports it.
    pub fn native() -> Option<Arch> {
        if cfg!(target_arch = "x86_64") {
            Some(Arch::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Arch::Aarch64)
        } else {
            None
        }
    }

    /// `AUDIT_ARCH_*` value the kernel reports in `seccomp_data.arch`.
    pub fn audit_arch(self) -> u32 {
        match self {
            Arch::X86_64 => 0xc000_003e,
            Arch::Aarch64 => 0xc000_00b7,
        }
    }

    fn nr(self) -> Nr {
        match self {
            Arch::X86_64 => Nr {
                socket: 41,
                sendto: 44,
                sendmsg: 46,
                sendmmsg: 307,
                ptrace: 101,
                process_vm_writev: 311,
                io_uring_setup: 425,
                io_uring_enter: 426,
                io_uring_register: 427,
            },
            Arch::Aarch64 => Nr {
                socket: 198,
                sendto: 206,
                sendmsg: 211,
                sendmmsg: 269,
                ptrace: 117,
                process_vm_writev: 271,
                io_uring_setup: 425,
                io_uring_enter: 426,
                io_uring_register: 427,
            },
        }
    }
}

/// What the filter must refuse beyond the always-on hardening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FilterOptions {
    /// The policy denies every network connection.
    pub deny_network: bool,
    /// Landlock refuses TCP connect/bind, so TCP sockets may still be
    /// created; without it every IPv4/IPv6 socket is refused.
    pub landlock_tcp: bool,
}

/// Human-readable list of what [`build`] refuses with these options.
pub fn describe(opts: FilterOptions) -> Vec<String> {
    let mut out = vec![
        "io_uring_setup, io_uring_enter and io_uring_register return EPERM (seccomp cannot see io_uring submissions)".to_string(),
        "ptrace and process_vm_writev return EPERM".to_string(),
        "socket(AF_PACKET, ...) and SOCK_RAW/SOCK_PACKET sockets outside AF_NETLINK return EPERM".to_string(),
        "system calls through a foreign ABI (x32, 32-bit compat) are refused; a foreign-architecture call kills the process".to_string(),
    ];
    if opts.deny_network {
        if opts.landlock_tcp {
            out.push("IPv4/IPv6 sockets other than TCP stream sockets return EPERM, and so do TCP fast-open sends (Landlock refuses TCP connect and bind)".into());
        } else {
            out.push(
                "every IPv4/IPv6 socket returns EPERM (Landlock TCP control needs ABI 4)".into(),
            );
        }
    }
    out
}

#[derive(Clone, Copy)]
enum L {
    Next,
    Allow,
    Errno,
    Kill,
    Socket,
    Inet,
    Send2,
    Send3,
}

enum Op {
    Ld(u32),
    And(u32),
    Jeq(u32, L, L),
    Jge(u32, L, L),
    Jset(u32, L, L),
    Ja(L),
    Ret(u32),
    Label(L),
}

/// Assemble the filter for `arch`.
pub fn build(arch: Arch, opts: FilterOptions) -> Vec<Insn> {
    use L::*;
    let nr = arch.nr();
    let mut p = vec![
        Op::Ld(OFF_ARCH),
        Op::Jeq(arch.audit_arch(), Next, Kill),
        Op::Ld(OFF_NR),
    ];
    if arch == Arch::X86_64 {
        p.push(Op::Jge(X32_SYSCALL_BIT, Errno, Next));
    }
    for n in [
        nr.io_uring_setup,
        nr.io_uring_enter,
        nr.io_uring_register,
        nr.ptrace,
        nr.process_vm_writev,
    ] {
        p.push(Op::Jeq(n, Errno, Next));
    }
    p.push(Op::Jeq(nr.socket, Socket, Next));
    if opts.deny_network {
        p.push(Op::Jeq(nr.sendto, Send3, Next));
        p.push(Op::Jeq(nr.sendmmsg, Send3, Next));
        p.push(Op::Jeq(nr.sendmsg, Send2, Next));
    }
    p.push(Op::Ret(SECCOMP_RET_ALLOW));

    // socket(domain, type, protocol)
    p.push(Op::Label(Socket));
    p.push(Op::Ld(off_arg_lo(0)));
    p.push(Op::Jeq(AF_PACKET, Errno, Next));
    if opts.deny_network {
        p.push(Op::Jeq(AF_INET, Inet, Next));
        p.push(Op::Jeq(AF_INET6, Inet, Next));
    }
    p.push(Op::Jeq(AF_NETLINK, Allow, Next));
    p.push(Op::Jeq(AF_UNIX, Allow, Next));
    p.push(Op::Ld(off_arg_lo(1)));
    p.push(Op::And(SOCK_TYPE_MASK));
    p.push(Op::Jeq(SOCK_RAW, Errno, Next));
    p.push(Op::Jeq(SOCK_PACKET, Errno, Next));
    p.push(Op::Ret(SECCOMP_RET_ALLOW));

    if opts.deny_network {
        p.push(Op::Label(Inet));
        if opts.landlock_tcp {
            p.push(Op::Ld(off_arg_lo(1)));
            p.push(Op::And(SOCK_TYPE_MASK));
            p.push(Op::Jeq(SOCK_STREAM, Next, Errno));
            p.push(Op::Ld(off_arg_lo(2)));
            p.push(Op::Jeq(0, Allow, Next));
            p.push(Op::Jeq(IPPROTO_TCP, Allow, Errno));
        } else {
            p.push(Op::Ja(Errno));
        }
        // sendto(fd, buf, len, flags, ...) and sendmmsg(fd, vec, n, flags)
        p.push(Op::Label(Send3));
        p.push(Op::Ld(off_arg_lo(3)));
        p.push(Op::Jset(MSG_FASTOPEN, Errno, Allow));
        // sendmsg(fd, msg, flags)
        p.push(Op::Label(Send2));
        p.push(Op::Ld(off_arg_lo(2)));
        p.push(Op::Jset(MSG_FASTOPEN, Errno, Allow));
    }

    p.push(Op::Label(Allow));
    p.push(Op::Ret(SECCOMP_RET_ALLOW));
    p.push(Op::Label(Errno));
    p.push(Op::Ret(SECCOMP_RET_ERRNO | EPERM));
    p.push(Op::Label(Kill));
    p.push(Op::Ret(SECCOMP_RET_KILL_PROCESS));
    assemble(&p)
}

fn assemble(ops: &[Op]) -> Vec<Insn> {
    // First pass: label positions in instruction indices.
    let mut pos = Vec::new();
    let mut idx = 0usize;
    for op in ops {
        match op {
            Op::Label(l) => pos.push((*l as u8, idx)),
            _ => idx += 1,
        }
    }
    let target = |l: L, at: usize| -> usize {
        match l {
            L::Next => at + 1,
            other => pos
                .iter()
                .find(|(k, _)| *k == other as u8)
                .map(|(_, p)| *p)
                .expect("undefined seccomp label"),
        }
    };
    let rel = |l: L, at: usize| -> u8 {
        let to = target(l, at);
        assert!(to > at, "seccomp jumps must go forward");
        u8::try_from(to - at - 1).expect("seccomp jump out of range")
    };
    let mut out = Vec::new();
    for op in ops {
        let at = out.len();
        let insn = match *op {
            Op::Label(_) => continue,
            Op::Ld(off) => Insn {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: off,
            },
            Op::And(k) => Insn {
                code: BPF_ALU_AND_K,
                jt: 0,
                jf: 0,
                k,
            },
            Op::Jeq(k, t, f) => Insn {
                code: BPF_JMP_JEQ_K,
                jt: rel(t, at),
                jf: rel(f, at),
                k,
            },
            Op::Jge(k, t, f) => Insn {
                code: BPF_JMP_JGE_K,
                jt: rel(t, at),
                jf: rel(f, at),
                k,
            },
            Op::Jset(k, t, f) => Insn {
                code: BPF_JMP_JSET_K,
                jt: rel(t, at),
                jf: rel(f, at),
                k,
            },
            Op::Ja(t) => Insn {
                code: BPF_JMP_JA,
                jt: 0,
                jf: 0,
                k: (target(t, at) - at - 1) as u32,
            },
            Op::Ret(k) => Insn {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k,
            },
        };
        out.push(insn);
    }
    out
}

/// Minimal interpreter for the instructions [`build`] emits, used by tests to
/// check the program's decisions without loading it.
pub fn run(prog: &[Insn], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
    let load = |off: u32| -> u32 {
        match off {
            OFF_NR => nr,
            OFF_ARCH => arch,
            o if (16..64).contains(&o) => {
                let i = ((o - 16) / 8) as usize;
                if (o - 16) % 8 == 0 {
                    args[i] as u32
                } else {
                    (args[i] >> 32) as u32
                }
            }
            _ => panic!("unsupported load offset {off}"),
        }
    };
    let mut a = 0u32;
    let mut pc = 0usize;
    loop {
        let i = prog[pc];
        pc += 1;
        match i.code {
            BPF_LD_W_ABS => a = load(i.k),
            BPF_ALU_AND_K => a &= i.k,
            BPF_JMP_JA => pc += i.k as usize,
            BPF_JMP_JEQ_K | BPF_JMP_JGE_K | BPF_JMP_JSET_K => {
                let taken = match i.code {
                    BPF_JMP_JEQ_K => a == i.k,
                    BPF_JMP_JGE_K => a >= i.k,
                    _ => a & i.k != 0,
                };
                pc += if taken { i.jt } else { i.jf } as usize;
            }
            BPF_RET_K => return i.k,
            other => panic!("unsupported opcode {other:#x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENY: u32 = SECCOMP_RET_ERRNO | EPERM;
    const SOCK_DGRAM: u64 = 2;
    const SOCK_CLOEXEC: u64 = 0o2000000;
    const SOCK_NONBLOCK: u64 = 0o4000;

    fn eval(arch: Arch, opts: FilterOptions, nr: u32, args: [u64; 6]) -> u32 {
        run(&build(arch, opts), arch.audit_arch(), nr, args)
    }

    fn socket(arch: Arch, opts: FilterOptions, domain: u64, ty: u64, proto: u64) -> u32 {
        eval(arch, opts, arch.nr().socket, [domain, ty, proto, 0, 0, 0])
    }

    const HARDENING: FilterOptions = FilterOptions {
        deny_network: false,
        landlock_tcp: false,
    };
    const NET_LANDLOCK: FilterOptions = FilterOptions {
        deny_network: true,
        landlock_tcp: true,
    };
    const NET_SECCOMP_ONLY: FilterOptions = FilterOptions {
        deny_network: true,
        landlock_tcp: false,
    };

    #[test]
    fn hardening_refuses_io_uring_ptrace_and_vm_writes() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            let nr = arch.nr();
            for n in [
                nr.io_uring_setup,
                nr.io_uring_enter,
                nr.io_uring_register,
                nr.ptrace,
                nr.process_vm_writev,
            ] {
                assert_eq!(eval(arch, HARDENING, n, [0; 6]), DENY, "{arch:?} nr {n}");
            }
            // read(2)/openat(2) are untouched.
            for n in [0, 56, 63, 257] {
                assert_eq!(
                    eval(arch, HARDENING, n, [0; 6]),
                    SECCOMP_RET_ALLOW,
                    "{arch:?} nr {n}"
                );
            }
        }
    }

    #[test]
    fn foreign_abi_is_refused() {
        let prog = build(Arch::X86_64, HARDENING);
        // i386 (AUDIT_ARCH_I386) through int 0x80
        assert_eq!(run(&prog, 0x4000_0003, 0, [0; 6]), SECCOMP_RET_KILL_PROCESS);
        // x32 io_uring_setup and x32 read
        assert_eq!(
            run(
                &prog,
                Arch::X86_64.audit_arch(),
                X32_SYSCALL_BIT | 425,
                [0; 6]
            ),
            DENY
        );
        assert_eq!(
            run(&prog, Arch::X86_64.audit_arch(), X32_SYSCALL_BIT, [0; 6]),
            DENY
        );
        let prog = build(Arch::Aarch64, HARDENING);
        // AUDIT_ARCH_ARM (32-bit compat)
        assert_eq!(run(&prog, 0x4000_0028, 0, [0; 6]), SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn packet_and_raw_sockets_are_refused_but_netlink_and_unix_stay() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            for opts in [HARDENING, NET_LANDLOCK, NET_SECCOMP_ONLY] {
                assert_eq!(socket(arch, opts, AF_PACKET as u64, SOCK_DGRAM, 0), DENY);
                assert_eq!(
                    socket(arch, opts, AF_PACKET as u64, SOCK_RAW as u64, 0),
                    DENY
                );
                assert_eq!(
                    socket(
                        arch,
                        opts,
                        AF_INET as u64,
                        SOCK_RAW as u64 | SOCK_CLOEXEC,
                        1
                    ),
                    DENY
                );
                assert_eq!(
                    socket(arch, opts, AF_INET6 as u64, SOCK_RAW as u64, 58),
                    DENY
                );
                assert_eq!(
                    socket(arch, opts, AF_INET as u64, SOCK_PACKET as u64, 0),
                    DENY
                );
                assert_eq!(
                    socket(
                        arch,
                        opts,
                        AF_NETLINK as u64,
                        SOCK_RAW as u64 | SOCK_CLOEXEC,
                        0
                    ),
                    SECCOMP_RET_ALLOW
                );
                assert_eq!(
                    socket(arch, opts, AF_UNIX as u64, SOCK_STREAM as u64, 0),
                    SECCOMP_RET_ALLOW
                );
                assert_eq!(
                    socket(arch, opts, AF_UNIX as u64, SOCK_DGRAM, 0),
                    SECCOMP_RET_ALLOW
                );
            }
        }
    }

    #[test]
    fn hardening_alone_keeps_tcp_and_udp() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            assert_eq!(
                socket(arch, HARDENING, AF_INET as u64, SOCK_DGRAM, 0),
                SECCOMP_RET_ALLOW
            );
            assert_eq!(
                socket(arch, HARDENING, AF_INET6 as u64, SOCK_STREAM as u64, 0),
                SECCOMP_RET_ALLOW
            );
            let n = arch.nr();
            assert_eq!(
                eval(
                    arch,
                    HARDENING,
                    n.sendto,
                    [3, 0, 0, MSG_FASTOPEN as u64, 0, 0]
                ),
                SECCOMP_RET_ALLOW
            );
        }
    }

    #[test]
    fn deny_network_with_landlock_tcp_keeps_only_tcp_sockets() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            let o = NET_LANDLOCK;
            for domain in [AF_INET, AF_INET6] {
                let d = domain as u64;
                assert_eq!(socket(arch, o, d, SOCK_STREAM as u64, 0), SECCOMP_RET_ALLOW);
                assert_eq!(
                    socket(
                        arch,
                        o,
                        d,
                        SOCK_STREAM as u64 | SOCK_CLOEXEC | SOCK_NONBLOCK,
                        IPPROTO_TCP as u64
                    ),
                    SECCOMP_RET_ALLOW
                );
                assert_eq!(socket(arch, o, d, SOCK_DGRAM, 0), DENY, "udp");
                assert_eq!(socket(arch, o, d, SOCK_DGRAM, 1), DENY, "icmp ping");
                assert_eq!(socket(arch, o, d, SOCK_STREAM as u64, 132), DENY, "sctp");
                assert_eq!(socket(arch, o, d, SOCK_STREAM as u64, 262), DENY, "mptcp");
                assert_eq!(socket(arch, o, d, 5, 132), DENY, "seqpacket");
            }
            let n = arch.nr();
            assert_eq!(
                eval(arch, o, n.sendto, [3, 0, 0, MSG_FASTOPEN as u64, 0, 0]),
                DENY
            );
            assert_eq!(
                eval(arch, o, n.sendmmsg, [3, 0, 1, MSG_FASTOPEN as u64, 0, 0]),
                DENY
            );
            assert_eq!(
                eval(arch, o, n.sendmsg, [3, 0, MSG_FASTOPEN as u64, 0, 0, 0]),
                DENY
            );
            assert_eq!(
                eval(arch, o, n.sendto, [3, 0, 0, 0x40, 0, 0]),
                SECCOMP_RET_ALLOW
            );
            assert_eq!(
                eval(arch, o, n.sendmsg, [3, 0, 0x4000, 0, 0, 0]),
                SECCOMP_RET_ALLOW
            );
            assert_eq!(
                socket(arch, o, AF_UNIX as u64, SOCK_STREAM as u64, 0),
                SECCOMP_RET_ALLOW
            );
        }
    }

    #[test]
    fn deny_network_without_landlock_refuses_every_inet_socket() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            let o = NET_SECCOMP_ONLY;
            for domain in [AF_INET, AF_INET6] {
                assert_eq!(socket(arch, o, domain as u64, SOCK_STREAM as u64, 0), DENY);
                assert_eq!(socket(arch, o, domain as u64, SOCK_DGRAM, 0), DENY);
            }
            assert_eq!(
                socket(arch, o, AF_UNIX as u64, SOCK_STREAM as u64, 0),
                SECCOMP_RET_ALLOW
            );
        }
    }

    #[test]
    fn only_low_32_bits_of_int_arguments_are_used() {
        // The kernel truncates int syscall arguments, so garbage in the high
        // half must not change the decision.
        let arch = Arch::X86_64;
        let hi = 0xdead_beef_0000_0000u64;
        assert_eq!(
            socket(arch, HARDENING, hi | AF_PACKET as u64, SOCK_DGRAM, 0),
            DENY
        );
        assert_eq!(
            socket(arch, NET_LANDLOCK, hi | AF_INET as u64, hi | SOCK_DGRAM, 0),
            DENY
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn syscall_numbers_match_libc_x86_64() {
        let n = Arch::X86_64.nr();
        assert_eq!(n.socket as i64, libc::SYS_socket);
        assert_eq!(n.sendto as i64, libc::SYS_sendto);
        assert_eq!(n.sendmsg as i64, libc::SYS_sendmsg);
        assert_eq!(n.sendmmsg as i64, libc::SYS_sendmmsg);
        assert_eq!(n.ptrace as i64, libc::SYS_ptrace);
        assert_eq!(n.process_vm_writev as i64, libc::SYS_process_vm_writev);
        assert_eq!(n.io_uring_setup as i64, libc::SYS_io_uring_setup);
        assert_eq!(n.io_uring_enter as i64, libc::SYS_io_uring_enter);
        assert_eq!(n.io_uring_register as i64, libc::SYS_io_uring_register);
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    #[test]
    fn syscall_numbers_match_libc_aarch64() {
        let n = Arch::Aarch64.nr();
        assert_eq!(n.socket as i64, libc::SYS_socket);
        assert_eq!(n.sendto as i64, libc::SYS_sendto);
        assert_eq!(n.sendmsg as i64, libc::SYS_sendmsg);
        assert_eq!(n.sendmmsg as i64, libc::SYS_sendmmsg);
        assert_eq!(n.ptrace as i64, libc::SYS_ptrace);
        assert_eq!(n.process_vm_writev as i64, libc::SYS_process_vm_writev);
        assert_eq!(n.io_uring_setup as i64, libc::SYS_io_uring_setup);
    }
}
