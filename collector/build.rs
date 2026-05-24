// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_dir = manifest_dir.parent().expect("collector has repo parent");
    let bpf_dir = repo_dir.join("bpf");
    let process = bpf_dir.join("process");
    let out_process = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("process");

    // Re-embed whenever any loader/engine source OR the built binary changes.
    // Watching `bpf/process` itself is what catches an out-of-band `make -C bpf`
    // (rebuilt binary) so the embedded copy can never go stale relative to disk.
    println!("cargo:rerun-if-changed=../bpf/Makefile");
    println!("cargo:rerun-if-changed=../bpf/process.c");
    println!("cargo:rerun-if-changed=../bpf/process.bpf.c");
    println!("cargo:rerun-if-changed=../bpf/process.h");
    println!("cargo:rerun-if-changed=../bpf/taint.h");
    println!("cargo:rerun-if-changed=../bpf/taint_engine.bpf.h");
    println!("cargo:rerun-if-changed=../bpf/process");

    // Always (re)build the eBPF loader so `cargo build` alone embeds the latest
    // bpf/process — no need to remember a separate `make -C bpf` first.
    let status = Command::new("make")
        .arg("-C")
        .arg(&bpf_dir)
        .arg("process")
        .status()
        .expect("failed to run make -C bpf process");
    assert!(status.success(), "make -C bpf process failed");

    std::fs::copy(&process, &out_process).expect("failed to copy bpf/process to OUT_DIR");
}
