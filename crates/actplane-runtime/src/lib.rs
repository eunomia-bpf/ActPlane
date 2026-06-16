// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! ActPlane runtime control library.
//!
//! This crate owns policy-file resolution, engine loading, runtime domains,
//! local control, MCP integration, and corrective-feedback reporting. The CLI is
//! a thin frontend over this library.

use std::path::PathBuf;

pub type AnyError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, AnyError>;

#[derive(Debug, Clone, Default)]
pub struct PolicyInput {
    pub policy: Option<PathBuf>,
    pub rule: Option<String>,
    pub domain: Option<String>,
    pub run_as_root: bool,
    pub internal_elevated: bool,
}

pub type Cli = PolicyInput;

pub use actplane_ifc_compiler as dsl;

pub mod audit;
pub mod config;
pub mod control;
pub mod feedback;
pub mod hook;
pub mod mcp;
pub mod report;
pub mod runtime;
