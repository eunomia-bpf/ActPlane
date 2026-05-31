// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! ActPlane MCP server — watches `actplane.yaml` for changes, validates the
//! policy on every save, and pushes the result to the MCP client via resource
//! updates and logging notifications. No explicit tool calls needed.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rmcp::model::*;
use rmcp::transport::io::stdio;
use rmcp::{Peer, RoleServer, ServerHandler, ServiceExt};
use serde_json::Value;

use crate::dsl;

const RESOURCE_URI: &str = "actplane:///policy";
const WATCH_INTERVAL: Duration = Duration::from_secs(2);

// ── Server state ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ActPlaneMcp {
    project_dir: PathBuf,
}

impl ActPlaneMcp {
    pub fn new() -> Self {
        let project_dir = std::env::var("CLAUDE_PROJECT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        Self { project_dir }
    }

    fn discover_policy_file(&self) -> Option<PathBuf> {
        let candidates = ["actplane.yaml", ".actplane/policy.yaml"];
        let mut dir = Some(self.project_dir.as_path());
        while let Some(d) = dir {
            for name in &candidates {
                let p = d.join(name);
                if p.is_file() {
                    return Some(p);
                }
            }
            dir = d.parent();
        }
        None
    }

    fn load_and_validate(&self) -> String {
        let path = match self.discover_policy_file() {
            Some(p) => p,
            None => return "No actplane.yaml found.".into(),
        };
        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => return format!("Cannot read {}: {}", path.display(), e),
        };
        let config: serde_yaml::Value = match serde_yaml::from_str(&src) {
            Ok(v) => v,
            Err(e) => return format!("YAML parse error in {}: {}", path.display(), e),
        };
        let dsl_src = match config.get("policy").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return format!("{} has no `policy:` field", path.display()),
        };
        match dsl::compile_str(dsl_src) {
            Ok(compiled) => {
                let mut out = format!(
                    "Policy valid ({}, {} rules):\n",
                    path.display(),
                    compiled.meta.len()
                );
                for (i, m) in compiled.meta.iter().enumerate() {
                    let eff = format!("{:?}", m.effect).to_lowercase();
                    let ops = if m.ops.is_empty() {
                        "—".into()
                    } else {
                        m.ops.join("/")
                    };
                    out.push_str(&format!(
                        "  {}. {} — {} {} ({})\n",
                        i + 1,
                        m.name,
                        eff,
                        ops,
                        m.reason
                    ));
                }
                out
            }
            Err(e) => format!("Policy compile error: {}", e),
        }
    }

    fn policy_mtime(&self) -> Option<SystemTime> {
        self.discover_policy_file()
            .and_then(|p| std::fs::metadata(&p).ok())
            .and_then(|m| m.modified().ok())
    }
}

// ── ServerHandler: resources only, no tools ─────────────────────────

impl ServerHandler for ActPlaneMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_resources()
                .build(),
        )
        .with_instructions(
            "ActPlane: OS-enforced agent harness. This server watches actplane.yaml \
             and pushes validation results when the policy changes.",
        )
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + Send + '_ {
        let resource = Annotated::new(RawResource {
            uri: RESOURCE_URI.into(),
            name: "actplane-policy".into(),
            title: Some("ActPlane Policy Status".into()),
            description: Some("Current policy validation result from actplane.yaml".into()),
            mime_type: Some("text/plain".into()),
            size: None,
            icons: None,
            meta: None,
        }, None);
        std::future::ready(Ok(ListResourcesResult { resources: vec![resource], ..Default::default() }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, rmcp::ErrorData>> + Send + '_ {
        let result = if request.uri == RESOURCE_URI {
            let text = self.load_and_validate();
            Ok(ReadResourceResult::new(vec![
                ResourceContents::TextResourceContents {
                    uri: RESOURCE_URI.into(),
                    mime_type: Some("text/plain".into()),
                    text,
                    meta: None,
                },
            ]))
        } else {
            Err(rmcp::ErrorData::new(
                ErrorCode::INVALID_PARAMS,
                format!("Unknown resource: {}", request.uri),
                None::<Value>,
            ))
        };
        std::future::ready(result)
    }
}

// ── File watcher ────────────────────────────────────────────────────

async fn watch_policy_file(server: Arc<ActPlaneMcp>, peer: Peer<RoleServer>) {
    let mut last_mtime = server.policy_mtime();

    // Send initial validation on startup.
    let initial = server.load_and_validate();
    let _ = peer
        .notify_logging_message(LoggingMessageNotificationParam::new(
            LoggingLevel::Info,
            Value::String(initial),
        ))
        .await;

    loop {
        tokio::time::sleep(WATCH_INTERVAL).await;

        let current_mtime = server.policy_mtime();
        if current_mtime == last_mtime {
            continue;
        }
        last_mtime = current_mtime;

        let result = server.load_and_validate();
        let level = if result.contains("error") || result.contains("No actplane") {
            LoggingLevel::Error
        } else {
            LoggingLevel::Info
        };

        let _ = peer
            .notify_logging_message(LoggingMessageNotificationParam::new(
                level,
                Value::String(result),
            ))
            .await;

        let _ = peer
            .notify_resource_updated(ResourceUpdatedNotificationParam::new(RESOURCE_URI))
            .await;
    }
}

// ── Entry point ─────────────────────────────────────────────────────

pub async fn run_mcp_server() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = ActPlaneMcp::new();
    let server_arc = Arc::new(server.clone());
    let transport = stdio();
    let service = server.serve(transport).await?;

    let peer = service.peer().clone();
    tokio::spawn(watch_policy_file(server_arc, peer));

    service.waiting().await?;
    Ok(())
}
