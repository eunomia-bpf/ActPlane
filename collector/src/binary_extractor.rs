// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

const PROCESS_BINARY: &[u8] = include_bytes!("../../bpf/process");

pub struct BinaryExtractor {
    _temp_dir: TempDir, // Keep alive to prevent cleanup
    pub process_path: PathBuf,
}

impl BinaryExtractor {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        eprintln!("Creating temporary directory...");

        let temp_dir = TempDir::new()?;
        let temp_path = temp_dir.path();

        eprintln!("Created temporary directory: {}", temp_path.display());

        // Extract and setup the process binary
        let process_path = temp_path.join("process");
        Self::extract_binary(&process_path, PROCESS_BINARY, "process").await?;

        // Small delay to ensure files are fully written
        sleep(Duration::from_millis(100)).await;

        Ok(Self {
            _temp_dir: temp_dir,
            process_path,
        })
    }

    async fn extract_binary(
        path: &Path,
        binary_data: &[u8],
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        {
            let mut file = fs::File::create(path)?;
            file.write_all(binary_data)?;
            file.flush()?;
        } // File is closed here

        // Make the binary executable
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;

        eprintln!("Extracted {} binary to: {}", name, path.display());

        Ok(())
    }

    pub fn get_process_path(&self) -> &Path {
        &self.process_path
    }
}
