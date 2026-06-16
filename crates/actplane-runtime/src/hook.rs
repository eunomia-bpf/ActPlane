use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crate::Result;
use crate::config::{DEFAULT_FEEDBACK_FILE, DEFAULT_HOOK_STATE_FILE, absolutize};

const HOOK_MAX_CHARS: usize = 8000;
const FEEDBACK_SEPARATOR: &str = "\n----\n";

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct HookState {
    feedback_file: Option<String>,
    root_pid: Option<i32>,
    offset: Option<u64>,
}

struct HookSelection {
    feedback: PathBuf,
    state: PathBuf,
}

pub async fn feedback_hook() -> Result<()> {
    let data: serde_json::Value = match serde_json::from_str(&read_stdin()?) {
        Ok(v) => v,
        Err(_) => serde_json::Value::Object(Default::default()),
    };
    let cwd = data
        .get("cwd")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or(std::env::current_dir()?);
    let event = data
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("PostToolUse");
    let default_feedback = env_path_or("ACTPLANE_FEEDBACK_FILE", &cwd, DEFAULT_FEEDBACK_FILE);
    let default_state = env_path_or(
        "ACTPLANE_HOOK_STATE",
        &cwd,
        default_feedback
            .parent()
            .map(|p| p.join("feedback-hook.state.json"))
            .unwrap_or_else(|| cwd.join(DEFAULT_HOOK_STATE_FILE))
            .to_string_lossy()
            .as_ref(),
    );

    let Some(selection) = select_feedback_file(&cwd, &default_feedback, &default_state) else {
        return Ok(());
    };

    let feedback_text = read_new_feedback(&selection)?;
    if feedback_text.trim().is_empty() {
        return Ok(());
    }
    let context = hook_context(&feedback_text);
    let output = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": context,
        }
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

pub fn write_hook_state(state: &Path, feedback: &Path, root_pid: i32) -> Result<()> {
    if let Some(parent) = state.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = state.with_extension("tmp");
    let value = HookState {
        feedback_file: Some(feedback.to_string_lossy().to_string()),
        root_pid: Some(root_pid),
        offset: Some(std::fs::metadata(feedback).map(|m| m.len()).unwrap_or(0)),
    };
    std::fs::write(&tmp, serde_json::to_string(&value)? + "\n")?;
    std::fs::rename(tmp, state)?;
    Ok(())
}

fn read_stdin() -> std::io::Result<String> {
    let mut raw = String::new();
    let mut stdin = std::io::stdin();
    std::io::Read::read_to_string(&mut stdin, &mut raw)?;
    Ok(raw)
}

fn env_path_or(name: &str, cwd: &Path, default: &str) -> PathBuf {
    let path = std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default));
    absolutize(&path, cwd)
}

fn load_hook_state(path: &Path) -> Option<HookState> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn select_feedback_file(
    cwd: &Path,
    default_feedback: &Path,
    default_state: &Path,
) -> Option<HookSelection> {
    if let Some(state) = load_hook_state(default_state) {
        if hook_matches_agent(&state) {
            let feedback = state
                .feedback_file
                .map(PathBuf::from)
                .unwrap_or_else(|| default_feedback.to_path_buf());
            return Some(HookSelection {
                feedback,
                state: default_state.to_path_buf(),
            });
        }
        return discover_matching_feedback(cwd);
    }
    discover_matching_feedback(cwd).or_else(|| {
        if default_feedback.exists() {
            Some(HookSelection {
                feedback: default_feedback.to_path_buf(),
                state: default_state.to_path_buf(),
            })
        } else {
            None
        }
    })
}

fn discover_matching_feedback(cwd: &Path) -> Option<HookSelection> {
    let runs = cwd.join(".actplane").join("runs");
    let entries = std::fs::read_dir(runs).ok()?;
    let mut matches = Vec::new();
    for entry in entries.flatten() {
        let state_path = entry.path().join("hook-state.json");
        let Some(state) = load_hook_state(&state_path) else {
            continue;
        };
        if hook_matches_agent(&state) {
            if let Some(path) = state.feedback_file {
                matches.push(HookSelection {
                    feedback: PathBuf::from(path),
                    state: state_path,
                });
            }
        }
    }
    matches.sort_by(|a, b| a.state.cmp(&b.state));
    matches.pop()
}

fn hook_matches_agent(state: &HookState) -> bool {
    let Some(root_pid) = state.root_pid else {
        return true;
    };
    root_pid > 1 && is_descendant_of(std::process::id() as i32, root_pid)
}

fn is_descendant_of(mut pid: i32, root_pid: i32) -> bool {
    for _ in 0..128 {
        if pid == root_pid {
            return true;
        }
        if pid <= 1 {
            return false;
        }
        let Some(ppid) = parent_pid(pid) else {
            return false;
        };
        pid = ppid;
    }
    false
}

fn parent_pid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rparen = stat.rfind(')')?;
    let after = stat.get(rparen + 2..)?;
    let mut fields = after.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

fn read_new_feedback(selection: &HookSelection) -> Result<String> {
    let Some(parent) = selection.feedback.parent() else {
        return read_new_feedback_locked(selection);
    };
    std::fs::create_dir_all(parent)?;
    let lock = parent.join(".feedback.lock");
    let _guard = match FeedbackLock::acquire(&lock)? {
        Some(guard) => guard,
        None => return Ok(String::new()),
    };
    read_new_feedback_locked(selection)
}

fn read_new_feedback_locked(selection: &HookSelection) -> Result<String> {
    let raw = match std::fs::read(&selection.feedback) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e.into()),
    };
    let len = raw.len() as u64;
    let mut state = load_hook_state(&selection.state).unwrap_or_default();
    if state.feedback_file.is_none() {
        state.feedback_file = Some(selection.feedback.to_string_lossy().to_string());
    }
    let same_feedback = state
        .feedback_file
        .as_deref()
        .is_some_and(|p| Path::new(p) == selection.feedback);

    if !same_feedback {
        state.feedback_file = Some(selection.feedback.to_string_lossy().to_string());
        state.offset = Some(len);
        store_hook_state(&selection.state, &state)?;
        return Ok(String::new());
    }

    let Some(offset) = state.offset else {
        state.offset = Some(len);
        store_hook_state(&selection.state, &state)?;
        return Ok(String::new());
    };
    let offset = if offset > len { 0 } else { offset as usize };
    state.offset = Some(len);
    store_hook_state(&selection.state, &state)?;

    let new_bytes = &raw[offset..];
    if new_bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(String::new());
    }
    let new_text = String::from_utf8_lossy(new_bytes);
    Ok(last_feedback_block(&new_text).trim().to_string())
}

fn store_hook_state(path: &Path, state: &HookState) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_string(state)? + "\n")?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn last_feedback_block(raw: &str) -> String {
    raw.split(FEEDBACK_SEPARATOR)
        .map(str::trim)
        .filter(|block| !block.is_empty())
        .last()
        .unwrap_or("")
        .to_string()
}

struct FeedbackLock {
    path: PathBuf,
}

impl FeedbackLock {
    fn acquire(path: &Path) -> Result<Option<Self>> {
        for _ in 0..20 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(_) => {
                    return Ok(Some(Self {
                        path: path.to_path_buf(),
                    }));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }
}

impl Drop for FeedbackLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn hook_context(feedback: &str) -> String {
    let text = if feedback.chars().count() > HOOK_MAX_CHARS {
        let tail: String = feedback
            .chars()
            .rev()
            .take(HOOK_MAX_CHARS)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("... truncated ...\n{tail}")
    } else {
        feedback.to_string()
    };
    format!(
        "ActPlane detected an OS-level harness violation during the previous \
         tool action. Treat this as authoritative feedback from the kernel \
         engine; do not retry the same operation unchanged. Follow the \
         suggested alternative or satisfy the listed precondition.\n\n{text}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_block_selects_latest_feedback() {
        let raw = "one\n----\ntwo\n----\n";
        assert_eq!(last_feedback_block(raw), "two");
    }

    #[test]
    fn last_block_handles_unsuffixed_feedback() {
        assert_eq!(last_feedback_block("one"), "one");
    }
}
