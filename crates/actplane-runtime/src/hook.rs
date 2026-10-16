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
    #[tokio::test(flavor = "current_thread")]
    #[cfg(unix)]
    async fn feedback_hook_emits_baseline_then_delivers_new_bytes() {
        use std::os::unix::io::AsRawFd;

        let dir = tempfile::tempdir().expect("tempdir");
        let feedback = dir.path().join("last-violation.txt");
        std::fs::write(&feedback, "").expect("feedback");
        let state = dir.path().join("hook-state.json");
        let input = dir.path().join("input.json");
        std::fs::write(
            &input,
            format!(
                "{{\"cwd\":\"{}\",\"hook_event_name\":\"PostToolUse\"}}\n",
                dir.path().display()
            ),
        )
        .expect("input");

        // SAFETY: single-threaded current-thread runtime; env is set and restored.
        unsafe { std::env::set_var("ACTPLANE_FEEDBACK_FILE", &feedback) };
        unsafe { std::env::set_var("ACTPLANE_HOOK_STATE", &state) };

        // First invocation establishes the offset baseline and emits nothing.
        let file = std::fs::File::open(&input).expect("open");
        let saved = unsafe { libc::dup(0) };
        assert!(saved >= 0, "dup(0) failed");
        assert_eq!(unsafe { libc::dup2(file.as_raw_fd(), 0) }, 0, "dup2 failed");
        let first = feedback_hook().await;
        assert_eq!(unsafe { libc::dup2(saved, 0) }, 0, "restore failed");
        unsafe { libc::close(saved) };
        first.expect("first hook");
        let text = std::fs::read_to_string(&state).expect("state");
        let value: serde_json::Value = serde_json::from_str(&text).expect("state json");
        assert_eq!(value["offset"], 0);
        assert_eq!(value["root_pid"], serde_json::Value::Null);

        // Appending feedback makes the next invocation report the new block.
        let feedback_text = "TAINT_VIOLATION: read /etc/secret\n";
        std::fs::write(&feedback, feedback_text).expect("append");
        let file = std::fs::File::open(&input).expect("open");
        let saved = unsafe { libc::dup(0) };
        assert!(saved >= 0, "dup(0) failed");
        assert_eq!(unsafe { libc::dup2(file.as_raw_fd(), 0) }, 0, "dup2 failed");
        let second = feedback_hook().await;
        assert_eq!(unsafe { libc::dup2(saved, 0) }, 0, "restore failed");
        unsafe { libc::close(saved) };
        second.expect("second hook");
        let text = std::fs::read_to_string(&state).expect("state");
        let value: serde_json::Value = serde_json::from_str(&text).expect("state json");
        assert_eq!(value["offset"], feedback_text.len() as u64);

        unsafe { std::env::remove_var("ACTPLANE_FEEDBACK_FILE") };
        unsafe { std::env::remove_var("ACTPLANE_HOOK_STATE") };
    }

    #[test]
    fn last_block_selects_latest_feedback() {
        let raw = "one\n----\ntwo\n----\n";
        assert_eq!(last_feedback_block(raw), "two");
    }

    #[test]
    fn last_block_handles_unsuffixed_feedback() {
        assert_eq!(last_feedback_block("one"), "one");
    }
    #[test]
    fn hook_context_truncates_overlong_feedback_to_the_tail() {
        // `hook_context` wraps feedback in the kernel-feedback preamble. Short
        // feedback is embedded verbatim; overlong feedback (more than
        // HOOK_MAX_CHARS) is truncated to its last HOOK_MAX_CHARS characters
        // with a `... truncated ...` marker. No base or branch test pins
        // either branch directly.
        //
        // `hook_context("")` is the bare preamble, so the assertions anchor
        // against it and pin the pass-through vs truncation split without
        // re-stating the multi-line preamble.
        let preamble = hook_context("");
        assert!(preamble.ends_with("\n\n"));

        // Pass-through: short feedback is embedded after the preamble verbatim.
        let short = "short-feedback";
        let s = hook_context(short);
        assert!(s.starts_with(preamble.as_str()));
        assert_eq!(s, format!("{preamble}{short}"));

        // Boundary: exactly HOOK_MAX_CHARS is not overlong, so it is passed
        // through verbatim.
        let at_limit = "X".repeat(HOOK_MAX_CHARS);
        assert_eq!(hook_context(&at_limit), format!("{preamble}{at_limit}"));

        // One over the limit truncates to the last HOOK_MAX_CHARS chars with
        // the marker.
        let over = "Y".repeat(HOOK_MAX_CHARS + 1);
        let t = hook_context(&over);
        let tail = "Y".repeat(HOOK_MAX_CHARS);
        assert!(t.starts_with(preamble.as_str()));
        assert!(t.contains("... truncated ...\n"));
        assert!(t.ends_with(tail.as_str()));
        assert_eq!(t, format!("{preamble}... truncated ...\n{tail}"));
    }

    #[test]
    fn discover_matching_feedback_picks_latest_matching_run() {
        // `discover_matching_feedback` scans .actplane/runs for hook states that
        // match this agent and returns the latest; no base or branch test calls
        // it.
        let me = std::process::id() as i32;
        let dir = tempfile::tempdir().expect("tempdir");
        let cwd = dir.path();

        // No runs directory -> None.
        assert!(discover_matching_feedback(cwd).is_none());

        let runs = cwd.join(".actplane/runs");
        let write_run = |name: &str, root_pid: Option<i32>, feedback: &str| {
            let run = runs.join(name);
            std::fs::create_dir_all(&run).unwrap();
            store_hook_state(
                &run.join("hook-state.json"),
                &HookState {
                    feedback_file: Some(feedback.to_string()),
                    root_pid,
                    offset: None,
                },
            )
            .unwrap();
        };
        // A matching run (self root) and two non-matching runs.
        write_run("run-a", Some(me), "/tmp/feedback-a.txt");
        write_run("run-b", Some(i32::MAX), "/tmp/feedback-b.txt");
        write_run("run-c", Some(i32::MAX), "/tmp/feedback-c.txt");

        let found = discover_matching_feedback(cwd).expect("matching run");
        assert_eq!(found.feedback, PathBuf::from("/tmp/feedback-a.txt"));
        assert!(found.state.ends_with("run-a/hook-state.json"));

        // Once that run's state is gone, discovery finds nothing.
        std::fs::remove_file(runs.join("run-a/hook-state.json")).unwrap();
        assert!(discover_matching_feedback(cwd).is_none());
    }

    #[test]
    fn env_path_or_uses_env_then_default_and_absolutizes() {
        // `env_path_or` resolves an env override or a default relative to cwd;
        // no base or branch test calls it.
        let cwd = Path::new("/base");
        // `set_var` is process-global (`unsafe` in edition 2024); a
        // test-specific key avoids collisions with other tests.
        unsafe { std::env::set_var("ACT_TEST_ENV_PATH_OR", "rel/from-env.txt") };
        assert_eq!(
            env_path_or("ACT_TEST_ENV_PATH_OR", cwd, "fallback.txt"),
            PathBuf::from("/base/rel/from-env.txt")
        );
        unsafe { std::env::set_var("ACT_TEST_ENV_PATH_OR", "/abs/from-env.txt") };
        assert_eq!(
            env_path_or("ACT_TEST_ENV_PATH_OR", cwd, "fallback.txt"),
            PathBuf::from("/abs/from-env.txt")
        );
        unsafe { std::env::remove_var("ACT_TEST_ENV_PATH_OR") };
        assert_eq!(
            env_path_or("ACT_TEST_ENV_PATH_OR", cwd, "fallback.txt"),
            PathBuf::from("/base/fallback.txt")
        );
    }

    #[test]
    fn is_descendant_of_walks_proc_ppid_chain() {
        // `is_descendant_of` walks the live /proc ppid chain; no base or branch
        // test calls it.
        let me = std::process::id() as i32;
        let ppid = parent_pid(me).expect("self ppid");
        assert!(ppid > 0);
        assert!(is_descendant_of(me, me));
        assert!(is_descendant_of(me, ppid));
        assert!(!is_descendant_of(ppid, me));
        assert!(!is_descendant_of(1, me));
    }

    #[test]
    fn env_path_or_prefers_env_then_defaults_under_cwd() {
        // `env_path_or` resolves a hook path from an env override or a cwd
        // default, absolutizing relative results; no base or branch test calls
        // it.
        let cwd = Path::new("/tmp/actplane-cwd");
        let probe = "ACTPLANE_TEST_ENV_PATH_OR";

        // Unset -> default join cwd.
        unsafe { std::env::remove_var(probe) };
        assert_eq!(
            env_path_or(probe, cwd, ".actplane/feedback.txt"),
            cwd.join(".actplane/feedback.txt")
        );

        // Relative env value is absolutized against cwd.
        unsafe { std::env::set_var(probe, "custom/feedback.txt") };
        assert_eq!(
            env_path_or(probe, cwd, ".actplane/feedback.txt"),
            cwd.join("custom/feedback.txt")
        );

        // Absolute env value is returned verbatim.
        unsafe { std::env::set_var(probe, "/var/tmp/absolute.txt") };
        assert_eq!(
            env_path_or(probe, cwd, ".actplane/feedback.txt"),
            PathBuf::from("/var/tmp/absolute.txt")
        );
        unsafe { std::env::remove_var(probe) };
    }

    #[test]
    fn feedback_lock_acquires_exclusively_and_releases_on_drop() {
        // `FeedbackLock::acquire` creates the lock file with create_new and
        // removes it on Drop, so a second acquire while held yields None; no
        // base or branch test exercises it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("feedback.lock");

        let guard = FeedbackLock::acquire(&path)
            .expect("acquire")
            .expect("free lock");
        assert!(path.exists(), "lock file created while held");

        let contended = FeedbackLock::acquire(&path).expect("second acquire");
        assert!(contended.is_none(), "held lock blocks a second acquire");

        drop(guard);
        assert!(!path.exists(), "lock file removed on drop");

        let again = FeedbackLock::acquire(&path)
            .expect("reacquire")
            .expect("free again");
        assert!(path.exists());
        drop(again);
        assert!(!path.exists());
    }

    #[test]
    fn feedback_selection_prefers_matching_state_then_discovery_then_default() {
        // `hook_matches_agent` and `select_feedback_file` decide which feedback
        // file a hook reads; no base or branch test calls them.
        let me = std::process::id() as i32;

        // No root pid -> any agent matches; a foreign root pid does not, and a
        // self-root matches via the pid chain.
        assert!(hook_matches_agent(&HookState {
            feedback_file: None,
            root_pid: None,
            offset: None,
        }));
        assert!(!hook_matches_agent(&HookState {
            feedback_file: None,
            root_pid: Some(i32::MAX),
            offset: None,
        }));
        assert!(hook_matches_agent(&HookState {
            feedback_file: None,
            root_pid: Some(me),
            offset: None,
        }));

        let dir = tempfile::tempdir().expect("tempdir");
        let cwd = dir.path();
        let state_path = cwd.join("state.json");
        let feedback = cwd.join("feedback.txt");
        let default_feedback = cwd.join("default.txt");
        let default_state = cwd.join("default-state.json");

        // Matching default state wins and returns its recorded feedback path.
        store_hook_state(
            &state_path,
            &HookState {
                feedback_file: Some(feedback.to_string_lossy().to_string()),
                root_pid: Some(me),
                offset: None,
            },
        )
        .unwrap();
        let picked = select_feedback_file(cwd, &default_feedback, &state_path).expect("picked");
        assert_eq!(picked.feedback, feedback);
        assert_eq!(picked.state, state_path);

        // A non-matching default state returns discovery (which finds nothing
        // here), so the default feedback file is not consulted.
        std::fs::write(&default_feedback, "x").unwrap();
        let foreign_state = cwd.join("foreign-state.json");
        store_hook_state(
            &foreign_state,
            &HookState {
                feedback_file: Some(feedback.to_string_lossy().to_string()),
                root_pid: Some(i32::MAX),
                offset: None,
            },
        )
        .unwrap();
        assert!(select_feedback_file(cwd, &default_feedback, &foreign_state).is_none());

        // With no state at all, discovery runs first and, finding nothing,
        // falls back to the default feedback file when it exists.
        let fallback =
            select_feedback_file(cwd, &default_feedback, &default_state).expect("fallback");
        assert_eq!(fallback.feedback, default_feedback);
        assert_eq!(fallback.state, default_state);

        std::fs::remove_file(&default_feedback).unwrap();
        assert!(select_feedback_file(cwd, &default_feedback, &default_state).is_none());
    }

    #[test]
    fn read_new_feedback_advances_offset_and_returns_new_blocks() {
        // `read_new_feedback`/`read_new_feedback_locked` return only the bytes
        // appended since the recorded offset and persist the new offset; no
        // base or branch test calls them.
        let dir = tempfile::tempdir().expect("tempdir");
        let feedback = dir.path().join("feedback.txt");
        let state_path = dir.path().join("hook-state.json");
        let selection = HookSelection {
            feedback: feedback.clone(),
            state: state_path.clone(),
        };

        // Missing feedback -> empty, no state written.
        assert_eq!(read_new_feedback(&selection).unwrap(), "");
        assert!(load_hook_state(&state_path).is_none());

        let block_a = "rule a\n  blocked\n";
        std::fs::write(&feedback, block_a).unwrap();
        // First read seeds the offset at the current length, so nothing new.
        assert_eq!(read_new_feedback(&selection).unwrap(), "");
        assert_eq!(
            load_hook_state(&state_path).unwrap().offset,
            Some(block_a.len() as u64)
        );

        // Appending a separator-delimited block returns the new block only.
        let block_b = "\n----\nrule b\n  killed\n";
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&feedback)
            .unwrap();
        std::io::Write::write_all(&mut file, block_b.as_bytes()).unwrap();
        drop(file);
        let got = read_new_feedback(&selection).unwrap();
        assert_eq!(got, "rule b\n  killed");
        assert_eq!(
            load_hook_state(&state_path).unwrap().offset,
            Some((block_a.len() + block_b.len()) as u64)
        );

        // Whitespace-only growth yields nothing.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&feedback)
            .unwrap();
        std::io::Write::write_all(&mut file, b"\n\n").unwrap();
        drop(file);
        assert_eq!(read_new_feedback(&selection).unwrap(), "");
    }

    #[test]
    fn read_new_feedback_locked_tracks_offset_and_truncation() {
        // `read_new_feedback_locked` advances a persisted byte offset, returns
        // only the newly appended block, resets on truncation, and ignores
        // whitespace; no base or branch test calls it.
        let dir = tempfile::tempdir().expect("tempdir");
        let feedback = dir.path().join("feedback.txt");
        let state = dir.path().join("state.json");
        let selection = HookSelection {
            feedback: feedback.clone(),
            state: state.clone(),
        };

        // Missing file -> empty, no state written.
        assert_eq!(read_new_feedback_locked(&selection).expect("missing"), "");

        // First read of an existing file records the offset and returns nothing.
        std::fs::write(&feedback, "first\n----\n").unwrap();
        assert_eq!(read_new_feedback_locked(&selection).expect("first"), "");

        // Appended content is returned as the latest block.
        std::fs::write(&feedback, "first\n----\nsecond\n----\n").unwrap();
        assert_eq!(
            read_new_feedback_locked(&selection).expect("second"),
            "second"
        );

        // Whitespace-only append yields nothing but still advances the offset.
        std::fs::write(&feedback, "first\n----\nsecond\n----\n   \n").unwrap();
        assert_eq!(read_new_feedback_locked(&selection).expect("blank"), "");

        // Truncation resets the offset and re-reads from the start.
        std::fs::write(&feedback, "reset\n----\n").unwrap();
        assert_eq!(
            read_new_feedback_locked(&selection).expect("reset"),
            "reset"
        );

        // Switching to a different feedback file records it and returns nothing.
        let other = dir.path().join("other.txt");
        std::fs::write(&other, "other\n----\n").unwrap();
        let other_selection = HookSelection {
            feedback: other,
            state: state.clone(),
        };
        assert_eq!(
            read_new_feedback_locked(&other_selection).expect("switch"),
            ""
        );
        assert!(state.exists());
    }

    #[test]
    #[cfg(unix)]
    fn read_stdin_collects_redirected_input() {
        use std::os::unix::io::AsRawFd;

        let input = tempfile::tempdir().expect("tempdir");
        let path = input.path().join("payload.txt");
        std::fs::write(&path, "TAINT_VIOLATION: read /etc/secret\n").expect("write");
        let file = std::fs::File::open(&path).expect("open");

        let saved = unsafe { libc::dup(0) };
        assert!(saved >= 0, "dup(0) failed");
        assert_eq!(unsafe { libc::dup2(file.as_raw_fd(), 0) }, 0, "dup2 failed");

        let captured = read_stdin();

        assert_eq!(unsafe { libc::dup2(saved, 0) }, 0, "restore failed");
        unsafe { libc::close(saved) };

        assert_eq!(
            captured.expect("read stdin"),
            "TAINT_VIOLATION: read /etc/secret\n"
        );
    }

    #[test]
    fn hook_state_round_trips_through_atomic_store() {
        // `store_hook_state` writes atomically via a `.tmp` rename and
        // `load_hook_state` parses it back; neither had any call.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("hook-state.json");
        assert!(load_hook_state(&path).is_none());

        let state = HookState {
            feedback_file: Some("/tmp/proj/feedback.txt".to_string()),
            root_pid: Some(4242),
            offset: Some(17),
        };
        store_hook_state(&path, &state).expect("store");
        // Intermediate temp file is gone after the rename.
        assert!(!path.with_extension("tmp").exists());

        let loaded = load_hook_state(&path).expect("load");
        assert_eq!(
            loaded.feedback_file.as_deref(),
            Some("/tmp/proj/feedback.txt")
        );
        assert_eq!(loaded.root_pid, Some(4242));
        assert_eq!(loaded.offset, Some(17));

        // Malformed content parses to None rather than panicking.
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(load_hook_state(&path).is_none());
    }

    #[test]
    fn write_hook_state_records_feedback_path_root_and_offset() {
        // `write_hook_state` seeds hook state (feedback path, root pid, and the
        // feedback file's current length as the read offset); no base or branch
        // test calls it.
        let dir = tempfile::tempdir().expect("tempdir");
        let feedback = dir.path().join("feedback.txt");
        std::fs::write(&feedback, "hello world").unwrap();
        let state_path = dir.path().join("nested/state.json");

        write_hook_state(&state_path, &feedback, 777).expect("write");
        let state = load_hook_state(&state_path).expect("state");
        assert_eq!(
            state.feedback_file.as_deref(),
            Some(feedback.to_str().unwrap())
        );
        assert_eq!(state.root_pid, Some(777));
        assert_eq!(state.offset, Some("hello world".len() as u64));

        // A missing feedback file records offset 0.
        let missing = dir.path().join("missing.txt");
        write_hook_state(&state_path, &missing, 8).expect("write missing");
        let state = load_hook_state(&state_path).expect("state");
        assert_eq!(state.offset, Some(0));
    }

    #[test]
    fn hook_context_keeps_short_feedback_intact() {
        let ctx = hook_context("blocked exec git");
        assert!(ctx.contains("authoritative feedback from the kernel"));
        assert!(ctx.ends_with("blocked exec git"));
        assert!(!ctx.contains("truncated"));
    }

    #[test]
    fn hook_context_truncates_to_the_tail() {
        let long = format!("{}TAIL", "x".repeat(HOOK_MAX_CHARS + 100));
        let ctx = hook_context(&long);
        assert!(ctx.contains("... truncated ..."));
        assert!(ctx.ends_with("TAIL"));
        assert!(!ctx.contains(&"x".repeat(HOOK_MAX_CHARS + 1)));
    }
}
