use std::io::{BufRead, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, audit};

const CONTROL_STATE_FILE: &str = ".actplane/control.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlState {
    pub schema: String,
    pub pid: i32,
    pub proc_start_time: Option<u64>,
    pub socket_path: PathBuf,
    pub project_dir: PathBuf,
    pub parent_pid: i32,
    pub parent_domain_id: u32,
}

pub struct LocalControlGuard {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    socket_path: PathBuf,
    state_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PeerCred {
    pub pid: i32,
    #[allow(dead_code)]
    pub uid: u32,
    #[allow(dead_code)]
    pub gid: u32,
    pub identity: audit::ProcessIdentity,
}

impl Drop for LocalControlGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
        if let Ok(text) = std::fs::read_to_string(&self.state_path) {
            if let Ok(state) = serde_json::from_str::<ControlState>(&text) {
                if state.socket_path == self.socket_path {
                    let _ = std::fs::remove_file(&self.state_path);
                }
            }
        }
    }
}

pub fn state_path(project_dir: &Path) -> PathBuf {
    project_dir.join(CONTROL_STATE_FILE)
}

pub fn read_state(project_dir: &Path) -> Result<ControlState> {
    let path = state_path(project_dir);
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()).into())
}

pub fn start_server<F>(
    project_dir: &Path,
    parent_pid: i32,
    parent_domain_id: u32,
    handler: F,
) -> Result<LocalControlGuard>
where
    F: Fn(Value, Option<PeerCred>) -> Value + Send + Sync + 'static,
{
    let pid = std::process::id() as i32;
    let socket_path = temp_socket_path(pid);
    let _ = std::fs::remove_file(&socket_path);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    listener.set_nonblocking(true)?;
    let target_user = sudo_target_user();
    if let Some((uid, gid)) = target_user {
        chown_path(&socket_path, uid, gid)?;
        set_mode(&socket_path, 0o660)?;
    }
    let state_path = state_path(project_dir);
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent)?;
        if let Some((uid, gid)) = target_user {
            chown_path(parent, uid, gid)?;
            set_mode(parent, 0o770)?;
        }
    }
    let state = ControlState {
        schema: "actplane.control.v1".to_string(),
        pid,
        proc_start_time: proc_start_time(pid),
        socket_path: socket_path.clone(),
        project_dir: project_dir.to_path_buf(),
        parent_pid,
        parent_domain_id,
    };
    std::fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;
    if let Some((uid, gid)) = target_user {
        chown_path(&state_path, uid, gid)?;
        set_mode(&state_path, 0o640)?;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let handler = Arc::new(handler);
    let thread = std::thread::spawn(move || {
        while !stop_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let handler = handler.clone();
                    std::thread::spawn(move || handle_stream(stream, handler));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    eprintln!("ActPlane: local control accept failed: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });

    Ok(LocalControlGuard {
        stop,
        thread: Some(thread),
        socket_path,
        state_path,
    })
}

pub fn send_request(project_dir: &Path, request: Value) -> Result<Value> {
    let path = state_path(project_dir);
    let state = read_state(project_dir)?;
    if !control_process_matches(&state) {
        return Err(format!(
            "stale ActPlane control state in {}; start `actplane mcp --auto-attach-parent` again",
            path.display()
        )
        .into());
    }
    let mut stream = std::os::unix::net::UnixStream::connect(&state.socket_path)
        .map_err(|e| format!("connect {}: {e}", state.socket_path.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    serde_json::to_writer(&mut stream, &request)?;
    writeln!(stream)?;
    let mut line = String::new();
    let mut reader = std::io::BufReader::new(stream);
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err("empty response from ActPlane control socket".into());
    }
    Ok(serde_json::from_str(&line)?)
}

fn handle_stream(
    mut stream: std::os::unix::net::UnixStream,
    handler: Arc<dyn Fn(Value, Option<PeerCred>) -> Value + Send + Sync>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let peer = peer_credentials(&stream);
    let response = match read_request(&stream) {
        Ok(request) => handler(request, peer),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    };
    let _ = serde_json::to_writer(&mut stream, &response);
    let _ = writeln!(stream);
}

fn peer_credentials(stream: &std::os::unix::net::UnixStream) -> Option<PeerCred> {
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    let cred = unsafe { cred.assume_init() };
    Some(PeerCred {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
        identity: audit::ProcessIdentity::capture(cred.pid, Some(cred.uid), Some(cred.gid)),
    })
}

fn read_request(stream: &std::os::unix::net::UnixStream) -> Result<Value> {
    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err("empty control request".into());
    }
    Ok(serde_json::from_str(&line)?)
}

fn temp_socket_path(pid: i32) -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("actplane-control-{uid}-{pid}-{now}.sock"))
}

fn sudo_target_user() -> Option<(libc::uid_t, libc::gid_t)> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let uid = std::env::var("SUDO_UID")
        .ok()?
        .parse::<libc::uid_t>()
        .ok()?;
    let gid = std::env::var("SUDO_GID")
        .ok()?
        .parse::<libc::gid_t>()
        .ok()?;
    Some((uid, gid))
}

fn chown_path(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms)
}

fn control_process_matches(state: &ControlState) -> bool {
    if state.pid <= 0 {
        return false;
    }
    match (state.proc_start_time, proc_start_time(state.pid)) {
        (Some(expected), Some(actual)) => expected == actual,
        (Some(_), None) => false,
        (None, _) => process_exists(state.pid),
    }
}

fn process_exists(pid: i32) -> bool {
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    err.raw_os_error() != Some(libc::ESRCH)
}

fn proc_start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = stat.rsplit_once(") ")?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_control_round_trips_json_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let guard = start_server(dir.path(), 11, 22, |request, peer| {
            json!({
                "ok": true,
                "echo": request["op"],
                "peer_pid": peer.as_ref().map(|p| p.pid),
                "peer_uid": peer.as_ref().map(|p| p.uid),
                "peer_gid": peer.as_ref().map(|p| p.gid),
                "peer_stable_id": peer.as_ref().map(|p| p.identity.stable_id.clone()),
            })
        })
        .expect("start control server");

        let response = send_request(dir.path(), json!({ "op": "status" })).expect("request");
        assert_eq!(response["ok"], true);
        assert_eq!(response["echo"], "status");
        assert_eq!(
            response["peer_pid"].as_i64(),
            Some(std::process::id() as i64)
        );
        assert!(
            response["peer_stable_id"]
                .as_str()
                .unwrap_or("")
                .starts_with("pid:")
        );
        assert!(state_path(dir.path()).is_file());

        drop(guard);
        assert!(!state_path(dir.path()).exists());
    }

    #[test]
    fn local_control_handles_concurrent_clients() {
        let dir = tempfile::tempdir().expect("tempdir");
        let project_dir = dir.path().to_path_buf();
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen_for_handler = seen.clone();
        let guard = start_server(&project_dir, 11, 22, move |request, _peer| {
            let n = seen_for_handler.fetch_add(1, Ordering::SeqCst) + 1;
            json!({
                "ok": true,
                "idx": request["idx"],
                "seen": n,
            })
        })
        .expect("start control server");

        let mut threads = Vec::new();
        for client in 0..16 {
            let project_dir = project_dir.clone();
            threads.push(std::thread::spawn(move || {
                for req in 0..8 {
                    let idx = client * 100 + req;
                    let response =
                        send_request(&project_dir, json!({ "op": "stress", "idx": idx }))
                            .expect("concurrent request");
                    assert_eq!(response["ok"], true);
                    assert_eq!(response["idx"], idx);
                    assert!(response["seen"].as_u64().unwrap() >= 1);
                }
            }));
        }
        for thread in threads {
            thread.join().expect("client thread");
        }
        assert_eq!(seen.load(Ordering::SeqCst), 128);

        drop(guard);
        assert!(!state_path(dir.path()).exists());
    }

    #[test]
    fn stale_control_state_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = state_path(dir.path());
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        let state = ControlState {
            schema: "actplane.control.v1".to_string(),
            pid: 1,
            proc_start_time: Some(u64::MAX),
            socket_path: PathBuf::from("/tmp/actplane-missing.sock"),
            project_dir: dir.path().to_path_buf(),
            parent_pid: 1,
            parent_domain_id: 1,
        };
        std::fs::write(&path, serde_json::to_string(&state).expect("json")).expect("write");

        let err = send_request(dir.path(), json!({ "op": "status" })).unwrap_err();
        assert!(err.to_string().contains("stale ActPlane control state"));
    }
}
