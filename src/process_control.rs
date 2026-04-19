use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

#[derive(Debug, Clone, Copy, Default)]
pub struct ControlRequest {
    pub start: bool,
    pub stop: bool,
    pub restart: bool,
    pub status: bool,
    pub daemon_child: bool,
}

impl ControlRequest {
    pub fn active_count(self) -> usize {
        self.start as usize + self.stop as usize + self.restart as usize + self.status as usize
    }
}

#[derive(Debug, Clone)]
pub struct ControlFiles {
    pub pid_file: PathBuf,
    pub log_file: PathBuf,
}

#[derive(Debug)]
pub struct PidFileGuard {
    path: PathBuf,
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn resolve_control_files(
    exe_name: &str,
    config_path: Option<&Path>,
    data_dir: Option<&Path>,
    pid_override: Option<&str>,
    log_override: Option<&str>,
) -> ControlFiles {
    let base_dir = if let Some(data_dir) = data_dir {
        data_dir.to_path_buf()
    } else if let Some(config_path) = config_path.and_then(Path::parent) {
        config_path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };

    let pid_file = pid_override
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir.join(format!("{exe_name}.pid")));
    let log_file = log_override
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir.join(format!("{exe_name}.log")));

    ControlFiles { pid_file, log_file }
}

pub fn install_pid_guard_if_needed(
    request: ControlRequest,
    files: &ControlFiles,
) -> Result<Option<PidFileGuard>> {
    if !request.daemon_child {
        return Ok(None);
    }

    if let Some(parent) = files.pid_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create pid file directory {}", parent.display()))?;
    }

    if let Some(pid) = read_pid(&files.pid_file)? {
        if process_is_running(pid) {
            bail!(
                "xledgrs is already running with pid {} (pid file {})",
                pid,
                files.pid_file.display()
            );
        }
        let _ = fs::remove_file(&files.pid_file);
    }

    fs::write(&files.pid_file, format!("{}\n", std::process::id()))
        .with_context(|| format!("failed to write pid file {}", files.pid_file.display()))?;

    Ok(Some(PidFileGuard {
        path: files.pid_file.clone(),
    }))
}

pub fn handle_control_request(request: ControlRequest, files: &ControlFiles) -> Result<bool> {
    if request.daemon_child {
        return Ok(false);
    }
    if request.active_count() == 0 {
        return Ok(false);
    }
    if request.active_count() > 1 {
        bail!("use only one of --start, --stop, --restart, or --status at a time");
    }

    if request.status {
        print_status(files)?;
        return Ok(true);
    }

    if request.stop {
        stop_process(files)?;
        return Ok(true);
    }

    if request.restart {
        stop_process(files)?;
        start_process(files)?;
        return Ok(true);
    }

    if request.start {
        start_process(files)?;
        return Ok(true);
    }

    Ok(false)
}

fn start_process(files: &ControlFiles) -> Result<()> {
    if let Some(pid) = read_pid(&files.pid_file)? {
        if process_is_running(pid) {
            bail!(
                "xledgrs is already running with pid {} (pid file {})",
                pid,
                files.pid_file.display()
            );
        }
        let _ = fs::remove_file(&files.pid_file);
    }

    if let Some(parent) = files.log_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create log file directory {}", parent.display()))?;
    }
    if let Some(parent) = files.pid_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create pid file directory {}", parent.display()))?;
    }

    let log_file = open_log_file(&files.log_file)?;
    let log_file_err = log_file
        .try_clone()
        .with_context(|| format!("failed to clone log handle {}", files.log_file.display()))?;
    let mut command =
        Command::new(std::env::current_exe().context("failed to locate xledgrs executable")?);
    command
        .args(filtered_child_args())
        .arg("--daemon-child")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command
        .spawn()
        .context("failed to spawn detached xledgrs")?;
    std::thread::sleep(Duration::from_millis(500));
    if let Some(status) = child
        .try_wait()
        .context("failed to poll detached xledgrs")?
    {
        bail!(
            "xledgrs exited early with status {}. Check {}",
            status,
            files.log_file.display()
        );
    }

    println!(
        "started xledgrs (pid {})\nlog: {}\npid: {}",
        child.id(),
        files.log_file.display(),
        files.pid_file.display()
    );
    Ok(())
}

fn stop_process(files: &ControlFiles) -> Result<()> {
    let Some(pid) = read_pid(&files.pid_file)? else {
        println!(
            "xledgrs is not running (no pid file at {})",
            files.pid_file.display()
        );
        return Ok(());
    };

    if !process_is_running(pid) {
        let _ = fs::remove_file(&files.pid_file);
        println!(
            "removed stale pid file {}; xledgrs is not running",
            files.pid_file.display()
        );
        return Ok(());
    }

    signal_process(pid, libc::SIGTERM)
        .with_context(|| format!("failed to signal xledgrs pid {}", pid))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if !process_is_running(pid) {
            let _ = fs::remove_file(&files.pid_file);
            println!("stopped xledgrs (pid {})", pid);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    bail!(
        "xledgrs pid {} did not stop within 15 seconds; check {}",
        pid,
        files.log_file.display()
    );
}

fn print_status(files: &ControlFiles) -> Result<()> {
    match read_pid(&files.pid_file)? {
        Some(pid) if process_is_running(pid) => {
            println!(
                "xledgrs is running (pid {})\nlog: {}\npid: {}",
                pid,
                files.log_file.display(),
                files.pid_file.display()
            );
        }
        Some(_) => {
            println!(
                "xledgrs is not running; stale pid file at {}",
                files.pid_file.display()
            );
        }
        None => {
            println!(
                "xledgrs is not running (no pid file at {})",
                files.pid_file.display()
            );
        }
    }
    Ok(())
}

fn filtered_child_args() -> Vec<OsString> {
    let mut filtered = Vec::new();
    let mut args = std::env::args_os().skip(1).peekable();
    while let Some(arg) = args.next() {
        if arg == "--start" || arg == "--stop" || arg == "--restart" || arg == "--status" {
            continue;
        }
        if arg == "--pid-file" || arg == "--log-file" {
            let _ = args.next();
            continue;
        }
        if arg == "--daemon-child" {
            continue;
        }
        if let Some(text) = arg.to_str() {
            if text.starts_with("--pid-file=")
                || text.starts_with("--log-file=")
                || text == "--daemon-child"
            {
                continue;
            }
        }
        filtered.push(arg);
    }
    filtered
}

fn read_pid(path: &Path) -> Result<Option<i32>> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let raw = contents.trim();
            if raw.is_empty() {
                return Ok(None);
            }
            let pid = raw
                .parse::<i32>()
                .with_context(|| format!("invalid pid file {}", path.display()))?;
            Ok(Some(pid))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("failed to read pid file {}", path.display())),
    }
}

fn open_log_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open log file {}", path.display()))
}

fn process_is_running(pid: i32) -> bool {
    unsafe {
        if libc::kill(pid, 0) == 0 {
            true
        } else {
            matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(code) if code == libc::EPERM
            )
        }
    }
}

fn signal_process(pid: i32, signal: i32) -> Result<()> {
    unsafe {
        if libc::kill(pid, signal) == 0 {
            Ok(())
        } else {
            Err(anyhow!(std::io::Error::last_os_error()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_control_files_prefers_data_dir() {
        let files = resolve_control_files(
            "xledgrs",
            Some(Path::new("/tmp/config/xledgrs.cfg")),
            Some(Path::new("/tmp/data")),
            None,
            None,
        );
        assert_eq!(files.pid_file, PathBuf::from("/tmp/data/xledgrs.pid"));
        assert_eq!(files.log_file, PathBuf::from("/tmp/data/xledgrs.log"));
    }

    #[test]
    fn filtered_child_args_removes_process_control_flags() {
        let args = vec![
            OsString::from("xledgrs"),
            OsString::from("--start"),
            OsString::from("--config"),
            OsString::from("node.cfg"),
            OsString::from("--pid-file=/tmp/xledgrs.pid"),
            OsString::from("--log-file"),
            OsString::from("/tmp/xledgrs.log"),
            OsString::from("--peer-addr"),
            OsString::from("0.0.0.0:51235"),
        ];
        let filtered = {
            let mut filtered = Vec::new();
            let mut iter = args.into_iter().skip(1).peekable();
            while let Some(arg) = iter.next() {
                if arg == "--start" || arg == "--stop" || arg == "--restart" || arg == "--status" {
                    continue;
                }
                if arg == "--pid-file" || arg == "--log-file" {
                    let _ = iter.next();
                    continue;
                }
                if arg == "--daemon-child" {
                    continue;
                }
                if let Some(text) = arg.to_str() {
                    if text.starts_with("--pid-file=")
                        || text.starts_with("--log-file=")
                        || text == "--daemon-child"
                    {
                        continue;
                    }
                }
                filtered.push(arg);
            }
            filtered
        };

        assert_eq!(
            filtered,
            vec![
                OsString::from("--config"),
                OsString::from("node.cfg"),
                OsString::from("--peer-addr"),
                OsString::from("0.0.0.0:51235"),
            ]
        );
    }
}
