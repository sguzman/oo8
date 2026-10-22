use std::{
    io::{self, Write},
    os::{
        fd::{FromRawFd, RawFd},
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::PathBuf,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};
use zeroize::Zeroizing;

use crate::protocol::{PamMessage, PamResponse};

/// Timeout for socket operations (in milliseconds)
const SOCKET_TIMEOUT_MS: u64 = 5000;

// Both request and response frames contain only short credentials and status.
// Reject client/server-controlled lengths before allocating buffers.
const MAX_PAM_FRAME_BYTES: usize = 64 * 1024;

fn checked_pam_frame_length(length: usize) -> Result<u32, SocketError> {
    if length == 0 || length > MAX_PAM_FRAME_BYTES {
        return Err(SocketError::Send(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid PAM frame length {length} (maximum {MAX_PAM_FRAME_BYTES})"),
        )));
    }

    u32::try_from(length).map_err(|_| {
        SocketError::Send(io::Error::new(
            io::ErrorKind::InvalidData,
            "PAM frame length overflow",
        ))
    })
}

struct SavedSignals {
    sigpipe: libc::sigaction,
    sigchld: libc::sigaction,
}

impl SavedSignals {
    fn new() -> Self {
        unsafe {
            let mut saved = Self {
                sigpipe: std::mem::zeroed(),
                sigchld: std::mem::zeroed(),
            };

            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_IGN;
            libc::sigaction(libc::SIGPIPE, &action, &mut saved.sigpipe);

            action.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGCHLD, &action, &mut saved.sigchld);

            saved
        }
    }
}

impl Drop for SavedSignals {
    fn drop(&mut self) {
        unsafe {
            libc::sigaction(libc::SIGPIPE, &self.sigpipe, std::ptr::null_mut());
            libc::sigaction(libc::SIGCHLD, &self.sigchld, std::ptr::null_mut());
        }
    }
}

/// Error type for socket operations
#[derive(Debug)]
pub enum SocketError {
    Connect(io::Error),
    Send(io::Error),
    Serialize(zgvariant::Error),
    Timeout,
    InvalidSocket(String),
    Rejected(String),
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "Failed to connect to daemon socket: {e}"),
            Self::Send(e) => write!(f, "Failed to send message: {e}"),
            Self::Serialize(e) => write!(f, "Failed to serialize message: {e}"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::InvalidSocket(msg) => write!(f, "Invalid socket: {msg}"),
            Self::Rejected(reason) => write!(f, "Daemon rejected PAM request: {reason}"),
        }
    }
}

impl std::error::Error for SocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) | Self::Send(e) => Some(e),
            Self::Serialize(e) => Some(e),
            Self::Timeout | Self::InvalidSocket(_) | Self::Rejected(_) => None,
        }
    }
}

pub fn send_secret_to_daemon(
    message: PamMessage,
    uid: u32,
    gid: u32,
    auto_start: bool,
) -> Result<(), SocketError> {
    // Check if we're already running as the target user
    let current_uid = unsafe { libc::getuid() };
    let current_gid = unsafe { libc::getgid() };
    let current_euid = unsafe { libc::geteuid() };
    let current_egid = unsafe { libc::getegid() };

    if uid == current_uid && gid == current_gid && uid == current_euid && gid == current_egid {
        tracing::debug!("Already running as target user (UID={uid}, GID={gid})",);
        let runtime = tokio::runtime::Runtime::new().map_err(SocketError::Connect)?;
        return runtime
            .block_on(async { send_secret_to_daemon_async(message, uid, auto_start, None).await });
    }

    // Need to fork and switch credentials
    tracing::debug!(
        "Running as different user (current UID={current_uid}, target UID={uid}), forking to switch credentials"
    );

    let saved_signals = SavedSignals::new();

    match unsafe { libc::fork() } {
        -1 => {
            drop(saved_signals);
            tracing::error!("Failed to fork process for credential switch");
            Err(SocketError::Connect(io::Error::last_os_error()))
        }
        0 => {
            unsafe {
                if libc::setgid(gid) < 0
                    || libc::setuid(uid) < 0
                    || libc::setegid(gid) < 0
                    || libc::seteuid(uid) < 0
                {
                    tracing::error!(
                        "Failed to switch to user credentials (UID={uid}, GID={gid}): {}",
                        io::Error::last_os_error()
                    );
                    libc::_exit(1);
                }
            }

            tracing::debug!("Child process switched to UID={uid}, GID={gid}");

            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("Failed to create tokio runtime in child: {e}",);
                    unsafe { libc::_exit(1) };
                }
            };

            let result = runtime.block_on(async {
                send_secret_to_daemon_async(message, uid, auto_start, None).await
            });

            match result {
                Ok(_) => unsafe { libc::_exit(0) },
                Err(e) => {
                    tracing::error!("Failed to send message in child process: {e}",);
                    unsafe { libc::_exit(1) }
                }
            }
        }
        child_pid => {
            // Parent process - wait for child to complete
            tracing::debug!("Forked child process with PID {child_pid}",);
            let mut status: libc::c_int = 0;

            loop {
                let wait_result = unsafe { libc::waitpid(child_pid, &mut status, 0) };
                if wait_result == child_pid {
                    break;
                } else if wait_result == -1 {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::Interrupted {
                        drop(saved_signals);
                        tracing::error!("Failed to wait for child process: {err}",);
                        return Err(SocketError::Connect(err));
                    }
                }
            }

            drop(saved_signals);

            if libc::WIFEXITED(status) {
                let exit_code = libc::WEXITSTATUS(status);
                if exit_code == 0 {
                    tracing::debug!("Child process completed successfully");
                    Ok(())
                } else {
                    tracing::error!("Child process exited with code {exit_code}");
                    Err(SocketError::Connect(io::Error::other(format!(
                        "Child process failed with exit code {exit_code}"
                    ))))
                }
            } else {
                tracing::error!("Child process terminated abnormally");
                Err(SocketError::Connect(io::Error::other(
                    "Child process terminated abnormally",
                )))
            }
        }
    }
}

// Take ownership of the descriptor so it is always closed, including after
// an interrupted write or a receiver that closes early. write_all retries
// short writes and EINTR and reports EPIPE rather than silently truncating.
fn send_secret_to_helper_pipe(write_fd: RawFd, secret: &[u8]) -> io::Result<()> {
    let mut writer = unsafe { std::fs::File::from_raw_fd(write_fd) };
    writer.write_all(secret)
}

/// Start the oo7-daemon-login helper, passing the secret via stdin pipe.
///
/// The helper holds the secret on a socket until oo7-daemon connects and
/// retrieves it via memfd.
fn start_login_helper(secret: &[u8]) -> Result<(), SocketError> {
    tracing::info!("Starting oo7-daemon-login helper");

    let mut pipe_fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } < 0 {
        return Err(SocketError::Connect(io::Error::last_os_error()));
    }
    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

    let saved_signals = SavedSignals::new();

    match unsafe { libc::fork() } {
        -1 => {
            drop(saved_signals);
            unsafe {
                libc::close(pipe_read);
                libc::close(pipe_write);
            }
            Err(SocketError::Connect(io::Error::last_os_error()))
        }
        0 => unsafe {
            libc::close(pipe_write);

            libc::dup2(pipe_read, 0);
            if pipe_read > 0 {
                libc::close(pipe_read);
            }

            let path = std::ffi::CString::new(
                option_env!("OO7_DAEMON_LOGIN_PATH").unwrap_or("/usr/libexec/oo7-daemon-login"),
            )
            .unwrap();
            let args = [path.as_ptr(), std::ptr::null()];
            libc::execv(path.as_ptr(), args.as_ptr());

            libc::_exit(1);
        },
        child_pid => {
            unsafe {
                libc::close(pipe_read);
            }
            let sent = send_secret_to_helper_pipe(pipe_write, secret);
            drop(saved_signals);
            sent.map_err(SocketError::Send)?;
            tracing::info!("Started oo7-daemon-login with PID {child_pid}");
            Ok(())
        }
    }
}

async fn send_secret_to_daemon_async(
    message: PamMessage,
    uid: u32,
    auto_start: bool,
    socket_path: Option<PathBuf>,
) -> Result<(), SocketError> {
    let socket_path = socket_path
        .or_else(|| std::env::var("OO7_PAM_SOCKET").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}/oo7-pam.sock")));

    tracing::debug!("Connecting to daemon socket at: {}", socket_path.display());

    // Validate socket ownership before connecting to prevent interception
    // by a fake socket placed by another user.
    match socket_path.symlink_metadata() {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(SocketError::InvalidSocket(
                    "socket path is a symlink".to_string(),
                ));
            }
            if !meta.file_type().is_socket() {
                return Err(SocketError::InvalidSocket(
                    "path is not a socket".to_string(),
                ));
            }
            if meta.uid() != uid {
                return Err(SocketError::InvalidSocket(format!(
                    "socket owned by UID {} but expected {}",
                    meta.uid(),
                    uid
                )));
            }
        }
        Err(e) if auto_start && e.kind() == io::ErrorKind::NotFound => {
            tracing::info!("Socket not found, starting login helper");
            start_login_helper(&message.new_secret)?;
            return Ok(());
        }
        Err(e) => {
            return Err(SocketError::Connect(e));
        }
    }

    let mut stream = match timeout(
        Duration::from_millis(SOCKET_TIMEOUT_MS),
        UnixStream::connect(&socket_path),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) if auto_start => {
            tracing::info!("Daemon not running ({}), starting login helper", e.kind());
            start_login_helper(&message.new_secret)?;
            return Ok(());
        }
        Ok(Err(e)) => {
            return Err(SocketError::Connect(e));
        }
        Err(_) => {
            return Err(SocketError::Timeout);
        }
    };

    tracing::debug!("Connected to daemon socket");

    tracing::debug!("Sending message for user {}", message.username);
    let message_bytes = Zeroizing::new(message.to_bytes().map_err(SocketError::Serialize)?);

    let length = checked_pam_frame_length(message_bytes.len())?;
    stream
        .write_all(&length.to_le_bytes())
        .await
        .map_err(SocketError::Send)?;

    timeout(
        Duration::from_millis(SOCKET_TIMEOUT_MS),
        stream.write_all(&message_bytes),
    )
    .await
    .map_err(|_| SocketError::Timeout)?
    .map_err(SocketError::Send)?;

    stream.flush().await.map_err(SocketError::Send)?;

    tracing::debug!("Sent message to daemon, reading response");

    // Sending credentials is not proof of acceptance. Read the entire
    // acknowledgment under one deadline, including its length and body.
    let response = timeout(Duration::from_millis(SOCKET_TIMEOUT_MS), async {
        let mut length_bytes = [0u8; 4];
        stream
            .read_exact(&mut length_bytes)
            .await
            .map_err(SocketError::Send)?;
        let length = checked_pam_frame_length(u32::from_le_bytes(length_bytes) as usize)? as usize;
        let mut response_bytes = vec![0u8; length];
        stream
            .read_exact(&mut response_bytes)
            .await
            .map_err(SocketError::Send)?;
        PamResponse::from_bytes(&response_bytes).map_err(SocketError::Serialize)
    })
    .await
    .map_err(|_| SocketError::Timeout)??;

    if response.success {
        tracing::debug!("Daemon accepted secret");
        Ok(())
    } else {
        tracing::warn!("Daemon rejected secret: {}", response.error_message);
        Err(SocketError::Rejected(response.error_message))
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    use super::*;

    #[test]
    fn helper_pipe_receives_complete_secret() -> Result<(), Box<dyn std::error::Error>> {
        use io::Read;

        let mut descriptors = [0; 2];
        if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let secret = b"disposable-helper-credential";
        send_secret_to_helper_pipe(descriptors[1], secret)?;

        let mut reader = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
        let mut transferred = Vec::new();
        reader.read_to_end(&mut transferred)?;
        assert_eq!(transferred, secret);
        Ok(())
    }

    #[test]
    fn pam_frames_must_have_bounded_lengths() {
        assert_eq!(checked_pam_frame_length(1).unwrap(), 1);
        assert_eq!(
            checked_pam_frame_length(MAX_PAM_FRAME_BYTES).unwrap(),
            MAX_PAM_FRAME_BYTES as u32
        );

        for length in [0, MAX_PAM_FRAME_BYTES + 1, u32::MAX as usize] {
            assert!(
                matches!(
                    checked_pam_frame_length(length),
                    Err(SocketError::Send(err)) if err.kind() == io::ErrorKind::InvalidData
                ),
                "Invalid PAM frame length {length} was accepted"
            );
        }
    }

    #[tokio::test]
    async fn rejected_daemon_reply_fails() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("rejected.sock");
        let listener = UnixListener::bind(&socket)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0u8; 4];
            stream.read_exact(&mut length).await.unwrap();
            let mut request = vec![0u8; u32::from_le_bytes(length) as usize];
            stream.read_exact(&mut request).await.unwrap();
            let reply = PamResponse {
                success: false,
                error_message: "keyring locked".into(),
            };
            let context = zgvariant::serialized::Context::new(zgvariant::LE, 0);
            let bytes = zgvariant::to_bytes(context, &reply).unwrap().to_vec();
            stream
                .write_all(&(bytes.len() as u32).to_le_bytes())
                .await
                .unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let uid = unsafe { libc::getuid() };
        let message = PamMessage::unlock("testuser".into(), b"testpassword".to_vec());
        let result = send_secret_to_daemon_async(message, uid, false, Some(socket)).await;
        assert!(
            matches!(result, Err(SocketError::Rejected(reason)) if reason == "keyring locked"),
            "Daemon rejection must not be interpreted as success"
        );
        server.await?;
        Ok(())
    }

    #[tokio::test]
    async fn missing_acknowledgment_fails() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("missing-ack.sock");
        let listener = UnixListener::bind(&socket)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0u8; 4];
            stream.read_exact(&mut length).await.unwrap();
            let mut request = vec![0u8; u32::from_le_bytes(length) as usize];
            stream.read_exact(&mut request).await.unwrap();
            // Drop without a response.
        });
        let uid = unsafe { libc::getuid() };
        let message = PamMessage::unlock("testuser".into(), b"testpassword".to_vec());
        let result = send_secret_to_daemon_async(message, uid, false, Some(socket)).await;
        assert!(
            matches!(result, Err(SocketError::Send(_))),
            "Missing daemon acknowledgment must not be interpreted as success"
        );
        server.await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_send_receive() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        let socket_path = temp_dir.path().join("test.sock");

        let socket_path_clone = socket_path.clone();
        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path_clone).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut length_bytes = [0u8; 4];
            stream.read_exact(&mut length_bytes).await.unwrap();
            let message_length = u32::from_le_bytes(length_bytes) as usize;

            let mut message_bytes = vec![0u8; message_length];
            stream.read_exact(&mut message_bytes).await.unwrap();

            let message = PamMessage::from_bytes(&message_bytes).unwrap();
            assert_eq!(message.username, "testuser");
            assert_eq!(message.new_secret, b"testpassword");

            let reply = PamResponse {
                success: true,
                error_message: String::new(),
            };
            let context = zgvariant::serialized::Context::new(zgvariant::LE, 0);
            let bytes = zgvariant::to_bytes(context, &reply).unwrap().to_vec();
            stream
                .write_all(&(bytes.len() as u32).to_le_bytes())
                .await
                .unwrap();
            stream.write_all(&bytes).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let message = PamMessage::unlock("testuser".to_string(), b"testpassword".to_vec());

        // The socket must be owned by the given UID
        let uid = unsafe { libc::getuid() };
        let result = send_secret_to_daemon_async(message, uid, false, Some(socket_path)).await;
        assert!(result.is_ok());

        server.await?;

        Ok(())
    }
}
