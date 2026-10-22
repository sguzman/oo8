#[cfg(target_os = "linux")]
use std::{
    io::{self, IoSlice, Read},
    mem::MaybeUninit,
    os::{fd::AsFd, unix::fs::{FileTypeExt, PermissionsExt}},
    path::{Path, PathBuf},
    sync::LazyLock,
};

#[cfg(target_os = "linux")]
use rustix::{
    fs::{MemfdFlags, SealFlags},
    net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags},
};

#[cfg(target_os = "linux")]
const HELPER_TIMEOUT_SECS: u64 = 120;
#[cfg(target_os = "linux")]
const BINARY_NAME: &str = env!("CARGO_BIN_NAME");

#[cfg(target_os = "linux")]
pub static SOCKET_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    let uid = rustix::process::getuid().as_raw();
    PathBuf::from(format!("/run/user/{uid}/oo7-daemon-login.sock"))
});

#[cfg(target_os = "linux")]
fn remove_stale_login_socket(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_socket() => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Existing login-helper path is not a Unix socket",
        )),
        Ok(_) => match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Another login helper is already listening",
            )),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                match std::fs::remove_file(path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "linux")]
fn main() {
    tracing_subscriber::fmt::init();

    let mut secret = vec![];
    io::stdin()
        .lock()
        .read_to_end(&mut secret)
        .unwrap_or_else(|e| {
            tracing::error!("Failed to read secret from stdin: {e}");
            std::process::exit(1);
        });

    if secret.is_empty() {
        tracing::error!("No secret provided on stdin");
        std::process::exit(1);
    }

    tracing::info!("Starting {BINARY_NAME}");

    let socket_path = &*SOCKET_PATH;

    // Never unlink an existing live helper's socket. Two login attempts may
    // overlap; the later one must not disconnect the first one's secret.
    remove_stale_login_socket(socket_path).unwrap_or_else(|e| {
        tracing::error!("Cannot prepare login helper socket {}: {e}", socket_path.display());
        std::process::exit(1);
    });

    let listener = std::os::unix::net::UnixListener::bind(socket_path).unwrap_or_else(|e| {
        tracing::error!("Failed to bind {}: {e}", socket_path.display());
        std::process::exit(1);
    });

    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).unwrap_or_else(
        |e| {
            tracing::error!("Failed to set socket permissions: {e}");
            std::process::exit(1);
        },
    );

    let uid = rustix::process::getuid();

    listener.set_nonblocking(false).ok();
    tracing::info!("Listening on {}", socket_path.display());

    // Poll with timeout
    let timeout = rustix::event::Timespec {
        tv_sec: HELPER_TIMEOUT_SECS as i64,
        tv_nsec: 0,
    };
    let poll_ret = rustix::event::poll(
        &mut [rustix::event::PollFd::from_borrowed_fd(
            listener.as_fd(),
            rustix::event::PollFlags::IN,
        )],
        Some(&timeout),
    );
    match poll_ret {
        Ok(0) => {
            tracing::info!("Timed out after {HELPER_TIMEOUT_SECS}s, no daemon connected");
            let _ = std::fs::remove_file(socket_path);
            std::process::exit(0);
        }
        Err(e) => {
            tracing::error!("Poll failed: {e}");
            let _ = std::fs::remove_file(socket_path);
            std::process::exit(1);
        }
        _ => {}
    }

    let (stream, _addr) = listener.accept().unwrap_or_else(|e| {
        tracing::error!("Failed to accept connection: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });

    let peer_cred = rustix::net::sockopt::socket_peercred(&stream).unwrap_or_else(|e| {
        tracing::error!("Failed to get peer credentials: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });
    if peer_cred.uid != uid {
        tracing::error!(
            "Rejected connection from UID {} (expected {})",
            peer_cred.uid.as_raw(),
            uid.as_raw()
        );
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    }

    // Create memfd, write secret, seal it
    let memfd = rustix::fs::memfd_create(
        c"oo7-login-secret",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .unwrap_or_else(|e| {
        tracing::error!("Failed to create memfd: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });

    rustix::io::write(&memfd, &secret).unwrap_or_else(|e| {
        tracing::error!("Failed to write to memfd: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });

    zeroize::Zeroize::zeroize(&mut secret);

    rustix::fs::fcntl_add_seals(
        &memfd,
        SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
    )
    .unwrap_or_else(|e| {
        tracing::error!("Failed to seal memfd: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });

    // Send the memfd via SCM_RIGHTS
    let fds = [std::os::fd::AsFd::as_fd(&memfd)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut cmsg_buf = SendAncillaryBuffer::new(&mut space);
    cmsg_buf.push(SendAncillaryMessage::ScmRights(&fds));

    let iov = [IoSlice::new(&[0u8])];
    rustix::net::sendmsg(&stream, &iov, &mut cmsg_buf, SendFlags::empty()).unwrap_or_else(|e| {
        tracing::error!("Failed to send memfd: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });

    tracing::info!("Secret delivered to daemon");
    let _ = std::fs::remove_file(socket_path);
}

#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn live_login_helper_socket_is_preserved() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("login.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        let result = remove_stale_login_socket(&path);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AddrInUse);
        assert!(path.exists(), "Active helper socket was removed");
        let _client = std::os::unix::net::UnixStream::connect(&path)?;
        drop(listener);
        Ok(())
    }

    #[test]
    fn stale_login_helper_socket_is_cleaned() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("stale.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        drop(listener);
        assert!(path.exists());
        remove_stale_login_socket(&path)?;
        assert!(!path.exists(), "Stale helper socket was not removed");
        Ok(())
    }

    #[test]
    fn regular_file_is_never_deleted_as_login_socket() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("protected.txt");
        std::fs::write(&path, b"leave this test file intact")?;
        assert_eq!(
            remove_stale_login_socket(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path)?, b"leave this test file intact");
        Ok(())
    }
}
