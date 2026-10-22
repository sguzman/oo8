#[cfg(target_os = "linux")]
use std::{
    io::{self, IoSlice, Read},
    mem::MaybeUninit,
    os::{
        fd::AsFd,
        unix::fs::{FileTypeExt, PermissionsExt},
    },
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
const MAX_LOGIN_SECRET_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const BINARY_NAME: &str = env!("CARGO_BIN_NAME");

#[cfg(target_os = "linux")]
pub static SOCKET_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    let uid = rustix::process::getuid().as_raw();
    PathBuf::from(format!("/run/user/{uid}/oo7-daemon-login.sock"))
});

#[cfg(target_os = "linux")]
fn ensure_login_socket_vacant(path: &Path) -> io::Result<()> {
    // This is a one-shot secret-delivery socket. Connecting to determine
    // whether it is active would consume the pending connection and could
    // discard the first helper's credential. Never probe it with connect().
    // A leftover socket from a crashed helper must be cleaned up separately.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "Login helper socket already exists; refusing to consume its one-shot connection",
        )),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Existing login-helper path is not a Unix socket",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "linux")]
fn write_secret_completely(
    secret: &[u8],
    mut write: impl FnMut(&[u8]) -> io::Result<usize>,
) -> io::Result<()> {
    let mut remaining = secret;
    while !remaining.is_empty() {
        match write(remaining) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(count) => remaining = &remaining[count..],
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_memfd_send_count(count: usize) -> io::Result<()> {
    if count == 1 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "Login secret descriptor was not fully transferred",
        ))
    }
}

#[cfg(target_os = "linux")]
fn read_login_secret(mut source: impl Read) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut secret = zeroize::Zeroizing::new(Vec::new());
    source
        .by_ref()
        .take((MAX_LOGIN_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut secret)?;
    if secret.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Empty login secret",
        ));
    }
    if secret.len() > MAX_LOGIN_SECRET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Login secret exceeds maximum accepted length",
        ));
    }
    Ok(secret)
}

#[cfg(target_os = "linux")]
fn main() {
    tracing_subscriber::fmt::init();

    let mut secret = read_login_secret(io::stdin().lock()).unwrap_or_else(|e| {
        tracing::error!("Invalid login secret on stdin: {e}");
        std::process::exit(1);
    });

    tracing::info!("Starting {BINARY_NAME}");

    let socket_path = &*SOCKET_PATH;

    // Refuse to probe or unlink another helper's one-shot socket. Two
    // overlapping login attempts must not consume or disconnect each other.
    ensure_login_socket_vacant(socket_path).unwrap_or_else(|e| {
        tracing::error!(
            "Cannot prepare login helper socket {}: {e}",
            socket_path.display()
        );
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

    write_secret_completely(&secret, |bytes| {
        rustix::io::write(&memfd, bytes)
            .map_err(|err| io::Error::from_raw_os_error(err.raw_os_error()))
    })
    .unwrap_or_else(|e| {
        tracing::error!("Failed to write complete secret to memfd: {e}");
        let _ = std::fs::remove_file(socket_path);
        std::process::exit(1);
    });

    zeroize::Zeroize::zeroize(&mut *secret);

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
    rustix::net::sendmsg(&stream, &iov, &mut cmsg_buf, SendFlags::empty())
        .map_err(|err| io::Error::from_raw_os_error(err.raw_os_error()))
        .and_then(check_memfd_send_count)
        .unwrap_or_else(|e| {
            tracing::error!("Failed to transfer sealed memfd: {e}");
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
    fn sealed_memfd_transfer_requires_complete_control_message() {
        assert!(check_memfd_send_count(1).is_ok());
        assert_eq!(
            check_memfd_send_count(0).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(
            check_memfd_send_count(2).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }

    #[test]
    fn login_secret_reader_rejects_empty_and_oversized_inputs() {
        let empty = read_login_secret(io::Cursor::new(Vec::<u8>::new()));
        assert_eq!(empty.unwrap_err().kind(), io::ErrorKind::InvalidInput);

        let oversized = read_login_secret(io::Cursor::new(vec![1u8; MAX_LOGIN_SECRET_BYTES + 10]));
        assert_eq!(oversized.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn login_secret_reader_accepts_maximum_length() -> io::Result<()> {
        let secret = vec![7u8; MAX_LOGIN_SECRET_BYTES];
        let read = read_login_secret(io::Cursor::new(&secret))?;
        assert_eq!(&*read, &secret);
        Ok(())
    }

    #[test]
    fn live_login_helper_socket_is_preserved() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("login.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        let result = ensure_login_socket_vacant(&path);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AddrInUse);
        assert!(path.exists(), "Active helper socket was removed");
        listener.set_nonblocking(true)?;
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "Checking for an active helper consumed its one-shot connection"
        );
        drop(listener);
        Ok(())
    }

    #[test]
    fn stale_login_helper_socket_is_preserved() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("stale.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        drop(listener);
        assert!(path.exists());
        assert_eq!(
            ensure_login_socket_vacant(&path).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        assert!(
            path.exists(),
            "Conservative validation must not remove an existing socket"
        );
        Ok(())
    }

    #[test]
    fn secret_transfer_handles_partial_and_interrupted_writes() -> io::Result<()> {
        let secret = b"disposable-complete-transfer";
        let mut output = Vec::new();
        let mut first = true;
        write_secret_completely(secret, |remaining| {
            if first {
                first = false;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let n = remaining.len().min(3);
            output.extend_from_slice(&remaining[..n]);
            Ok(n)
        })?;
        assert_eq!(output, secret);
        Ok(())
    }

    #[test]
    fn secret_transfer_rejects_write_zero() {
        let failure = write_secret_completely(b"test", |_| Ok(0));
        assert_eq!(failure.unwrap_err().kind(), io::ErrorKind::WriteZero);
    }

    #[test]
    fn regular_file_is_never_deleted_as_login_socket() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("protected.txt");
        std::fs::write(&path, b"leave this test file intact")?;
        assert_eq!(
            ensure_login_socket_vacant(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path)?, b"leave this test file intact");
        Ok(())
    }
}
