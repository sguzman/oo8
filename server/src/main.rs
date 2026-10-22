#![deny(unsafe_code)]
#[cfg(target_os = "linux")]
mod capability;
mod collection;
mod error;
#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
mod gnome;
mod item;
mod migration;
mod pam_listener;
#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
mod plasma;
mod prompt;
mod service;
mod session;
#[cfg(test)]
mod tests;

use std::{
    io::{IoSliceMut, IsTerminal, Read},
    mem::MaybeUninit,
    path::PathBuf,
    sync::LazyLock,
};

use clap::Parser;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
use service::Service;
use tokio_stream::StreamExt;

use crate::error::Error;

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");
const MAX_LOGIN_SECRET_BYTES: usize = 64 * 1024;

static LOGIN_HELPER_SOCKET: LazyLock<PathBuf> = LazyLock::new(|| {
    let uid = rustix::process::getuid().as_raw();
    PathBuf::from(format!("/run/user/{uid}/oo7-daemon-login.sock"))
});

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        short = 'l',
        long,
        default_value_t = false,
        help = "Read a password from stdin, and use it to unlock the login keyring."
    )]
    login: bool,
    #[arg(short, long, help = "Replace a running instance.")]
    replace: bool,
    #[arg(
        short = 'v',
        long = "verbose",
        help = "Print debug information during command processing."
    )]
    is_verbose: bool,
}

// Bound every credential entry point before constructing a long-lived secret.
// Temporary buffers zeroize on drop, including malformed and oversized input.
fn validate_login_secret(secret: zeroize::Zeroizing<Vec<u8>>) -> std::io::Result<oo7::Secret> {
    if secret.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Login secret is empty",
        ));
    }
    if secret.len() > MAX_LOGIN_SECRET_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Login secret exceeds maximum accepted length",
        ));
    }
    Ok(oo7::Secret::from(secret))
}

fn read_bounded_login_secret(mut source: impl Read) -> std::io::Result<oo7::Secret> {
    let mut buffer = zeroize::Zeroizing::new(Vec::new());
    source
        .by_ref()
        .take((MAX_LOGIN_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut buffer)?;
    validate_login_secret(buffer)
}

fn read_secret_from_login_helper() -> Option<oo7::Secret> {
    let socket_path = &*LOGIN_HELPER_SOCKET;

    let stream = match std::os::unix::net::UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(_) => return None,
    };

    tracing::info!("Connected to login helper at {}", socket_path.display());

    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut cmsg_buf = RecvAncillaryBuffer::new(&mut space);

    match rustix::net::recvmsg(&stream, &mut iov, &mut cmsg_buf, RecvFlags::empty()) {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to receive from login helper: {e}");
            return None;
        }
    }

    for msg in cmsg_buf.drain() {
        if let RecvAncillaryMessage::ScmRights(fds) = msg {
            for fd in fds {
                // Seek to start and read the secret
                if rustix::fs::seek(&fd, rustix::fs::SeekFrom::Start(0)).is_err() {
                    continue;
                }
                let file = std::fs::File::from(fd);
                match read_bounded_login_secret(file) {
                    Ok(secret) => {
                        tracing::info!("Received login secret from helper");
                        return Some(secret);
                    }
                    Err(e) => tracing::warn!("Invalid secret from login helper: {e}"),
                }
            }
        }
    }

    tracing::warn!("Login helper sent no usable secret");
    None
}

async fn read_secret_from_credentials_directory() -> Option<oo7::Secret> {
    let credential_dir = std::env::var("CREDENTIALS_DIRECTORY").ok()?;
    let cred_path = std::path::Path::new(&credential_dir).join("oo7.keyring-encryption-password");

    match tokio::fs::File::open(&cred_path).await {
        Ok(mut cred_file) => {
            use tokio::io::AsyncReadExt;

            let mut contents = zeroize::Zeroizing::new(Vec::new());
            let result = cred_file
                .take((MAX_LOGIN_SECRET_BYTES + 1) as u64)
                .read_to_end(&mut contents)
                .await
                .and_then(|_| validate_login_secret(contents));
            match result {
                Ok(secret) => {
                    tracing::info!("Unlocking session keyring with systemd credential");
                    Some(secret)
                }
                Err(e) => {
                    tracing::error!("Invalid systemd credential: {e}");
                    None
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::error!("Failed to open credential: {e}");
            None
        }
    }
}

/// Exit when another connection takes ownership of the Secret Service name.
///
/// Losing a well-known D-Bus name does not close a process's bus connection,
/// so waiting on `connection.closed()` alone leaves a displaced daemon alive.
/// Subscribe before querying current ownership to cover the handoff race.
async fn wait_for_name_loss(connection: &zbus::Connection) -> Result<(), Error> {
    let bus = zbus::fdo::DBusProxy::new(connection).await?;
    let mut signals = bus
        .receive_name_lost_with_args(&[(0, "org.freedesktop.secrets")])
        .await?;

    let service_name = zbus::names::BusName::try_from("org.freedesktop.secrets")
        .expect("valid static Secret Service bus name");
    let our_name = connection
        .unique_name()
        .ok_or_else(|| std::io::Error::other("Session D-Bus connection lacks a unique name"))?;

    // Recheck after installing the match rule, since replacement might have
    // occurred before this monitor was initially polled.
    if bus.get_name_owner(service_name).await.ok().as_ref() != Some(our_name) {
        return Ok(());
    }

    let _ = signals.next().await;
    Ok(())
}

async fn inner_main(args: Args) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    capability::drop_unnecessary_capabilities()?;

    let secret = if args.login {
        let mut stdin = std::io::stdin().lock();
        if stdin.is_terminal() {
            let password = rpassword::prompt_password("Enter the login password: ")?;
            if password.is_empty() {
                tracing::error!("Login password can't be empty.");
                return Err(Error::EmptyPassword);
            }
            Some(oo7::Secret::text(password))
        } else {
            Some(read_bounded_login_secret(&mut stdin)?)
        }
    } else {
        match read_secret_from_login_helper() {
            Some(secret) => Some(secret),
            None => read_secret_from_credentials_directory().await,
        }
    };

    tracing::info!("Starting {BINARY_NAME}");

    let connection = match Service::run(secret, args.replace).await {
        Ok(connection) => connection,
        Err(err @ Error::File(oo7::file::Error::IncorrectSecret)) if !args.login => {
            // A failed daemon startup must not be reported as a successful
            // systemd service exit. The collection-loading path normally
            // keeps an existing keyring locked when its password is wrong.
            tracing::error!("Daemon startup failed: supplied keyring secret was rejected");
            return Err(err);
        }
        Err(Error::Zbus(zbus::Error::NameTaken)) if !args.replace => {
            tracing::error!(
                "There is an instance already running. Run with --replace to replace it."
            );
            return Err(Error::Zbus(zbus::Error::NameTaken));
        }
        Err(err) => return Err(err),
    };

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        _ = connection.closed() => tracing::info!("D-Bus connection lost, shutting down"),
        result = wait_for_name_loss(&connection) => {
            result?;
            tracing::info!("Secret Service name was replaced, shutting down displaced daemon");
        },
        _ = tokio::signal::ctrl_c() => tracing::info!("Received SIGINT, shutting down"),
        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();

    if args.is_verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
            .init();
        tracing::debug!("Running in verbose mode");
    } else {
        tracing_subscriber::fmt::init();
    }

    inner_main(args).await.inspect_err(|err| {
        tracing::error!("{err:#}");
    })
}

#[cfg(test)]
mod login_secret_tests {
    use super::*;

    #[test]
    fn rejects_empty_and_oversized_credentials() {
        assert_eq!(
            read_bounded_login_secret(std::io::Cursor::new(Vec::<u8>::new()))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            read_bounded_login_secret(std::io::Cursor::new(vec![
                5u8;
                MAX_LOGIN_SECRET_BYTES + 20
            ]))
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn accepts_maximum_credential_length() -> std::io::Result<()> {
        let expected = vec![6u8; MAX_LOGIN_SECRET_BYTES];
        let secret = read_bounded_login_secret(std::io::Cursor::new(&expected))?;
        assert_eq!(secret.as_bytes(), &expected);
        Ok(())
    }
}
