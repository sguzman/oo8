//! PAM integration - Unix socket listener for receiving secrets from PAM module

use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};

use oo7::Secret;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tokio::{
    io::AsyncReadExt,
    net::{UnixListener, UnixStream},
    sync::{RwLock, Semaphore},
};
use zeroize::{Zeroize, ZeroizeOnDrop};
use zgvariant::{
    self, Type,
    serialized::{Context, Data},
};

use crate::{Service, error::Error};

// A PAM frame holds a username and two credentials, not bulk data.
// Check the client-controlled length before allocating or reading its body.
const MAX_PAM_MESSAGE_BYTES: usize = 64 * 1024;
// Limit tasks awaiting partially sent frames or slow credential processing.
const MAX_ACTIVE_PAM_CONNECTIONS: usize = 32;

// Bound the entire read, including the length prefix and payload, so an
// incomplete same-user connection cannot hold a daemon task forever.
const PAM_FRAME_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn read_pam_message(stream: &mut UnixStream) -> Result<PamMessage, Error> {
    read_pam_message_with_timeout(stream, PAM_FRAME_READ_TIMEOUT).await
}

async fn read_pam_message_with_timeout(
    stream: &mut UnixStream,
    read_timeout: std::time::Duration,
) -> Result<PamMessage, Error> {
    tokio::time::timeout(read_timeout, async {
        let mut length_bytes = [0u8; 4];
        stream.read_exact(&mut length_bytes).await?;
        let message_length = u32::from_le_bytes(length_bytes) as usize;

        if message_length == 0 || message_length > MAX_PAM_MESSAGE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid PAM message length {message_length} (maximum {MAX_PAM_MESSAGE_BYTES})"
                ),
            )
            .into());
        }

        // The serialized frame contains plaintext credentials; wipe it on drop,
        // including when the read times out with a partially populated buffer.
        let mut message_bytes = zeroize::Zeroizing::new(vec![0u8; message_length]);
        stream.read_exact(message_bytes.as_mut_slice()).await?;

        PamMessage::from_bytes(&message_bytes).map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()).into()
        })
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Timed out reading PAM credential frame",
        )
    })?
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, Type, PartialEq, Eq)]
#[repr(u8)]
enum PamOperation {
    Unlock = 0,
    ChangePassword = 1,
}

#[derive(Serialize, Deserialize, Type, Zeroize, ZeroizeOnDrop)]
struct PamMessage {
    #[zeroize(skip)]
    operation: PamOperation,
    username: String,
    old_secret: Vec<u8>,
    new_secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Type)]
struct PamResponse {
    success: bool,
    error_message: String,
}

impl PamMessage {
    fn from_bytes(bytes: &[u8]) -> Result<Self, zgvariant::Error> {
        let ctxt = Context::new(zgvariant::LE, 0);
        let data = Data::new(bytes, ctxt);
        data.deserialize().map(|(msg, _)| msg)
    }
}

impl PamResponse {
    fn success() -> Self {
        Self {
            success: true,
            error_message: String::new(),
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            error_message: message,
        }
    }

    #[cfg(test)]
    fn from_bytes(bytes: &[u8]) -> Result<Self, zgvariant::Error> {
        let ctxt = Context::new(zgvariant::LE, 0);
        let data = Data::new(bytes, ctxt);
        data.deserialize().map(|(msg, _)| msg)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, zgvariant::Error> {
        let ctxt = Context::new(zgvariant::LE, 0);
        let encoded = zgvariant::to_bytes(ctxt, self)?;
        let message_bytes = encoded.to_vec();

        // Prepend length prefix (4 bytes, little-endian)
        let mut result = (message_bytes.len() as u32).to_le_bytes().to_vec();
        result.extend_from_slice(&message_bytes);
        Ok(result)
    }
}

/// Write the complete PAM acknowledgment or report why it could not be sent.
async fn send_pam_response(stream: &mut UnixStream, response: &PamResponse) -> Result<(), Error> {
    use tokio::io::AsyncWriteExt;

    let bytes = response
        .to_bytes()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

    tokio::time::timeout(PAM_FRAME_READ_TIMEOUT, async {
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Timed out writing PAM acknowledgment",
        )
    })??;

    Ok(())
}

/// PAM listener that receives authentication secrets from the PAM module
#[derive(Clone)]
pub struct PamListener {
    pub(crate) socket_path: PathBuf,
    service: Service,
    /// Current user's secret, used to unlock their keyring <username, secret>
    // Some while startup is pending; None after the one-time replay.
    user_secrets: Arc<RwLock<Option<std::collections::HashMap<String, Secret>>>>,
}

impl PamListener {
    pub fn new(service: Service) -> Self {
        let uid = rustix::process::getuid().as_raw();
        let socket_path = service
            .pam_socket
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}/oo7-pam.sock")));

        Self {
            socket_path,
            service,
            user_secrets: Arc::new(RwLock::new(Some(std::collections::HashMap::new()))),
        }
    }

    /// Start the PAM listener
    pub async fn start(self) -> Result<(), Error> {
        self.start_with_semaphore(Arc::new(Semaphore::new(MAX_ACTIVE_PAM_CONNECTIONS)))
            .await
    }

    async fn start_with_semaphore(self, active: Arc<Semaphore>) -> Result<(), Error> {
        // Only unlink a *stale* socket. Another daemon may already be
        // serving PAM requests here, even if this process has not yet lost
        // the Secret Service D-Bus name race. Unlinking a live listener's
        // pathname permanently disconnects new PAM clients from it.
        if self.socket_path.exists() {
            match UnixStream::connect(&self.socket_path).await {
                Ok(stream) => {
                    drop(stream);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        format!("Active PAM listener at {}", self.socket_path.display()),
                    )
                    .into());
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) =>
                {
                    // A socket left behind by a dead daemon is safe to
                    // remove. Ignore disappearance if another startup
                    // removed it concurrently.
                    match tokio::fs::remove_file(&self.socket_path).await {
                        Ok(()) => {}
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => return Err(err.into()),
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        tracing::info!("PAM listener started on {}", self.socket_path.display());

        // Set socket permissions to 0600
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&self.socket_path, perms)?;

        let listener = Arc::new(listener);

        // Accept connections in a loop
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    // Reject overflow instead of spawning an unbounded number
                    // of tasks. Dropping an excess stream makes the PAM client
                    // observe a failed request rather than silent success.
                    let Ok(permit) = active.clone().try_acquire_owned() else {
                        tracing::warn!("PAM connection limit reached; rejecting connection");
                        drop(stream);
                        continue;
                    };
                    let pam_listener = self.clone();

                    tokio::spawn(async move {
                        // Dropping this guard releases the slot on any exit
                        // path.
                        let _permit = permit;
                        if let Err(e) = pam_listener.handle_connection(stream).await {
                            tracing::error!("Error handling PAM connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Error accepting PAM connection: {}", e);
                }
            }
        }
    }

    /// Handle a single PAM connection
    async fn handle_connection(&self, mut stream: UnixStream) -> Result<(), Error> {
        // Accept connections from:
        // 1. Root (UID 0) as PAM modules run as root during authentication
        // 2. Same UID as us
        let peer_cred = stream.peer_cred()?;
        let our_uid = rustix::process::getuid().as_raw();
        let peer_uid = peer_cred.uid();

        if peer_uid != 0 && peer_uid != our_uid {
            tracing::warn!(
                "Rejected PAM connection from UID {} PID {} (expected UID 0 or {})",
                peer_uid,
                peer_cred.pid().unwrap_or(0),
                our_uid
            );
            return Err(Error::IO(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Connection rejected: unauthorized UID (peer={}, daemon={}, root=0)",
                    peer_uid, our_uid
                ),
            )));
        }

        tracing::debug!(
            "Accepted PAM connection from {} (UID {}, PID {})",
            if peer_uid == 0 {
                "root/PAM"
            } else {
                "same user"
            },
            peer_uid,
            peer_cred.pid().unwrap_or(0)
        );

        let message = read_pam_message(&mut stream).await?;

        let response = match message.operation {
            PamOperation::Unlock => {
                tracing::info!("Received unlock request for user: {}", message.username);
                tracing::debug!(
                    "Received secret of length {} bytes",
                    message.new_secret.len()
                );

                let secret = Secret::from(message.new_secret.to_vec());
                if let Some(buffered) = self.user_secrets.write().await.as_mut() {
                    buffered.insert(message.username.clone(), secret.clone());
                }

                match self.try_unlock_collections(&secret).await {
                    Ok(_) => {
                        tracing::info!(
                            "Successfully unlocked collections for user: {}",
                            message.username
                        );
                        PamResponse::success()
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to unlock collections for user {}: {}",
                            message.username,
                            e
                        );
                        PamResponse::error(e.to_string())
                    }
                }
            }
            PamOperation::ChangePassword => {
                tracing::info!(
                    "Received password change request for user: {}",
                    message.username
                );
                tracing::debug!(
                    "Old secret: {} bytes, new secret: {} bytes",
                    message.old_secret.len(),
                    message.new_secret.len()
                );

                let old_secret = Secret::from(message.old_secret.to_vec());
                let new_secret = Secret::from(message.new_secret.to_vec());

                match self
                    .change_collection_passwords(&old_secret, &new_secret)
                    .await
                {
                    Ok(changed_count) => {
                        tracing::info!(
                            "Successfully changed password for {} collection(s) for user: {}",
                            changed_count,
                            message.username
                        );
                        // Update stored secret
                        if let Some(buffered) = self.user_secrets.write().await.as_mut() {
                            buffered.insert(message.username.clone(), new_secret);
                        }
                        PamResponse::success()
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to change password for user {}: {}",
                            message.username,
                            e
                        );
                        PamResponse::error(e.to_string())
                    }
                }
            }
        };

        // A successful request is not complete until its acknowledgment
        // has been written; propagate disconnects and serialization errors.
        send_pam_response(&mut stream, &response).await
    }

    /// Replay any secrets buffered before collections were initialized.
    pub async fn replay_buffered_secrets(&self) {
        // End buffering atomically and drain the startup credentials. New
        // requests unlock keyrings directly and must not retain passwords.
        // Do not hold the lock across the potentially slow replay.
        let secrets = self.user_secrets.write().await.take().unwrap_or_default();
        if secrets.is_empty() {
            return;
        }
        tracing::info!(
            "Replaying {} buffered secret(s) received during startup",
            secrets.len()
        );
        for (username, secret) in secrets.iter() {
            match self.try_unlock_collections(secret).await {
                Ok(_) => tracing::info!("Replayed unlock for user: {}", username),
                Err(e) => tracing::warn!("Failed to replay unlock for user {}: {}", username, e),
            }
        }
    }

    async fn try_unlock_collections(&self, secret: &Secret) -> Result<(), Error> {
        // A wrong credential must not be acknowledged as a successful unlock.
        // Pending migrations are also credential-bearing keyrings and count
        // as incomplete when none of the provided secrets can open them.
        let pending_before = self.service.pending_migrations.lock().await.len();
        let migrated = self.service.migrate_pending_keyrings(secret).await;
        if !migrated.is_empty() {
            tracing::info!("Migrated {} v0 keyring(s): {:?}", migrated.len(), migrated);
        }

        let collections = self.service.collections.lock().await;
        let mut unlocked = 0;
        let mut failed_unlocks = 0;

        for collection in collections.values() {
            if collection.is_locked().await {
                tracing::debug!("Attempting to unlock collection: {}", collection.path());

                match collection.set_locked(false, Some(secret.clone())).await {
                    Ok(()) => {
                        unlocked += 1;
                        tracing::info!("Unlocked collection: {}", collection.path());
                    }
                    Err(e) => {
                        failed_unlocks += 1;
                        tracing::warn!("Failed to unlock collection {}: {}", collection.path(), e);
                    }
                }
            }
        }

        let failed_migrations = pending_before.saturating_sub(migrated.len());
        if failed_unlocks > 0 || failed_migrations > 0 {
            // A partial success is not an all-clear: the PAM client can now
            // distinguish a completely unlocked keyring from a partial state.
            return Err(std::io::Error::other(format!(
                "PAM unlock incomplete: {unlocked} collection(s) unlocked, {failed_unlocks} collection(s) failed, {failed_migrations} pending migration(s) unresolved"
            ))
            .into());
        }

        // No locked collections is an idempotent success, including early PAM
        // requests buffered before collections have been discovered.
        Ok(())
    }

    /// Change passwords for all matching persistent collections. Restore the
    /// previous lock state on every path, including validation/write errors.
    async fn change_collection_passwords(
        &self,
        old_secret: &Secret,
        new_secret: &Secret,
    ) -> Result<usize, Error> {
        let collections = self.service.collections.lock().await;
        let mut changed_count = 0;
        let mut failed_count = 0;

        for (path, collection) in collections.iter() {
            // The ephemeral session collection has no persistent password.
            if collection.alias().await == oo7::dbus::Service::SESSION_COLLECTION {
                continue;
            }

            let keyring_guard = collection.keyring.read().await;
            let Some(keyring) = keyring_guard.as_ref() else {
                tracing::debug!("Collection {} has no keyring", path);
                continue;
            };
            let was_locked = keyring.is_locked();
            drop(keyring_guard);

            if was_locked
                && let Err(e) = collection.set_locked(false, Some(old_secret.clone())).await
            {
                    tracing::warn!(
                        "Failed to unlock collection {} with old password: {}",
                        path,
                        e
                    );
                    failed_count += 1;
                    continue;
            }

            // Re-locking must happen after this scope, even if password
            // validation or changing the keyring fails.
            let change_result: Result<(), Error> = async {
                let keyring_guard = collection.keyring.read().await;
                let Some(oo7::file::Keyring::Unlocked(keyring)) = keyring_guard.as_ref() else {
                    return Err(std::io::Error::other("Collection is not unlocked").into());
                };

                if !keyring.validate_secret(old_secret).await? {
                    return Err(std::io::Error::other(
                        "Old password does not match keyring password",
                    )
                    .into());
                }

                keyring.change_secret(new_secret.clone()).await?;
                Ok(())
            }
            .await;

            match change_result {
                Ok(()) => {
                    changed_count += 1;
                    tracing::info!("Changed password for collection: {}", path);
                }
                Err(e) => {
                    failed_count += 1;
                    tracing::warn!("Failed to change password for collection {}: {}", path, e);
                }
            }

            if was_locked && let Err(e) = collection.set_locked(true, None).await {
                    failed_count += 1;
                    tracing::warn!(
                        "Failed to restore lock state for collection {}: {}",
                        path,
                        e
                    );
            }
        }

        if failed_count > 0 {
            return Err(std::io::Error::other(format!(
                "PAM password change incomplete: {changed_count} collection(s) changed, {failed_count} operation(s) failed"
            ))
            .into());
        }
        if changed_count == 0 {
            return Err(std::io::Error::other(
                "PAM password change did not update any persistent keyrings",
            )
            .into());
        }

        Ok(changed_count)
    }
}

#[cfg(test)]
mod tests;
