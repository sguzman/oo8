use oo7::file::UnlockedKeyring;
use zgvariant::serialized::Context;

use super::*;

fn create_pam_message(
    operation: PamOperation,
    username: &str,
    old_secret: &[u8],
    new_secret: &[u8],
) -> Vec<u8> {
    let message = PamMessage {
        operation,
        username: username.to_owned(),
        old_secret: old_secret.to_vec(),
        new_secret: new_secret.to_vec(),
    };

    let ctxt = Context::new(zgvariant::LE, 0);
    let encoded = zgvariant::to_bytes(ctxt, &message).unwrap();
    let message_bytes = encoded.to_vec();

    // Prepend length prefix (4 bytes, little-endian)
    let mut result = (message_bytes.len() as u32).to_le_bytes().to_vec();
    result.extend_from_slice(&message_bytes);
    result
}

async fn send_pam_message(
    socket_path: &std::path::Path,
    message_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::UnixStream::connect(socket_path).await?;
    stream.write_all(message_bytes).await?;
    stream.flush().await?;

    // Read response
    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes).await?;
    let response_length = u32::from_le_bytes(length_bytes) as usize;

    let mut response_bytes = vec![0u8; response_length];
    stream.read_exact(&mut response_bytes).await?;

    let response = PamResponse::from_bytes(&response_bytes)?;

    // Check if response indicates success or error
    if !response.success {
        return Err(format!("PAM operation failed: {}", response.error_message).into());
    }

    Ok(())
}

#[tokio::test]
async fn pam_migrates_v0_keyrings() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let keyrings_dir = temp_dir.path().join("keyrings");
    let v1_dir = keyrings_dir.join("v1");
    tokio::fs::create_dir_all(&v1_dir).await?;

    let v0_secret = Secret::from("test");
    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("client/fixtures/legacy.keyring");
    let v0_path = keyrings_dir.join("legacy.keyring");
    tokio::fs::copy(&fixture_path, &v0_path).await?;

    let pam_socket_path = temp_dir.path().join("pam.sock");
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp_dir.path().to_path_buf(),
        Some(pam_socket_path),
        None,
    )
    .await?;

    assert_eq!(
        setup.server.pending_migrations.lock().await.len(),
        1,
        "V0 keyring should be pending migration"
    );

    let pam_listener = PamListener::new(setup.server.clone());
    let socket_path = pam_listener.socket_path.clone();
    tokio::spawn(async move {
        let _ = pam_listener.start().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let message = create_pam_message(PamOperation::Unlock, "testuser", &[], v0_secret.as_bytes());
    send_pam_message(&socket_path, &message).await?;

    // Response received means operation completed
    let pending = setup.server.pending_migrations.lock().await;
    assert_eq!(
        pending.len(),
        0,
        "V0 keyring should be migrated. Remaining: {:?}",
        pending.keys().collect::<Vec<_>>()
    );
    drop(pending);

    let collections = setup.server.collections.lock().await;
    let mut legacy_collection = None;
    for collection in collections.values() {
        if collection.label().await == "Legacy" {
            legacy_collection = Some(collection);
            break;
        }
    }
    assert!(
        legacy_collection.is_some(),
        "Migrated Legacy collection should exist"
    );

    let v1_migrated = v1_dir.join("legacy.keyring");
    assert!(v1_migrated.exists(), "V1 file should exist after migration");

    assert!(
        v0_path.exists(),
        "V0 file should still exist after migration"
    );
    assert!(
        crate::migration::stamp_path(&v0_path).exists(),
        "Migration stamp file should exist"
    );

    Ok(())
}

#[tokio::test]
async fn pam_unlocks_locked_collections() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    // Create the v1 directory structure
    let v1_dir = temp_dir.path().join("keyrings/v1");
    tokio::fs::create_dir_all(&v1_dir).await?;

    // Create a v1 keyring with a known password
    let secret = Secret::from("my-secure-password");
    let keyring = UnlockedKeyring::open_at(temp_dir.path(), "work", Some(secret.clone())).await?;
    keyring
        .create_item(
            "Work Item",
            &[("type", "work")],
            Secret::text("work-secret"),
            false,
        )
        .await?;
    keyring.write().await?;

    let pam_socket_path = temp_dir.path().join("pam.sock");
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp_dir.path().to_path_buf(),
        Some(pam_socket_path),
        None,
    )
    .await?;

    let collections = setup.server.collections.lock().await;
    let mut work_collection = None;
    for collection in collections.values() {
        if collection.label().await == "Work" {
            work_collection = Some(collection);
            break;
        }
    }
    assert!(work_collection.is_some(), "Work collection should exist");
    let work_collection = work_collection.unwrap();
    assert!(
        work_collection.is_locked().await,
        "Work collection should be locked"
    );
    drop(collections);

    let pam_listener = PamListener::new(setup.server.clone());
    let socket_path = pam_listener.socket_path.clone();
    tokio::spawn(async move {
        let _ = pam_listener.start().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let message = create_pam_message(PamOperation::Unlock, "testuser", &[], secret.as_bytes());
    send_pam_message(&socket_path, &message).await?;

    // Response received means unlock completed
    let collections = setup.server.collections.lock().await;
    let mut work_collection = None;
    for collection in collections.values() {
        if collection.label().await == "Work" {
            work_collection = Some(collection);
            break;
        }
    }
    let work_collection = work_collection.unwrap();
    assert!(
        !work_collection.is_locked().await,
        "Work collection should be unlocked"
    );

    Ok(())
}

#[tokio::test]
async fn pam_change_password() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let old_secret = Secret::from("old-password");
    let keyring =
        UnlockedKeyring::open_at(temp_dir.path(), "work", Some(old_secret.clone())).await?;
    keyring
        .create_item(
            "Work Item",
            &[("type", "work")],
            Secret::text("work-secret"),
            false,
        )
        .await?;
    keyring.write().await?;

    let pam_socket_path = temp_dir.path().join("pam.sock");
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp_dir.path().to_path_buf(),
        Some(pam_socket_path),
        None,
    )
    .await?;

    let collections = setup.server.collections.lock().await;
    let mut work_collection = None;
    for collection in collections.values() {
        if collection.label().await == "Work" {
            work_collection = Some(collection);
            break;
        }
    }
    let work_collection = work_collection.unwrap();
    assert!(
        work_collection.is_locked().await,
        "Work collection should be locked"
    );
    drop(collections);

    let pam_listener = PamListener::new(setup.server.clone());
    let socket_path = pam_listener.socket_path.clone();
    tokio::spawn(async move {
        let _ = pam_listener.start().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let new_secret = Secret::from("new-password");
    let message = create_pam_message(
        PamOperation::ChangePassword,
        "testuser",
        old_secret.as_bytes(),
        new_secret.as_bytes(),
    );
    send_pam_message(&socket_path, &message).await?;

    let collections = setup.server.collections.lock().await;
    let mut work_collection = None;
    for collection in collections.values() {
        if collection.label().await == "Work" {
            work_collection = Some(collection);
            break;
        }
    }
    let work_collection = work_collection.unwrap();
    assert!(
        work_collection.is_locked().await,
        "Collection should be locked after password change"
    );

    let unlock_result = work_collection
        .set_locked(false, Some(old_secret.clone()))
        .await;
    assert!(
        unlock_result.is_err(),
        "Old password should not unlock collection"
    );

    work_collection
        .set_locked(false, Some(new_secret.clone()))
        .await?;
    assert!(
        !work_collection.is_locked().await,
        "New password should unlock collection"
    );

    Ok(())
}

#[tokio::test]
async fn message_serialization() -> Result<(), Box<dyn std::error::Error>> {
    // Test that PamMessage can be properly serialized and deserialized
    let message = PamMessage {
        operation: PamOperation::Unlock,
        username: "testuser".to_owned(),
        old_secret: vec![],
        new_secret: b"my-password".to_vec(),
    };

    let ctxt = Context::new(zgvariant::LE, 0);
    let encoded = zgvariant::to_bytes(ctxt, &message)?;
    let decoded = PamMessage::from_bytes(&encoded)?;

    assert_eq!(decoded.operation, PamOperation::Unlock);
    assert_eq!(decoded.username, "testuser");
    assert_eq!(decoded.new_secret, b"my-password");

    let message = PamMessage {
        operation: PamOperation::ChangePassword,
        username: "testuser".to_owned(),
        old_secret: b"old-pass".to_vec(),
        new_secret: b"new-pass".to_vec(),
    };

    let ctxt = Context::new(zgvariant::LE, 0);
    let encoded = zgvariant::to_bytes(ctxt, &message)?;
    let decoded = PamMessage::from_bytes(&encoded)?;

    assert_eq!(decoded.operation, PamOperation::ChangePassword);
    assert_eq!(decoded.old_secret, b"old-pass");
    assert_eq!(decoded.new_secret, b"new-pass");

    // Test PamResponse serialization
    let success_response = PamResponse::success();
    let encoded = success_response.to_bytes()?;
    let decoded = PamResponse::from_bytes(&encoded[4..])?; // Skip length prefix
    assert!(decoded.success);
    assert!(decoded.error_message.is_empty());

    let error_response = PamResponse::error("Something went wrong".to_string());
    let encoded = error_response.to_bytes()?;
    let decoded = PamResponse::from_bytes(&encoded[4..])?; // Skip length prefix
    assert!(!decoded.success);
    assert_eq!(decoded.error_message, "Something went wrong");

    Ok(())
}

#[tokio::test]
async fn pam_rejects_invalid_frame_lengths_before_allocation()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::{
        io::AsyncWriteExt,
        time::{Duration, timeout},
    };

    for length in [0u32, (MAX_PAM_MESSAGE_BYTES + 1) as u32, u32::MAX] {
        let (mut client, mut server) = tokio::net::UnixStream::pair()?;
        client.write_all(&length.to_le_bytes()).await?;

        // A rejected header must not wait for a body or allocate its claimed
        // length.
        let result = timeout(Duration::from_secs(1), read_pam_message(&mut server)).await?;
        assert!(
            matches!(&result, Err(Error::IO(err)) if err.kind() == std::io::ErrorKind::InvalidData),
            "Invalid PAM frame length {length} was not rejected"
        );
    }

    Ok(())
}

#[tokio::test]
async fn pam_accepts_well_formed_bounded_frame() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;

    let (mut client, mut server) = tokio::net::UnixStream::pair()?;
    let frame = create_pam_message(PamOperation::Unlock, "tester", &[], b"test-password");
    assert!(frame.len() - 4 <= MAX_PAM_MESSAGE_BYTES);
    client.write_all(&frame).await?;

    let message = read_pam_message(&mut server).await?;
    assert_eq!(message.operation, PamOperation::Unlock);
    assert_eq!(message.username, "tester");
    assert_eq!(message.new_secret, b"test-password");
    Ok(())
}

#[tokio::test]
async fn pam_rejects_stalled_frame_header() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::{io::AsyncWriteExt, time::Duration};

    let (mut client, mut server) = tokio::net::UnixStream::pair()?;
    client.write_all(&[1u8, 2u8]).await?;
    let result = read_pam_message_with_timeout(&mut server, Duration::from_millis(25)).await;
    assert!(
        matches!(result, Err(Error::IO(err)) if err.kind() == std::io::ErrorKind::TimedOut),
        "Stalled frame header must fail with a timeout"
    );
    Ok(())
}

#[tokio::test]
async fn pam_rejects_stalled_frame_payload() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::{io::AsyncWriteExt, time::Duration};

    let (mut client, mut server) = tokio::net::UnixStream::pair()?;
    let message = create_pam_message(PamOperation::Unlock, "tester", &[], b"test-password");
    client.write_all(&message[..message.len() - 2]).await?;
    let result = read_pam_message_with_timeout(&mut server, Duration::from_millis(25)).await;
    assert!(
        matches!(result, Err(Error::IO(err)) if err.kind() == std::io::ErrorKind::TimedOut),
        "Incomplete frame payload must fail with a timeout"
    );
    Ok(())
}

#[tokio::test]
async fn pam_connection_limit_rejects_overflow_and_recovers()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::{
        io::AsyncReadExt,
        sync::Semaphore,
        time::{Duration, sleep, timeout},
    };

    let dir = tempfile::tempdir()?;
    let socket_path = dir.path().join("bounded-pam.sock");
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        dir.path().to_path_buf(),
        Some(socket_path.clone()),
        None,
    )
    .await?;
    let listener = PamListener::new(setup.server.clone());
    let slots = Arc::new(Semaphore::new(2));
    let worker = tokio::spawn(listener.start_with_semaphore(slots.clone()));

    // Wait for the private listener to bind before opening test connections.
    timeout(Duration::from_secs(2), async {
        while !socket_path.exists() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;

    // Keep two valid same-user connections open without sending a frame.
    let first = tokio::net::UnixStream::connect(&socket_path).await?;
    let second = tokio::net::UnixStream::connect(&socket_path).await?;
    timeout(Duration::from_secs(2), async {
        while slots.available_permits() != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;

    // Overflow must be rejected promptly while the original two remain
    // connected, rather than creating another pending credential task.
    let mut overflow = tokio::net::UnixStream::connect(&socket_path).await?;
    let mut byte = [0u8; 1];
    let size = timeout(Duration::from_secs(2), overflow.read(&mut byte)).await??;
    assert_eq!(size, 0, "Excess connection was not closed");

    // Disconnecting one peer frees capacity for a complete PAM request.
    drop(first);
    timeout(Duration::from_secs(2), async {
        while slots.available_permits() == 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    let message = create_pam_message(PamOperation::Unlock, "testuser", &[], b"test-password");
    send_pam_message(&socket_path, &message).await?;

    drop(second);
    worker.abort();
    Ok(())
}

#[tokio::test]
async fn pam_replay_discards_startup_secrets_and_stops_buffering()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::time::{Duration, sleep, timeout};

    let dir = tempfile::tempdir()?;
    let socket_path = dir.path().join("replay-pam.sock");
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        dir.path().to_path_buf(),
        Some(socket_path.clone()),
        None,
    )
    .await?;
    let listener = PamListener::new(setup.server.clone());

    {
        let mut buffered = listener.user_secrets.write().await;
        buffered
            .as_mut()
            .expect("Buffering should be enabled at startup")
            .insert("early".to_owned(), Secret::text("early-password"));
    }

    listener.replay_buffered_secrets().await;
    assert!(
        listener.user_secrets.read().await.is_none(),
        "Startup secret buffer must be dropped after replay"
    );

    // A later successful request must not recreate the password cache.
    let server = listener.clone();
    let worker = tokio::spawn(async move {
        let _ = server.start().await;
    });
    timeout(Duration::from_secs(2), async {
        while !socket_path.exists() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;

    let frame = create_pam_message(PamOperation::Unlock, "late", &[], b"late-password");
    send_pam_message(&socket_path, &frame).await?;
    assert!(
        listener.user_secrets.read().await.is_none(),
        "A post-startup request must not retain its password"
    );

    worker.abort();
    Ok(())
}

#[tokio::test]
async fn pam_acknowledgment_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncReadExt;

    let (mut daemon, mut client) = tokio::net::UnixStream::pair()?;
    send_pam_response(&mut daemon, &PamResponse::success()).await?;

    let mut header = [0u8; 4];
    client.read_exact(&mut header).await?;
    let mut payload = vec![0u8; u32::from_le_bytes(header) as usize];
    client.read_exact(&mut payload).await?;
    let response = PamResponse::from_bytes(&payload)?;

    assert!(response.success);
    assert!(response.error_message.is_empty());
    Ok(())
}

#[tokio::test]
async fn pam_acknowledgment_reports_disconnected_client() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut daemon, client) = tokio::net::UnixStream::pair()?;
    drop(client);

    let result = send_pam_response(&mut daemon, &PamResponse::success()).await;
    assert!(
        matches!(result, Err(Error::IO(err)) if matches!(
            err.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        )),
        "Closed PAM client connection must not be reported as a successful response"
    );
    Ok(())
}

#[tokio::test]
async fn pam_rejects_wrong_unlock_and_accepts_correct_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let correct = Secret::from("correct-unlock-password");
    let keyring = UnlockedKeyring::open_at(temp.path(), "work", Some(correct.clone())).await?;
    keyring
        .create_item(
            "Work Item",
            &[("type", "work")],
            Secret::text("disposable-secret"),
            false,
        )
        .await?;
    keyring.write().await?;

    let socket = temp.path().join("pam-unlock-rejection.sock");
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp.path().to_path_buf(),
        Some(socket.clone()),
        None,
    )
    .await?;
    let listener = PamListener::new(setup.server.clone());
    let wrong = Secret::from("wrong-unlock-password");
    let result = listener.try_unlock_collections(&wrong).await;
    assert!(
        result.is_err(),
        "Wrong unlock password must not report success"
    );
    {
        let collections = setup.server.collections.lock().await;
        for collection in collections.values() {
            if collection.label().await == "Work" {
                assert!(
                    collection.is_locked().await,
                    "Wrong password unlocked collection"
                );
            }
        }
    }

    // Exercise the real PAM socket and acknowledgment as well as the
    // internal result, so the client cannot mistake a rejected password
    // for a completed unlock.
    let server = listener.clone();
    let worker = tokio::spawn(async move {
        let _ = server.start().await;
    });
    tokio::time::timeout(tokio::time::Duration::from_secs(2), async {
        while !socket.exists() {
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }
    })
    .await?;
    let invalid_frame = create_pam_message(PamOperation::Unlock, "testuser", &[], wrong.as_bytes());
    assert!(
        send_pam_message(&socket, &invalid_frame).await.is_err(),
        "PAM socket acknowledged a rejected password"
    );
    assert!(
        !listener
            .user_secrets
            .read()
            .await
            .as_ref()
            .is_some_and(|buffered| buffered.contains_key("testuser")),
        "Rejected credential must not be buffered for replay"
    );
    let valid_frame = create_pam_message(PamOperation::Unlock, "testuser", &[], correct.as_bytes());
    send_pam_message(&socket, &valid_frame).await?;
    worker.abort();

    listener.try_unlock_collections(&correct).await?;
    {
        let collections = setup.server.collections.lock().await;
        let mut found = false;
        for collection in collections.values() {
            if collection.label().await == "Work" {
                found = true;
                assert!(
                    !collection.is_locked().await,
                    "Correct password did not unlock"
                );
            }
        }
        assert!(found, "Test collection missing");
    }
    Ok(())
}

#[tokio::test]
async fn pam_wrong_old_password_rejected_without_changing_keyring()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let original = Secret::from("old-test-password");
    let changed = Secret::from("new-test-password");
    let keyring = UnlockedKeyring::open_at(temp.path(), "work", Some(original.clone())).await?;
    keyring
        .create_item(
            "Work Item",
            &[("type", "work")],
            Secret::text("disposable-secret"),
            false,
        )
        .await?;
    keyring.write().await?;

    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp.path().to_path_buf(),
        Some(temp.path().join("pam-password-rejection.sock")),
        None,
    )
    .await?;
    let listener = PamListener::new(setup.server.clone());

    let bad = listener
        .change_collection_passwords(&Secret::from("incorrect-old"), &changed)
        .await;
    assert!(bad.is_err(), "Wrong old password must not report success");

    {
        let collections = setup.server.collections.lock().await;
        for collection in collections.values() {
            if collection.label().await == "Work" {
                assert!(
                    collection.is_locked().await,
                    "Failure changed the lock state"
                );
            }
        }
    }

    listener
        .change_collection_passwords(&original, &changed)
        .await?;
    {
        let collections = setup.server.collections.lock().await;
        let mut found = false;
        for collection in collections.values() {
            if collection.label().await == "Work" {
                found = true;
                assert!(
                    collection.is_locked().await,
                    "Password change left collection unlocked"
                );
                assert!(
                    collection
                        .set_locked(false, Some(original.clone()))
                        .await
                        .is_err()
                );
                collection.set_locked(false, Some(changed.clone())).await?;
            }
        }
        assert!(found, "Test collection missing");
    }
    Ok(())
}

#[tokio::test]
async fn pam_password_change_with_no_persistent_keyrings_is_not_success()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp.path().to_path_buf(),
        Some(temp.path().join("pam-no-keyrings.sock")),
        None,
    )
    .await?;
    let listener = PamListener::new(setup.server.clone());
    let result = listener
        .change_collection_passwords(
            &Secret::from("previous-password"),
            &Secret::from("next-password"),
        )
        .await;
    assert!(
        result.is_err(),
        "A zero-keyring change must not report success"
    );
    Ok(())
}

#[tokio::test]
async fn wrong_unlock_preserves_keyring_without_backing_file()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let correct = Secret::from("correct-offline-password");
    let keyring = UnlockedKeyring::open_at(temp.path(), "work", Some(correct.clone())).await?;
    keyring
        .create_item(
            "Offline Item",
            &[("kind", "offline")],
            Secret::text("disposable-secret"),
            false,
        )
        .await?;
    keyring.write().await?;

    let keyring_file = temp.path().join("keyrings/v1/work.keyring");
    assert!(keyring_file.exists(), "Test requires a disk-backed keyring");

    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp.path().to_path_buf(),
        Some(temp.path().join("offline-pam.sock")),
        None,
    )
    .await?;
    let work = {
        let collections = setup.server.collections.lock().await;
        let mut work = None;
        for collection in collections.values() {
            if collection.label().await == "Work" {
                work = Some(collection.clone());
            }
        }
        work.expect("Work collection missing")
    };
    assert!(
        work.is_locked().await,
        "Test starts with a locked collection"
    );

    // Simulate a missing/unreadable backing file. The incorrect password
    // must not consume the live in-memory keyring and leave an empty slot.
    tokio::fs::remove_file(&keyring_file).await?;
    let result = work
        .set_locked(false, Some(Secret::from("incorrect-password")))
        .await;
    assert!(result.is_err(), "Invalid credential must fail");
    assert!(
        work.keyring.read().await.is_some(),
        "Failed unlock discarded the in-memory keyring"
    );
    assert!(
        work.is_locked().await,
        "Failed unlock changed the collection lock state"
    );

    // The same in-memory encrypted keyring must still accept its original
    // credential even though the disposable backing file was removed.
    work.set_locked(false, Some(correct)).await?;
    assert!(
        !work.is_locked().await,
        "Valid retry did not unlock the keyring"
    );
    Ok(())
}

async fn create_persistent_pam_test_keyring(
    dir: &std::path::Path,
    name: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let keyring = UnlockedKeyring::open_at(dir, name, Some(Secret::from(password))).await?;
    keyring
        .create_item(
            "Mixed Credential Item",
            &[("kind", name)],
            Secret::text("disposable-secret"),
            false,
        )
        .await?;
    keyring.write().await?;
    Ok(())
}

#[tokio::test]
async fn pam_partial_unlock_reports_failure_then_recovers() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    create_persistent_pam_test_keyring(temp.path(), "alpha", "alpha-password").await?;
    create_persistent_pam_test_keyring(temp.path(), "beta", "beta-password").await?;
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp.path().to_path_buf(),
        Some(temp.path().join("pam-partial-unlock.sock")),
        None,
    )
    .await?;
    let listener = PamListener::new(setup.server.clone());
    let (alpha, beta) = {
        let collections = setup.server.collections.lock().await;
        let mut alpha = None;
        let mut beta = None;
        for collection in collections.values() {
            if collection.label().await == "Alpha" {
                alpha = Some(collection.clone());
            } else if collection.label().await == "Beta" {
                beta = Some(collection.clone());
            }
        }
        (alpha.expect("Alpha missing"), beta.expect("Beta missing"))
    };
    assert!(alpha.is_locked().await);
    assert!(beta.is_locked().await);

    let partial = listener
        .try_unlock_collections(&Secret::from("alpha-password"))
        .await;
    assert!(partial.is_err(), "Partial unlock must not return success");
    assert!(
        !alpha.is_locked().await,
        "Matching collection should unlock"
    );
    assert!(
        beta.is_locked().await,
        "Wrong password must leave Beta locked"
    );

    listener
        .try_unlock_collections(&Secret::from("beta-password"))
        .await?;
    assert!(!alpha.is_locked().await);
    assert!(!beta.is_locked().await);
    Ok(())
}

#[tokio::test]
async fn pam_mixed_old_passwords_reject_without_partial_change()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    create_persistent_pam_test_keyring(temp.path(), "alpha", "old-alpha-password").await?;
    create_persistent_pam_test_keyring(temp.path(), "beta", "beta-password").await?;
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp.path().to_path_buf(),
        Some(temp.path().join("pam-partial-change.sock")),
        None,
    )
    .await?;
    let listener = PamListener::new(setup.server.clone());
    let (alpha, beta) = {
        let collections = setup.server.collections.lock().await;
        let mut alpha = None;
        let mut beta = None;
        for collection in collections.values() {
            if collection.label().await == "Alpha" {
                alpha = Some(collection.clone());
            } else if collection.label().await == "Beta" {
                beta = Some(collection.clone());
            }
        }
        (alpha.expect("Alpha missing"), beta.expect("Beta missing"))
    };

    let partial = listener
        .change_collection_passwords(
            &Secret::from("old-alpha-password"),
            &Secret::from("new-alpha-password"),
        )
        .await;
    assert!(
        partial.is_err(),
        "A change that fails on another persistent keyring is incomplete"
    );
    assert!(
        alpha.is_locked().await,
        "Preflight unexpectedly unlocked Alpha"
    );
    assert!(
        beta.is_locked().await,
        "Unmatched keyring was left unlocked"
    );

    assert!(
        alpha
            .set_locked(false, Some(Secret::from("new-alpha-password")))
            .await
            .is_err(),
        "Rejected change unexpectedly updated Alpha's password"
    );
    alpha
        .set_locked(false, Some(Secret::from("old-alpha-password")))
        .await?;
    beta.set_locked(false, Some(Secret::from("beta-password")))
        .await?;
    assert!(!alpha.is_locked().await);
    assert!(!beta.is_locked().await);
    Ok(())
}

#[tokio::test]
async fn pam_changes_multiple_keyrings_when_every_old_password_matches()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    create_persistent_pam_test_keyring(temp.path(), "alpha", "shared-old-password").await?;
    create_persistent_pam_test_keyring(temp.path(), "beta", "shared-old-password").await?;
    let setup = crate::tests::TestServiceSetup::with_disk_keyrings(
        temp.path().to_path_buf(),
        Some(temp.path().join("pam-shared-password-change.sock")),
        None,
    )
    .await?;
    let listener = PamListener::new(setup.server.clone());

    let count = listener
        .change_collection_passwords(
            &Secret::from("shared-old-password"),
            &Secret::from("shared-new-password"),
        )
        .await?;
    assert_eq!(count, 2, "Both persistent keyrings must be updated");

    let collections = setup.server.collections.lock().await;
    let mut checked = 0;
    for collection in collections.values() {
        if collection.label().await == "Alpha" || collection.label().await == "Beta" {
            checked += 1;
            assert!(
                collection.is_locked().await,
                "Password change left keyring unlocked"
            );
            assert!(
                collection
                    .set_locked(false, Some(Secret::from("shared-old-password")))
                    .await
                    .is_err(),
                "Old password unexpectedly still unlocks changed keyring"
            );
            collection
                .set_locked(false, Some(Secret::from("shared-new-password")))
                .await?;
        }
    }
    assert_eq!(checked, 2);
    Ok(())
}
