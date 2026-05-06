use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time;
use tracing::{info, warn};

use crate::handlers::AppState;
use crate::snapshot_store::SnapshotStoreClient;
use crate::state::{
    ArciumAuthorityMode, ArciumBudgetGrant, ArciumWithdrawalGrant, ChannelState, ClientBalance,
    PendingWithdrawal, ProviderCredit, ProviderRegistration, Reservation, SettlementBatchInfo,
    SettlementRecord,
};

const DEFAULT_SNAPSHOT_EVERY_SEC: u64 = 30;
const DEFAULT_SNAPSHOT_EVERY_N_EVENTS: u64 = 1_000;
const DEFAULT_SNAPSHOT_RETAIN_COUNT: usize = 16;
const SNAPSHOT_LOOP_INTERVAL_SEC: u64 = 5;

#[derive(Debug, Clone)]
pub struct SnapshotManager {
    client: SnapshotStoreClient,
    prefix: String,
    key: [u8; 32],
    every_sec: Duration,
    every_n_events: u64,
    retain_count: usize,
    progress: Arc<Mutex<SnapshotProgress>>,
}

#[derive(Debug)]
struct SnapshotProgress {
    last_included_wal_seqno: Option<u64>,
    last_persisted_at: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedSnapshotEnvelope {
    version: u8,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateSnapshot {
    version: u32,
    snapshot_seqno: u64,
    included_wal_seqno: Option<u64>,
    created_at: i64,
    client_balances: Vec<SnapshotClientBalance>,
    reservations: Vec<Reservation>,
    provider_credits: Vec<ProviderCredit>,
    providers: Vec<ProviderRegistration>,
    settlement_history: Vec<SettlementRecord>,
    #[serde(default)]
    settlement_batches: Vec<SnapshotSettlementBatch>,
    #[serde(default)]
    pending_withdrawals: Vec<PendingWithdrawal>,
    #[serde(default)]
    arcium_mode: Option<String>,
    #[serde(default)]
    arcium_budget_grants: Vec<ArciumBudgetGrant>,
    #[serde(default)]
    arcium_withdrawal_grants: Vec<ArciumWithdrawalGrant>,
    active_channels: Vec<ChannelState>,
    auditor_master_secret: String,
    auditor_epoch: u32,
    receipt_nonce: u64,
    withdraw_nonce: u64,
    last_batch_at: i64,
    last_finalized_slot: u64,
    processed_signatures: Vec<String>,
    last_processed_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotClientBalance {
    client: String,
    balance: ClientBalance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotSettlementBatch {
    settlement_id: String,
    batch: SettlementBatchInfo,
}

impl SnapshotManager {
    pub fn from_env(
        client: SnapshotStoreClient,
        key: [u8; 32],
        vault_config: Pubkey,
    ) -> Option<Self> {
        if std::env::var("SUBLY402_ENABLE_SNAPSHOTS").ok().as_deref() == Some("0") {
            return None;
        }

        let prefix = std::env::var("SUBLY402_SNAPSHOT_PREFIX")
            .unwrap_or_else(|_| format!("snapshot/{vault_config}"));
        let every_sec =
            read_env_u64("SUBLY402_SNAPSHOT_EVERY_SEC").unwrap_or(DEFAULT_SNAPSHOT_EVERY_SEC);
        let every_n_events = read_env_u64("SUBLY402_SNAPSHOT_EVERY_N_EVENTS")
            .unwrap_or(DEFAULT_SNAPSHOT_EVERY_N_EVENTS);
        let retain_count = read_env_usize("SUBLY402_SNAPSHOT_RETAIN_COUNT")
            .unwrap_or(DEFAULT_SNAPSHOT_RETAIN_COUNT);

        Some(Self {
            client,
            prefix,
            key,
            every_sec: Duration::from_secs(every_sec.max(1)),
            every_n_events,
            retain_count,
            progress: Arc::new(Mutex::new(SnapshotProgress {
                last_included_wal_seqno: None,
                last_persisted_at: Instant::now(),
            })),
        })
    }

    pub async fn recover_latest(&self, state: &Arc<AppState>) -> Result<Option<u64>, String> {
        let mut keys = self
            .client
            .list(&self.prefix)
            .await
            .map_err(|error| format!("failed to list snapshots: {error}"))?;
        if keys.is_empty() {
            return Ok(None);
        }

        keys.sort();
        let latest = keys
            .into_iter()
            .last()
            .ok_or_else(|| "snapshot list unexpectedly empty".to_string())?;
        let blob = self
            .client
            .get(&latest)
            .await
            .map_err(|error| format!("failed to fetch latest snapshot {latest}: {error}"))?
            .ok_or_else(|| format!("latest snapshot {latest} disappeared"))?;
        let envelope: EncryptedSnapshotEnvelope = serde_json::from_slice(&blob)
            .map_err(|error| format!("invalid snapshot envelope JSON: {error}"))?;
        let plaintext = decrypt_snapshot(self.key, &envelope)?;
        let snapshot: StateSnapshot = serde_json::from_slice(&plaintext)
            .map_err(|error| format!("invalid decrypted snapshot JSON: {error}"))?;

        apply_snapshot(state, &snapshot).await?;

        let mut progress = self.progress.lock().await;
        progress.last_included_wal_seqno = snapshot.included_wal_seqno;
        progress.last_persisted_at = Instant::now();

        info!(
            snapshot_seqno = snapshot.snapshot_seqno,
            included_wal_seqno = ?snapshot.included_wal_seqno,
            "Recovered state from encrypted snapshot"
        );

        Ok(snapshot.included_wal_seqno)
    }

    pub fn spawn_background_task(self: Arc<Self>, state: Arc<AppState>) {
        tokio::spawn(async move {
            self.background_loop(state).await;
        });
    }

    async fn background_loop(self: Arc<Self>, state: Arc<AppState>) {
        let mut interval = time::interval(Duration::from_secs(SNAPSHOT_LOOP_INTERVAL_SEC));

        loop {
            interval.tick().await;

            let current_wal_seqno = state.wal.last_seqno();
            let progress = self.progress.lock().await;
            let last_wal_seqno = progress.last_included_wal_seqno;
            let elapsed = progress.last_persisted_at.elapsed();
            let should_persist = match current_wal_seqno {
                None => false,
                Some(current) if Some(current) == last_wal_seqno => false,
                Some(current) => {
                    let delta = match last_wal_seqno {
                        Some(last) => current.saturating_sub(last),
                        None => u64::MAX,
                    };
                    delta >= self.every_n_events || elapsed >= self.every_sec
                }
            };
            drop(progress);

            if !should_persist {
                continue;
            }

            if let Err(error) = self.persist_now(&state).await {
                warn!(error = %error, "Failed to persist encrypted snapshot");
            }
        }
    }

    pub async fn persist_now(&self, state: &Arc<AppState>) -> Result<u64, String> {
        let snapshot_blob;
        let snapshot_key;
        let snapshot_seqno;
        let included_wal_seqno;

        {
            let _guard = state.persistence_lock.lock().await;
            snapshot_seqno = state
                .vault
                .snapshot_seqno
                .load(Ordering::SeqCst)
                .saturating_add(1);
            included_wal_seqno = state.wal.last_seqno();
            let snapshot = capture_snapshot(state, snapshot_seqno, included_wal_seqno).await;
            let plaintext = serde_json::to_vec(&snapshot)
                .map_err(|error| format!("failed to serialize snapshot: {error}"))?;
            let envelope = encrypt_snapshot(self.key, &plaintext)?;
            snapshot_blob = serde_json::to_vec(&envelope)
                .map_err(|error| format!("failed to serialize snapshot envelope: {error}"))?;
            snapshot_key = snapshot_object_key(&self.prefix, snapshot_seqno);
        }

        self.client
            .put(&snapshot_key, &snapshot_blob)
            .await
            .map_err(|error| {
                format!("failed to store encrypted snapshot {snapshot_key}: {error}")
            })?;

        self.prune_old_snapshots(&snapshot_key).await?;

        state
            .vault
            .snapshot_seqno
            .store(snapshot_seqno, Ordering::SeqCst);

        let mut progress = self.progress.lock().await;
        progress.last_included_wal_seqno = included_wal_seqno;
        progress.last_persisted_at = Instant::now();

        info!(
            snapshot_seqno,
            included_wal_seqno = ?included_wal_seqno,
            key = %snapshot_key,
            "Persisted encrypted snapshot"
        );

        Ok(snapshot_seqno)
    }

    async fn prune_old_snapshots(&self, latest_key: &str) -> Result<(), String> {
        if self.retain_count == 0 {
            return Ok(());
        }

        let mut keys = self
            .client
            .list(&self.prefix)
            .await
            .map_err(|error| format!("failed to list snapshots for pruning: {error}"))?;
        keys.sort();

        let stale_keys = snapshot_keys_to_prune(&keys, self.retain_count);
        if stale_keys.is_empty() {
            return Ok(());
        }

        for key in &stale_keys {
            if key == latest_key {
                continue;
            }
            self.client
                .delete(key)
                .await
                .map_err(|error| format!("failed to delete stale snapshot {key}: {error}"))?;
        }

        info!(
            kept = self.retain_count,
            deleted = stale_keys.len(),
            latest = %latest_key,
            "Pruned stale encrypted snapshots"
        );

        Ok(())
    }
}

async fn capture_snapshot(
    state: &Arc<AppState>,
    snapshot_seqno: u64,
    included_wal_seqno: Option<u64>,
) -> StateSnapshot {
    let mut client_balances = state
        .vault
        .client_balances
        .iter()
        .map(|entry| SnapshotClientBalance {
            client: entry.key().to_string(),
            balance: entry.value().clone(),
        })
        .collect::<Vec<_>>();
    client_balances.sort_by(|a, b| a.client.cmp(&b.client));

    let mut reservations = state
        .vault
        .reservations
        .iter()
        .map(|entry| entry.value().clone())
        .collect::<Vec<_>>();
    reservations.sort_by(|a, b| a.verification_id.cmp(&b.verification_id));

    let mut provider_credits = state
        .vault
        .provider_credits
        .iter()
        .map(|entry| entry.value().clone())
        .collect::<Vec<_>>();
    provider_credits.sort_by(|a, b| a.provider_id.cmp(&b.provider_id));

    let mut providers = state
        .vault
        .providers
        .iter()
        .map(|entry| entry.value().clone())
        .collect::<Vec<_>>();
    providers.sort_by(|a, b| a.provider_id.cmp(&b.provider_id));

    let mut settlement_history = state
        .vault
        .settlement_history
        .iter()
        .map(|entry| entry.value().clone())
        .collect::<Vec<_>>();
    settlement_history.sort_by(|a, b| a.settlement_id.cmp(&b.settlement_id));

    let mut settlement_batches = state
        .vault
        .settlement_batches
        .iter()
        .map(|entry| SnapshotSettlementBatch {
            settlement_id: entry.key().clone(),
            batch: entry.value().clone(),
        })
        .collect::<Vec<_>>();
    settlement_batches.sort_by(|a, b| a.settlement_id.cmp(&b.settlement_id));
    let mut pending_withdrawals = state
        .vault
        .pending_withdrawals
        .iter()
        .map(|entry| entry.clone())
        .collect::<Vec<_>>();
    pending_withdrawals.sort_by(|a, b| a.withdraw_nonce.cmp(&b.withdraw_nonce));

    let mut arcium_budget_grants = state
        .vault
        .arcium_budget_grants
        .iter()
        .map(|entry| entry.value().clone())
        .collect::<Vec<_>>();
    arcium_budget_grants.sort_by(|a, b| a.grant_id.cmp(&b.grant_id));

    let mut arcium_withdrawal_grants = state
        .vault
        .arcium_withdrawal_grants
        .iter()
        .map(|entry| entry.value().clone())
        .collect::<Vec<_>>();
    arcium_withdrawal_grants.sort_by(|a, b| a.grant_id.cmp(&b.grant_id));

    let mut active_channels = state
        .vault
        .active_channels
        .iter()
        .map(|entry| entry.value().clone())
        .collect::<Vec<_>>();
    active_channels.sort_by(|a, b| a.channel_id.cmp(&b.channel_id));

    let mut processed_signatures = state
        .deposit_detector
        .processed_signatures
        .read()
        .await
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    processed_signatures.sort();

    let auditor_master_secret = *state.vault.auditor_master_secret.read().await;
    let last_batch_at = *state.vault.last_batch_at.read().await;
    let last_processed_signature = state
        .deposit_detector
        .last_processed_signature
        .read()
        .await
        .clone();

    StateSnapshot {
        version: 1,
        snapshot_seqno,
        included_wal_seqno,
        created_at: chrono::Utc::now().timestamp(),
        client_balances,
        reservations,
        provider_credits,
        providers,
        settlement_history,
        settlement_batches,
        pending_withdrawals,
        arcium_mode: Some(state.vault.arcium_mode().as_str().to_string()),
        arcium_budget_grants,
        arcium_withdrawal_grants,
        active_channels,
        auditor_master_secret: BASE64.encode(auditor_master_secret),
        auditor_epoch: state.vault.auditor_epoch.load(Ordering::SeqCst),
        receipt_nonce: state.vault.receipt_nonce.load(Ordering::SeqCst),
        withdraw_nonce: state.vault.withdraw_nonce.load(Ordering::SeqCst),
        last_batch_at,
        last_finalized_slot: state.vault.last_finalized_slot.load(Ordering::SeqCst),
        processed_signatures,
        last_processed_signature,
    }
}

async fn apply_snapshot(state: &Arc<AppState>, snapshot: &StateSnapshot) -> Result<(), String> {
    state.vault.client_balances.clear();
    state.vault.reservations.clear();
    state.vault.payment_id_index.clear();
    state.vault.provider_credits.clear();
    state.vault.providers.clear();
    state.vault.settlement_history.clear();
    state.vault.settlement_batches.clear();
    state.vault.pending_withdrawals.clear();
    state.vault.arcium_budget_grants.clear();
    state.vault.arcium_withdrawal_grants.clear();
    state.vault.active_channels.clear();

    for item in &snapshot.client_balances {
        let client = Pubkey::from_str(&item.client)
            .map_err(|error| format!("invalid client pubkey in snapshot: {error}"))?;
        state
            .vault
            .client_balances
            .insert(client, item.balance.clone());
    }

    for reservation in &snapshot.reservations {
        state.vault.payment_id_index.insert(
            reservation.payment_id.clone(),
            reservation.verification_id.clone(),
        );
        state
            .vault
            .reservations
            .insert(reservation.verification_id.clone(), reservation.clone());
    }

    for provider_credit in &snapshot.provider_credits {
        state
            .vault
            .provider_credits
            .insert(provider_credit.provider_id.clone(), provider_credit.clone());
    }

    for provider in &snapshot.providers {
        state
            .vault
            .providers
            .insert(provider.provider_id.clone(), provider.clone());
    }

    for record in &snapshot.settlement_history {
        state
            .vault
            .settlement_history
            .insert(record.settlement_id.clone(), record.clone());
    }

    for item in &snapshot.settlement_batches {
        state
            .vault
            .settlement_batches
            .insert(item.settlement_id.clone(), item.batch.clone());
    }

    for withdrawal in &snapshot.pending_withdrawals {
        state
            .vault
            .pending_withdrawals
            .insert(withdrawal.withdraw_nonce, withdrawal.clone());
    }

    if let Some(mode) = snapshot.arcium_mode.as_deref() {
        let arcium_mode = ArciumAuthorityMode::from_env_value(Some(mode))
            .map_err(|error| format!("invalid arcium mode in snapshot: {error}"))?;
        state.vault.set_arcium_mode(arcium_mode);
    }

    for grant in &snapshot.arcium_budget_grants {
        state
            .vault
            .load_arcium_budget_grant(grant.clone())
            .map_err(|error| format!("failed to restore Arcium budget grant: {error}"))?;
    }

    for grant in &snapshot.arcium_withdrawal_grants {
        state
            .vault
            .load_arcium_withdrawal_grant(grant.clone())
            .map_err(|error| format!("failed to restore Arcium withdrawal grant: {error}"))?;
    }

    for channel in &snapshot.active_channels {
        state
            .vault
            .active_channels
            .insert(channel.channel_id.clone(), channel.clone());
    }

    let mut processed = state.deposit_detector.processed_signatures.write().await;
    processed.clear();
    processed.extend(snapshot.processed_signatures.iter().cloned());
    drop(processed);

    *state
        .deposit_detector
        .last_processed_signature
        .write()
        .await = snapshot.last_processed_signature.clone();

    *state.vault.auditor_master_secret.write().await =
        decode_fixed_b64::<32>(&snapshot.auditor_master_secret, "auditor_master_secret")?;
    state
        .vault
        .auditor_epoch
        .store(snapshot.auditor_epoch, Ordering::SeqCst);
    state
        .vault
        .receipt_nonce
        .store(snapshot.receipt_nonce, Ordering::SeqCst);
    state
        .vault
        .withdraw_nonce
        .store(snapshot.withdraw_nonce, Ordering::SeqCst);
    state
        .vault
        .snapshot_seqno
        .store(snapshot.snapshot_seqno, Ordering::SeqCst);
    *state.vault.last_batch_at.write().await = snapshot.last_batch_at;
    state
        .vault
        .last_finalized_slot
        .store(snapshot.last_finalized_slot, Ordering::SeqCst);

    let clients: Vec<Pubkey> = state
        .vault
        .client_balances
        .iter()
        .map(|entry| *entry.key())
        .collect();
    for client in clients {
        state
            .vault
            .refresh_client_max_lock_expires_at(&client)
            .map_err(|error| format!("failed to recompute client lock expiry: {error}"))?;
    }

    Ok(())
}

fn snapshot_object_key(prefix: &str, snapshot_seqno: u64) -> String {
    format!(
        "{}/snapshot-{snapshot_seqno:020}.json",
        prefix.trim_end_matches('/')
    )
}

fn encrypt_snapshot(key: [u8; 32], plaintext: &[u8]) -> Result<EncryptedSnapshotEnvelope, String> {
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| format!("invalid snapshot key: {error}"))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|error| format!("failed to encrypt snapshot: {error}"))?;
    Ok(EncryptedSnapshotEnvelope {
        version: 1,
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn decrypt_snapshot(
    key: [u8; 32],
    envelope: &EncryptedSnapshotEnvelope,
) -> Result<Vec<u8>, String> {
    if envelope.version != 1 {
        return Err(format!(
            "unsupported snapshot envelope version {}",
            envelope.version
        ));
    }
    let nonce = BASE64
        .decode(&envelope.nonce)
        .map_err(|error| format!("invalid snapshot nonce base64: {error}"))?;
    if nonce.len() != 12 {
        return Err("snapshot nonce must be 12 bytes".to_string());
    }
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|error| format!("invalid snapshot ciphertext base64: {error}"))?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| format!("invalid snapshot key: {error}"))?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|error| format!("failed to decrypt snapshot: {error}"))
}

fn read_env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().map(|value| {
        value
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a valid u64"))
    })
}

fn read_env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok().map(|value| {
        value
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a valid usize"))
    })
}

fn snapshot_keys_to_prune(keys: &[String], retain_count: usize) -> Vec<String> {
    if retain_count == 0 || keys.len() <= retain_count {
        return Vec::new();
    }
    keys[..keys.len() - retain_count].to_vec()
}

fn decode_fixed_b64<const N: usize>(encoded: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = BASE64
        .decode(encoded)
        .map_err(|error| format!("{label} must be valid base64: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must decode to exactly {N} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deposit_detector::DepositDetector;
    use crate::state::{
        ChannelBalance, ChannelRequest, ChannelStatus, SolanaRuntimeConfig, VaultState,
    };
    use crate::wal::Wal;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::path::PathBuf;
    use tokio::sync::Mutex as TokioMutex;

    async fn make_state() -> Arc<AppState> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        let vault = Arc::new(VaultState::new(
            Pubkey::new_unique(),
            signing_key,
            Pubkey::new_unique(),
            [0u8; 32],
            solana.clone(),
        ));
        let wal = Arc::new(
            Wal::new_with_key(
                PathBuf::from(std::env::temp_dir().join(format!(
                    "subly402-snapshot-test-{}.jsonl",
                    uuid::Uuid::now_v7()
                ))),
                [7u8; 32],
            )
            .await,
        );
        let detector = Arc::new(DepositDetector::new(
            solana.vault_token_account,
            solana.program_id,
            solana.rpc_url,
            solana.ws_url,
            crate::outbound::OutboundTransport::direct(),
        ));

        Arc::new(AppState {
            vault,
            wal,
            deposit_detector: detector,
            batch_privacy: crate::batch::BatchPrivacyConfig::default(),
            attestation_provider: Arc::new(
                crate::attestation::AttestationProvider::test_local_dev(),
            ),
            asc_ops_lock: TokioMutex::new(()),
            persistence_lock: TokioMutex::new(()),
            watchtower_url: None,
            attestation_document: String::new(),
            attestation_is_local_dev: true,
            provider_mtls_enabled: false,
            outbound: crate::outbound::OutboundTransport::direct(),
            arcium_grant_decryptor: None,
            arcium_mxe_public_key: None,
            arcium_domain_hashes: None,
        })
    }

    #[tokio::test]
    async fn snapshot_capture_and_apply_roundtrip() {
        let state = make_state().await;
        let client = Pubkey::new_unique();
        state.vault.client_balances.insert(
            client,
            ClientBalance {
                free: 10,
                locked: 5,
                max_lock_expires_at: 42,
                total_deposited: 15,
                total_withdrawn: 0,
            },
        );
        state.vault.providers.insert(
            "provider".to_string(),
            ProviderRegistration {
                provider_id: "provider".to_string(),
                display_name: "Provider".to_string(),
                participant_pubkey: None,
                participant_attestation_policy_hash: None,
                participant_attestation_verified_at_ms: None,
                participant_attestation_mode: None,
                settlement_token_account: Pubkey::new_unique(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: Some(vec![1, 2, 3]),
                mtls_cert_fingerprint: None,
            },
        );
        state.vault.provider_credits.insert(
            "provider".to_string(),
            ProviderCredit {
                provider_id: "provider".to_string(),
                settlement_token_account: Pubkey::new_unique(),
                credited_amount: 77,
                oldest_credit_at: 123,
                settlement_ids: vec!["set-1".to_string()],
            },
        );
        state.vault.active_channels.insert(
            "channel-1".to_string(),
            ChannelState {
                channel_id: "channel-1".to_string(),
                client,
                provider_id: "provider".to_string(),
                balance: ChannelBalance {
                    client_free: 1,
                    client_locked: 2,
                    provider_earned: 3,
                },
                status: ChannelStatus::Pending,
                nonce: 9,
                created_at: 10,
                updated_at: 11,
                used_request_ids: ["req-1".to_string()].into_iter().collect(),
                active_request: Some(ChannelRequest {
                    request_id: "req-1".to_string(),
                    amount: 5,
                    request_hash: [4u8; 32],
                    provider_pubkey: Some([5u8; 32]),
                    adaptor_point: Some([6u8; 32]),
                    provider_pre_sig: None,
                    encrypted_result: Some(vec![1, 2, 3]),
                    result_hash: Some([7u8; 32]),
                    created_at: 12,
                    expires_at: 13,
                }),
            },
        );
        state.vault.set_arcium_mode(ArciumAuthorityMode::Enforced);
        state
            .vault
            .load_arcium_budget_grant(ArciumBudgetGrant {
                grant_id: "budget-grant".to_string(),
                client,
                budget_id: 1,
                request_nonce: 2,
                remaining: 33,
                expires_at: 44,
            })
            .unwrap();
        state
            .vault
            .load_arcium_withdrawal_grant(ArciumWithdrawalGrant {
                grant_id: "withdrawal-grant".to_string(),
                client,
                withdrawal_id: 3,
                recipient_ata: Pubkey::new_unique(),
                amount: 22,
                expires_at: 55,
                consumed: true,
            })
            .unwrap();
        state.deposit_detector.mark_processed("sig-1").await;
        *state
            .deposit_detector
            .last_processed_signature
            .write()
            .await = Some("sig-1".to_string());
        *state.vault.auditor_master_secret.write().await = [9u8; 32];
        state.vault.auditor_epoch.store(3, Ordering::SeqCst);
        state.vault.receipt_nonce.store(8, Ordering::SeqCst);
        state.vault.withdraw_nonce.store(4, Ordering::SeqCst);
        state.vault.last_finalized_slot.store(99, Ordering::SeqCst);
        *state.vault.last_batch_at.write().await = 222;

        let snapshot = capture_snapshot(&state, 2, Some(7)).await;

        let restored = make_state().await;
        apply_snapshot(&restored, &snapshot).await.unwrap();

        assert_eq!(
            restored.vault.client_balances.get(&client).unwrap().free,
            10
        );
        assert_eq!(
            restored
                .vault
                .provider_credits
                .get("provider")
                .unwrap()
                .credited_amount,
            77
        );
        assert_eq!(
            restored
                .vault
                .active_channels
                .get("channel-1")
                .unwrap()
                .nonce,
            9
        );
        assert_eq!(restored.vault.arcium_mode(), ArciumAuthorityMode::Enforced);
        assert_eq!(
            restored
                .vault
                .arcium_budget_grants
                .get("budget-grant")
                .unwrap()
                .remaining,
            33
        );
        assert!(
            restored
                .vault
                .arcium_withdrawal_grants
                .get("withdrawal-grant")
                .unwrap()
                .consumed
        );
        assert!(restored.deposit_detector.is_processed("sig-1").await);
        assert_eq!(restored.vault.snapshot_seqno.load(Ordering::SeqCst), 2);
        assert_eq!(restored.vault.receipt_nonce.load(Ordering::SeqCst), 8);
        assert_eq!(
            *restored.vault.auditor_master_secret.read().await,
            [9u8; 32]
        );
    }

    #[test]
    fn snapshot_pruning_keeps_latest_n_keys() {
        let keys = vec![
            "snapshot/vault/snapshot-00000000000000000001.json".to_string(),
            "snapshot/vault/snapshot-00000000000000000002.json".to_string(),
            "snapshot/vault/snapshot-00000000000000000003.json".to_string(),
            "snapshot/vault/snapshot-00000000000000000004.json".to_string(),
        ];

        assert_eq!(
            snapshot_keys_to_prune(&keys, 2),
            vec![
                "snapshot/vault/snapshot-00000000000000000001.json".to_string(),
                "snapshot/vault/snapshot-00000000000000000002.json".to_string(),
            ]
        );
        assert!(snapshot_keys_to_prune(&keys, 4).is_empty());
        assert!(snapshot_keys_to_prune(&keys, 0).is_empty());
    }
}
