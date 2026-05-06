use anchor_client::anchor_lang::AccountDeserialize;
use axum::extract::State;
use axum::http::{header::AUTHORIZATION, HeaderMap};
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use spl_associated_token_account::get_associated_token_address;
use std::any::Any;
use std::env;
use std::panic::AssertUnwindSafe;
use std::str::FromStr;
use std::sync::Arc;
use subly402_vault::asc_claim::{
    build_asc_claim_voucher_message, hash_identifier, AscClaimVoucherFields,
};
use subly402_vault::constants::{
    VAULT_STATUS_ACTIVE, VAULT_STATUS_MIGRATING, VAULT_STATUS_PAUSED, VAULT_STATUS_RETIRED,
};
use subly402_vault::state::VaultConfig as OnChainVaultConfig;
use tokio::sync::Mutex;
use tracing::{error, info};

use crate::adaptor_sig::AdaptorPreSignature;
use crate::asc_manager;
use crate::attestation::response_window;
use crate::batch;
use crate::deposit_detector::DepositDetector;
use crate::error::EnclaveError;
use crate::outbound::OutboundTransport;
use crate::state::{
    ArciumAuthorityMode, ArciumBudgetGrant, ArciumWithdrawalGrant, PendingWithdrawal, Reservation,
    ReservationStatus, VaultLifecycle, VaultState,
};
use crate::tls::INTERNAL_MTLS_FINGERPRINT_HEADER;
use crate::wal::{Wal, WalEntry};

const PROVIDER_ID_HEADER: &str = "x-subly402-provider-id";
const PROVIDER_AUTH_HEADER: &str = "x-subly402-provider-auth";
const CLIENT_AUTH_MAX_WINDOW_SEC: i64 = 300;
const CLIENT_AUTH_MAX_CLOCK_SKEW_SEC: i64 = 60;
const OPEN_PROVIDER_ID_PREFIX: &str = "payto_";

pub struct AppState {
    pub vault: Arc<VaultState>,
    pub wal: Arc<Wal>,
    pub deposit_detector: Arc<DepositDetector>,
    pub batch_privacy: crate::batch::BatchPrivacyConfig,
    pub attestation_provider: Arc<crate::attestation::AttestationProvider>,
    pub asc_ops_lock: Mutex<()>,
    pub persistence_lock: Mutex<()>,
    /// Watchtower URL for receipt replication (Phase 4).
    pub watchtower_url: Option<String>,
    pub attestation_document: String,
    pub attestation_is_local_dev: bool,
    pub provider_mtls_enabled: bool,
    pub outbound: OutboundTransport,
    pub arcium_grant_decryptor: Option<Arc<crate::arcium::ArciumGrantDecryptor>>,
    pub arcium_mxe_public_key: Option<[u8; 32]>,
    pub arcium_domain_hashes: Option<crate::arcium::ArciumGrantDomainHashes>,
}

// ── Attestation ──

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponse {
    pub vault_config: String,
    pub vault_signer: String,
    pub attestation_policy_hash: String,
    pub arcium_mode: String,
    pub attestation_document: String,
    pub snapshot_seqno: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_public_key_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    pub issued_at: String,
    pub expires_at: String,
}

pub async fn get_attestation(State(state): State<Arc<AppState>>) -> Json<AttestationResponse> {
    let (issued_at, expires_at) = response_window();
    let snapshot_seqno = state
        .vault
        .snapshot_seqno
        .load(std::sync::atomic::Ordering::SeqCst);
    let runtime_attestation = state
        .attestation_provider
        .runtime_attestation(
            state.vault.vault_config,
            state.vault.vault_signer_pubkey,
            state.vault.attestation_policy_hash,
            Some(state.vault.arcium_mode().as_str()),
            snapshot_seqno,
        )
        .expect("runtime attestation generation must succeed");

    Json(AttestationResponse {
        vault_config: state.vault.vault_config.to_string(),
        vault_signer: state.vault.vault_signer_pubkey.to_string(),
        attestation_policy_hash: hex::encode(state.vault.attestation_policy_hash),
        arcium_mode: state.vault.arcium_mode().as_str().to_string(),
        attestation_document: runtime_attestation.document_b64,
        snapshot_seqno: runtime_attestation.snapshot_seqno,
        tls_public_key_sha256: runtime_attestation.tls_public_key_sha256,
        manifest_hash: runtime_attestation.manifest_hash,
        issued_at: issued_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    })
}

// ── Verify ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestContext {
    pub method: String,
    pub origin: String,
    pub path_and_query: String,
    pub body_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub version: u32,
    pub scheme: String,
    pub payment_id: String,
    pub client: String,
    pub vault: String,
    pub provider_id: String,
    pub pay_to: String,
    pub network: String,
    pub asset_mint: String,
    pub amount: String,
    pub request_hash: String,
    pub payment_details_hash: String,
    pub expires_at: String,
    pub nonce: String,
    pub client_sig: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    pub payment_payload: PaymentPayload,
    #[serde(default)]
    pub payment_details: Option<serde_json::Value>,
    pub request_context: RequestContext,
}

// ── Provider Authentication Helper (§8.2 requirement 1) ──

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn derive_open_provider_id(network: &str, asset_mint: &str, pay_to: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"SUBLY402-OPEN-PROVIDER-V1\n");
    hasher.update(network.as_bytes());
    hasher.update(b"\n");
    hasher.update(asset_mint.as_bytes());
    hasher.update(b"\n");
    hasher.update(pay_to.as_bytes());
    hasher.update(b"\n");
    let digest = hex::encode(hasher.finalize());
    format!("{}{}", OPEN_PROVIDER_ID_PREFIX, &digest[..32])
}

fn payment_details_str<'a>(
    payment_details: &'a serde_json::Value,
    path: &[&str],
) -> Result<&'a str, EnclaveError> {
    let mut current = payment_details;
    for key in path {
        current = current
            .get(*key)
            .ok_or(EnclaveError::InvalidPaymentDetails)?;
    }
    current.as_str().ok_or(EnclaveError::InvalidPaymentDetails)
}

fn validate_payment_details_match_payload(
    payment_details: &serde_json::Value,
    payload: &PaymentPayload,
) -> Result<(), EnclaveError> {
    if payment_details_str(payment_details, &["providerId"])? != payload.provider_id {
        return Err(EnclaveError::ProviderIdMismatch);
    }
    if payment_details_str(payment_details, &["payTo"])? != payload.pay_to {
        return Err(EnclaveError::PayToMismatch);
    }
    if payment_details_str(payment_details, &["network"])? != payload.network {
        return Err(EnclaveError::NetworkMismatch);
    }
    if payment_details_str(payment_details, &["asset", "mint"])? != payload.asset_mint {
        return Err(EnclaveError::AssetMintMismatch);
    }
    if payment_details_str(payment_details, &["amount"])? != payload.amount {
        return Err(EnclaveError::InvalidPaymentDetails);
    }
    if payment_details_str(payment_details, &["vault", "config"])? != payload.vault {
        return Err(EnclaveError::VaultNotActive);
    }
    Ok(())
}

async fn load_vault_lifecycle(state: &Arc<AppState>) -> Result<VaultLifecycle, EnclaveError> {
    if cfg!(test) {
        return Ok(state.vault.lifecycle.read().await.clone());
    }

    let now_ms = Utc::now().timestamp_millis();
    let rpc = state.outbound.solana_rpc_client(
        state.vault.solana.rpc_url.clone(),
        CommitmentConfig::confirmed(),
    );
    let account_data = rpc
        .get_account_data(&state.vault.vault_config)
        .await
        .map_err(|_| EnclaveError::VaultStatusUnavailable)?;
    let mut slice: &[u8] = account_data.as_slice();
    let vault_config = OnChainVaultConfig::try_deserialize(&mut slice)
        .map_err(|_| EnclaveError::VaultStatusUnavailable)?;

    let lifecycle = VaultLifecycle {
        status: vault_config.status,
        successor_vault: vault_config.successor_vault,
        exit_deadline: vault_config.exit_deadline,
        synced_at_ms: now_ms,
    };
    *state.vault.lifecycle.write().await = lifecycle.clone();
    Ok(lifecycle)
}

async fn ensure_vault_allows_new_verification(state: &Arc<AppState>) -> Result<(), EnclaveError> {
    let lifecycle = load_vault_lifecycle(state).await?;
    match lifecycle.status {
        VAULT_STATUS_ACTIVE => Ok(()),
        VAULT_STATUS_PAUSED => Err(EnclaveError::VaultPaused),
        VAULT_STATUS_MIGRATING => Err(EnclaveError::VaultMigrating),
        VAULT_STATUS_RETIRED => Err(EnclaveError::VaultRetired),
        _ => Err(EnclaveError::VaultStatusUnavailable),
    }
}

async fn ensure_vault_allows_existing_reservation_ops(
    state: &Arc<AppState>,
) -> Result<(), EnclaveError> {
    let lifecycle = load_vault_lifecycle(state).await?;
    match lifecycle.status {
        VAULT_STATUS_ACTIVE => Ok(()),
        VAULT_STATUS_PAUSED => Err(EnclaveError::VaultPaused),
        VAULT_STATUS_MIGRATING => {
            if Utc::now().timestamp() <= lifecycle.exit_deadline {
                Ok(())
            } else {
                Err(EnclaveError::VaultRetired)
            }
        }
        VAULT_STATUS_RETIRED => Err(EnclaveError::VaultRetired),
        _ => Err(EnclaveError::VaultStatusUnavailable),
    }
}

async fn ensure_vault_allows_withdraw(state: &Arc<AppState>) -> Result<(), EnclaveError> {
    let lifecycle = load_vault_lifecycle(state).await?;
    match lifecycle.status {
        VAULT_STATUS_ACTIVE => Ok(()),
        VAULT_STATUS_MIGRATING => {
            if Utc::now().timestamp() <= lifecycle.exit_deadline {
                Ok(())
            } else {
                Err(EnclaveError::VaultRetired)
            }
        }
        VAULT_STATUS_PAUSED => Err(EnclaveError::VaultPaused),
        VAULT_STATUS_RETIRED => Err(EnclaveError::VaultRetired),
        _ => Err(EnclaveError::VaultStatusUnavailable),
    }
}

fn authenticate_registered_provider(
    provider: &crate::state::ProviderRegistration,
    headers: &HeaderMap,
) -> Result<(), EnclaveError> {
    match provider.auth_mode.as_str() {
        "bearer" => {
            let api_key_hash = provider
                .api_key_hash
                .as_deref()
                .ok_or(EnclaveError::InvalidProviderAuthConfig)?;
            if api_key_hash.len() != 32 {
                return Err(EnclaveError::InvalidProviderAuthConfig);
            }

            let provider_id = header_value(headers, PROVIDER_ID_HEADER)
                .ok_or(EnclaveError::ProviderAuthFailed)?;
            if provider_id != provider.provider_id {
                return Err(EnclaveError::ProviderIdMismatch);
            }

            let auth_header = headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(EnclaveError::ProviderAuthFailed)?;
            let token = auth_header
                .strip_prefix("Bearer ")
                .ok_or(EnclaveError::ProviderAuthFailed)?;
            if Sha256::digest(token.as_bytes()).as_slice() != api_key_hash {
                return Err(EnclaveError::ProviderAuthFailed);
            }
            Ok(())
        }
        "api-key" => {
            let api_key_hash = provider
                .api_key_hash
                .as_deref()
                .ok_or(EnclaveError::InvalidProviderAuthConfig)?;
            if api_key_hash.len() != 32 {
                return Err(EnclaveError::InvalidProviderAuthConfig);
            }

            if let Some(provider_id) = header_value(headers, PROVIDER_ID_HEADER) {
                if provider_id != provider.provider_id {
                    return Err(EnclaveError::ProviderIdMismatch);
                }
            }

            let token = header_value(headers, PROVIDER_AUTH_HEADER)
                .or_else(|| {
                    headers
                        .get(AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.strip_prefix("Bearer "))
                })
                .ok_or(EnclaveError::ProviderAuthFailed)?;
            if Sha256::digest(token.as_bytes()).as_slice() != api_key_hash {
                return Err(EnclaveError::ProviderAuthFailed);
            }
            Ok(())
        }
        "mtls" => {
            let expected_fingerprint = provider
                .mtls_cert_fingerprint
                .as_deref()
                .ok_or(EnclaveError::InvalidProviderAuthConfig)?;
            if expected_fingerprint.len() != 32 {
                return Err(EnclaveError::InvalidProviderAuthConfig);
            }

            if let Some(provider_id) = header_value(headers, PROVIDER_ID_HEADER) {
                if provider_id != provider.provider_id {
                    return Err(EnclaveError::ProviderIdMismatch);
                }
            }

            let presented_fingerprint = header_value(headers, INTERNAL_MTLS_FINGERPRINT_HEADER)
                .ok_or(EnclaveError::ProviderAuthFailed)?;
            let presented_fingerprint =
                hex::decode(presented_fingerprint).map_err(|_| EnclaveError::ProviderAuthFailed)?;
            if presented_fingerprint.as_slice() != expected_fingerprint {
                return Err(EnclaveError::ProviderAuthFailed);
            }
            Ok(())
        }
        "none" => {
            if let Some(provider_id) = header_value(headers, PROVIDER_ID_HEADER) {
                if provider_id != provider.provider_id {
                    return Err(EnclaveError::ProviderIdMismatch);
                }
            }
            Ok(())
        }
        _ => Err(EnclaveError::UnsupportedProviderAuthMode),
    }
}

fn authenticate_provider(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    expected_provider_id: &str,
) -> Result<String, EnclaveError> {
    let provider = state
        .vault
        .providers
        .get(expected_provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;
    authenticate_registered_provider(provider.value(), headers)?;
    Ok(expected_provider_id.to_string())
}

async fn ensure_open_provider_registered(
    state: &Arc<AppState>,
    payload: &PaymentPayload,
) -> Result<(), EnclaveError> {
    if state.vault.providers.contains_key(&payload.provider_id) {
        return Ok(());
    }

    let derived_provider_id =
        derive_open_provider_id(&payload.network, &payload.asset_mint, &payload.pay_to);
    if payload.provider_id != derived_provider_id {
        return Ok(());
    }

    let settlement_token_account =
        Pubkey::from_str(&payload.pay_to).map_err(|_| EnclaveError::InvalidPaymentDetails)?;
    let asset_mint =
        Pubkey::from_str(&payload.asset_mint).map_err(|_| EnclaveError::InvalidPaymentDetails)?;
    let registration = crate::state::ProviderRegistration {
        provider_id: payload.provider_id.clone(),
        display_name: "Open x402 seller".to_string(),
        participant_pubkey: None,
        participant_attestation_policy_hash: None,
        participant_attestation_verified_at_ms: None,
        participant_attestation_mode: None,
        settlement_token_account,
        network: payload.network.clone(),
        asset_mint,
        allowed_origins: Vec::new(),
        auth_mode: "none".to_string(),
        api_key_hash: None,
        mtls_cert_fingerprint: None,
    };

    let _persist_guard = state.persistence_lock.lock().await;
    if state.vault.providers.contains_key(&payload.provider_id) {
        return Ok(());
    }
    state
        .wal
        .append(WalEntry::ProviderRegistered {
            provider_id: payload.provider_id.clone(),
            display_name: registration.display_name.clone(),
            participant_pubkey: None,
            participant_attestation_policy_hash: None,
            participant_attestation_verified_at_ms: None,
            participant_attestation_mode: None,
            settlement_token_account: payload.pay_to.clone(),
            network: payload.network.clone(),
            asset_mint: payload.asset_mint.clone(),
            allowed_origins: Vec::new(),
            auth_mode: "none".to_string(),
            api_key_hash: None,
            mtls_cert_fingerprint: None,
        })
        .await
        .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

    state
        .vault
        .providers
        .insert(payload.provider_id.clone(), registration);
    info!(provider_id = %payload.provider_id, "Open provider auto-registered");
    Ok(())
}

/// Compute canonical JSON hash of payment details (§6, paymentDetailsHash).
fn compute_payment_details_hash(details: &serde_json::Value) -> Vec<u8> {
    // canonical_json: UTF-8, keys in lexicographic order, no extra whitespace
    let canonical = canonical_json(details);
    Sha256::digest(canonical.as_bytes()).to_vec()
}

/// Produce canonical JSON: sorted keys, no extra whitespace.
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonical_json(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        serde_json::Value::Array(arr) => {
            let entries: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", entries.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub ok: bool,
    pub verification_id: String,
    pub reservation_id: String,
    pub reservation_expires_at: String,
    pub provider_id: String,
    pub amount: String,
    pub verification_receipt: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReceiptEnvelope {
    pub verification_id: String,
    pub reservation_id: String,
    pub payment_id: String,
    pub client: String,
    pub provider_id: String,
    pub amount: String,
    pub request_hash: String,
    pub payment_details_hash: String,
    pub reservation_expires_at: String,
    pub vault_config: String,
    pub signature: String,
    pub message: String,
}

fn encode_verification_receipt_envelope(
    receipt: &VerificationReceiptEnvelope,
) -> Result<String, EnclaveError> {
    serde_json::to_vec(receipt)
        .map(|json| BASE64.encode(json))
        .map_err(|e| {
            EnclaveError::Internal(format!("VerificationReceipt serialization failed: {e}"))
        })
}

fn issue_verification_receipt(
    state: &Arc<AppState>,
    reservation: &Reservation,
) -> Result<String, EnclaveError> {
    let reservation_expires_at =
        chrono::DateTime::from_timestamp(reservation.expires_at, 0).unwrap_or_default();
    let request_hash = hex::encode(reservation.request_hash);
    let payment_details_hash = hex::encode(reservation.payment_details_hash);
    let message = state.vault.build_verification_receipt_message(
        &reservation.verification_id,
        &reservation.reservation_id,
        &reservation.payment_id,
        &reservation.client,
        &reservation.provider_id,
        reservation.amount,
        &request_hash,
        &payment_details_hash,
        reservation.expires_at,
    );
    let signature = state.vault.sign_message(&message);

    encode_verification_receipt_envelope(&VerificationReceiptEnvelope {
        verification_id: reservation.verification_id.clone(),
        reservation_id: reservation.reservation_id.clone(),
        payment_id: reservation.payment_id.clone(),
        client: reservation.client.to_string(),
        provider_id: reservation.provider_id.clone(),
        amount: reservation.amount.to_string(),
        request_hash,
        payment_details_hash,
        reservation_expires_at: reservation_expires_at.to_rfc3339(),
        vault_config: state.vault.vault_config.to_string(),
        signature: BASE64.encode(signature),
        message: BASE64.encode(message),
    })
}

pub async fn post_verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, EnclaveError> {
    let payload = &req.payment_payload;
    let payment_details = req
        .payment_details
        .as_ref()
        .ok_or(EnclaveError::PaymentDetailsRequired)?;

    if state.deposit_detector.is_enabled() && !state.deposit_detector.is_ready() {
        return Err(EnclaveError::DepositSyncInProgress);
    }

    ensure_vault_allows_new_verification(&state).await?;

    // 1. Validate scheme
    if payload.scheme != "subly402-svm-v1" {
        return Err(EnclaveError::InvalidScheme);
    }
    if payment_details
        .get("scheme")
        .and_then(|value| value.as_str())
        != Some("subly402-svm-v1")
    {
        return Err(EnclaveError::InvalidScheme);
    }

    // C7: Validate paymentDetailsHash via canonical JSON (§8.2 requirement 3).
    // Registrationless providers rely on these signed details, so this runs
    // before provider lookup can auto-create an open seller entry.
    let computed_hash = compute_payment_details_hash(payment_details);
    let provided_hash = hex::decode(&payload.payment_details_hash)
        .map_err(|_| EnclaveError::PaymentDetailsHashMismatch)?;
    if computed_hash != provided_hash {
        return Err(EnclaveError::PaymentDetailsHashMismatch);
    }
    validate_payment_details_match_payload(payment_details, payload)?;

    // 3. Validate vault address
    if payload.vault != state.vault.vault_config.to_string() {
        return Err(EnclaveError::VaultNotActive);
    }

    // 4. Validate expiration
    let expires_at = chrono::DateTime::parse_from_rfc3339(&payload.expires_at)
        .map_err(|_| EnclaveError::PaymentExpired)?;
    if expires_at < Utc::now() {
        return Err(EnclaveError::PaymentExpired);
    }

    // 5. Verify client signature
    let client_pubkey =
        Pubkey::from_str(&payload.client).map_err(|_| EnclaveError::InvalidClientSignature)?;

    verify_client_signature(payload)?;

    // 6. Verify request hash
    let computed_request_hash =
        compute_request_hash(&req.request_context, &payload.payment_details_hash);
    let provided_request_hash =
        hex::decode(&payload.request_hash).map_err(|_| EnclaveError::RequestHashMismatch)?;
    if computed_request_hash != provided_request_hash.as_slice() {
        return Err(EnclaveError::RequestHashMismatch);
    }

    let amount: u64 = payload
        .amount
        .parse()
        .map_err(|_| EnclaveError::Internal("Invalid amount".into()))?;
    let verify_window_sec = parse_verify_window_sec(payment_details)?;

    ensure_open_provider_registered(&state, payload).await?;

    // C5: Authenticate provider from provider registration + headers (§8.2 requirement 1)
    let authenticated_provider_id = authenticate_provider(&state, &headers, &payload.provider_id)?;

    // 2. Validate provider exists and matches authenticated identity
    let provider = state
        .vault
        .providers
        .get(&payload.provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;

    if authenticated_provider_id != payload.provider_id {
        return Err(EnclaveError::ProviderIdMismatch);
    }

    // C6: Validate registration fields match payload (§8.2 requirement 7)
    if payload.pay_to != provider.settlement_token_account.to_string() {
        return Err(EnclaveError::PayToMismatch);
    }
    if payload.asset_mint != provider.asset_mint.to_string() {
        return Err(EnclaveError::AssetMintMismatch);
    }
    if payload.network != provider.network {
        return Err(EnclaveError::NetworkMismatch);
    }

    // C9: Validate request origin against provider allowedOrigins (§4)
    if !provider.allowed_origins.is_empty()
        && !provider
            .allowed_origins
            .contains(&req.request_context.origin)
    {
        return Err(EnclaveError::OriginNotAllowed);
    }

    // Drop the provider reference before further borrows
    drop(provider);

    // 7. Idempotency: check if payment_id already used
    if let Some(existing_ver_id) = state.vault.payment_id_index.get(&payload.payment_id) {
        if let Some(existing) = state.vault.reservations.get(existing_ver_id.value()) {
            // Same payment_id + same request_hash → idempotent retry
            let req_hash: [u8; 32] = computed_request_hash.try_into().unwrap();
            if existing.request_hash == req_hash {
                let res_expires =
                    chrono::DateTime::from_timestamp(existing.expires_at, 0).unwrap_or_default();
                let verification_receipt = issue_verification_receipt(&state, &existing)?;
                return Ok(Json(VerifyResponse {
                    ok: true,
                    verification_id: existing.verification_id.clone(),
                    reservation_id: existing.reservation_id.clone(),
                    reservation_expires_at: res_expires.to_rfc3339(),
                    provider_id: existing.provider_id.clone(),
                    amount: existing.amount.to_string(),
                    verification_receipt,
                }));
            } else {
                return Err(EnclaveError::PaymentIdReused);
            }
        }
    }

    let now = Utc::now().timestamp();
    let verification_id = format!("ver_{}", uuid::Uuid::now_v7());
    let reservation_id = format!("res_{}", uuid::Uuid::now_v7());
    let reservation_expires_at = now
        .checked_add(verify_window_sec)
        .ok_or(EnclaveError::InvalidVerifyWindowSec)?;

    let request_hash: [u8; 32] = computed_request_hash.try_into().unwrap();
    let payment_details_hash: [u8; 32] = hex::decode(&payload.payment_details_hash)
        .map_err(|_| EnclaveError::PaymentDetailsHashMismatch)?
        .try_into()
        .map_err(|_| EnclaveError::PaymentDetailsHashMismatch)?;

    let reservation = Reservation {
        verification_id: verification_id.clone(),
        reservation_id: reservation_id.clone(),
        payment_id: payload.payment_id.clone(),
        client: client_pubkey,
        provider_id: payload.provider_id.clone(),
        amount,
        request_hash,
        payment_details_hash,
        status: ReservationStatus::Reserved,
        created_at: now,
        expires_at: reservation_expires_at,
        settlement_id: None,
        settled_at: None,
        arcium_grant_id: None,
    };

    {
        let _persist_guard = state.persistence_lock.lock().await;

        let arcium_grant_id = if state.vault.arcium_enforced() {
            Some(
                state
                    .vault
                    .reserve_arcium_budget(&client_pubkey, amount, now)?,
            )
        } else {
            state.vault.reserve_balance(&client_pubkey, amount)?;
            None
        };

        // 10. WAL append (durable before response)
        if let Err(error) = state
            .wal
            .append(WalEntry::ReservationCreated {
                verification_id: verification_id.clone(),
                reservation_id: Some(reservation_id.clone()),
                payment_id: payload.payment_id.clone(),
                client: payload.client.clone(),
                provider_id: payload.provider_id.clone(),
                amount,
                request_hash: Some(hex::encode(request_hash)),
                payment_details_hash: Some(hex::encode(payment_details_hash)),
                created_at: Some(now),
                expires_at: Some(reservation_expires_at),
                arcium_grant_id: arcium_grant_id.clone(),
            })
            .await
        {
            if let Some(grant_id) = arcium_grant_id.as_deref() {
                let _ = state.vault.release_arcium_budget(grant_id, amount);
            } else {
                let _ = state.vault.release_balance(&client_pubkey, amount);
            }
            return Err(EnclaveError::Internal(format!(
                "WAL append failed: {error}"
            )));
        }

        let mut reservation = reservation;
        reservation.arcium_grant_id = arcium_grant_id;
        state
            .vault
            .reservations
            .insert(verification_id.clone(), reservation);
        state
            .vault
            .payment_id_index
            .insert(payload.payment_id.clone(), verification_id.clone());
        if !state.vault.arcium_enforced() {
            state
                .vault
                .refresh_client_max_lock_expires_at(&client_pubkey)?;
            issue_client_receipt_locked(&state, client_pubkey).await?;
        }
    }

    let res_expires =
        chrono::DateTime::from_timestamp(reservation_expires_at, 0).unwrap_or_default();

    info!(verification_id = %verification_id, amount, "Payment verified and reserved");

    let verification_receipt = issue_verification_receipt(
        &state,
        state
            .vault
            .reservations
            .get(&verification_id)
            .ok_or(EnclaveError::ReservationNotFound)?
            .value(),
    )?;

    Ok(Json(VerifyResponse {
        ok: true,
        verification_id,
        reservation_id,
        reservation_expires_at: res_expires.to_rfc3339(),
        provider_id: payload.provider_id.clone(),
        amount: amount.to_string(),
        verification_receipt,
    }))
}

// ── Settle ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleRequest {
    pub verification_id: String,
    pub result_hash: String,
    pub status_code: u16,
}

const PARTICIPANT_KIND_CLIENT: u8 = 0;
const PARTICIPANT_KIND_PROVIDER: u8 = 1;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleResponse {
    pub ok: bool,
    pub settlement_id: String,
    pub offchain_settled_at: String,
    pub provider_credit_amount: String,
    pub batch_id: Option<u64>,
    pub participant_receipt: String,
}

pub async fn post_settle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SettleRequest>,
) -> Result<Json<SettleResponse>, EnclaveError> {
    enum SettleDecision {
        Idempotent {
            settlement_id: String,
            settled_at: i64,
            amount: u64,
        },
        Fresh {
            settlement_id: String,
            settled_at: i64,
            amount: u64,
            participant_receipt: String,
        },
    }

    let (status, provider_id, amount, existing_settlement_id, settled_at) = {
        let reservation = state
            .vault
            .reservations
            .get(&req.verification_id)
            .ok_or(EnclaveError::ReservationNotFound)?;
        (
            reservation.status.clone(),
            reservation.provider_id.clone(),
            reservation.amount,
            reservation.settlement_id.clone(),
            reservation.settled_at,
        )
    };

    ensure_vault_allows_existing_reservation_ops(&state).await?;

    // C5: Authenticate provider (§8.3 — same auth as /verify)
    let authenticated_provider_id = authenticate_provider(&state, &headers, &provider_id)?;

    // Verify authenticated provider owns this reservation
    if authenticated_provider_id != provider_id {
        return Err(EnclaveError::ProviderIdMismatch);
    }

    if status == ReservationStatus::SettledOffchain {
        let settled_at = settled_at.unwrap_or(0);
        let settled_time = chrono::DateTime::from_timestamp(settled_at, 0).unwrap_or_default();
        return Ok(Json(SettleResponse {
            ok: true,
            settlement_id: existing_settlement_id.unwrap_or_default(),
            offchain_settled_at: settled_time.to_rfc3339(),
            provider_credit_amount: amount.to_string(),
            batch_id: None,
            participant_receipt: encode_receipt_envelope(
                &issue_provider_receipt(&state, &provider_id).await?,
            )?,
        }));
    }

    // Must be Reserved
    if status != ReservationStatus::Reserved {
        return Err(match status {
            ReservationStatus::Expired => EnclaveError::ReservationExpired,
            _ => EnclaveError::InvalidReservationStatus(format!("{:?}", status)),
        });
    }

    let now = Utc::now().timestamp();
    let settlement_id = format!("set_{}", uuid::Uuid::now_v7());

    let decision = {
        let _persist_guard = state.persistence_lock.lock().await;
        let reservation = state
            .vault
            .reservations
            .get(&req.verification_id)
            .ok_or(EnclaveError::ReservationNotFound)?;
        match reservation.status.clone() {
            ReservationStatus::SettledOffchain => SettleDecision::Idempotent {
                settlement_id: reservation.settlement_id.clone().unwrap_or_default(),
                settled_at: reservation.settled_at.unwrap_or(0),
                amount: reservation.amount,
            },
            ReservationStatus::Expired => return Err(EnclaveError::ReservationExpired),
            ReservationStatus::Reserved => {
                if now > reservation.expires_at {
                    drop(reservation);
                    expire_reserved_reservation_with_lock(&state, &req.verification_id, now)
                        .await?;
                    return Err(EnclaveError::ReservationExpired);
                }
                let client = reservation.client;
                let amount = reservation.amount;
                let arcium_grant_id = reservation.arcium_grant_id.clone();
                drop(reservation);

                if arcium_grant_id.is_some() {
                    state
                        .vault
                        .credit_provider(amount, &provider_id, &settlement_id, now)?;
                } else {
                    state.vault.settle_payment(
                        &client,
                        amount,
                        &provider_id,
                        &settlement_id,
                        now,
                    )?;
                }

                // Record settlement for audit record generation (Phase 2)
                let provider_reg = state.vault.providers.get(&provider_id);
                let provider_pubkey = provider_reg
                    .as_ref()
                    .map(|p| p.settlement_token_account)
                    .unwrap_or_default();
                state.vault.settlement_history.insert(
                    settlement_id.clone(),
                    crate::state::SettlementRecord {
                        settlement_id: settlement_id.clone(),
                        client,
                        provider: provider_pubkey,
                        amount,
                        timestamp: now,
                    },
                );

                // WAL append (durable before response)
                state
                    .wal
                    .append(WalEntry::SettlementCommitted {
                        settlement_id: settlement_id.clone(),
                        verification_id: req.verification_id.clone(),
                        provider_id: provider_id.clone(),
                        amount,
                        settled_at: Some(now),
                    })
                    .await
                    .map_err(|error| {
                        state.vault.settlement_history.remove(&settlement_id);
                        if arcium_grant_id.is_none() {
                            let _ = state.vault.rollback_settle_payment(
                                &client,
                                amount,
                                &provider_id,
                                &settlement_id,
                            );
                        } else {
                            let _ = state.vault.rollback_credit_provider(
                                amount,
                                &provider_id,
                                &settlement_id,
                            );
                        }
                        EnclaveError::Internal(format!("WAL append failed: {error}"))
                    })?;

                {
                    let mut reservation = state
                        .vault
                        .reservations
                        .get_mut(&req.verification_id)
                        .ok_or(EnclaveError::ReservationNotFound)?;
                    reservation.status = ReservationStatus::SettledOffchain;
                    reservation.settlement_id = Some(settlement_id.clone());
                    reservation.settled_at = Some(now);
                }
                if arcium_grant_id.is_none() {
                    state.vault.refresh_client_max_lock_expires_at(&client)?;
                    issue_client_receipt_locked(&state, client).await?;
                }
                let participant_receipt = encode_receipt_envelope(
                    &issue_provider_receipt_locked(&state, &provider_id).await?,
                )?;

                SettleDecision::Fresh {
                    settlement_id: settlement_id.clone(),
                    settled_at: now,
                    amount,
                    participant_receipt,
                }
            }
            ref other => {
                return Err(EnclaveError::InvalidReservationStatus(format!("{other:?}")));
            }
        }
    };

    let (settlement_id, settled_at, amount, participant_receipt) = match decision {
        SettleDecision::Idempotent {
            settlement_id,
            settled_at,
            amount,
        } => (
            settlement_id,
            settled_at,
            amount,
            encode_receipt_envelope(&issue_provider_receipt(&state, &provider_id).await?)?,
        ),
        SettleDecision::Fresh {
            settlement_id,
            settled_at,
            amount,
            participant_receipt,
        } => (settlement_id, settled_at, amount, participant_receipt),
    };
    let settled_time = chrono::DateTime::from_timestamp(settled_at, 0).unwrap_or_default();

    info!(settlement_id = %settlement_id, "Payment settled off-chain");

    Ok(Json(SettleResponse {
        ok: true,
        settlement_id,
        offchain_settled_at: settled_time.to_rfc3339(),
        provider_credit_amount: amount.to_string(),
        batch_id: None,
        participant_receipt,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementStatusRequest {
    pub settlement_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementStatusResponse {
    pub ok: bool,
    pub settlement_id: String,
    pub verification_id: String,
    pub provider_id: String,
    pub status: String,
    pub batch_id: Option<u64>,
    pub tx_signature: Option<String>,
}

pub async fn post_settlement_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SettlementStatusRequest>,
) -> Result<Json<SettlementStatusResponse>, EnclaveError> {
    let reservation = state
        .vault
        .reservations
        .iter()
        .find(|entry| {
            entry
                .settlement_id
                .as_ref()
                .map(|settlement_id| settlement_id == &req.settlement_id)
                .unwrap_or(false)
        })
        .map(|entry| entry.clone())
        .ok_or(EnclaveError::SettlementNotFound)?;

    authenticate_provider(&state, &headers, &reservation.provider_id)?;

    let batch_info = state
        .vault
        .settlement_batches
        .get(&req.settlement_id)
        .map(|entry| entry.clone());

    Ok(Json(SettlementStatusResponse {
        ok: true,
        settlement_id: req.settlement_id,
        verification_id: reservation.verification_id,
        provider_id: reservation.provider_id,
        status: format!("{:?}", reservation.status),
        batch_id: batch_info.as_ref().map(|entry| entry.batch_id),
        tx_signature: batch_info.map(|entry| entry.tx_signature),
    }))
}

// ── Cancel ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelRequest {
    pub verification_id: String,
    pub reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelResponse {
    pub ok: bool,
    pub cancelled_at: String,
}

pub async fn post_cancel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CancelRequest>,
) -> Result<Json<CancelResponse>, EnclaveError> {
    let (provider_id, status) = {
        let reservation = state
            .vault
            .reservations
            .get(&req.verification_id)
            .ok_or(EnclaveError::ReservationNotFound)?;
        (reservation.provider_id.clone(), reservation.status.clone())
    };

    ensure_vault_allows_existing_reservation_ops(&state).await?;

    // C8: Authenticate provider (§8.5)
    let authenticated_provider_id = authenticate_provider(&state, &headers, &provider_id)?;

    // C8: Check provider_mismatch — only the provider that owns the reservation can cancel (§8.5)
    if authenticated_provider_id != provider_id {
        return Err(EnclaveError::ProviderIdMismatch);
    }

    if status == ReservationStatus::Cancelled {
        let now_str = Utc::now().to_rfc3339();
        return Ok(Json(CancelResponse {
            ok: true,
            cancelled_at: now_str,
        }));
    }

    if status != ReservationStatus::Reserved {
        return Err(EnclaveError::InvalidReservationStatus(format!(
            "{status:?}"
        )));
    }

    {
        let _persist_guard = state.persistence_lock.lock().await;
        let (client, amount, arcium_grant_id) = {
            let reservation = state
                .vault
                .reservations
                .get(&req.verification_id)
                .ok_or(EnclaveError::ReservationNotFound)?;
            if reservation.status == ReservationStatus::Cancelled {
                let now_str = Utc::now().to_rfc3339();
                return Ok(Json(CancelResponse {
                    ok: true,
                    cancelled_at: now_str,
                }));
            }
            if reservation.status != ReservationStatus::Reserved {
                return Err(EnclaveError::InvalidReservationStatus(format!(
                    "{:?}",
                    reservation.status
                )));
            }
            (
                reservation.client,
                reservation.amount,
                reservation.arcium_grant_id.clone(),
            )
        };

        if let Some(grant_id) = arcium_grant_id.as_deref() {
            state.vault.release_arcium_budget(grant_id, amount)?;
        } else {
            state.vault.release_balance(&client, amount)?;
        }

        // WAL
        if let Err(error) = state
            .wal
            .append(WalEntry::ReservationCancelled {
                verification_id: req.verification_id.clone(),
                reason: req.reason.clone(),
            })
            .await
        {
            if let Some(grant_id) = arcium_grant_id.as_deref() {
                let _ = state.vault.reserve_arcium_budget_from_grant(
                    grant_id,
                    &client,
                    amount,
                    Utc::now().timestamp(),
                );
            } else {
                let _ = state.vault.reserve_balance(&client, amount);
            }
            return Err(EnclaveError::Internal(format!(
                "WAL append failed: {error}"
            )));
        }

        {
            let mut reservation = state
                .vault
                .reservations
                .get_mut(&req.verification_id)
                .ok_or(EnclaveError::ReservationNotFound)?;
            reservation.status = ReservationStatus::Cancelled;
        }
        if arcium_grant_id.is_none() {
            state.vault.refresh_client_max_lock_expires_at(&client)?;
            issue_client_receipt_locked(&state, client).await?;
        }
    }

    let now_str = Utc::now().to_rfc3339();

    info!(verification_id = %req.verification_id, reason = %req.reason, "Reservation cancelled");

    Ok(Json(CancelResponse {
        ok: true,
        cancelled_at: now_str,
    }))
}

// ── Withdraw Authorization ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientRequestAuth {
    pub issued_at: i64,
    pub expires_at: i64,
    pub client_sig: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawAuthRequest {
    pub client: String,
    pub recipient_ata: String,
    pub amount: u64,
    #[serde(flatten)]
    auth: ClientRequestAuth,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawAuthResponse {
    pub ok: bool,
    pub withdraw_nonce: u64,
    pub expires_at: i64,
    pub signature: String,
    pub message: String,
}

pub async fn post_withdraw_auth(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WithdrawAuthRequest>,
) -> Result<Json<WithdrawAuthResponse>, EnclaveError> {
    ensure_vault_allows_withdraw(&state).await?;

    let message = build_withdraw_auth_message(
        &req.client,
        &req.recipient_ata,
        req.amount,
        req.auth.issued_at,
        req.auth.expires_at,
    );
    let client = verify_client_request_auth(&req.client, &message, &req.auth)?;
    let recipient_ata = Pubkey::from_str(&req.recipient_ata)
        .map_err(|_| EnclaveError::Internal("Invalid recipient ATA".into()))?;
    let (withdraw_nonce, expires_at, signature, message) = {
        let _persist_guard = state.persistence_lock.lock().await;
        let withdraw_nonce = state.vault.next_withdraw_nonce();
        let now = Utc::now().timestamp();
        let mut expires_at = now + 300; // 5 minutes
        let mut arcium_grant_id = None;
        if state.vault.arcium_enforced() {
            let (grant_id, grant_expires_at) = state.vault.select_arcium_withdrawal_grant(
                &client,
                &recipient_ata,
                req.amount,
                now,
            )?;
            expires_at = expires_at.min(grant_expires_at);
            arcium_grant_id = Some(grant_id);
        }
        if expires_at <= now {
            return Err(EnclaveError::InsufficientArciumWithdrawalGrant);
        }
        let message = state.vault.build_withdraw_authorization_message(
            &client,
            &recipient_ata,
            req.amount,
            withdraw_nonce,
            expires_at,
        );
        let signature = state.vault.sign_message(&message);

        let withdrawal = PendingWithdrawal {
            client,
            recipient_ata,
            amount: req.amount,
            withdraw_nonce,
            issued_at: now,
            expires_at,
            arcium_grant_id: arcium_grant_id.clone(),
        };

        if let Some(grant_id) = arcium_grant_id.as_deref() {
            state
                .vault
                .authorize_arcium_withdrawal_from_grant(grant_id, withdrawal, now)?;
        } else {
            state.vault.authorize_withdrawal(withdrawal)?;
        }

        if let Err(error) = state
            .wal
            .append(WalEntry::WithdrawAuthorized {
                client: client.to_string(),
                recipient_ata: recipient_ata.to_string(),
                amount: req.amount,
                withdraw_nonce,
                issued_at: now,
                expires_at,
                arcium_grant_id: arcium_grant_id.clone(),
            })
            .await
        {
            let _ = state.vault.rollback_authorized_withdrawal(withdraw_nonce);
            return Err(EnclaveError::Internal(format!(
                "WAL append failed: {error}"
            )));
        }
        if arcium_grant_id.is_none() {
            state.vault.refresh_client_max_lock_expires_at(&client)?;
            issue_client_receipt_locked(&state, client).await?;
        }

        (withdraw_nonce, expires_at, signature, message)
    };

    Ok(Json(WithdrawAuthResponse {
        ok: true,
        withdraw_nonce,
        expires_at,
        signature: BASE64.encode(&signature),
        message: BASE64.encode(&message),
    }))
}

// ── Client Balance ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceRequest {
    pub client: String,
    #[serde(flatten)]
    auth: ClientRequestAuth,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    pub ok: bool,
    pub client: String,
    pub free: u64,
    pub locked: u64,
    pub total_deposited: u64,
    pub total_withdrawn: u64,
}

pub async fn post_balance(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BalanceRequest>,
) -> Result<Json<BalanceResponse>, EnclaveError> {
    if state.vault.arcium_enforced() {
        return Err(EnclaveError::ArciumBalanceUnavailable);
    }

    let message = build_balance_auth_message(&req.client, req.auth.issued_at, req.auth.expires_at);
    let client = verify_client_request_auth(&req.client, &message, &req.auth)?;

    let balance = state
        .vault
        .client_balances
        .get(&client)
        .ok_or(EnclaveError::ClientNotFound)?;

    Ok(Json(BalanceResponse {
        ok: true,
        client: req.client,
        free: balance.free,
        locked: balance.locked,
        total_deposited: balance.total_deposited,
        total_withdrawn: balance.total_withdrawn,
    }))
}

// ── Client Receipt ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptRequest {
    pub client: String,
    pub recipient_ata: String,
    #[serde(flatten)]
    auth: ClientRequestAuth,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptResponse {
    pub ok: bool,
    pub participant: String,
    pub participant_kind: u8,
    pub recipient_ata: String,
    pub free_balance: u64,
    pub locked_balance: u64,
    pub max_lock_expires_at: i64,
    pub nonce: u64,
    pub timestamp: i64,
    pub snapshot_seqno: u64,
    pub vault_config: String,
    pub signature: String,
    pub message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WatchtowerStoreReceiptResponse {
    pub ok: bool,
    pub stored: bool,
    pub current_nonce: u64,
}

pub async fn post_receipt(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ReceiptRequest>,
) -> Result<Json<ReceiptResponse>, EnclaveError> {
    if state.vault.arcium_enforced() {
        return Err(EnclaveError::ArciumBalanceUnavailable);
    }

    let message = build_receipt_auth_message(
        &req.client,
        &req.recipient_ata,
        req.auth.issued_at,
        req.auth.expires_at,
    );
    let client = verify_client_request_auth(&req.client, &message, &req.auth)?;
    let recipient_ata = Pubkey::from_str(&req.recipient_ata)
        .map_err(|_| EnclaveError::Internal("Invalid recipient ATA".into()))?;

    let balance = state
        .vault
        .client_balances
        .get(&client)
        .ok_or(EnclaveError::ClientNotFound)?;
    let free_balance = balance.free;
    let locked_balance = balance.locked;
    let max_lock_expires_at = balance.max_lock_expires_at;
    drop(balance);

    Ok(Json(
        issue_participant_receipt(
            &state,
            client,
            PARTICIPANT_KIND_CLIENT,
            recipient_ata,
            free_balance,
            locked_balance,
            max_lock_expires_at,
        )
        .await?,
    ))
}

fn encode_receipt_envelope(receipt: &ReceiptResponse) -> Result<String, EnclaveError> {
    serde_json::to_vec(receipt)
        .map(|json| BASE64.encode(json))
        .map_err(|e| EnclaveError::Internal(format!("Receipt serialization failed: {e}")))
}

pub(crate) async fn issue_client_receipt(
    state: &Arc<AppState>,
    client: Pubkey,
) -> Result<ReceiptResponse, EnclaveError> {
    let _persist_guard = state.persistence_lock.lock().await;
    issue_client_receipt_locked(state, client).await
}

pub(crate) async fn issue_client_receipt_locked(
    state: &Arc<AppState>,
    client: Pubkey,
) -> Result<ReceiptResponse, EnclaveError> {
    let recipient_ata = get_associated_token_address(&client, &state.vault.usdc_mint);
    let balance = state
        .vault
        .client_balances
        .get(&client)
        .ok_or(EnclaveError::ClientNotFound)?;
    let free_balance = balance.free;
    let locked_balance = balance.locked;
    let max_lock_expires_at = balance.max_lock_expires_at;
    drop(balance);

    issue_participant_receipt_locked(
        state,
        client,
        PARTICIPANT_KIND_CLIENT,
        recipient_ata,
        free_balance,
        locked_balance,
        max_lock_expires_at,
    )
    .await
}

pub(crate) async fn issue_provider_receipt(
    state: &Arc<AppState>,
    provider_id: &str,
) -> Result<ReceiptResponse, EnclaveError> {
    let _persist_guard = state.persistence_lock.lock().await;
    issue_provider_receipt_locked(state, provider_id).await
}

pub(crate) async fn issue_provider_receipt_locked(
    state: &Arc<AppState>,
    provider_id: &str,
) -> Result<ReceiptResponse, EnclaveError> {
    let provider = state
        .vault
        .providers
        .get(provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;
    let participant = provider
        .participant_pubkey
        .unwrap_or(provider.settlement_token_account);
    let recipient_ata = provider.settlement_token_account;
    drop(provider);

    let free_balance = state
        .vault
        .provider_credits
        .get(provider_id)
        .map(|credit| credit.credited_amount)
        .unwrap_or(0);

    issue_participant_receipt_locked(
        state,
        participant,
        PARTICIPANT_KIND_PROVIDER,
        recipient_ata,
        free_balance,
        0,
        0,
    )
    .await
}

async fn issue_participant_receipt(
    state: &Arc<AppState>,
    participant: Pubkey,
    participant_kind: u8,
    recipient_ata: Pubkey,
    free_balance: u64,
    locked_balance: u64,
    max_lock_expires_at: i64,
) -> Result<ReceiptResponse, EnclaveError> {
    let _persist_guard = state.persistence_lock.lock().await;
    issue_participant_receipt_locked(
        state,
        participant,
        participant_kind,
        recipient_ata,
        free_balance,
        locked_balance,
        max_lock_expires_at,
    )
    .await
}

async fn issue_participant_receipt_locked(
    state: &Arc<AppState>,
    participant: Pubkey,
    participant_kind: u8,
    recipient_ata: Pubkey,
    free_balance: u64,
    locked_balance: u64,
    max_lock_expires_at: i64,
) -> Result<ReceiptResponse, EnclaveError> {
    let nonce = state.vault.next_receipt_nonce();
    let timestamp = Utc::now().timestamp();
    let snapshot_seqno = state
        .vault
        .snapshot_seqno
        .load(std::sync::atomic::Ordering::SeqCst);
    let receipt_message = state.vault.build_participant_receipt_message(
        &participant,
        participant_kind,
        &recipient_ata,
        free_balance,
        locked_balance,
        max_lock_expires_at,
        nonce,
        timestamp,
        snapshot_seqno,
    );
    let signature = state.vault.sign_message(&receipt_message);

    let receipt = ReceiptResponse {
        ok: true,
        participant: participant.to_string(),
        participant_kind,
        recipient_ata: recipient_ata.to_string(),
        free_balance,
        locked_balance,
        max_lock_expires_at,
        nonce,
        timestamp,
        snapshot_seqno,
        vault_config: state.vault.vault_config.to_string(),
        signature: BASE64.encode(signature),
        message: BASE64.encode(receipt_message),
    };

    state
        .wal
        .append(WalEntry::ParticipantReceiptIssued {
            participant: receipt.participant.clone(),
            participant_kind,
            nonce,
        })
        .await
        .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

    replicate_receipt_to_watchtower(state, &receipt).await?;

    state
        .wal
        .append(WalEntry::ParticipantReceiptMirrored {
            participant: receipt.participant.clone(),
            participant_kind,
            nonce,
        })
        .await
        .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

    info!(
        participant = %receipt.participant,
        participant_kind,
        nonce = receipt.nonce,
        "ParticipantReceipt issued"
    );

    Ok(receipt)
}

async fn replicate_receipt_to_watchtower(
    state: &Arc<AppState>,
    receipt: &ReceiptResponse,
) -> Result<(), EnclaveError> {
    let Some(watchtower_url) = state.watchtower_url.as_ref() else {
        if cfg!(test) {
            return Ok(());
        }
        return Err(EnclaveError::ReceiptWatchtowerUnavailable);
    };
    let url = format!("{watchtower_url}/v1/receipt/store");
    let response = state
        .outbound
        .post_json(&url, receipt)
        .await
        .map_err(|e| EnclaveError::Internal(format!("Watchtower replication failed: {e}")))?;

    if !response.status.is_success() {
        return Err(EnclaveError::Internal(format!(
            "Watchtower replication failed with status {}",
            response.status
        )));
    }

    let body = serde_json::from_slice::<WatchtowerStoreReceiptResponse>(&response.body)
        .map_err(|e| EnclaveError::Internal(format!("Watchtower response decode failed: {e}")))?;

    if !body.ok || body.current_nonce != receipt.nonce {
        return Err(EnclaveError::Internal(format!(
            "Watchtower rejected receipt nonce {} (stored={}, current_nonce={})",
            receipt.nonce, body.stored, body.current_nonce
        )));
    }

    Ok(())
}

// ── Provider Registration ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterProviderRequest {
    pub provider_id: String,
    pub display_name: String,
    pub participant_pubkey: Option<String>,
    #[serde(default)]
    pub participant_attestation:
        Option<crate::provider_attestation::ProviderParticipantAttestationRequest>,
    pub settlement_token_account: String,
    pub network: String,
    pub asset_mint: String,
    pub allowed_origins: Vec<String>,
    pub auth_mode: String,
    #[serde(default)]
    pub api_key_hash: String,
    #[serde(default)]
    pub mtls_cert_fingerprint: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterProviderResponse {
    pub ok: bool,
    pub provider_id: String,
    pub registered_at: String,
}

pub async fn post_register_provider(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterProviderRequest>,
) -> Result<Json<RegisterProviderResponse>, EnclaveError> {
    let settlement_token_account = Pubkey::from_str(&req.settlement_token_account)
        .map_err(|_| EnclaveError::Internal("Invalid settlement token account".into()))?;
    let participant_pubkey = req
        .participant_pubkey
        .as_deref()
        .map(|value| Pubkey::from_str(value).map_err(|_| EnclaveError::InvalidProviderParticipant))
        .transpose()?;
    let participant_attestation = match participant_pubkey {
        Some(participant_pubkey) => {
            let attestation = req
                .participant_attestation
                .as_ref()
                .ok_or(EnclaveError::ProviderParticipantAttestationRequired)?;
            Some(
                crate::provider_attestation::verify_provider_participant_attestation(
                    attestation,
                    &req.provider_id,
                    &participant_pubkey,
                )
                .map_err(EnclaveError::InvalidProviderParticipantAttestation)?,
            )
        }
        None => None,
    };
    let asset_mint = Pubkey::from_str(&req.asset_mint)
        .map_err(|_| EnclaveError::Internal("Invalid asset mint".into()))?;

    let (api_key_hash, mtls_cert_fingerprint) = match req.auth_mode.as_str() {
        "bearer" | "api-key" => {
            let api_key_hash = hex::decode(&req.api_key_hash)
                .map_err(|_| EnclaveError::InvalidProviderAuthConfig)?;
            if api_key_hash.len() != 32 {
                return Err(EnclaveError::InvalidProviderAuthConfig);
            }
            (Some(api_key_hash), None)
        }
        "mtls" => {
            if !state.provider_mtls_enabled {
                return Err(EnclaveError::MtlsNotEnabled);
            }
            let fingerprint_hex = req
                .mtls_cert_fingerprint
                .as_deref()
                .ok_or(EnclaveError::InvalidProviderAuthConfig)?;
            let fingerprint = hex::decode(fingerprint_hex)
                .map_err(|_| EnclaveError::InvalidProviderAuthConfig)?;
            if fingerprint.len() != 32 {
                return Err(EnclaveError::InvalidProviderAuthConfig);
            }
            (None, Some(fingerprint))
        }
        "none" => {
            if participant_pubkey.is_some() {
                return Err(EnclaveError::InvalidProviderAuthConfig);
            }
            (None, None)
        }
        _ => return Err(EnclaveError::UnsupportedProviderAuthMode),
    };

    let registration = crate::state::ProviderRegistration {
        provider_id: req.provider_id.clone(),
        display_name: req.display_name.clone(),
        participant_pubkey,
        participant_attestation_policy_hash: participant_attestation.as_ref().map(|attestation| {
            hex::decode(&attestation.policy_hash_hex)
                .expect("verified provider attestation policy hash must be hex")
                .try_into()
                .expect("verified provider attestation policy hash must be 32 bytes")
        }),
        participant_attestation_verified_at_ms: participant_attestation
            .as_ref()
            .map(|attestation| attestation.verified_at_ms),
        participant_attestation_mode: participant_attestation
            .as_ref()
            .map(|attestation| attestation.mode.as_str().to_string()),
        settlement_token_account,
        network: req.network.clone(),
        asset_mint,
        allowed_origins: req.allowed_origins.clone(),
        auth_mode: req.auth_mode.clone(),
        api_key_hash,
        mtls_cert_fingerprint,
    };

    {
        let _persist_guard = state.persistence_lock.lock().await;
        if state.vault.providers.contains_key(&req.provider_id) {
            return Err(EnclaveError::ProviderAlreadyRegistered);
        }
        state
            .wal
            .append(WalEntry::ProviderRegistered {
                provider_id: req.provider_id.clone(),
                display_name: req.display_name.clone(),
                participant_pubkey: req.participant_pubkey.clone(),
                participant_attestation_policy_hash: participant_attestation
                    .as_ref()
                    .map(|attestation| attestation.policy_hash_hex.clone()),
                participant_attestation_verified_at_ms: participant_attestation
                    .as_ref()
                    .map(|attestation| attestation.verified_at_ms),
                participant_attestation_mode: participant_attestation
                    .as_ref()
                    .map(|attestation| attestation.mode.as_str().to_string()),
                settlement_token_account: req.settlement_token_account.clone(),
                network: req.network.clone(),
                asset_mint: req.asset_mint.clone(),
                allowed_origins: req.allowed_origins.clone(),
                auth_mode: req.auth_mode.clone(),
                api_key_hash: if req.api_key_hash.is_empty() {
                    None
                } else {
                    Some(req.api_key_hash.clone())
                },
                mtls_cert_fingerprint: req.mtls_cert_fingerprint.clone(),
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

        state
            .vault
            .providers
            .insert(req.provider_id.clone(), registration);
    }

    let now = Utc::now().to_rfc3339();
    info!(provider_id = %req.provider_id, "Provider registered");

    Ok(Json(RegisterProviderResponse {
        ok: true,
        provider_id: req.provider_id,
        registered_at: now,
    }))
}

// ── Admin (local dev / tests) ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedBalanceRequest {
    pub client: String,
    pub free: u64,
    pub locked: Option<u64>,
    pub max_lock_expires_at: Option<i64>,
    pub total_deposited: Option<u64>,
    pub total_withdrawn: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedBalanceResponse {
    pub ok: bool,
    pub client: String,
    pub free: u64,
    pub locked: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetArciumModeRequest {
    pub mode: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetArciumModeResponse {
    pub ok: bool,
    pub mode: String,
}

pub async fn post_set_arcium_mode(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetArciumModeRequest>,
) -> Result<Json<SetArciumModeResponse>, EnclaveError> {
    let mode = ArciumAuthorityMode::from_env_value(Some(&req.mode))?;
    {
        let _persist_guard = state.persistence_lock.lock().await;
        state
            .wal
            .append(WalEntry::ArciumModeSet {
                mode: mode.as_str().to_string(),
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;
        state.vault.set_arcium_mode(mode);
    }

    Ok(Json(SetArciumModeResponse {
        ok: true,
        mode: mode.as_str().to_string(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadArciumBudgetGrantRequest {
    pub grant_id: String,
    pub client: String,
    pub budget_id: u64,
    pub request_nonce: u64,
    pub remaining: u64,
    pub expires_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadArciumBudgetGrantResponse {
    pub ok: bool,
    pub grant_id: String,
    pub remaining: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadEncryptedArciumBudgetGrantRequest {
    pub grant_id: String,
    pub vault_config: String,
    pub client: String,
    pub budget_id: u64,
    pub request_nonce: u64,
    pub expires_at: i64,
    pub state_version_at_authorization: u64,
    pub domain_hash_lo: u128,
    pub domain_hash_hi: u128,
    pub tee_x25519_pubkey: [u8; 32],
    pub mxe_public_key: [u8; 32],
    pub grant_ciphertexts: Vec<[u8; 32]>,
    pub grant_nonce: [u8; 16],
}

async fn load_arcium_budget_grant_locked(
    state: Arc<AppState>,
    grant: ArciumBudgetGrant,
) -> Result<Json<LoadArciumBudgetGrantResponse>, EnclaveError> {
    let grant_id = grant.grant_id.clone();
    let applied_remaining;
    {
        let _persist_guard = state.persistence_lock.lock().await;
        state.vault.validate_arcium_budget_grant_reload(&grant)?;
        state
            .wal
            .append(WalEntry::ArciumBudgetGrantLoaded {
                grant_id: grant.grant_id.clone(),
                client: grant.client.to_string(),
                budget_id: grant.budget_id,
                request_nonce: grant.request_nonce,
                remaining: grant.remaining,
                expires_at: grant.expires_at,
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;
        applied_remaining = state.vault.load_arcium_budget_grant(grant)?;
    }

    Ok(Json(LoadArciumBudgetGrantResponse {
        ok: true,
        grant_id,
        remaining: applied_remaining,
    }))
}

pub async fn post_load_arcium_budget_grant(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoadArciumBudgetGrantRequest>,
) -> Result<Json<LoadArciumBudgetGrantResponse>, EnclaveError> {
    reject_plaintext_arcium_grant_load_in_enforced_mode(&state)?;
    let client = Pubkey::from_str(&req.client).map_err(|_| EnclaveError::ClientNotFound)?;
    load_arcium_budget_grant_locked(
        state,
        ArciumBudgetGrant {
            grant_id: req.grant_id,
            client,
            budget_id: req.budget_id,
            request_nonce: req.request_nonce,
            remaining: req.remaining,
            expires_at: req.expires_at,
        },
    )
    .await
}

pub async fn post_load_encrypted_arcium_budget_grant(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoadEncryptedArciumBudgetGrantRequest>,
) -> Result<Json<LoadArciumBudgetGrantResponse>, EnclaveError> {
    let decryptor = state
        .arcium_grant_decryptor
        .as_ref()
        .ok_or_else(|| EnclaveError::Internal("Arcium grant decryptor is not configured".into()))?;
    let grant_pubkey = Pubkey::from_str(&req.grant_id)
        .map_err(|_| EnclaveError::Internal("Invalid Arcium budget grant pubkey".into()))?;
    let vault_config = Pubkey::from_str(&req.vault_config)
        .map_err(|_| EnclaveError::Internal("Invalid Arcium vault config pubkey".into()))?;
    if vault_config != state.vault.vault_config {
        return Err(EnclaveError::VaultNotActive);
    }
    require_arcium_mxe_public_key(&state, req.mxe_public_key)?;
    let expected_domain_hash = require_arcium_budget_domain_hash(&state)?;
    let client = Pubkey::from_str(&req.client).map_err(|_| EnclaveError::ClientNotFound)?;
    let expires_at_u64 = u64::try_from(req.expires_at)
        .map_err(|_| EnclaveError::Internal("Arcium budget grant expiresAt is negative".into()))?;
    require_equal(
        "requestDomainHashLo",
        req.domain_hash_lo,
        expected_domain_hash.lo,
    )?;
    require_equal(
        "requestDomainHashHi",
        req.domain_hash_hi,
        expected_domain_hash.hi,
    )?;
    let view = decryptor
        .decrypt_budget_grant_view(
            req.tee_x25519_pubkey,
            req.mxe_public_key,
            &req.grant_ciphertexts,
            req.grant_nonce,
        )
        .map_err(|error| {
            EnclaveError::Internal(format!("Arcium budget grant decrypt failed: {error}"))
        })?;
    if !view.approved {
        return Err(EnclaveError::InsufficientArciumBudget);
    }
    require_equal("budgetId", view.budget_id, req.budget_id)?;
    require_equal("requestNonce", view.request_nonce, req.request_nonce)?;
    require_equal("expiresAt", view.expires_at, expires_at_u64)?;
    require_equal(
        "stateVersion",
        view.state_version,
        req.state_version_at_authorization,
    )?;
    require_equal("domainHashLo", view.domain_hash_lo, expected_domain_hash.lo)?;
    require_equal("domainHashHi", view.domain_hash_hi, expected_domain_hash.hi)?;
    require_pubkey_split(
        "vaultConfig",
        view.vault_config_lo,
        view.vault_config_hi,
        &vault_config,
    )?;
    require_pubkey_split("client", view.client_lo, view.client_hi, &client)?;
    require_pubkey_split(
        "budgetGrant",
        view.budget_grant_lo,
        view.budget_grant_hi,
        &grant_pubkey,
    )?;

    load_arcium_budget_grant_locked(
        state,
        ArciumBudgetGrant {
            grant_id: req.grant_id,
            client,
            budget_id: view.budget_id,
            request_nonce: view.request_nonce,
            remaining: view.remaining,
            expires_at: req.expires_at,
        },
    )
    .await
}

fn require_equal<T>(field: &str, actual: T, expected: T) -> Result<(), EnclaveError>
where
    T: Eq + std::fmt::Display,
{
    if actual != expected {
        return Err(EnclaveError::Internal(format!(
            "Arcium {field} mismatch: actual={actual} expected={expected}"
        )));
    }
    Ok(())
}

fn split_pubkey_u128(pubkey: &Pubkey) -> (u128, u128) {
    let bytes = pubkey.to_bytes();
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&bytes[..16]);
    hi.copy_from_slice(&bytes[16..]);
    (u128::from_le_bytes(lo), u128::from_le_bytes(hi))
}

fn require_pubkey_split(
    field: &str,
    actual_lo: u128,
    actual_hi: u128,
    expected: &Pubkey,
) -> Result<(), EnclaveError> {
    let (expected_lo, expected_hi) = split_pubkey_u128(expected);
    if actual_lo != expected_lo || actual_hi != expected_hi {
        return Err(EnclaveError::Internal(format!(
            "Arcium {field} split does not match decrypted grant"
        )));
    }
    Ok(())
}

fn require_arcium_mxe_public_key(
    state: &Arc<AppState>,
    actual: [u8; 32],
) -> Result<(), EnclaveError> {
    let expected = state
        .arcium_mxe_public_key
        .ok_or_else(|| EnclaveError::Internal("Arcium MXE public key is not configured".into()))?;
    if actual != expected {
        return Err(EnclaveError::Internal(
            "Arcium MXE public key mismatch".into(),
        ));
    }
    Ok(())
}

fn require_arcium_budget_domain_hash(
    state: &Arc<AppState>,
) -> Result<crate::arcium::ArciumDomainHashParts, EnclaveError> {
    let hashes = state.arcium_domain_hashes.ok_or_else(|| {
        EnclaveError::Internal("Arcium grant domain hashes are not configured".into())
    })?;
    Ok(hashes.authorize_budget)
}

fn require_arcium_withdrawal_domain_hash(
    state: &Arc<AppState>,
) -> Result<crate::arcium::ArciumDomainHashParts, EnclaveError> {
    let hashes = state.arcium_domain_hashes.ok_or_else(|| {
        EnclaveError::Internal("Arcium grant domain hashes are not configured".into())
    })?;
    Ok(hashes.authorize_withdrawal)
}

fn reject_plaintext_arcium_grant_load_in_enforced_mode(
    state: &Arc<AppState>,
) -> Result<(), EnclaveError> {
    if state.vault.arcium_enforced() {
        return Err(EnclaveError::Internal(
            "Plaintext Arcium grant loading is disabled in enforced mode".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadArciumWithdrawalGrantRequest {
    pub grant_id: String,
    pub client: String,
    pub withdrawal_id: u64,
    pub recipient_ata: String,
    pub amount: u64,
    pub expires_at: i64,
    #[serde(default)]
    pub consumed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadArciumWithdrawalGrantResponse {
    pub ok: bool,
    pub grant_id: String,
    pub amount: u64,
    pub consumed: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadEncryptedArciumWithdrawalGrantRequest {
    pub grant_id: String,
    pub vault_config: String,
    pub client: String,
    pub withdrawal_id: u64,
    pub recipient_ata: String,
    pub expires_at: i64,
    pub state_version_at_authorization: u64,
    pub domain_hash_lo: u128,
    pub domain_hash_hi: u128,
    pub tee_x25519_pubkey: [u8; 32],
    pub mxe_public_key: [u8; 32],
    pub grant_ciphertexts: Vec<[u8; 32]>,
    pub grant_nonce: [u8; 16],
    #[serde(default)]
    pub consumed: bool,
}

async fn load_arcium_withdrawal_grant_locked(
    state: Arc<AppState>,
    grant: ArciumWithdrawalGrant,
) -> Result<Json<LoadArciumWithdrawalGrantResponse>, EnclaveError> {
    if grant.amount == 0 {
        return Err(EnclaveError::InsufficientArciumWithdrawalGrant);
    }
    let grant_id = grant.grant_id.clone();
    let amount = grant.amount;
    let applied_consumed;
    {
        let _persist_guard = state.persistence_lock.lock().await;
        state
            .vault
            .validate_arcium_withdrawal_grant_reload(&grant)?;
        state
            .wal
            .append(WalEntry::ArciumWithdrawalGrantLoaded {
                grant_id: grant.grant_id.clone(),
                client: grant.client.to_string(),
                withdrawal_id: grant.withdrawal_id,
                recipient_ata: grant.recipient_ata.to_string(),
                amount: grant.amount,
                expires_at: grant.expires_at,
                consumed: grant.consumed,
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;
        applied_consumed = state.vault.load_arcium_withdrawal_grant(grant)?;
    }

    Ok(Json(LoadArciumWithdrawalGrantResponse {
        ok: true,
        grant_id,
        amount,
        consumed: applied_consumed,
    }))
}

pub async fn post_load_arcium_withdrawal_grant(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoadArciumWithdrawalGrantRequest>,
) -> Result<Json<LoadArciumWithdrawalGrantResponse>, EnclaveError> {
    reject_plaintext_arcium_grant_load_in_enforced_mode(&state)?;
    let client = Pubkey::from_str(&req.client).map_err(|_| EnclaveError::ClientNotFound)?;
    let recipient_ata = Pubkey::from_str(&req.recipient_ata)
        .map_err(|_| EnclaveError::Internal("Invalid recipient ATA".into()))?;
    load_arcium_withdrawal_grant_locked(
        state,
        ArciumWithdrawalGrant {
            grant_id: req.grant_id,
            client,
            withdrawal_id: req.withdrawal_id,
            recipient_ata,
            amount: req.amount,
            expires_at: req.expires_at,
            consumed: req.consumed,
        },
    )
    .await
}

pub async fn post_load_encrypted_arcium_withdrawal_grant(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoadEncryptedArciumWithdrawalGrantRequest>,
) -> Result<Json<LoadArciumWithdrawalGrantResponse>, EnclaveError> {
    let decryptor = state
        .arcium_grant_decryptor
        .as_ref()
        .ok_or_else(|| EnclaveError::Internal("Arcium grant decryptor is not configured".into()))?;
    let grant_pubkey = Pubkey::from_str(&req.grant_id)
        .map_err(|_| EnclaveError::Internal("Invalid Arcium withdrawal grant pubkey".into()))?;
    let vault_config = Pubkey::from_str(&req.vault_config)
        .map_err(|_| EnclaveError::Internal("Invalid Arcium vault config pubkey".into()))?;
    if vault_config != state.vault.vault_config {
        return Err(EnclaveError::VaultNotActive);
    }
    require_arcium_mxe_public_key(&state, req.mxe_public_key)?;
    let expected_domain_hash = require_arcium_withdrawal_domain_hash(&state)?;
    let client = Pubkey::from_str(&req.client).map_err(|_| EnclaveError::ClientNotFound)?;
    let recipient_ata = Pubkey::from_str(&req.recipient_ata)
        .map_err(|_| EnclaveError::Internal("Invalid recipient ATA".into()))?;
    let expires_at_u64 = u64::try_from(req.expires_at).map_err(|_| {
        EnclaveError::Internal("Arcium withdrawal grant expiresAt is negative".into())
    })?;
    require_equal(
        "requestDomainHashLo",
        req.domain_hash_lo,
        expected_domain_hash.lo,
    )?;
    require_equal(
        "requestDomainHashHi",
        req.domain_hash_hi,
        expected_domain_hash.hi,
    )?;
    let view = decryptor
        .decrypt_withdrawal_grant_view(
            req.tee_x25519_pubkey,
            req.mxe_public_key,
            &req.grant_ciphertexts,
            req.grant_nonce,
        )
        .map_err(|error| {
            EnclaveError::Internal(format!("Arcium withdrawal grant decrypt failed: {error}"))
        })?;
    if !view.approved {
        return Err(EnclaveError::InsufficientArciumWithdrawalGrant);
    }
    require_equal("withdrawalId", view.withdrawal_id, req.withdrawal_id)?;
    require_equal("expiresAt", view.expires_at, expires_at_u64)?;
    require_equal(
        "stateVersion",
        view.state_version,
        req.state_version_at_authorization,
    )?;
    require_equal("domainHashLo", view.domain_hash_lo, expected_domain_hash.lo)?;
    require_equal("domainHashHi", view.domain_hash_hi, expected_domain_hash.hi)?;
    require_pubkey_split(
        "vaultConfig",
        view.vault_config_lo,
        view.vault_config_hi,
        &vault_config,
    )?;
    require_pubkey_split("client", view.client_lo, view.client_hi, &client)?;
    require_pubkey_split(
        "withdrawalGrant",
        view.withdrawal_grant_lo,
        view.withdrawal_grant_hi,
        &grant_pubkey,
    )?;
    require_pubkey_split(
        "recipientAta",
        view.recipient_lo,
        view.recipient_hi,
        &recipient_ata,
    )?;

    load_arcium_withdrawal_grant_locked(
        state,
        ArciumWithdrawalGrant {
            grant_id: req.grant_id,
            client,
            withdrawal_id: view.withdrawal_id,
            recipient_ata,
            amount: view.amount,
            expires_at: req.expires_at,
            consumed: req.consumed,
        },
    )
    .await
}

pub async fn post_seed_balance(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SeedBalanceRequest>,
) -> Result<Json<SeedBalanceResponse>, EnclaveError> {
    let client = Pubkey::from_str(&req.client).map_err(|_| EnclaveError::ClientNotFound)?;
    let locked = req.locked.unwrap_or(0);
    let max_lock_expires_at = req.max_lock_expires_at.unwrap_or(0);
    let total_deposited = req
        .total_deposited
        .unwrap_or(req.free.saturating_add(locked));
    let total_withdrawn = req.total_withdrawn.unwrap_or(0);

    {
        let _persist_guard = state.persistence_lock.lock().await;
        state
            .wal
            .append(WalEntry::ClientBalanceSeeded {
                client: req.client.clone(),
                free: req.free,
                locked,
                max_lock_expires_at,
                total_deposited,
                total_withdrawn,
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

        state.vault.client_balances.insert(
            client,
            crate::state::ClientBalance {
                free: req.free,
                locked,
                max_lock_expires_at,
                total_deposited,
                total_withdrawn,
            },
        );
        issue_client_receipt_locked(&state, client).await?;
    }

    info!(client = %req.client, free = req.free, locked, "Seeded client balance for local dev");

    Ok(Json(SeedBalanceResponse {
        ok: true,
        client: req.client,
        free: req.free,
        locked,
    }))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FireBatchRequest {
    #[serde(default)]
    pub privacy_bypass: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FireBatchResponse {
    pub ok: bool,
    pub submitted: bool,
    pub batch_id: Option<u64>,
    pub provider_count: usize,
    pub settlement_count: usize,
    pub total_amount: u64,
    pub tx_signatures: Vec<String>,
}

pub async fn post_fire_batch(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FireBatchRequest>,
) -> Result<Json<FireBatchResponse>, EnclaveError> {
    info!(
        privacy_bypass = req.privacy_bypass,
        "Admin fire-batch requested"
    );

    if req.privacy_bypass && !admin_privacy_bypass_enabled() {
        return Err(EnclaveError::AdminPrivacyBypassDisabled);
    }

    let batch_future: futures_util::future::BoxFuture<
        '_,
        Result<batch::BatchSubmitResult, String>,
    > = if req.privacy_bypass {
        Box::pin(batch::fire_batch_privacy_bypass_now(&state))
    } else {
        Box::pin(batch::fire_ready_batch_now(&state))
    };

    let result = AssertUnwindSafe(batch_future)
        .catch_unwind()
        .await
        .map_err(|panic| {
            let message = panic_payload_message(panic.as_ref());
            error!(%message, "Admin fire-batch panicked");
            EnclaveError::Internal(format!("fire_batch panicked: {message}"))
        })?
        .map_err(|error| EnclaveError::Internal(format!("fire_batch failed: {error}")))?;

    info!(
        submitted = result.submitted,
        batch_id = ?result.batch_id,
        provider_count = result.provider_count,
        settlement_count = result.settlement_count,
        total_amount = result.total_amount,
        tx_signature_count = result.tx_signatures.len(),
        "Admin fire-batch completed"
    );

    Ok(Json(FireBatchResponse {
        ok: true,
        submitted: result.submitted,
        batch_id: result.batch_id,
        provider_count: result.provider_count,
        settlement_count: result.settlement_count,
        total_amount: result.total_amount,
        tx_signatures: result.tx_signatures,
    }))
}

// ── Helper functions ──

fn admin_privacy_bypass_enabled() -> bool {
    matches!(
        env::var("SUBLY402_ALLOW_ADMIN_PRIVACY_BYPASS_BATCH")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "unknown panic payload".to_string()
}

fn compute_request_hash(ctx: &RequestContext, payment_details_hash: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"SUBLY402-SVM-V1-REQ\n");
    hasher.update(ctx.method.as_bytes());
    hasher.update(b"\n");
    hasher.update(ctx.origin.as_bytes());
    hasher.update(b"\n");
    hasher.update(ctx.path_and_query.as_bytes());
    hasher.update(b"\n");
    hasher.update(ctx.body_sha256.as_bytes());
    hasher.update(b"\n");
    hasher.update(payment_details_hash.as_bytes());
    hasher.update(b"\n");
    hasher.finalize().to_vec()
}

fn build_balance_auth_message(client: &str, issued_at: i64, expires_at: i64) -> String {
    format!("SUBLY402-CLIENT-BALANCE\n{client}\n{issued_at}\n{expires_at}\n")
}

fn build_receipt_auth_message(
    client: &str,
    recipient_ata: &str,
    issued_at: i64,
    expires_at: i64,
) -> String {
    format!("SUBLY402-CLIENT-RECEIPT\n{client}\n{recipient_ata}\n{issued_at}\n{expires_at}\n")
}

fn build_withdraw_auth_message(
    client: &str,
    recipient_ata: &str,
    amount: u64,
    issued_at: i64,
    expires_at: i64,
) -> String {
    format!(
        "SUBLY402-CLIENT-WITHDRAW-AUTH\n{client}\n{recipient_ata}\n{amount}\n{issued_at}\n{expires_at}\n"
    )
}

fn verify_client_request_auth(
    client: &str,
    message: &str,
    auth: &ClientRequestAuth,
) -> Result<Pubkey, EnclaveError> {
    validate_client_auth_window(auth.issued_at, auth.expires_at)?;
    let client_pubkey =
        Pubkey::from_str(client).map_err(|_| EnclaveError::InvalidClientSignature)?;
    verify_ed25519_signature(&client_pubkey, message.as_bytes(), &auth.client_sig)?;
    Ok(client_pubkey)
}

fn validate_client_auth_window(issued_at: i64, expires_at: i64) -> Result<(), EnclaveError> {
    let now = Utc::now().timestamp();
    if expires_at <= now {
        return Err(EnclaveError::ClientAuthExpired);
    }
    if expires_at <= issued_at {
        return Err(EnclaveError::InvalidClientAuthWindow);
    }
    if issued_at > now + CLIENT_AUTH_MAX_CLOCK_SKEW_SEC {
        return Err(EnclaveError::InvalidClientAuthWindow);
    }
    if issued_at < now - CLIENT_AUTH_MAX_WINDOW_SEC {
        return Err(EnclaveError::InvalidClientAuthWindow);
    }
    if expires_at - issued_at > CLIENT_AUTH_MAX_WINDOW_SEC {
        return Err(EnclaveError::InvalidClientAuthWindow);
    }
    Ok(())
}

fn parse_verify_window_sec(payment_details: &serde_json::Value) -> Result<i64, EnclaveError> {
    let verify_window_sec = payment_details
        .get("verifyWindowSec")
        .and_then(|value| {
            value.as_i64().or_else(|| {
                value
                    .as_u64()
                    .and_then(|seconds| i64::try_from(seconds).ok())
            })
        })
        .ok_or(EnclaveError::VerifyWindowSecRequired)?;

    if verify_window_sec <= 0 {
        return Err(EnclaveError::InvalidVerifyWindowSec);
    }

    Ok(verify_window_sec)
}

pub(crate) async fn expire_reserved_reservation(
    state: &Arc<AppState>,
    verification_id: &str,
    now: i64,
) -> Result<bool, EnclaveError> {
    let _persist_guard = state.persistence_lock.lock().await;
    expire_reserved_reservation_with_lock(state, verification_id, now).await
}

pub(crate) async fn expire_reserved_reservation_with_lock(
    state: &Arc<AppState>,
    verification_id: &str,
    now: i64,
) -> Result<bool, EnclaveError> {
    let (client, amount, arcium_grant_id) = {
        let reservation = state
            .vault
            .reservations
            .get(verification_id)
            .ok_or(EnclaveError::ReservationNotFound)?;
        if reservation.status != ReservationStatus::Reserved || now <= reservation.expires_at {
            return Ok(false);
        }
        (
            reservation.client,
            reservation.amount,
            reservation.arcium_grant_id.clone(),
        )
    };

    state
        .wal
        .append(WalEntry::ReservationExpired {
            verification_id: verification_id.to_string(),
        })
        .await
        .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

    {
        let mut reservation = state
            .vault
            .reservations
            .get_mut(verification_id)
            .ok_or(EnclaveError::ReservationNotFound)?;
        if reservation.status != ReservationStatus::Reserved {
            return Ok(false);
        }
        reservation.status = ReservationStatus::Expired;
    }

    if let Some(grant_id) = arcium_grant_id {
        state.vault.release_arcium_budget(&grant_id, amount)?;
    } else {
        state.vault.release_balance(&client, amount)?;
        state.vault.refresh_client_max_lock_expires_at(&client)?;
        issue_client_receipt_locked(state, client).await?;
    }
    info!(verification_id = %verification_id, "Reservation expired, balance released");

    Ok(true)
}

pub(crate) async fn expire_pending_withdrawal(
    state: &Arc<AppState>,
    withdraw_nonce: u64,
    now: i64,
) -> Result<bool, EnclaveError> {
    let _persist_guard = state.persistence_lock.lock().await;
    let Some(withdrawal) = state
        .vault
        .pending_withdrawals
        .get(&withdraw_nonce)
        .map(|entry| entry.clone())
    else {
        return Ok(false);
    };
    if now <= withdrawal.expires_at {
        return Ok(false);
    }

    state
        .wal
        .append(WalEntry::WithdrawExpired {
            client: withdrawal.client.to_string(),
            withdraw_nonce,
        })
        .await
        .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

    let expired = state.vault.expire_pending_withdrawal(withdraw_nonce)?;
    if expired.arcium_grant_id.is_none() {
        state
            .vault
            .refresh_client_max_lock_expires_at(&expired.client)?;
        issue_client_receipt_locked(state, expired.client).await?;
    }

    info!(
        client = %expired.client,
        amount = expired.amount,
        withdraw_nonce,
        "Pending withdrawal expired and balance released"
    );

    Ok(true)
}

async fn expire_stale_channel_request_with_lock(
    state: &Arc<AppState>,
    channel_id: &str,
    now: i64,
) -> Result<bool, EnclaveError> {
    let Some(outcome) = asc_manager::expire_request(&state.vault, channel_id, now)? else {
        return Ok(false);
    };
    let request_id = outcome.request.request_id.clone();
    let amount = outcome.request.amount;
    let client = outcome.client;

    if let Err(error) = state
        .wal
        .append(WalEntry::ChannelRequestExpired {
            channel_id: channel_id.to_string(),
            request_id: request_id.clone(),
            amount,
        })
        .await
    {
        let _ = asc_manager::rollback_expire_request(&state.vault, outcome);
        return Err(EnclaveError::Internal(format!(
            "WAL append failed: {error}"
        )));
    }

    state.vault.refresh_client_max_lock_expires_at(&client)?;
    issue_client_receipt_locked(state, client).await?;

    info!(
        %channel_id,
        %request_id,
        amount,
        "Channel request expired and balance released"
    );

    Ok(true)
}

pub(crate) async fn expire_stale_channel_request(
    state: &Arc<AppState>,
    channel_id: &str,
    now: i64,
) -> Result<bool, EnclaveError> {
    let _asc_guard = state.asc_ops_lock.lock().await;
    let _persist_guard = state.persistence_lock.lock().await;
    expire_stale_channel_request_with_lock(state, channel_id, now).await
}

fn verify_client_signature(payload: &PaymentPayload) -> Result<(), EnclaveError> {
    // Build signature message per spec
    let mut message = String::new();
    message.push_str("SUBLY402-SVM-V1-AUTH\n");
    message.push_str(&format!("{}\n", payload.version));
    message.push_str(&format!("{}\n", payload.scheme));
    message.push_str(&format!("{}\n", payload.payment_id));
    message.push_str(&format!("{}\n", payload.client));
    message.push_str(&format!("{}\n", payload.vault));
    message.push_str(&format!("{}\n", payload.provider_id));
    message.push_str(&format!("{}\n", payload.pay_to));
    message.push_str(&format!("{}\n", payload.network));
    message.push_str(&format!("{}\n", payload.asset_mint));
    message.push_str(&format!("{}\n", payload.amount));
    message.push_str(&format!("{}\n", payload.request_hash));
    message.push_str(&format!("{}\n", payload.payment_details_hash));
    message.push_str(&format!("{}\n", payload.expires_at));
    message.push_str(&format!("{}\n", payload.nonce));

    let client_pubkey =
        Pubkey::from_str(&payload.client).map_err(|_| EnclaveError::InvalidClientSignature)?;
    verify_ed25519_signature(&client_pubkey, message.as_bytes(), &payload.client_sig)
}

fn verify_channel_open_signature(req: &OpenChannelRequest) -> Result<(), EnclaveError> {
    let client_pubkey =
        Pubkey::from_str(&req.client).map_err(|_| EnclaveError::InvalidClientSignature)?;
    let message = build_channel_open_message(&req.client, &req.provider_id, req.initial_deposit);
    verify_ed25519_signature(&client_pubkey, message.as_bytes(), &req.client_sig)
}

fn verify_ed25519_signature(
    signer: &Pubkey,
    message: &[u8],
    signature_b64: &str,
) -> Result<(), EnclaveError> {
    let verifying_key = VerifyingKey::from_bytes(&signer.to_bytes())
        .map_err(|_| EnclaveError::InvalidClientSignature)?;

    let sig_bytes = BASE64
        .decode(signature_b64)
        .map_err(|_| EnclaveError::InvalidClientSignature)?;

    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| EnclaveError::InvalidClientSignature)?,
    );

    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| EnclaveError::InvalidClientSignature)?;

    Ok(())
}

fn verify_channel_client_signature(
    state: &AppState,
    channel_id: &str,
    message: &str,
    client_sig: &str,
) -> Result<(), EnclaveError> {
    let client = state
        .vault
        .active_channels
        .get(channel_id)
        .map(|channel| channel.client)
        .ok_or(EnclaveError::ChannelNotFound)?;

    verify_ed25519_signature(&client, message.as_bytes(), client_sig)
}

fn verify_channel_provider_auth(
    state: &AppState,
    channel_id: &str,
    headers: &HeaderMap,
) -> Result<(), EnclaveError> {
    let provider_id = state
        .vault
        .active_channels
        .get(channel_id)
        .map(|channel| channel.provider_id.clone())
        .ok_or(EnclaveError::ChannelNotFound)?;

    let provider = state
        .vault
        .providers
        .get(&provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;
    authenticate_registered_provider(provider.value(), headers)
}

fn registered_provider_participant_pubkey(
    state: &AppState,
    provider_id: &str,
) -> Result<[u8; 32], EnclaveError> {
    let provider = state
        .vault
        .providers
        .get(provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;
    provider
        .participant_pubkey
        .map(|pubkey| pubkey.to_bytes())
        .ok_or(EnclaveError::ProviderParticipantRequired)
}

fn registered_channel_provider_participant_pubkey(
    state: &AppState,
    channel_id: &str,
) -> Result<[u8; 32], EnclaveError> {
    let provider_id = state
        .vault
        .active_channels
        .get(channel_id)
        .map(|channel| channel.provider_id.clone())
        .ok_or(EnclaveError::ChannelNotFound)?;
    registered_provider_participant_pubkey(state, &provider_id)
}

fn build_channel_open_message(client: &str, provider_id: &str, initial_deposit: u64) -> String {
    format!(
        "SUBLY402-CHANNEL-OPEN\n{}\n{}\n{}\n",
        client, provider_id, initial_deposit
    )
}

fn build_channel_request_message(
    channel_id: &str,
    request_id: &str,
    amount: u64,
    request_hash: &str,
) -> String {
    format!(
        "SUBLY402-CHANNEL-REQUEST\n{}\n{}\n{}\n{}\n",
        channel_id, request_id, amount, request_hash
    )
}

fn build_channel_finalize_message(channel_id: &str, adaptor_secret: &str) -> String {
    format!(
        "SUBLY402-CHANNEL-FINALIZE\n{}\n{}\n",
        channel_id, adaptor_secret
    )
}

fn build_channel_close_message(channel_id: &str) -> String {
    format!("SUBLY402-CHANNEL-CLOSE\n{}\n", channel_id)
}

fn issue_asc_claim_voucher(
    state: &Arc<AppState>,
    channel_id: &str,
    request_id: &str,
    amount: u64,
    request_hash: [u8; 32],
    provider_pubkey: [u8; 32],
) -> AscClaimVoucherResponse {
    let issued_at = Utc::now().timestamp();
    let channel_id_hash = hash_identifier(channel_id);
    let request_id_hash = hash_identifier(request_id);
    let message = build_asc_claim_voucher_message(&AscClaimVoucherFields {
        channel_id_hash,
        request_id_hash,
        amount,
        request_hash,
        provider_pubkey,
        issued_at,
        vault_config: state.vault.vault_config.to_bytes(),
    });
    let signature = state.vault.sign_message(&message);

    AscClaimVoucherResponse {
        message: BASE64.encode(message),
        signature: BASE64.encode(signature),
        issued_at,
        channel_id_hash: hex::encode(channel_id_hash),
        request_id_hash: hex::encode(request_id_hash),
    }
}

// ── Phase 3: Atomic Service Channel Endpoints ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenChannelRequest {
    pub client: String,
    pub provider_id: String,
    pub initial_deposit: u64,
    /// Ed25519 signature over "SUBLY402-CHANNEL-OPEN\n{client}\n{provider_id}\n{initial_deposit}\n"
    pub client_sig: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenChannelResponse {
    pub ok: bool,
    pub channel_id: String,
    pub client_free: u64,
    pub client_locked: u64,
}

pub async fn post_channel_open(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OpenChannelRequest>,
) -> Result<Json<OpenChannelResponse>, EnclaveError> {
    ensure_vault_allows_new_verification(&state).await?;

    let _guard = state.asc_ops_lock.lock().await;
    let _persist_guard = state.persistence_lock.lock().await;
    let client = Pubkey::from_str(&req.client).map_err(|_| EnclaveError::ClientNotFound)?;

    // Verify client signature
    verify_channel_open_signature(&req)?;
    let _provider_participant = registered_provider_participant_pubkey(&state, &req.provider_id)?;

    let channel_id =
        asc_manager::open_channel(&state.vault, &client, &req.provider_id, req.initial_deposit)?;

    if let Err(error) = state
        .wal
        .append(WalEntry::ChannelOpened {
            channel_id: channel_id.clone(),
            client: req.client.clone(),
            provider_id: req.provider_id.clone(),
            initial_deposit: req.initial_deposit,
        })
        .await
    {
        let _ = asc_manager::rollback_open_channel(&state.vault, &channel_id);
        return Err(EnclaveError::Internal(format!(
            "WAL append failed: {error}"
        )));
    }
    issue_client_receipt_locked(&state, client).await?;

    Ok(Json(OpenChannelResponse {
        ok: true,
        channel_id,
        client_free: req.initial_deposit,
        client_locked: 0,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelRequestReq {
    pub channel_id: String,
    pub request_id: String,
    pub amount: u64,
    pub request_hash: String,
    pub client_sig: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelRequestResponse {
    pub ok: bool,
    pub channel_id: String,
    pub request_id: String,
    pub status: String,
}

pub async fn post_channel_request(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChannelRequestReq>,
) -> Result<Json<ChannelRequestResponse>, EnclaveError> {
    ensure_vault_allows_new_verification(&state).await?;

    let _guard = state.asc_ops_lock.lock().await;
    let _persist_guard = state.persistence_lock.lock().await;
    let message = build_channel_request_message(
        &req.channel_id,
        &req.request_id,
        req.amount,
        &req.request_hash,
    );
    verify_channel_client_signature(&state, &req.channel_id, &message, &req.client_sig)?;

    let request_hash: [u8; 32] = hex::decode(&req.request_hash)
        .map_err(|_| EnclaveError::RequestHashMismatch)?
        .try_into()
        .map_err(|_| EnclaveError::RequestHashMismatch)?;

    asc_manager::submit_request(
        &state.vault,
        &req.channel_id,
        &req.request_id,
        req.amount,
        request_hash,
    )?;

    if let Err(error) = state
        .wal
        .append(WalEntry::ChannelRequestSubmitted {
            channel_id: req.channel_id.clone(),
            request_id: req.request_id.clone(),
            amount: req.amount,
            request_hash: Some(req.request_hash.clone()),
        })
        .await
    {
        let _ =
            asc_manager::rollback_submit_request(&state.vault, &req.channel_id, &req.request_id);
        return Err(EnclaveError::Internal(format!(
            "WAL append failed: {error}"
        )));
    }
    let client = state
        .vault
        .active_channels
        .get(&req.channel_id)
        .map(|channel| channel.client)
        .ok_or(EnclaveError::ChannelNotFound)?;
    state.vault.refresh_client_max_lock_expires_at(&client)?;
    issue_client_receipt_locked(&state, client).await?;

    Ok(Json(ChannelRequestResponse {
        ok: true,
        channel_id: req.channel_id,
        request_id: req.request_id,
        status: "locked".to_string(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelDeliverRequest {
    pub channel_id: String,
    pub adaptor_point: String,
    pub pre_sig_r_prime: String,
    pub pre_sig_s_prime: String,
    pub encrypted_result: String,
    pub result_hash: String,
    pub provider_pubkey: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelDeliverResponse {
    pub ok: bool,
    pub channel_id: String,
    pub status: String,
    pub claim_voucher: AscClaimVoucherResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AscClaimVoucherResponse {
    pub message: String,
    pub signature: String,
    pub issued_at: i64,
    pub channel_id_hash: String,
    pub request_id_hash: String,
}

pub async fn post_channel_deliver(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ChannelDeliverRequest>,
) -> Result<Json<ChannelDeliverResponse>, EnclaveError> {
    ensure_vault_allows_existing_reservation_ops(&state).await?;

    let _guard = state.asc_ops_lock.lock().await;
    let _persist_guard = state.persistence_lock.lock().await;
    verify_channel_provider_auth(&state, &req.channel_id, &headers)?;

    let adaptor_point: [u8; 32] = hex::decode(&req.adaptor_point)
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?
        .try_into()
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?;

    let r_prime: [u8; 32] = hex::decode(&req.pre_sig_r_prime)
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?
        .try_into()
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?;

    let s_prime: [u8; 32] = hex::decode(&req.pre_sig_s_prime)
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?
        .try_into()
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?;

    let pre_sig = AdaptorPreSignature { r_prime, s_prime };

    let encrypted_result = BASE64
        .decode(&req.encrypted_result)
        .map_err(|_| EnclaveError::Internal("Invalid encrypted_result base64".into()))?;

    let result_hash: [u8; 32] = hex::decode(&req.result_hash)
        .map_err(|_| EnclaveError::Internal("Invalid result_hash hex".into()))?
        .try_into()
        .map_err(|_| EnclaveError::Internal("result_hash must be 32 bytes".into()))?;

    let provider_pubkey: [u8; 32] = hex::decode(&req.provider_pubkey)
        .map_err(|_| EnclaveError::Internal("Invalid provider_pubkey hex".into()))?
        .try_into()
        .map_err(|_| EnclaveError::Internal("provider_pubkey must be 32 bytes".into()))?;
    let registered_provider_pubkey =
        registered_channel_provider_participant_pubkey(&state, &req.channel_id)?;
    if provider_pubkey != registered_provider_pubkey {
        return Err(EnclaveError::ProviderParticipantMismatch);
    }

    let (request_id, request_amount, request_hash) = state
        .vault
        .active_channels
        .get(&req.channel_id)
        .and_then(|channel| channel.active_request.as_ref().cloned())
        .map(|request| (request.request_id, request.amount, request.request_hash))
        .ok_or(EnclaveError::ChannelNotFound)?;

    if let Err(error) = asc_manager::deliver_adaptor(
        &state.vault,
        &req.channel_id,
        adaptor_point,
        pre_sig,
        encrypted_result,
        result_hash,
        &registered_provider_pubkey,
    ) {
        if matches!(error, EnclaveError::ChannelRequestExpired) {
            let now = Utc::now().timestamp();
            expire_stale_channel_request_with_lock(&state, &req.channel_id, now).await?;
        }
        return Err(error);
    }

    if let Err(error) = state
        .wal
        .append(WalEntry::ChannelAdaptorDelivered {
            channel_id: req.channel_id.clone(),
            request_id: request_id.clone(),
            adaptor_point: Some(req.adaptor_point.clone()),
            pre_sig_r_prime: Some(req.pre_sig_r_prime.clone()),
            pre_sig_s_prime: Some(req.pre_sig_s_prime.clone()),
            encrypted_result: Some(req.encrypted_result.clone()),
            result_hash: Some(req.result_hash.clone()),
            provider_pubkey: Some(req.provider_pubkey.clone()),
        })
        .await
    {
        let _ = asc_manager::rollback_deliver_adaptor(&state.vault, &req.channel_id, &request_id);
        return Err(EnclaveError::Internal(format!(
            "WAL append failed: {error}"
        )));
    }

    let channel_id = req.channel_id.clone();

    Ok(Json(ChannelDeliverResponse {
        ok: true,
        channel_id: channel_id.clone(),
        status: "pending".to_string(),
        claim_voucher: issue_asc_claim_voucher(
            &state,
            &channel_id,
            &request_id,
            request_amount,
            request_hash,
            registered_provider_pubkey,
        ),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelFinalizeRequest {
    pub channel_id: String,
    pub adaptor_secret: String,
    pub client_sig: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelFinalizeResponse {
    pub ok: bool,
    pub channel_id: String,
    pub result: String,
    pub amount_paid: u64,
    pub status: String,
}

pub async fn post_channel_finalize(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChannelFinalizeRequest>,
) -> Result<Json<ChannelFinalizeResponse>, EnclaveError> {
    ensure_vault_allows_existing_reservation_ops(&state).await?;

    let _guard = state.asc_ops_lock.lock().await;
    let _persist_guard = state.persistence_lock.lock().await;
    let message = build_channel_finalize_message(&req.channel_id, &req.adaptor_secret);
    verify_channel_client_signature(&state, &req.channel_id, &message, &req.client_sig)?;

    let adaptor_secret: [u8; 32] = hex::decode(&req.adaptor_secret)
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?
        .try_into()
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?;

    let outcome = asc_manager::finalize_offchain(&state.vault, &req.channel_id, adaptor_secret)?;

    if let Err(error) = state
        .wal
        .append(WalEntry::ChannelFinalized {
            channel_id: req.channel_id.clone(),
            request_id: outcome.request_id.clone(),
            amount_paid: outcome.amount,
        })
        .await
    {
        let _ = asc_manager::rollback_finalize_offchain(
            &state.vault,
            &req.channel_id,
            outcome.request.clone(),
        );
        return Err(EnclaveError::Internal(format!(
            "WAL append failed: {error}"
        )));
    }
    let client = state
        .vault
        .active_channels
        .get(&req.channel_id)
        .map(|channel| channel.client)
        .ok_or(EnclaveError::ChannelNotFound)?;
    state.vault.refresh_client_max_lock_expires_at(&client)?;
    issue_client_receipt_locked(&state, client).await?;

    Ok(Json(ChannelFinalizeResponse {
        ok: true,
        channel_id: req.channel_id,
        result: BASE64.encode(&outcome.result_bytes),
        amount_paid: outcome.amount,
        status: "open".to_string(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseChannelRequest {
    pub channel_id: String,
    pub client_sig: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseChannelResponse {
    pub ok: bool,
    pub channel_id: String,
    pub provider_id: String,
    pub returned_to_client: u64,
    pub provider_earned: u64,
}

pub async fn post_channel_close(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CloseChannelRequest>,
) -> Result<Json<CloseChannelResponse>, EnclaveError> {
    ensure_vault_allows_existing_reservation_ops(&state).await?;

    let _guard = state.asc_ops_lock.lock().await;
    let _persist_guard = state.persistence_lock.lock().await;
    let message = build_channel_close_message(&req.channel_id);
    verify_channel_client_signature(&state, &req.channel_id, &message, &req.client_sig)?;

    let outcome = asc_manager::close_channel(&state.vault, &req.channel_id)?;

    if let Err(error) = state
        .wal
        .append(WalEntry::ChannelClosed {
            channel_id: req.channel_id.clone(),
            returned_to_client: outcome.returned_to_client,
            provider_earned: outcome.provider_earned,
            settlement_id: outcome.settlement_id.clone(),
        })
        .await
    {
        let _ = asc_manager::rollback_close_channel(&state.vault, outcome);
        return Err(EnclaveError::Internal(format!(
            "WAL append failed: {error}"
        )));
    }
    state
        .vault
        .refresh_client_max_lock_expires_at(&outcome.client)?;
    issue_client_receipt_locked(&state, outcome.client).await?;
    if outcome.provider_earned > 0 {
        issue_provider_receipt_locked(&state, &outcome.provider_id).await?;
    }

    Ok(Json(CloseChannelResponse {
        ok: true,
        channel_id: req.channel_id,
        provider_id: outcome.provider_id,
        returned_to_client: outcome.returned_to_client,
        provider_earned: outcome.provider_earned,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptor_sig::{self, AdaptorKeyPair};
    use crate::arcium::{
        encrypt_shared_scalars_for_test, public_key_from_private_key_for_test,
        ArciumDomainHashParts, ArciumGrantDecryptor, ArciumGrantDomainHashes,
    };
    use crate::provider_attestation::{
        build_local_dev_provider_attestation, test_policy, ProviderParticipantAttestationRequest,
    };
    use crate::state::{SolanaRuntimeConfig, VaultState};
    use crate::wal::{self, Wal};
    use axum::http::{header::AUTHORIZATION, HeaderName, HeaderValue};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use solana_sdk::pubkey::Pubkey;
    use std::path::PathBuf;

    fn sign_text_message(signing_key: &SigningKey, message: &str) -> String {
        use ed25519_dalek::Signer;
        BASE64.encode(signing_key.sign(message.as_bytes()).to_bytes())
    }

    fn sign_payment_payload(signing_key: &SigningKey, payload: &PaymentPayload) -> String {
        use ed25519_dalek::Signer;

        let mut message = String::new();
        message.push_str("SUBLY402-SVM-V1-AUTH\n");
        message.push_str(&format!("{}\n", payload.version));
        message.push_str(&format!("{}\n", payload.scheme));
        message.push_str(&format!("{}\n", payload.payment_id));
        message.push_str(&format!("{}\n", payload.client));
        message.push_str(&format!("{}\n", payload.vault));
        message.push_str(&format!("{}\n", payload.provider_id));
        message.push_str(&format!("{}\n", payload.pay_to));
        message.push_str(&format!("{}\n", payload.network));
        message.push_str(&format!("{}\n", payload.asset_mint));
        message.push_str(&format!("{}\n", payload.amount));
        message.push_str(&format!("{}\n", payload.request_hash));
        message.push_str(&format!("{}\n", payload.payment_details_hash));
        message.push_str(&format!("{}\n", payload.expires_at));
        message.push_str(&format!("{}\n", payload.nonce));

        BASE64.encode(signing_key.sign(message.as_bytes()).to_bytes())
    }

    fn build_test_provider_participant_attestation(
        provider_id: &str,
        participant_pubkey: Pubkey,
    ) -> ProviderParticipantAttestationRequest {
        let policy = test_policy();
        let document =
            build_local_dev_provider_attestation(provider_id, participant_pubkey, &policy, None);
        ProviderParticipantAttestationRequest {
            document,
            policy,
            max_age_ms: Some(10 * 60 * 1000),
        }
    }

    async fn make_app_state_with_options(
        provider_mtls_enabled: bool,
        arcium_grant_decryptor: Option<Arc<ArciumGrantDecryptor>>,
        arcium_mxe_public_key: Option<[u8; 32]>,
        arcium_domain_hashes: Option<ArciumGrantDomainHashes>,
    ) -> (Arc<AppState>, PathBuf) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let usdc_mint = Pubkey::new_unique();
        let solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        let vault = Arc::new(VaultState::new(
            Pubkey::new_unique(),
            signing_key,
            usdc_mint,
            [0u8; 32],
            solana.clone(),
        ));
        let wal_path =
            std::env::temp_dir().join(format!("subly402-phase3-{}.jsonl", uuid::Uuid::now_v7()));
        let wal = Arc::new(Wal::new(wal_path.clone()).await);
        let detector = Arc::new(DepositDetector::new(
            solana.vault_token_account,
            solana.program_id,
            solana.rpc_url,
            solana.ws_url,
            crate::outbound::OutboundTransport::direct(),
        ));

        (
            Arc::new(AppState {
                vault,
                wal,
                deposit_detector: detector,
                batch_privacy: crate::batch::BatchPrivacyConfig::default(),
                attestation_provider: Arc::new(
                    crate::attestation::AttestationProvider::test_local_dev(),
                ),
                asc_ops_lock: Mutex::new(()),
                persistence_lock: Mutex::new(()),
                watchtower_url: None,
                attestation_document: String::new(),
                attestation_is_local_dev: true,
                provider_mtls_enabled,
                outbound: crate::outbound::OutboundTransport::direct(),
                arcium_grant_decryptor,
                arcium_mxe_public_key,
                arcium_domain_hashes,
            }),
            wal_path,
        )
    }

    async fn make_app_state_with_mtls(provider_mtls_enabled: bool) -> (Arc<AppState>, PathBuf) {
        make_app_state_with_options(provider_mtls_enabled, None, None, None).await
    }

    async fn make_app_state_with_arcium_decryptor(
        decryptor: Arc<ArciumGrantDecryptor>,
        mxe_public_key: [u8; 32],
        arcium_domain_hashes: ArciumGrantDomainHashes,
    ) -> (Arc<AppState>, PathBuf) {
        make_app_state_with_options(
            false,
            Some(decryptor),
            Some(mxe_public_key),
            Some(arcium_domain_hashes),
        )
        .await
    }

    fn test_arcium_domain_hashes(
        budget_lo: u128,
        budget_hi: u128,
        withdrawal_lo: u128,
        withdrawal_hi: u128,
    ) -> ArciumGrantDomainHashes {
        ArciumGrantDomainHashes {
            authorize_budget: ArciumDomainHashParts {
                lo: budget_lo,
                hi: budget_hi,
            },
            authorize_withdrawal: ArciumDomainHashParts {
                lo: withdrawal_lo,
                hi: withdrawal_hi,
            },
        }
    }

    async fn make_app_state() -> (Arc<AppState>, PathBuf) {
        make_app_state_with_mtls(false).await
    }

    #[tokio::test]
    async fn register_provider_rejects_mtls_when_listener_disabled() {
        let (state, wal_path) = make_app_state().await;

        let error = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: "provider-mtls-disabled".to_string(),
                display_name: "mTLS Provider".to_string(),
                participant_pubkey: None,
                participant_attestation: None,
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "mtls".to_string(),
                api_key_hash: String::new(),
                mtls_cert_fingerprint: Some("ab".repeat(32)),
            }),
        )
        .await
        .err()
        .unwrap();

        assert!(matches!(error, EnclaveError::MtlsNotEnabled));
        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn register_provider_requires_attestation_for_participant_pubkey() {
        let (state, wal_path) = make_app_state().await;
        let provider_signing_key = SigningKey::generate(&mut OsRng);

        let error = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: "provider-phase3-attestation-required".to_string(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: Some(
                    Pubkey::new_from_array(provider_signing_key.verifying_key().to_bytes())
                        .to_string(),
                ),
                participant_attestation: None,
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: hex::encode(Sha256::digest(b"phase3-provider-secret")),
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .err()
        .unwrap();

        assert!(matches!(
            error,
            EnclaveError::ProviderParticipantAttestationRequired
        ));
        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn register_provider_persists_verified_attestation_metadata() {
        let (state, wal_path) = make_app_state().await;
        let provider_id = "provider-phase3-attested".to_string();
        let provider_signing_key = SigningKey::generate(&mut OsRng);
        let participant_pubkey =
            Pubkey::new_from_array(provider_signing_key.verifying_key().to_bytes());

        let response = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: Some(participant_pubkey.to_string()),
                participant_attestation: Some(build_test_provider_participant_attestation(
                    &provider_id,
                    participant_pubkey,
                )),
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: hex::encode(Sha256::digest(b"phase3-provider-secret")),
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0.provider_id, provider_id);

        let provider = state.vault.providers.get(&provider_id).unwrap();
        assert_eq!(provider.participant_pubkey, Some(participant_pubkey));
        assert!(provider.participant_attestation_policy_hash.is_some());
        assert_eq!(
            provider.participant_attestation_mode.as_deref(),
            Some("local-dev")
        );
        assert!(provider.participant_attestation_verified_at_ms.is_some());
        drop(provider);

        let wal_records = state.wal.read_records().await.unwrap();
        assert!(wal_records.iter().any(|record| {
            matches!(
                &record.entry,
                WalEntry::ProviderRegistered {
                    provider_id: recorded_provider_id,
                    participant_attestation_policy_hash: Some(_),
                    participant_attestation_mode: Some(mode),
                    ..
                } if recorded_provider_id == &provider_id && mode == "local-dev"
            )
        }));

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn verify_accepts_mtls_provider_with_matching_client_certificate_fingerprint() {
        let (state, wal_path) = make_app_state_with_mtls(true).await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-mtls".to_string();
        let settlement_token_account = Pubkey::new_unique();
        let asset_mint = Pubkey::new_unique();
        let fingerprint_hex = "cd".repeat(32);

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "mTLS Provider".to_string(),
                participant_pubkey: None,
                participant_attestation: None,
                settlement_token_account: settlement_token_account.to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: asset_mint.to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "mtls".to_string(),
                api_key_hash: String::new(),
                mtls_cert_fingerprint: Some(fingerprint_hex.clone()),
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 2_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(2_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        state
            .deposit_detector
            .is_synced
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let request_context = RequestContext {
            method: "POST".to_string(),
            origin: "http://localhost".to_string(),
            path_and_query: "/demo".to_string(),
            body_sha256: "11".repeat(32),
        };
        let payment_details = serde_json::json!({
            "scheme": "subly402-svm-v1",
            "network": "solana:localnet",
            "amount": "600000",
            "asset": {
                "kind": "spl-token",
                "mint": asset_mint.to_string(),
                "decimals": 6,
                "symbol": "USDC",
            },
            "payTo": settlement_token_account.to_string(),
            "providerId": provider_id,
            "facilitatorUrl": "https://localhost:3100/v1",
            "vault": {
                "config": state.vault.vault_config.to_string(),
                "signer": state.vault.vault_signer_pubkey.to_string(),
                "attestationPolicyHash": hex::encode(state.vault.attestation_policy_hash),
            },
            "paymentDetailsId": "paydet_test_mtls",
            "verifyWindowSec": 60,
            "maxSettlementDelaySec": 900,
            "privacyMode": "vault-batched-v1",
        });
        let payment_details_hash = hex::encode(compute_payment_details_hash(&payment_details));
        let request_hash = hex::encode(compute_request_hash(
            &request_context,
            &payment_details_hash,
        ));

        let mut payment_payload = PaymentPayload {
            version: 1,
            scheme: "subly402-svm-v1".to_string(),
            payment_id: "pay_mtls_test".to_string(),
            client: client.to_string(),
            vault: state.vault.vault_config.to_string(),
            provider_id: "provider-mtls".to_string(),
            pay_to: settlement_token_account.to_string(),
            network: "solana:localnet".to_string(),
            asset_mint: asset_mint.to_string(),
            amount: "600000".to_string(),
            request_hash,
            payment_details_hash,
            expires_at: (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
            nonce: "1".to_string(),
            client_sig: String::new(),
        };
        payment_payload.client_sig = sign_payment_payload(&client_signing_key, &payment_payload);

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_static("provider-mtls"),
        );
        headers.insert(
            HeaderName::from_static(INTERNAL_MTLS_FINGERPRINT_HEADER),
            HeaderValue::from_str(&fingerprint_hex).unwrap(),
        );

        let response = post_verify(
            State(state.clone()),
            headers,
            Json(VerifyRequest {
                payment_payload,
                payment_details: Some(payment_details),
                request_context,
            }),
        )
        .await
        .unwrap();

        assert!(response.0.ok);
        assert_eq!(response.0.provider_id, "provider-mtls");
        assert!(!response.0.verification_receipt.is_empty());

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn verify_uses_verify_window_sec_from_payment_details() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-verify-window".to_string();
        let provider_api_key = "verify-window-provider-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));
        let settlement_token_account = Pubkey::new_unique();
        let asset_mint = Pubkey::new_unique();

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Verify Window Provider".to_string(),
                participant_pubkey: None,
                participant_attestation: None,
                settlement_token_account: settlement_token_account.to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: asset_mint.to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: provider_api_key_hash,
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 2_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(2_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        state
            .deposit_detector
            .is_synced
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let request_context = RequestContext {
            method: "POST".to_string(),
            origin: "http://localhost".to_string(),
            path_and_query: "/demo".to_string(),
            body_sha256: "33".repeat(32),
        };
        let payment_details = serde_json::json!({
            "scheme": "subly402-svm-v1",
            "network": "solana:localnet",
            "amount": "600000",
            "asset": {
                "kind": "spl-token",
                "mint": asset_mint.to_string(),
                "decimals": 6,
                "symbol": "USDC",
            },
            "payTo": settlement_token_account.to_string(),
            "providerId": provider_id.clone(),
            "facilitatorUrl": "https://localhost:3100/v1",
            "vault": {
                "config": state.vault.vault_config.to_string(),
                "signer": state.vault.vault_signer_pubkey.to_string(),
                "attestationPolicyHash": hex::encode(state.vault.attestation_policy_hash),
            },
            "paymentDetailsId": "paydet_verify_window",
            "verifyWindowSec": 137,
            "maxSettlementDelaySec": 900,
            "privacyMode": "vault-batched-v1",
        });
        let payment_details_hash = hex::encode(compute_payment_details_hash(&payment_details));
        let request_hash = hex::encode(compute_request_hash(
            &request_context,
            &payment_details_hash,
        ));

        let mut payment_payload = PaymentPayload {
            version: 1,
            scheme: "subly402-svm-v1".to_string(),
            payment_id: "pay_verify_window".to_string(),
            client: client.to_string(),
            vault: state.vault.vault_config.to_string(),
            provider_id: provider_id.clone(),
            pay_to: settlement_token_account.to_string(),
            network: "solana:localnet".to_string(),
            asset_mint: asset_mint.to_string(),
            amount: "600000".to_string(),
            request_hash,
            payment_details_hash,
            expires_at: (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
            nonce: "1".to_string(),
            client_sig: String::new(),
        };
        payment_payload.client_sig = sign_payment_payload(&client_signing_key, &payment_payload);

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {provider_api_key}")).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_str(&provider_id).unwrap(),
        );

        let response = post_verify(
            State(state.clone()),
            headers,
            Json(VerifyRequest {
                payment_payload,
                payment_details: Some(payment_details),
                request_context,
            }),
        )
        .await
        .unwrap();

        let reservation = state
            .vault
            .reservations
            .get(&response.0.verification_id)
            .unwrap();
        assert_eq!(reservation.expires_at - reservation.created_at, 137);
        let response_expires_at =
            chrono::DateTime::parse_from_rfc3339(&response.0.reservation_expires_at)
                .unwrap()
                .timestamp();
        assert_eq!(response_expires_at, reservation.expires_at);

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn verify_and_settle_auto_register_open_provider_without_auth_headers() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let settlement_token_account = Pubkey::new_unique();
        let asset_mint = Pubkey::new_unique();
        let provider_id = derive_open_provider_id(
            "solana:localnet",
            &asset_mint.to_string(),
            &settlement_token_account.to_string(),
        );

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 2_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(2_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        state
            .deposit_detector
            .is_synced
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let request_context = RequestContext {
            method: "GET".to_string(),
            origin: "http://localhost".to_string(),
            path_and_query: "/open".to_string(),
            body_sha256: "00".repeat(32),
        };
        let payment_details = serde_json::json!({
            "scheme": "subly402-svm-v1",
            "network": "solana:localnet",
            "amount": "600000",
            "asset": {
                "kind": "spl-token",
                "mint": asset_mint.to_string(),
                "decimals": 6,
                "symbol": "USDC",
            },
            "payTo": settlement_token_account.to_string(),
            "providerId": provider_id,
            "facilitatorUrl": "https://localhost:3100/v1",
            "vault": {
                "config": state.vault.vault_config.to_string(),
                "signer": state.vault.vault_signer_pubkey.to_string(),
                "attestationPolicyHash": hex::encode(state.vault.attestation_policy_hash),
            },
            "paymentDetailsId": "paydet_open_provider",
            "verifyWindowSec": 60,
            "maxSettlementDelaySec": 900,
            "privacyMode": "vault-batched-v1",
        });
        let payment_details_hash = hex::encode(compute_payment_details_hash(&payment_details));
        let request_hash = hex::encode(compute_request_hash(
            &request_context,
            &payment_details_hash,
        ));

        let mut payment_payload = PaymentPayload {
            version: 1,
            scheme: "subly402-svm-v1".to_string(),
            payment_id: "pay_open_provider".to_string(),
            client: client.to_string(),
            vault: state.vault.vault_config.to_string(),
            provider_id: provider_id.clone(),
            pay_to: settlement_token_account.to_string(),
            network: "solana:localnet".to_string(),
            asset_mint: asset_mint.to_string(),
            amount: "600000".to_string(),
            request_hash,
            payment_details_hash,
            expires_at: (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
            nonce: "1".to_string(),
            client_sig: String::new(),
        };
        payment_payload.client_sig = sign_payment_payload(&client_signing_key, &payment_payload);

        let verify_response = post_verify(
            State(state.clone()),
            HeaderMap::new(),
            Json(VerifyRequest {
                payment_payload,
                payment_details: Some(payment_details),
                request_context,
            }),
        )
        .await
        .unwrap();

        let provider = state.vault.providers.get(&provider_id).unwrap();
        assert_eq!(provider.auth_mode, "none");
        assert_eq!(provider.settlement_token_account, settlement_token_account);
        drop(provider);

        let settle_response = post_settle(
            State(state.clone()),
            HeaderMap::new(),
            Json(SettleRequest {
                verification_id: verify_response.0.verification_id,
                result_hash: "55".repeat(32),
                status_code: 200,
            }),
        )
        .await
        .unwrap();

        assert!(settle_response.0.ok);
        let credit = state.vault.provider_credits.get(&provider_id).unwrap();
        assert_eq!(credit.settlement_token_account, settlement_token_account);
        assert_eq!(credit.credited_amount, 600_000);

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn enforced_arcium_verify_and_settle_spend_loaded_budget_grant() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let settlement_token_account = Pubkey::new_unique();
        let asset_mint = Pubkey::new_unique();
        let provider_id = derive_open_provider_id(
            "solana:localnet",
            &asset_mint.to_string(),
            &settlement_token_account.to_string(),
        );

        let _ = post_load_arcium_budget_grant(
            State(state.clone()),
            Json(LoadArciumBudgetGrantRequest {
                grant_id: "budget-grant-1".to_string(),
                client: client.to_string(),
                budget_id: 1,
                request_nonce: 9,
                remaining: 1_000_000,
                expires_at: Utc::now().timestamp() + 600,
            }),
        )
        .await
        .unwrap();
        let _ = post_set_arcium_mode(
            State(state.clone()),
            Json(SetArciumModeRequest {
                mode: "enforced".to_string(),
            }),
        )
        .await
        .unwrap();
        let plaintext_load_error = post_load_arcium_budget_grant(
            State(state.clone()),
            Json(LoadArciumBudgetGrantRequest {
                grant_id: "budget-grant-plaintext-rejected".to_string(),
                client: client.to_string(),
                budget_id: 2,
                request_nonce: 10,
                remaining: 1_000_000,
                expires_at: Utc::now().timestamp() + 600,
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            plaintext_load_error,
            EnclaveError::Internal(message) if message.contains("Plaintext Arcium grant loading")
        ));

        state
            .deposit_detector
            .is_synced
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let request_context = RequestContext {
            method: "GET".to_string(),
            origin: "http://localhost".to_string(),
            path_and_query: "/arcium".to_string(),
            body_sha256: "00".repeat(32),
        };
        let payment_details = serde_json::json!({
            "scheme": "subly402-svm-v1",
            "network": "solana:localnet",
            "amount": "600000",
            "asset": {
                "kind": "spl-token",
                "mint": asset_mint.to_string(),
                "decimals": 6,
                "symbol": "USDC",
            },
            "payTo": settlement_token_account.to_string(),
            "providerId": provider_id,
            "facilitatorUrl": "https://localhost:3100/v1",
            "vault": {
                "config": state.vault.vault_config.to_string(),
                "signer": state.vault.vault_signer_pubkey.to_string(),
                "attestationPolicyHash": hex::encode(state.vault.attestation_policy_hash),
            },
            "paymentDetailsId": "paydet_arcium_enforced",
            "verifyWindowSec": 60,
            "maxSettlementDelaySec": 900,
            "privacyMode": "arcium-enforced-v1",
        });
        let payment_details_hash = hex::encode(compute_payment_details_hash(&payment_details));
        let request_hash = hex::encode(compute_request_hash(
            &request_context,
            &payment_details_hash,
        ));
        let mut payment_payload = PaymentPayload {
            version: 1,
            scheme: "subly402-svm-v1".to_string(),
            payment_id: "pay_arcium_enforced".to_string(),
            client: client.to_string(),
            vault: state.vault.vault_config.to_string(),
            provider_id: provider_id.clone(),
            pay_to: settlement_token_account.to_string(),
            network: "solana:localnet".to_string(),
            asset_mint: asset_mint.to_string(),
            amount: "600000".to_string(),
            request_hash,
            payment_details_hash,
            expires_at: (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
            nonce: "1".to_string(),
            client_sig: String::new(),
        };
        payment_payload.client_sig = sign_payment_payload(&client_signing_key, &payment_payload);

        let verify_response = post_verify(
            State(state.clone()),
            HeaderMap::new(),
            Json(VerifyRequest {
                payment_payload,
                payment_details: Some(payment_details),
                request_context,
            }),
        )
        .await
        .unwrap();

        assert!(state.vault.client_balances.get(&client).is_none());
        let reservation = state
            .vault
            .reservations
            .get(&verify_response.0.verification_id)
            .unwrap();
        assert_eq!(
            reservation.arcium_grant_id.as_deref(),
            Some("budget-grant-1")
        );
        drop(reservation);
        assert_eq!(
            state
                .vault
                .arcium_budget_grants
                .get("budget-grant-1")
                .unwrap()
                .remaining,
            400_000
        );

        let settle_response = post_settle(
            State(state.clone()),
            HeaderMap::new(),
            Json(SettleRequest {
                verification_id: verify_response.0.verification_id,
                result_hash: "55".repeat(32),
                status_code: 200,
            }),
        )
        .await
        .unwrap();
        assert!(settle_response.0.ok);
        assert_eq!(
            state
                .vault
                .provider_credits
                .get(&provider_id)
                .unwrap()
                .credited_amount,
            600_000
        );

        let issued_at = Utc::now().timestamp();
        let expires_at = issued_at + 60;
        let balance_message =
            build_balance_auth_message(&client.to_string(), issued_at, expires_at);
        let balance_error = post_balance(
            State(state.clone()),
            Json(BalanceRequest {
                client: client.to_string(),
                auth: ClientRequestAuth {
                    issued_at,
                    expires_at,
                    client_sig: sign_text_message(&client_signing_key, &balance_message),
                },
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            balance_error,
            EnclaveError::ArciumBalanceUnavailable
        ));

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn arcium_settle_rolls_back_provider_credit_when_wal_append_fails() {
        let (state, wal_path) = make_app_state().await;
        tokio::fs::create_dir_all(&wal_path).await.unwrap();

        let client = Pubkey::new_unique();
        let provider_id = "provider-arcium-wal-fail".to_string();
        let verification_id = "ver_arcium_wal_fail".to_string();
        let now = Utc::now().timestamp();

        state.vault.set_arcium_mode(ArciumAuthorityMode::Enforced);
        state.vault.providers.insert(
            provider_id.clone(),
            crate::state::ProviderRegistration {
                provider_id: provider_id.clone(),
                display_name: "Arcium WAL Failure Provider".to_string(),
                participant_pubkey: None,
                participant_attestation_policy_hash: None,
                participant_attestation_verified_at_ms: None,
                participant_attestation_mode: None,
                settlement_token_account: Pubkey::new_unique(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "none".to_string(),
                api_key_hash: None,
                mtls_cert_fingerprint: None,
            },
        );
        state.vault.reservations.insert(
            verification_id.clone(),
            crate::state::Reservation {
                verification_id: verification_id.clone(),
                reservation_id: "res_arcium_wal_fail".to_string(),
                payment_id: "pay_arcium_wal_fail".to_string(),
                client,
                provider_id: provider_id.clone(),
                amount: 700_000,
                request_hash: [1u8; 32],
                payment_details_hash: [2u8; 32],
                status: ReservationStatus::Reserved,
                created_at: now,
                expires_at: now + 60,
                settlement_id: None,
                settled_at: None,
                arcium_grant_id: Some("budget-grant-wal-fail".to_string()),
            },
        );

        let error = post_settle(
            State(state.clone()),
            HeaderMap::new(),
            Json(SettleRequest {
                verification_id: verification_id.clone(),
                result_hash: "55".repeat(32),
                status_code: 200,
            }),
        )
        .await
        .err()
        .unwrap();

        assert!(matches!(error, EnclaveError::Internal(_)));
        assert!(state.vault.provider_credits.get(&provider_id).is_none());
        assert!(state.vault.settlement_history.is_empty());
        let reservation = state.vault.reservations.get(&verification_id).unwrap();
        assert_eq!(reservation.status, ReservationStatus::Reserved);
        assert!(reservation.settlement_id.is_none());
        assert!(reservation.settled_at.is_none());

        let _ = tokio::fs::remove_dir_all(wal_path).await;
    }

    #[tokio::test]
    async fn arcium_grant_reloads_are_monotonic() {
        let (state, wal_path) = make_app_state().await;
        let client = Pubkey::new_unique();
        let recipient_ata = Pubkey::new_unique();
        let grant_expires_at = Utc::now().timestamp() + 600;

        let first_budget = post_load_arcium_budget_grant(
            State(state.clone()),
            Json(LoadArciumBudgetGrantRequest {
                grant_id: "budget-grant-monotonic".to_string(),
                client: client.to_string(),
                budget_id: 1,
                request_nonce: 2,
                remaining: 1_000,
                expires_at: grant_expires_at,
            }),
        )
        .await
        .unwrap();
        assert_eq!(first_budget.0.remaining, 1_000);

        state
            .vault
            .reserve_arcium_budget_from_grant(
                "budget-grant-monotonic",
                &client,
                400,
                Utc::now().timestamp(),
            )
            .unwrap();

        let duplicate_budget = post_load_arcium_budget_grant(
            State(state.clone()),
            Json(LoadArciumBudgetGrantRequest {
                grant_id: "budget-grant-monotonic".to_string(),
                client: client.to_string(),
                budget_id: 1,
                request_nonce: 2,
                remaining: 1_000,
                expires_at: grant_expires_at,
            }),
        )
        .await
        .unwrap();
        assert_eq!(duplicate_budget.0.remaining, 600);
        assert_eq!(
            state
                .vault
                .arcium_budget_grants
                .get("budget-grant-monotonic")
                .unwrap()
                .remaining,
            600
        );

        let lower_budget = post_load_arcium_budget_grant(
            State(state.clone()),
            Json(LoadArciumBudgetGrantRequest {
                grant_id: "budget-grant-monotonic".to_string(),
                client: client.to_string(),
                budget_id: 1,
                request_nonce: 2,
                remaining: 500,
                expires_at: grant_expires_at,
            }),
        )
        .await
        .unwrap();
        assert_eq!(lower_budget.0.remaining, 500);

        let conflicting_budget = post_load_arcium_budget_grant(
            State(state.clone()),
            Json(LoadArciumBudgetGrantRequest {
                grant_id: "budget-grant-monotonic".to_string(),
                client: client.to_string(),
                budget_id: 1,
                request_nonce: 99,
                remaining: 500,
                expires_at: grant_expires_at,
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(conflicting_budget, EnclaveError::Internal(_)));

        let first_withdrawal = post_load_arcium_withdrawal_grant(
            State(state.clone()),
            Json(LoadArciumWithdrawalGrantRequest {
                grant_id: "withdrawal-grant-monotonic".to_string(),
                client: client.to_string(),
                withdrawal_id: 7,
                recipient_ata: recipient_ata.to_string(),
                amount: 250,
                expires_at: grant_expires_at,
                consumed: false,
            }),
        )
        .await
        .unwrap();
        assert!(!first_withdrawal.0.consumed);

        state
            .vault
            .authorize_arcium_withdrawal_from_grant(
                "withdrawal-grant-monotonic",
                PendingWithdrawal {
                    client,
                    recipient_ata,
                    amount: 250,
                    withdraw_nonce: 1,
                    issued_at: Utc::now().timestamp(),
                    expires_at: Utc::now().timestamp() + 60,
                    arcium_grant_id: None,
                },
                Utc::now().timestamp(),
            )
            .unwrap();

        let duplicate_withdrawal = post_load_arcium_withdrawal_grant(
            State(state.clone()),
            Json(LoadArciumWithdrawalGrantRequest {
                grant_id: "withdrawal-grant-monotonic".to_string(),
                client: client.to_string(),
                withdrawal_id: 7,
                recipient_ata: recipient_ata.to_string(),
                amount: 250,
                expires_at: grant_expires_at,
                consumed: false,
            }),
        )
        .await
        .unwrap();
        assert!(duplicate_withdrawal.0.consumed);

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn encrypted_arcium_budget_grant_load_decrypts_inside_enclave() {
        let tee_private_key = [3u8; 32];
        let mxe_private_key = [5u8; 32];
        let decryptor = Arc::new(ArciumGrantDecryptor::new(tee_private_key).unwrap());
        let mxe_public_key = public_key_from_private_key_for_test(mxe_private_key);
        let (state, wal_path) = make_app_state_with_arcium_decryptor(
            decryptor.clone(),
            mxe_public_key,
            test_arcium_domain_hashes(31, 32, 43, 44),
        )
        .await;
        let client = Pubkey::new_unique();
        let grant_pubkey = Pubkey::new_unique();
        let grant_id = grant_pubkey.to_string();
        let budget_id = 19u64;
        let request_nonce = 23u64;
        let amount = 1_000u64;
        let remaining = 777u64;
        let expires_at = Utc::now().timestamp() + 600;
        let expires_at_u64 = u64::try_from(expires_at).unwrap();
        let state_version = 4u64;
        let domain_hash_lo = 31u128;
        let domain_hash_hi = 32u128;
        let (vault_config_lo, vault_config_hi) = split_pubkey_u128(&state.vault.vault_config);
        let (client_lo, client_hi) = split_pubkey_u128(&client);
        let (grant_lo, grant_hi) = split_pubkey_u128(&grant_pubkey);
        let grant_nonce = [9u8; 16];
        let plaintexts = [
            1,
            u128::from(budget_id),
            u128::from(request_nonce),
            u128::from(amount),
            u128::from(remaining),
            u128::from(expires_at_u64),
            u128::from(state_version),
            domain_hash_lo,
            domain_hash_hi,
            vault_config_lo,
            vault_config_hi,
            client_lo,
            client_hi,
            grant_lo,
            grant_hi,
        ];
        let grant_ciphertexts = encrypt_shared_scalars_for_test(
            mxe_private_key,
            decryptor.public_key(),
            &plaintexts,
            grant_nonce,
        );
        let build_request = |vault_config: Pubkey| LoadEncryptedArciumBudgetGrantRequest {
            grant_id: grant_id.clone(),
            vault_config: vault_config.to_string(),
            client: client.to_string(),
            budget_id,
            request_nonce,
            expires_at,
            state_version_at_authorization: state_version,
            domain_hash_lo,
            domain_hash_hi,
            tee_x25519_pubkey: decryptor.public_key(),
            mxe_public_key,
            grant_ciphertexts: grant_ciphertexts.clone(),
            grant_nonce,
        };

        let wrong_vault_error = post_load_encrypted_arcium_budget_grant(
            State(state.clone()),
            Json(build_request(Pubkey::new_unique())),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(wrong_vault_error, EnclaveError::VaultNotActive));
        let wrong_mxe_error = post_load_encrypted_arcium_budget_grant(
            State(state.clone()),
            Json(LoadEncryptedArciumBudgetGrantRequest {
                mxe_public_key: [99u8; 32],
                ..build_request(state.vault.vault_config)
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            wrong_mxe_error,
            EnclaveError::Internal(message) if message.contains("MXE public key mismatch")
        ));
        let wrong_domain_error = post_load_encrypted_arcium_budget_grant(
            State(state.clone()),
            Json(LoadEncryptedArciumBudgetGrantRequest {
                domain_hash_lo: 99,
                ..build_request(state.vault.vault_config)
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            wrong_domain_error,
            EnclaveError::Internal(message) if message.contains("requestDomainHashLo")
        ));

        let response = post_load_encrypted_arcium_budget_grant(
            State(state.clone()),
            Json(build_request(state.vault.vault_config)),
        )
        .await
        .unwrap();

        assert_eq!(response.0.remaining, remaining);
        assert_eq!(
            state
                .vault
                .arcium_budget_grants
                .get(&grant_id)
                .unwrap()
                .remaining,
            remaining
        );

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn encrypted_arcium_withdrawal_grant_load_binds_decrypted_identity() {
        let tee_private_key = [7u8; 32];
        let mxe_private_key = [11u8; 32];
        let decryptor = Arc::new(ArciumGrantDecryptor::new(tee_private_key).unwrap());
        let mxe_public_key = public_key_from_private_key_for_test(mxe_private_key);
        let (state, wal_path) = make_app_state_with_arcium_decryptor(
            decryptor.clone(),
            mxe_public_key,
            test_arcium_domain_hashes(31, 32, 43, 44),
        )
        .await;
        let client = Pubkey::new_unique();
        let wrong_client = Pubkey::new_unique();
        let recipient_ata = Pubkey::new_unique();
        let grant_pubkey = Pubkey::new_unique();
        let grant_id = grant_pubkey.to_string();
        let withdrawal_id = 41u64;
        let amount = 900u64;
        let expires_at = Utc::now().timestamp() + 600;
        let expires_at_u64 = u64::try_from(expires_at).unwrap();
        let state_version = 6u64;
        let domain_hash_lo = 43u128;
        let domain_hash_hi = 44u128;
        let (vault_config_lo, vault_config_hi) = split_pubkey_u128(&state.vault.vault_config);
        let (client_lo, client_hi) = split_pubkey_u128(&client);
        let (grant_lo, grant_hi) = split_pubkey_u128(&grant_pubkey);
        let (recipient_lo, recipient_hi) = split_pubkey_u128(&recipient_ata);
        let grant_nonce = [13u8; 16];
        let plaintexts = [
            1,
            u128::from(withdrawal_id),
            u128::from(amount),
            u128::from(expires_at_u64),
            u128::from(state_version),
            domain_hash_lo,
            domain_hash_hi,
            vault_config_lo,
            vault_config_hi,
            client_lo,
            client_hi,
            grant_lo,
            grant_hi,
            recipient_lo,
            recipient_hi,
        ];
        let grant_ciphertexts = encrypt_shared_scalars_for_test(
            mxe_private_key,
            decryptor.public_key(),
            &plaintexts,
            grant_nonce,
        );
        let build_request = |request_client: Pubkey| LoadEncryptedArciumWithdrawalGrantRequest {
            grant_id: grant_id.clone(),
            vault_config: state.vault.vault_config.to_string(),
            client: request_client.to_string(),
            withdrawal_id,
            recipient_ata: recipient_ata.to_string(),
            expires_at,
            state_version_at_authorization: state_version,
            domain_hash_lo,
            domain_hash_hi,
            tee_x25519_pubkey: decryptor.public_key(),
            mxe_public_key,
            grant_ciphertexts: grant_ciphertexts.clone(),
            grant_nonce,
            consumed: false,
        };

        let error = post_load_encrypted_arcium_withdrawal_grant(
            State(state.clone()),
            Json(build_request(wrong_client)),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            error,
            EnclaveError::Internal(message) if message.contains("client split")
        ));
        assert!(state
            .vault
            .arcium_withdrawal_grants
            .get(&grant_id)
            .is_none());
        let wrong_mxe_error = post_load_encrypted_arcium_withdrawal_grant(
            State(state.clone()),
            Json(LoadEncryptedArciumWithdrawalGrantRequest {
                mxe_public_key: [99u8; 32],
                ..build_request(client)
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            wrong_mxe_error,
            EnclaveError::Internal(message) if message.contains("MXE public key mismatch")
        ));
        assert!(state
            .vault
            .arcium_withdrawal_grants
            .get(&grant_id)
            .is_none());

        let response = post_load_encrypted_arcium_withdrawal_grant(
            State(state.clone()),
            Json(build_request(client)),
        )
        .await
        .unwrap();
        assert_eq!(response.0.amount, amount);
        assert!(!response.0.consumed);

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn withdraw_auth_locks_balance_until_expiry() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let recipient_ata = Pubkey::new_unique();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 1_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(1_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        let issued_at = Utc::now().timestamp();
        let expires_at = issued_at + 60;
        let auth_message = build_withdraw_auth_message(
            &client.to_string(),
            &recipient_ata.to_string(),
            800_000,
            issued_at,
            expires_at,
        );
        let response = post_withdraw_auth(
            State(state.clone()),
            Json(WithdrawAuthRequest {
                client: client.to_string(),
                recipient_ata: recipient_ata.to_string(),
                amount: 800_000,
                auth: ClientRequestAuth {
                    issued_at,
                    expires_at,
                    client_sig: sign_text_message(&client_signing_key, &auth_message),
                },
            }),
        )
        .await
        .unwrap();

        let balance = state.vault.client_balances.get(&client).unwrap();
        assert_eq!(balance.free, 200_000);
        assert_eq!(balance.locked, 800_000);
        assert_eq!(balance.total_withdrawn, 0);
        assert_eq!(balance.max_lock_expires_at, response.0.expires_at);
        drop(balance);
        assert!(state
            .vault
            .pending_withdrawals
            .contains_key(&response.0.withdraw_nonce));

        let second_issued_at = Utc::now().timestamp();
        let second_expires_at = second_issued_at + 60;
        let second_message = build_withdraw_auth_message(
            &client.to_string(),
            &recipient_ata.to_string(),
            300_000,
            second_issued_at,
            second_expires_at,
        );
        let error = post_withdraw_auth(
            State(state.clone()),
            Json(WithdrawAuthRequest {
                client: client.to_string(),
                recipient_ata: recipient_ata.to_string(),
                amount: 300_000,
                auth: ClientRequestAuth {
                    issued_at: second_issued_at,
                    expires_at: second_expires_at,
                    client_sig: sign_text_message(&client_signing_key, &second_message),
                },
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(error, EnclaveError::InsufficientBalance));

        assert!(expire_pending_withdrawal(
            &state,
            response.0.withdraw_nonce,
            response.0.expires_at + 1
        )
        .await
        .unwrap());
        let balance = state.vault.client_balances.get(&client).unwrap();
        assert_eq!(balance.free, 1_000_000);
        assert_eq!(balance.locked, 0);
        assert_eq!(balance.total_withdrawn, 0);
        assert_eq!(balance.max_lock_expires_at, 0);
        drop(balance);
        assert!(state
            .vault
            .pending_withdrawals
            .get(&response.0.withdraw_nonce)
            .is_none());

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn enforced_arcium_withdraw_auth_requires_and_consumes_withdrawal_grant() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let recipient_ata = Pubkey::new_unique();

        let _ = post_set_arcium_mode(
            State(state.clone()),
            Json(SetArciumModeRequest {
                mode: "enforced".to_string(),
            }),
        )
        .await
        .unwrap();

        let issued_at = Utc::now().timestamp();
        let expires_at = issued_at + 60;
        let auth_message = build_withdraw_auth_message(
            &client.to_string(),
            &recipient_ata.to_string(),
            500_000,
            issued_at,
            expires_at,
        );
        let missing_grant_error = post_withdraw_auth(
            State(state.clone()),
            Json(WithdrawAuthRequest {
                client: client.to_string(),
                recipient_ata: recipient_ata.to_string(),
                amount: 500_000,
                auth: ClientRequestAuth {
                    issued_at,
                    expires_at,
                    client_sig: sign_text_message(&client_signing_key, &auth_message),
                },
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            missing_grant_error,
            EnclaveError::InsufficientArciumWithdrawalGrant
        ));

        state.vault.set_arcium_mode(ArciumAuthorityMode::Mirror);
        let grant_expires_at = Utc::now().timestamp() + 600;
        let _ = post_load_arcium_withdrawal_grant(
            State(state.clone()),
            Json(LoadArciumWithdrawalGrantRequest {
                grant_id: "withdraw-grant-1".to_string(),
                client: client.to_string(),
                withdrawal_id: 7,
                recipient_ata: recipient_ata.to_string(),
                amount: 500_000,
                expires_at: grant_expires_at,
                consumed: false,
            }),
        )
        .await
        .unwrap();
        state.vault.set_arcium_mode(ArciumAuthorityMode::Enforced);
        let plaintext_load_error = post_load_arcium_withdrawal_grant(
            State(state.clone()),
            Json(LoadArciumWithdrawalGrantRequest {
                grant_id: "withdraw-grant-plaintext-rejected".to_string(),
                client: client.to_string(),
                withdrawal_id: 8,
                recipient_ata: recipient_ata.to_string(),
                amount: 500_000,
                expires_at: grant_expires_at,
                consumed: false,
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            plaintext_load_error,
            EnclaveError::Internal(message) if message.contains("Plaintext Arcium grant loading")
        ));

        let issued_at = Utc::now().timestamp();
        let expires_at = issued_at + 60;
        let auth_message = build_withdraw_auth_message(
            &client.to_string(),
            &recipient_ata.to_string(),
            500_000,
            issued_at,
            expires_at,
        );
        let response = post_withdraw_auth(
            State(state.clone()),
            Json(WithdrawAuthRequest {
                client: client.to_string(),
                recipient_ata: recipient_ata.to_string(),
                amount: 500_000,
                auth: ClientRequestAuth {
                    issued_at,
                    expires_at,
                    client_sig: sign_text_message(&client_signing_key, &auth_message),
                },
            }),
        )
        .await
        .unwrap();

        assert!(state.vault.client_balances.get(&client).is_none());
        let pending = state
            .vault
            .pending_withdrawals
            .get(&response.0.withdraw_nonce)
            .unwrap();
        assert_eq!(pending.arcium_grant_id.as_deref(), Some("withdraw-grant-1"));
        drop(pending);
        let grant = state
            .vault
            .arcium_withdrawal_grants
            .get("withdraw-grant-1")
            .unwrap();
        assert!(grant.consumed);
        drop(grant);

        assert!(expire_pending_withdrawal(
            &state,
            response.0.withdraw_nonce,
            response.0.expires_at + 1
        )
        .await
        .unwrap());
        let grant = state
            .vault
            .arcium_withdrawal_grants
            .get("withdraw-grant-1")
            .unwrap();
        assert!(!grant.consumed);
        assert!(state
            .vault
            .pending_withdrawals
            .get(&response.0.withdraw_nonce)
            .is_none());

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn settle_rejects_expired_reservation_before_background_sweeper_runs() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-expired-settle".to_string();
        let provider_api_key = "expired-settle-provider-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));
        let settlement_token_account = Pubkey::new_unique();
        let asset_mint = Pubkey::new_unique();

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Expired Settle Provider".to_string(),
                participant_pubkey: None,
                participant_attestation: None,
                settlement_token_account: settlement_token_account.to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: asset_mint.to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: provider_api_key_hash,
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 2_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(2_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        state
            .deposit_detector
            .is_synced
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let request_context = RequestContext {
            method: "POST".to_string(),
            origin: "http://localhost".to_string(),
            path_and_query: "/demo".to_string(),
            body_sha256: "44".repeat(32),
        };
        let payment_details = serde_json::json!({
            "scheme": "subly402-svm-v1",
            "network": "solana:localnet",
            "amount": "600000",
            "asset": {
                "kind": "spl-token",
                "mint": asset_mint.to_string(),
                "decimals": 6,
                "symbol": "USDC",
            },
            "payTo": settlement_token_account.to_string(),
            "providerId": provider_id.clone(),
            "facilitatorUrl": "https://localhost:3100/v1",
            "vault": {
                "config": state.vault.vault_config.to_string(),
                "signer": state.vault.vault_signer_pubkey.to_string(),
                "attestationPolicyHash": hex::encode(state.vault.attestation_policy_hash),
            },
            "paymentDetailsId": "paydet_expired_settle",
            "verifyWindowSec": 30,
            "maxSettlementDelaySec": 900,
            "privacyMode": "vault-batched-v1",
        });
        let payment_details_hash = hex::encode(compute_payment_details_hash(&payment_details));
        let request_hash = hex::encode(compute_request_hash(
            &request_context,
            &payment_details_hash,
        ));

        let mut payment_payload = PaymentPayload {
            version: 1,
            scheme: "subly402-svm-v1".to_string(),
            payment_id: "pay_expired_settle".to_string(),
            client: client.to_string(),
            vault: state.vault.vault_config.to_string(),
            provider_id: provider_id.clone(),
            pay_to: settlement_token_account.to_string(),
            network: "solana:localnet".to_string(),
            asset_mint: asset_mint.to_string(),
            amount: "600000".to_string(),
            request_hash,
            payment_details_hash,
            expires_at: (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
            nonce: "1".to_string(),
            client_sig: String::new(),
        };
        payment_payload.client_sig = sign_payment_payload(&client_signing_key, &payment_payload);

        let mut verify_headers = HeaderMap::new();
        verify_headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {provider_api_key}")).unwrap(),
        );
        verify_headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_str(&provider_id).unwrap(),
        );

        let verify_response = post_verify(
            State(state.clone()),
            verify_headers,
            Json(VerifyRequest {
                payment_payload,
                payment_details: Some(payment_details),
                request_context,
            }),
        )
        .await
        .unwrap();

        {
            let mut reservation = state
                .vault
                .reservations
                .get_mut(&verify_response.0.verification_id)
                .unwrap();
            reservation.expires_at = Utc::now().timestamp() - 1;
        }

        let mut settle_headers = HeaderMap::new();
        settle_headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {provider_api_key}")).unwrap(),
        );
        settle_headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_str(&provider_id).unwrap(),
        );

        let error = post_settle(
            State(state.clone()),
            settle_headers,
            Json(SettleRequest {
                verification_id: verify_response.0.verification_id.clone(),
                result_hash: "55".repeat(32),
                status_code: 200,
            }),
        )
        .await
        .err()
        .unwrap();

        assert!(matches!(error, EnclaveError::ReservationExpired));

        let reservation = state
            .vault
            .reservations
            .get(&verify_response.0.verification_id)
            .unwrap();
        assert_eq!(reservation.status, ReservationStatus::Expired);
        drop(reservation);

        let balance = state.vault.client_balances.get(&client).unwrap();
        assert_eq!(balance.free, 2_000_000);
        assert_eq!(balance.locked, 0);
        drop(balance);

        let wal_records = state.wal.read_records().await.unwrap();
        assert!(wal_records.iter().any(|record| {
            matches!(
                &record.entry,
                WalEntry::ReservationExpired { verification_id }
                if verification_id == &verify_response.0.verification_id
            )
        }));
        assert!(!wal_records.iter().any(|record| {
            matches!(
                &record.entry,
                WalEntry::SettlementCommitted { verification_id, .. }
                if verification_id == &verify_response.0.verification_id
            )
        }));

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn channel_open_requires_registered_provider_participant_pubkey() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-phase3-missing-participant".to_string();
        let provider_api_key = "phase3-provider-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: None,
                participant_attestation: None,
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: provider_api_key_hash,
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 5_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(5_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        let open_message = build_channel_open_message(&client.to_string(), &provider_id, 3_000_000);
        let error = post_channel_open(
            State(state.clone()),
            Json(OpenChannelRequest {
                client: client.to_string(),
                provider_id,
                initial_deposit: 3_000_000,
                client_sig: sign_text_message(&client_signing_key, &open_message),
            }),
        )
        .await
        .err()
        .unwrap();

        assert!(matches!(error, EnclaveError::ProviderParticipantRequired));
        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn channel_api_flow_requires_auth_and_records_request_id() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-phase3".to_string();
        let provider_api_key = "phase3-provider-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));
        let provider_signing_key = SigningKey::generate(&mut OsRng);

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: Some(
                    Pubkey::new_from_array(provider_signing_key.verifying_key().to_bytes())
                        .to_string(),
                ),
                participant_attestation: Some(build_test_provider_participant_attestation(
                    &provider_id,
                    Pubkey::new_from_array(provider_signing_key.verifying_key().to_bytes()),
                )),
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: provider_api_key_hash,
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 5_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(5_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        let open_message = build_channel_open_message(&client.to_string(), &provider_id, 3_000_000);
        let open_res = post_channel_open(
            State(state.clone()),
            Json(OpenChannelRequest {
                client: client.to_string(),
                provider_id: provider_id.clone(),
                initial_deposit: 3_000_000,
                client_sig: sign_text_message(&client_signing_key, &open_message),
            }),
        )
        .await
        .unwrap();
        let channel_id = open_res.0.channel_id.clone();

        let request_hash_hex = "ab".repeat(32);
        let request_message =
            build_channel_request_message(&channel_id, "req-123", 1_250_000, &request_hash_hex);
        let _ = post_channel_request(
            State(state.clone()),
            Json(ChannelRequestReq {
                channel_id: channel_id.clone(),
                request_id: "req-123".to_string(),
                amount: 1_250_000,
                request_hash: request_hash_hex.clone(),
                client_sig: sign_text_message(&client_signing_key, &request_message),
            }),
        )
        .await
        .unwrap();

        let provider_pubkey = provider_signing_key.verifying_key().to_bytes();
        let adaptor = AdaptorKeyPair::generate();
        let request_hash: [u8; 32] = hex::decode(&request_hash_hex).unwrap().try_into().unwrap();
        let payment_message = subly402_vault::asc_claim::build_asc_payment_message(
            &channel_id,
            "req-123",
            1_250_000,
            &request_hash,
        );
        let pre_sig = adaptor_sig::pre_sign(
            &provider_signing_key.to_bytes(),
            &payment_message,
            &adaptor.public,
        );
        let plaintext = br#"{"ok":true,"payload":"phase3"}"#.to_vec();
        let encrypted_result =
            crate::asc_manager::encrypt_with_scalar(&plaintext, &adaptor.secret.to_bytes());
        let result_hash = hex::encode(Sha256::digest(&plaintext));

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {provider_api_key}")).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_str(&provider_id).unwrap(),
        );

        let _ = post_channel_deliver(
            State(state.clone()),
            headers,
            Json(ChannelDeliverRequest {
                channel_id: channel_id.clone(),
                adaptor_point: hex::encode(adaptor.public_compressed),
                pre_sig_r_prime: hex::encode(pre_sig.r_prime),
                pre_sig_s_prime: hex::encode(pre_sig.s_prime),
                encrypted_result: BASE64.encode(&encrypted_result),
                result_hash,
                provider_pubkey: hex::encode(provider_pubkey),
            }),
        )
        .await
        .unwrap();

        let finalize_secret = hex::encode(adaptor.secret.to_bytes());
        let finalize_message = build_channel_finalize_message(&channel_id, &finalize_secret);
        let finalize_res = post_channel_finalize(
            State(state.clone()),
            Json(ChannelFinalizeRequest {
                channel_id: channel_id.clone(),
                adaptor_secret: finalize_secret,
                client_sig: sign_text_message(&client_signing_key, &finalize_message),
            }),
        )
        .await
        .unwrap();
        assert_eq!(BASE64.decode(finalize_res.0.result).unwrap(), plaintext);
        assert_eq!(finalize_res.0.amount_paid, 1_250_000);

        let close_message = build_channel_close_message(&channel_id);
        let close_res = post_channel_close(
            State(state.clone()),
            Json(CloseChannelRequest {
                channel_id: channel_id.clone(),
                client_sig: sign_text_message(&client_signing_key, &close_message),
            }),
        )
        .await
        .unwrap();
        assert_eq!(close_res.0.returned_to_client, 1_750_000);
        assert_eq!(close_res.0.provider_earned, 1_250_000);

        let wal_records = state.wal.read_records().await.unwrap();
        assert!(wal_records.iter().any(|record| {
            matches!(
                &record.entry,
                WalEntry::ChannelFinalized {
                    request_id,
                    amount_paid,
                    ..
                } if request_id == "req-123" && *amount_paid == 1_250_000
            )
        }));

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn channel_deliver_expires_stale_request_durably() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-phase3-expiry".to_string();
        let provider_api_key = "phase3-provider-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));
        let provider_signing_key = SigningKey::generate(&mut OsRng);

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: Some(
                    Pubkey::new_from_array(provider_signing_key.verifying_key().to_bytes())
                        .to_string(),
                ),
                participant_attestation: Some(build_test_provider_participant_attestation(
                    &provider_id,
                    Pubkey::new_from_array(provider_signing_key.verifying_key().to_bytes()),
                )),
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: provider_api_key_hash,
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 5_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(5_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        let open_message = build_channel_open_message(&client.to_string(), &provider_id, 3_000_000);
        let open_res = post_channel_open(
            State(state.clone()),
            Json(OpenChannelRequest {
                client: client.to_string(),
                provider_id: provider_id.clone(),
                initial_deposit: 3_000_000,
                client_sig: sign_text_message(&client_signing_key, &open_message),
            }),
        )
        .await
        .unwrap();
        let channel_id = open_res.0.channel_id.clone();

        let request_hash_hex = "cc".repeat(32);
        let request_message =
            build_channel_request_message(&channel_id, "req-expired", 1_250_000, &request_hash_hex);
        let _ = post_channel_request(
            State(state.clone()),
            Json(ChannelRequestReq {
                channel_id: channel_id.clone(),
                request_id: "req-expired".to_string(),
                amount: 1_250_000,
                request_hash: request_hash_hex,
                client_sig: sign_text_message(&client_signing_key, &request_message),
            }),
        )
        .await
        .unwrap();

        {
            let mut channel = state.vault.active_channels.get_mut(&channel_id).unwrap();
            channel.active_request.as_mut().unwrap().expires_at = Utc::now().timestamp() - 1;
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {provider_api_key}")).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_str(&provider_id).unwrap(),
        );

        let error = post_channel_deliver(
            State(state.clone()),
            headers,
            Json(ChannelDeliverRequest {
                channel_id: channel_id.clone(),
                adaptor_point: "11".repeat(32),
                pre_sig_r_prime: "22".repeat(32),
                pre_sig_s_prime: "33".repeat(32),
                encrypted_result: BASE64.encode(b"expired"),
                result_hash: "44".repeat(32),
                provider_pubkey: hex::encode(provider_signing_key.verifying_key().to_bytes()),
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(error, EnclaveError::ChannelRequestExpired));

        let channel = state.vault.active_channels.get(&channel_id).unwrap();
        assert!(matches!(channel.status, crate::state::ChannelStatus::Open));
        assert_eq!(channel.balance.client_free, 3_000_000);
        assert_eq!(channel.balance.client_locked, 0);
        assert!(channel.active_request.is_none());
        drop(channel);

        let balance = state.vault.client_balances.get(&client).unwrap();
        assert_eq!(balance.free, 2_000_000);
        assert_eq!(balance.locked, 3_000_000);
        assert_eq!(balance.max_lock_expires_at, 0);
        drop(balance);

        let wal_records = state.wal.read_records().await.unwrap();
        assert!(wal_records.iter().any(|record| {
            matches!(
                &record.entry,
                WalEntry::ChannelRequestExpired {
                    channel_id: wal_channel_id,
                    request_id,
                    amount,
                } if wal_channel_id == &channel_id
                    && request_id == "req-expired"
                    && *amount == 1_250_000
            )
        }));

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn channel_deliver_rejects_provider_pubkey_not_bound_to_registration() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-phase3-mismatch".to_string();
        let provider_api_key = "phase3-provider-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));
        let registered_provider_signing_key = SigningKey::generate(&mut OsRng);

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: Some(
                    Pubkey::new_from_array(
                        registered_provider_signing_key.verifying_key().to_bytes(),
                    )
                    .to_string(),
                ),
                participant_attestation: Some(build_test_provider_participant_attestation(
                    &provider_id,
                    Pubkey::new_from_array(
                        registered_provider_signing_key.verifying_key().to_bytes(),
                    ),
                )),
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: provider_api_key_hash,
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 5_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(5_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        let open_message = build_channel_open_message(&client.to_string(), &provider_id, 3_000_000);
        let open_res = post_channel_open(
            State(state.clone()),
            Json(OpenChannelRequest {
                client: client.to_string(),
                provider_id: provider_id.clone(),
                initial_deposit: 3_000_000,
                client_sig: sign_text_message(&client_signing_key, &open_message),
            }),
        )
        .await
        .unwrap();
        let channel_id = open_res.0.channel_id.clone();

        let request_hash_hex = "aa".repeat(32);
        let request_message = build_channel_request_message(
            &channel_id,
            "req-mismatch",
            1_250_000,
            &request_hash_hex,
        );
        let _ = post_channel_request(
            State(state.clone()),
            Json(ChannelRequestReq {
                channel_id: channel_id.clone(),
                request_id: "req-mismatch".to_string(),
                amount: 1_250_000,
                request_hash: request_hash_hex.clone(),
                client_sig: sign_text_message(&client_signing_key, &request_message),
            }),
        )
        .await
        .unwrap();

        let mismatched_provider_signing_key = SigningKey::generate(&mut OsRng);
        let adaptor = AdaptorKeyPair::generate();
        let request_hash: [u8; 32] = hex::decode(&request_hash_hex).unwrap().try_into().unwrap();
        let pre_sig = adaptor_sig::pre_sign(
            &mismatched_provider_signing_key.to_bytes(),
            &subly402_vault::asc_claim::build_asc_payment_message(
                &channel_id,
                "req-mismatch",
                1_250_000,
                &request_hash,
            ),
            &adaptor.public,
        );
        let plaintext = br#"{"ok":true,"payload":"phase3"}"#.to_vec();
        let encrypted_result =
            crate::asc_manager::encrypt_with_scalar(&plaintext, &adaptor.secret.to_bytes());

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {provider_api_key}")).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_str(&provider_id).unwrap(),
        );

        let error = post_channel_deliver(
            State(state.clone()),
            headers,
            Json(ChannelDeliverRequest {
                channel_id,
                adaptor_point: hex::encode(adaptor.public_compressed),
                pre_sig_r_prime: hex::encode(pre_sig.r_prime),
                pre_sig_s_prime: hex::encode(pre_sig.s_prime),
                encrypted_result: BASE64.encode(&encrypted_result),
                result_hash: hex::encode(Sha256::digest(&plaintext)),
                provider_pubkey: hex::encode(
                    mismatched_provider_signing_key.verifying_key().to_bytes(),
                ),
            }),
        )
        .await
        .err()
        .unwrap();

        assert!(matches!(error, EnclaveError::ProviderParticipantMismatch));
        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn channel_request_id_cannot_be_reused_after_finalize() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-phase3-reuse".to_string();
        let provider_api_key = "phase3-provider-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));
        let provider_signing_key = SigningKey::generate(&mut OsRng);

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: Some(
                    Pubkey::new_from_array(provider_signing_key.verifying_key().to_bytes())
                        .to_string(),
                ),
                participant_attestation: Some(build_test_provider_participant_attestation(
                    &provider_id,
                    Pubkey::new_from_array(provider_signing_key.verifying_key().to_bytes()),
                )),
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "api-key".to_string(),
                api_key_hash: provider_api_key_hash,
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 5_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(5_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        let open_message = build_channel_open_message(&client.to_string(), &provider_id, 3_000_000);
        let open_res = post_channel_open(
            State(state.clone()),
            Json(OpenChannelRequest {
                client: client.to_string(),
                provider_id: provider_id.clone(),
                initial_deposit: 3_000_000,
                client_sig: sign_text_message(&client_signing_key, &open_message),
            }),
        )
        .await
        .unwrap();
        let channel_id = open_res.0.channel_id;

        let request_hash_hex = "cd".repeat(32);
        let request_message =
            build_channel_request_message(&channel_id, "req-reuse", 1_000_000, &request_hash_hex);
        let _ = post_channel_request(
            State(state.clone()),
            Json(ChannelRequestReq {
                channel_id: channel_id.clone(),
                request_id: "req-reuse".to_string(),
                amount: 1_000_000,
                request_hash: request_hash_hex.clone(),
                client_sig: sign_text_message(&client_signing_key, &request_message),
            }),
        )
        .await
        .unwrap();

        let adaptor = AdaptorKeyPair::generate();
        let request_hash: [u8; 32] = hex::decode(&request_hash_hex).unwrap().try_into().unwrap();
        let pre_sig = adaptor_sig::pre_sign(
            &provider_signing_key.to_bytes(),
            &subly402_vault::asc_claim::build_asc_payment_message(
                &channel_id,
                "req-reuse",
                1_000_000,
                &request_hash,
            ),
            &adaptor.public,
        );
        let plaintext = br#"{"ok":true,"payload":"phase3"}"#.to_vec();
        let encrypted_result =
            crate::asc_manager::encrypt_with_scalar(&plaintext, &adaptor.secret.to_bytes());

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-subly402-provider-auth"),
            HeaderValue::from_str(provider_api_key).unwrap(),
        );

        let _ = post_channel_deliver(
            State(state.clone()),
            headers,
            Json(ChannelDeliverRequest {
                channel_id: channel_id.clone(),
                adaptor_point: hex::encode(adaptor.public_compressed),
                pre_sig_r_prime: hex::encode(pre_sig.r_prime),
                pre_sig_s_prime: hex::encode(pre_sig.s_prime),
                encrypted_result: BASE64.encode(&encrypted_result),
                result_hash: hex::encode(Sha256::digest(&plaintext)),
                provider_pubkey: hex::encode(provider_signing_key.verifying_key().to_bytes()),
            }),
        )
        .await
        .unwrap();

        let finalize_secret = hex::encode(adaptor.secret.to_bytes());
        let finalize_message = build_channel_finalize_message(&channel_id, &finalize_secret);
        let _ = post_channel_finalize(
            State(state.clone()),
            Json(ChannelFinalizeRequest {
                channel_id: channel_id.clone(),
                adaptor_secret: finalize_secret,
                client_sig: sign_text_message(&client_signing_key, &finalize_message),
            }),
        )
        .await
        .unwrap();

        let reuse_err = post_channel_request(
            State(state.clone()),
            Json(ChannelRequestReq {
                channel_id: channel_id.clone(),
                request_id: "req-reuse".to_string(),
                amount: 1_000_000,
                request_hash: request_hash_hex,
                client_sig: sign_text_message(&client_signing_key, &request_message),
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(reuse_err, EnclaveError::ChannelRequestIdReused));

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn wal_replay_restores_pending_channel_and_allows_finalize() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-phase3-replay".to_string();
        let provider_api_key = "phase3-provider-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));
        let provider_signing_key = SigningKey::generate(&mut OsRng);

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: Some(
                    Pubkey::new_from_array(provider_signing_key.verifying_key().to_bytes())
                        .to_string(),
                ),
                participant_attestation: Some(build_test_provider_participant_attestation(
                    &provider_id,
                    Pubkey::new_from_array(provider_signing_key.verifying_key().to_bytes()),
                )),
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: provider_api_key_hash,
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 5_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(5_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        let open_message = build_channel_open_message(&client.to_string(), &provider_id, 3_000_000);
        let open_res = post_channel_open(
            State(state.clone()),
            Json(OpenChannelRequest {
                client: client.to_string(),
                provider_id: provider_id.clone(),
                initial_deposit: 3_000_000,
                client_sig: sign_text_message(&client_signing_key, &open_message),
            }),
        )
        .await
        .unwrap();
        let channel_id = open_res.0.channel_id;

        let request_hash_hex = "ef".repeat(32);
        let request_message =
            build_channel_request_message(&channel_id, "req-replay", 1_250_000, &request_hash_hex);
        let _ = post_channel_request(
            State(state.clone()),
            Json(ChannelRequestReq {
                channel_id: channel_id.clone(),
                request_id: "req-replay".to_string(),
                amount: 1_250_000,
                request_hash: request_hash_hex.clone(),
                client_sig: sign_text_message(&client_signing_key, &request_message),
            }),
        )
        .await
        .unwrap();

        let adaptor = AdaptorKeyPair::generate();
        let request_hash: [u8; 32] = hex::decode(&request_hash_hex).unwrap().try_into().unwrap();
        let pre_sig = adaptor_sig::pre_sign(
            &provider_signing_key.to_bytes(),
            &subly402_vault::asc_claim::build_asc_payment_message(
                &channel_id,
                "req-replay",
                1_250_000,
                &request_hash,
            ),
            &adaptor.public,
        );
        let plaintext = br#"{"ok":true,"payload":"phase3-replay"}"#.to_vec();
        let encrypted_result =
            crate::asc_manager::encrypt_with_scalar(&plaintext, &adaptor.secret.to_bytes());

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {provider_api_key}")).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_str(&provider_id).unwrap(),
        );

        let _ = post_channel_deliver(
            State(state.clone()),
            headers,
            Json(ChannelDeliverRequest {
                channel_id: channel_id.clone(),
                adaptor_point: hex::encode(adaptor.public_compressed),
                pre_sig_r_prime: hex::encode(pre_sig.r_prime),
                pre_sig_s_prime: hex::encode(pre_sig.s_prime),
                encrypted_result: BASE64.encode(&encrypted_result),
                result_hash: hex::encode(Sha256::digest(&plaintext)),
                provider_pubkey: hex::encode(provider_signing_key.verifying_key().to_bytes()),
            }),
        )
        .await
        .unwrap();

        let replay_signing_key = SigningKey::generate(&mut OsRng);
        let replay_solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        let replay_state = Arc::new(AppState {
            vault: Arc::new(VaultState::new(
                Pubkey::new_unique(),
                replay_signing_key,
                Pubkey::new_unique(),
                [0u8; 32],
                replay_solana.clone(),
            )),
            wal: Arc::new(Wal::new(wal_path.clone()).await),
            deposit_detector: Arc::new(DepositDetector::new(
                replay_solana.vault_token_account,
                replay_solana.program_id,
                replay_solana.rpc_url,
                replay_solana.ws_url,
                crate::outbound::OutboundTransport::direct(),
            )),
            batch_privacy: crate::batch::BatchPrivacyConfig::default(),
            attestation_provider: Arc::new(
                crate::attestation::AttestationProvider::test_local_dev(),
            ),
            asc_ops_lock: Mutex::new(()),
            persistence_lock: Mutex::new(()),
            watchtower_url: None,
            attestation_document: String::new(),
            attestation_is_local_dev: true,
            provider_mtls_enabled: false,
            outbound: crate::outbound::OutboundTransport::direct(),
            arcium_grant_decryptor: None,
            arcium_mxe_public_key: None,
            arcium_domain_hashes: None,
        });

        wal::replay_app_state(&replay_state).await.unwrap();

        let replay_channel = replay_state.vault.active_channels.get(&channel_id).unwrap();
        assert_eq!(replay_channel.status, crate::state::ChannelStatus::Pending);
        assert_eq!(
            replay_channel
                .active_request
                .as_ref()
                .map(|request| request.request_id.as_str()),
            Some("req-replay")
        );
        drop(replay_channel);

        let finalize_secret = hex::encode(adaptor.secret.to_bytes());
        let finalize_message = build_channel_finalize_message(&channel_id, &finalize_secret);
        let finalize_res = post_channel_finalize(
            State(replay_state.clone()),
            Json(ChannelFinalizeRequest {
                channel_id: channel_id.clone(),
                adaptor_secret: finalize_secret,
                client_sig: sign_text_message(&client_signing_key, &finalize_message),
            }),
        )
        .await
        .unwrap();
        assert_eq!(BASE64.decode(finalize_res.0.result).unwrap(), plaintext);

        let close_message = build_channel_close_message(&channel_id);
        let close_res = post_channel_close(
            State(replay_state.clone()),
            Json(CloseChannelRequest {
                channel_id: channel_id.clone(),
                client_sig: sign_text_message(&client_signing_key, &close_message),
            }),
        )
        .await
        .unwrap();
        assert_eq!(close_res.0.returned_to_client, 1_750_000);
        assert_eq!(close_res.0.provider_earned, 1_250_000);

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn channel_open_rolls_back_when_wal_append_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let usdc_mint = Pubkey::new_unique();
        let solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        let vault = Arc::new(VaultState::new(
            Pubkey::new_unique(),
            signing_key,
            usdc_mint,
            [0u8; 32],
            solana.clone(),
        ));
        let wal_path =
            std::env::temp_dir().join(format!("subly402-phase3-dir-{}", uuid::Uuid::now_v7()));
        tokio::fs::create_dir_all(&wal_path).await.unwrap();
        let state = Arc::new(AppState {
            vault: vault.clone(),
            wal: Arc::new(Wal::new(wal_path.clone()).await),
            deposit_detector: Arc::new(DepositDetector::new(
                solana.vault_token_account,
                solana.program_id,
                solana.rpc_url,
                solana.ws_url,
                crate::outbound::OutboundTransport::direct(),
            )),
            batch_privacy: crate::batch::BatchPrivacyConfig::default(),
            attestation_provider: Arc::new(
                crate::attestation::AttestationProvider::test_local_dev(),
            ),
            asc_ops_lock: Mutex::new(()),
            persistence_lock: Mutex::new(()),
            watchtower_url: None,
            attestation_document: String::new(),
            attestation_is_local_dev: true,
            provider_mtls_enabled: false,
            outbound: crate::outbound::OutboundTransport::direct(),
            arcium_grant_decryptor: None,
            arcium_mxe_public_key: None,
            arcium_domain_hashes: None,
        });

        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_signing_key = SigningKey::generate(&mut OsRng);
        state.vault.providers.insert(
            "provider-phase3".to_string(),
            crate::state::ProviderRegistration {
                provider_id: "provider-phase3".to_string(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: Some(Pubkey::new_from_array(
                    provider_signing_key.verifying_key().to_bytes(),
                )),
                participant_attestation_policy_hash: None,
                participant_attestation_verified_at_ms: None,
                participant_attestation_mode: None,
                settlement_token_account: Pubkey::new_unique(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "api-key".to_string(),
                api_key_hash: Some(Sha256::digest(b"secret").to_vec()),
                mtls_cert_fingerprint: None,
            },
        );
        state.vault.client_balances.insert(
            client,
            crate::state::ClientBalance {
                free: 5_000_000,
                locked: 0,
                max_lock_expires_at: 0,
                total_deposited: 5_000_000,
                total_withdrawn: 0,
            },
        );

        let open_message =
            build_channel_open_message(&client.to_string(), "provider-phase3", 3_000_000);
        let error = post_channel_open(
            State(state.clone()),
            Json(OpenChannelRequest {
                client: client.to_string(),
                provider_id: "provider-phase3".to_string(),
                initial_deposit: 3_000_000,
                client_sig: sign_text_message(&client_signing_key, &open_message),
            }),
        )
        .await
        .err()
        .unwrap();

        assert!(matches!(error, EnclaveError::Internal(_)));
        assert!(state.vault.active_channels.is_empty());
        let balance = state.vault.client_balances.get(&client).unwrap();
        assert_eq!(balance.free, 5_000_000);
        assert_eq!(balance.locked, 0);

        let _ = tokio::fs::remove_dir_all(wal_path).await;
    }

    #[tokio::test]
    async fn wal_replay_restores_receipt_nonce() {
        let (state, wal_path) = make_app_state().await;
        state
            .wal
            .append(WalEntry::ParticipantReceiptIssued {
                participant: Pubkey::new_unique().to_string(),
                participant_kind: PARTICIPANT_KIND_CLIENT,
                nonce: 7,
            })
            .await
            .unwrap();
        state
            .wal
            .append(WalEntry::ParticipantReceiptMirrored {
                participant: Pubkey::new_unique().to_string(),
                participant_kind: PARTICIPANT_KIND_PROVIDER,
                nonce: 7,
            })
            .await
            .unwrap();

        let replay_signing_key = SigningKey::generate(&mut OsRng);
        let replay_solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        let replay_state = Arc::new(AppState {
            vault: Arc::new(VaultState::new(
                Pubkey::new_unique(),
                replay_signing_key,
                Pubkey::new_unique(),
                [0u8; 32],
                replay_solana.clone(),
            )),
            wal: Arc::new(Wal::new(wal_path.clone()).await),
            deposit_detector: Arc::new(DepositDetector::new(
                replay_solana.vault_token_account,
                replay_solana.program_id,
                replay_solana.rpc_url,
                replay_solana.ws_url,
                crate::outbound::OutboundTransport::direct(),
            )),
            batch_privacy: crate::batch::BatchPrivacyConfig::default(),
            attestation_provider: Arc::new(
                crate::attestation::AttestationProvider::test_local_dev(),
            ),
            asc_ops_lock: Mutex::new(()),
            persistence_lock: Mutex::new(()),
            watchtower_url: None,
            attestation_document: String::new(),
            attestation_is_local_dev: true,
            provider_mtls_enabled: false,
            outbound: crate::outbound::OutboundTransport::direct(),
            arcium_grant_decryptor: None,
            arcium_mxe_public_key: None,
            arcium_domain_hashes: None,
        });

        wal::replay_app_state(&replay_state).await.unwrap();
        assert_eq!(replay_state.vault.next_receipt_nonce(), 8);

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn wal_replay_restores_batched_settlement_lookup_state() {
        let (state, wal_path) = make_app_state().await;
        let client = Pubkey::new_unique();
        let provider_id = "provider-replay-batch".to_string();
        let provider_api_key = "provider-replay-batch-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));
        let provider_settlement_account = Pubkey::new_unique();
        let asset_mint = Pubkey::new_unique();

        state
            .wal
            .append(WalEntry::ProviderRegistered {
                provider_id: provider_id.clone(),
                display_name: "Replay Batch Provider".to_string(),
                participant_pubkey: None,
                participant_attestation_policy_hash: None,
                participant_attestation_verified_at_ms: None,
                participant_attestation_mode: None,
                settlement_token_account: provider_settlement_account.to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: asset_mint.to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: Some(provider_api_key_hash.clone()),
                mtls_cert_fingerprint: None,
            })
            .await
            .unwrap();
        state
            .wal
            .append(WalEntry::ClientBalanceSeeded {
                client: client.to_string(),
                free: 2_000_000,
                locked: 0,
                max_lock_expires_at: 0,
                total_deposited: 2_000_000,
                total_withdrawn: 0,
            })
            .await
            .unwrap();
        state
            .wal
            .append(WalEntry::ReservationCreated {
                verification_id: "ver_replay_batch".to_string(),
                reservation_id: Some("res_replay_batch".to_string()),
                payment_id: "pay_replay_batch".to_string(),
                client: client.to_string(),
                provider_id: provider_id.clone(),
                amount: 600_000,
                request_hash: Some("11".repeat(32)),
                payment_details_hash: Some("22".repeat(32)),
                created_at: Some(1_700_000_000),
                expires_at: Some(1_700_000_060),
                arcium_grant_id: None,
            })
            .await
            .unwrap();
        state
            .wal
            .append(WalEntry::SettlementCommitted {
                settlement_id: "set_replay_batch".to_string(),
                verification_id: "ver_replay_batch".to_string(),
                provider_id: provider_id.clone(),
                amount: 600_000,
                settled_at: Some(1_700_000_010),
            })
            .await
            .unwrap();
        state
            .wal
            .append(WalEntry::BatchConfirmed {
                batch_id: 7,
                tx_signature: "txsig_replay_batch".to_string(),
                settlement_ids: vec!["set_replay_batch".to_string()],
            })
            .await
            .unwrap();

        let replay_signing_key = SigningKey::generate(&mut OsRng);
        let replay_solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        let replay_state = Arc::new(AppState {
            vault: Arc::new(VaultState::new(
                Pubkey::new_unique(),
                replay_signing_key,
                Pubkey::new_unique(),
                [0u8; 32],
                replay_solana.clone(),
            )),
            wal: Arc::new(Wal::new(wal_path.clone()).await),
            deposit_detector: Arc::new(DepositDetector::new(
                replay_solana.vault_token_account,
                replay_solana.program_id,
                replay_solana.rpc_url,
                replay_solana.ws_url,
                crate::outbound::OutboundTransport::direct(),
            )),
            batch_privacy: crate::batch::BatchPrivacyConfig::default(),
            attestation_provider: Arc::new(
                crate::attestation::AttestationProvider::test_local_dev(),
            ),
            asc_ops_lock: Mutex::new(()),
            persistence_lock: Mutex::new(()),
            watchtower_url: None,
            attestation_document: String::new(),
            attestation_is_local_dev: true,
            provider_mtls_enabled: false,
            outbound: crate::outbound::OutboundTransport::direct(),
            arcium_grant_decryptor: None,
            arcium_mxe_public_key: None,
            arcium_domain_hashes: None,
        });

        wal::replay_app_state(&replay_state).await.unwrap();

        let reservation = replay_state
            .vault
            .reservations
            .get("ver_replay_batch")
            .unwrap();
        assert_eq!(reservation.status, ReservationStatus::BatchedOnchain);
        assert_eq!(
            reservation.settlement_id.as_deref(),
            Some("set_replay_batch")
        );
        drop(reservation);

        assert!(replay_state
            .vault
            .provider_credits
            .get(&provider_id)
            .is_none());
        assert!(replay_state
            .vault
            .settlement_history
            .get("set_replay_batch")
            .is_none());

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {provider_api_key}")).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_str(&provider_id).unwrap(),
        );

        let response = post_settlement_status(
            State(replay_state.clone()),
            headers,
            Json(SettlementStatusRequest {
                settlement_id: "set_replay_batch".to_string(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(response.0.batch_id, Some(7));
        assert_eq!(
            response.0.tx_signature.as_deref(),
            Some("txsig_replay_batch")
        );
        assert_eq!(response.0.status, "BatchedOnchain");

        let _ = tokio::fs::remove_file(wal_path).await;
    }
}
