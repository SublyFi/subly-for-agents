#![allow(dead_code)]

mod adaptor_sig;
mod admin_auth;
mod arcium;
mod asc_manager;
mod attestation;
mod audit;
mod batch;
mod deposit_detector;
mod error;
mod handlers;
mod interconnect;
mod kms_bootstrap;
mod outbound;
mod provider_attestation;
mod snapshot;
mod snapshot_store;
mod state;
mod tls;
mod wal;

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use solana_sdk::pubkey::Pubkey;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use deposit_detector::DepositDetector;
use handlers::AppState;
use interconnect::ParentInterconnect;
use kms_bootstrap::bootstrap_materials;
use outbound::OutboundTransport;
use snapshot::SnapshotManager;
use snapshot_store::SnapshotStoreClient;
use state::{ArciumAuthorityMode, SolanaRuntimeConfig, VaultState};
use wal::Wal;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let vault_config = read_pubkey_env("SUBLY402_VAULT_CONFIG", Pubkey::default());
    let usdc_mint = read_pubkey_env("SUBLY402_USDC_MINT", Pubkey::default());
    let attestation_policy_hash = attestation::resolve_attestation_policy_hash_from_env()
        .expect("attestation policy hash must resolve from env or Nitro measurements");
    let solana = SolanaRuntimeConfig {
        program_id: read_pubkey_env("SUBLY402_PROGRAM_ID", subly402_vault::ID),
        vault_token_account: read_pubkey_env("SUBLY402_VAULT_TOKEN_ACCOUNT", Pubkey::default()),
        rpc_url: env::var("SUBLY402_SOLANA_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8899".to_string()),
        ws_url: env::var("SUBLY402_SOLANA_WS_URL")
            .unwrap_or_else(|_| "ws://127.0.0.1:8900".to_string()),
    };
    let wal_path = env::var("SUBLY402_WAL_PATH").unwrap_or_else(|_| "data/wal.jsonl".to_string());
    let listen_addr =
        env::var("SUBLY402_ENCLAVE_LISTEN").unwrap_or_else(|_| "0.0.0.0:3100".to_string());
    let ingress_port = read_env_u32("SUBLY402_ENCLAVE_INGRESS_PORT", 5000);
    let parent_interconnect = ParentInterconnect::from_env();
    let outbound = OutboundTransport::from_env(parent_interconnect);
    let snapshot_store = SnapshotStoreClient::from_env(parent_interconnect);
    let bootstrap = bootstrap_materials(
        vault_config,
        attestation_policy_hash,
        snapshot_store.clone(),
    )
    .await
    .expect("runtime bootstrap must succeed");
    let vault_signer_pubkey =
        Pubkey::new_from_array(bootstrap.signing_key.verifying_key().to_bytes());
    info!(vault_signer = %vault_signer_pubkey, "Loaded vault signer keypair");

    let vault_state = Arc::new(VaultState::new(
        vault_config,
        bootstrap.signing_key,
        usdc_mint,
        attestation_policy_hash,
        solana.clone(),
    ));
    let arcium_mode =
        ArciumAuthorityMode::from_env_value(env::var("SUBLY402_ARCIUM_MODE").ok().as_deref())
            .expect("SUBLY402_ARCIUM_MODE must be disabled, mirror, or enforced");
    let arcium_grant_decryptor = arcium::ArciumGrantDecryptor::from_env()
        .expect("SUBLY402_ARCIUM_TEE_X25519_PRIVATE_KEY must be valid when set")
        .map(Arc::new);
    let arcium_mxe_public_key = arcium::mxe_public_key_from_env()
        .expect("SUBLY402_ARCIUM_MXE_PUBLIC_KEY must be valid when set");
    let arcium_domain_hashes = arcium::grant_domain_hashes_from_env()
        .expect("SUBLY402_ARCIUM_AUTHORIZE_*_DOMAIN_HASH_* must be valid when set");
    if arcium_mode == ArciumAuthorityMode::Enforced {
        assert!(
            arcium_grant_decryptor.is_some(),
            "SUBLY402_ARCIUM_TEE_X25519_PRIVATE_KEY_HEX or _B64 is required in Arcium enforced mode"
        );
        assert!(
            arcium_mxe_public_key.is_some(),
            "SUBLY402_ARCIUM_MXE_PUBLIC_KEY_HEX or _B64 is required in Arcium enforced mode"
        );
        assert!(
            arcium_domain_hashes.is_some(),
            "SUBLY402_ARCIUM_AUTHORIZE_BUDGET_DOMAIN_HASH_LO/HI and SUBLY402_ARCIUM_AUTHORIZE_WITHDRAWAL_DOMAIN_HASH_LO/HI are required in Arcium enforced mode"
        );
    }
    vault_state.set_arcium_mode(arcium_mode);
    info!(
        arcium_mode = arcium_mode.as_str(),
        arcium_grant_decryptor = arcium_grant_decryptor.is_some(),
        arcium_mxe_public_key = arcium_mxe_public_key.is_some(),
        arcium_domain_hashes = arcium_domain_hashes.is_some(),
        "Configured Arcium authority mode"
    );

    let wal = if let Some(snapshot_store) = snapshot_store.clone() {
        let wal_prefix =
            env::var("SUBLY402_WAL_PREFIX").unwrap_or_else(|_| format!("wal/{vault_config}"));
        Arc::new(
            Wal::new_with_snapshot_store(
                PathBuf::from(&wal_path),
                bootstrap.storage_key,
                snapshot_store,
                wal_prefix,
            )
            .await,
        )
    } else {
        Arc::new(Wal::new_with_key(PathBuf::from(&wal_path), bootstrap.storage_key).await)
    };
    let deposit_detector = Arc::new(DepositDetector::new(
        solana.vault_token_account,
        solana.program_id,
        solana.rpc_url.clone(),
        solana.ws_url.clone(),
        outbound,
    ));

    let watchtower_url = env::var("SUBLY402_WATCHTOWER_URL")
        .expect("SUBLY402_WATCHTOWER_URL must be set for Phase 4 receipt mirroring");
    ensure_watchtower_ready(&watchtower_url, outbound)
        .await
        .expect("watchtower health check must succeed before enclave starts serving");
    let batch_privacy = batch::BatchPrivacyConfig::from_env();
    let manifest_hash = env::var("SUBLY402_MANIFEST_HASH_HEX").ok();

    let tls_runtime = tls::TlsRuntime::from_env().expect("TLS configuration must be valid");
    if !bootstrap.attestation.is_local_dev
        && tls_runtime
            .as_ref()
            .and_then(|runtime| runtime.binding())
            .is_none()
    {
        panic!("non-local attested runtime requires enclave TLS with attested public key binding");
    }
    let provider_mtls_enabled = tls_runtime
        .as_ref()
        .map(|runtime| runtime.mtls_enabled())
        .unwrap_or(false);
    let attestation_provider = Arc::new(
        attestation::AttestationProvider::from_bootstrap_bundle(
            bootstrap.attestation.clone(),
            tls_runtime
                .as_ref()
                .and_then(|runtime| runtime.binding().cloned()),
            manifest_hash,
        )
        .expect("attestation provider must initialize"),
    );

    let app_state = Arc::new(AppState {
        vault: vault_state,
        wal,
        deposit_detector: deposit_detector.clone(),
        batch_privacy,
        attestation_provider,
        asc_ops_lock: tokio::sync::Mutex::new(()),
        persistence_lock: tokio::sync::Mutex::new(()),
        watchtower_url: Some(watchtower_url),
        attestation_document: bootstrap.attestation.document_b64,
        attestation_is_local_dev: bootstrap.attestation.is_local_dev,
        provider_mtls_enabled,
        outbound,
        arcium_grant_decryptor,
        arcium_mxe_public_key,
        arcium_domain_hashes,
    });

    let snapshot_manager = snapshot_store
        .clone()
        .and_then(|client| SnapshotManager::from_env(client, bootstrap.storage_key, vault_config))
        .map(Arc::new);
    let enable_provider_registration_api =
        read_env_bool("SUBLY402_ENABLE_PROVIDER_REGISTRATION_API");
    let enable_admin_api = read_env_bool("SUBLY402_ENABLE_ADMIN_API");

    let replay_from = if let Some(manager) = snapshot_manager.as_ref() {
        manager
            .recover_latest(&app_state)
            .await
            .expect("snapshot recovery must succeed")
    } else {
        None
    };

    wal::replay_app_state_from(&app_state, replay_from)
        .await
        .expect("WAL replay must succeed on startup");

    // Spawn background tasks (batch settlement, reservation expiry)
    batch::spawn_background_tasks(app_state.clone());

    // Spawn deposit detection (monitors on-chain deposits to update client balances)
    deposit_detector::spawn_deposit_detector(app_state.clone(), deposit_detector);

    if let Some(manager) = snapshot_manager {
        manager.spawn_background_task(app_state.clone());
    }

    let mut app = Router::new()
        .route("/v1/attestation", get(handlers::get_attestation))
        .route("/v1/verify", post(handlers::post_verify))
        .route("/v1/settle", post(handlers::post_settle))
        .route(
            "/v1/settlement/status",
            post(handlers::post_settlement_status),
        )
        .route("/v1/cancel", post(handlers::post_cancel))
        .route("/v1/withdraw-auth", post(handlers::post_withdraw_auth))
        .route("/v1/balance", post(handlers::post_balance))
        .route("/v1/receipt", post(handlers::post_receipt))
        // Phase 3: ASC channel endpoints
        .route("/v1/channel/open", post(handlers::post_channel_open))
        .route("/v1/channel/request", post(handlers::post_channel_request))
        .route("/v1/channel/deliver", post(handlers::post_channel_deliver))
        .route(
            "/v1/channel/finalize",
            post(handlers::post_channel_finalize),
        )
        .route("/v1/channel/close", post(handlers::post_channel_close));
    if enable_provider_registration_api {
        let provider_registration_routes = Router::new()
            .route(
                "/v1/provider/register",
                post(handlers::post_register_provider),
            )
            .route_layer(middleware::from_fn(admin_auth::require_admin_auth));
        app = app.merge(provider_registration_routes);
    }
    if enable_admin_api {
        let admin_routes = Router::new()
            .route("/v1/admin/seed-balance", post(handlers::post_seed_balance))
            .route(
                "/v1/admin/arcium/mode",
                post(handlers::post_set_arcium_mode),
            )
            .route(
                "/v1/admin/arcium/budget-grant",
                post(handlers::post_load_arcium_budget_grant),
            )
            .route(
                "/v1/admin/arcium/budget-grant-encrypted",
                post(handlers::post_load_encrypted_arcium_budget_grant),
            )
            .route(
                "/v1/admin/arcium/withdrawal-grant",
                post(handlers::post_load_arcium_withdrawal_grant),
            )
            .route(
                "/v1/admin/arcium/withdrawal-grant-encrypted",
                post(handlers::post_load_encrypted_arcium_withdrawal_grant),
            )
            .route("/v1/admin/fire-batch", post(handlers::post_fire_batch))
            .route_layer(middleware::from_fn(admin_auth::require_admin_auth));
        app = app.merge(admin_routes);
    }
    let app = app.with_state(app_state);

    let bind_label = match parent_interconnect.mode() {
        interconnect::InterconnectMode::Tcp => listen_addr.clone(),
        interconnect::InterconnectMode::Vsock => format!("vsock:{ingress_port}"),
    };
    info!(
        addr = %bind_label,
        interconnect = parent_interconnect.mode().label(),
        vault_config = %vault_config,
        program_id = %solana.program_id,
        provider_registration_api = enable_provider_registration_api,
        admin_api = enable_admin_api,
        "Enclave facilitator starting"
    );

    let listener =
        interconnect::bind_ingress_listener(parent_interconnect.mode(), &listen_addr, ingress_port)
            .await
            .unwrap();
    tls::serve(listener, app, tls_runtime).await.unwrap();
}

async fn ensure_watchtower_ready(url: &str, outbound: OutboundTransport) -> Result<(), String> {
    let status_url = format!("{url}/v1/status");
    let (status, _) = outbound
        .get_json::<serde_json::Value>(&status_url)
        .await
        .map_err(|error| format!("failed to reach watchtower at {status_url}: {error}"))?;
    if !status.is_success() {
        return Err(format!(
            "watchtower health check returned status {}",
            status
        ));
    }
    Ok(())
}

fn read_pubkey_env(name: &str, default: Pubkey) -> Pubkey {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be a valid Pubkey"))
        })
        .unwrap_or(default)
}

fn read_env_u32(name: &str, default: u32) -> u32 {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be a valid u32"))
        })
        .unwrap_or(default)
}

fn read_env_bool(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}
