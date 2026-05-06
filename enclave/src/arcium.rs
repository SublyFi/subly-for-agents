use arcis_compiler::traits::FromLeBytes;
use arcis_compiler::utils::crypto::key::{X25519PrivateKey, X25519PublicKey};
use arcis_compiler::utils::crypto::rescue_cipher::RescueCipher;
use arcis_compiler::utils::curve_point::CurvePoint;
use arcis_compiler::utils::field::{BaseField, ScalarField};
use arcis_compiler::utils::number::Number;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::env;

const BUDGET_GRANT_VIEW_SCALARS: usize = 15;
const WITHDRAWAL_GRANT_VIEW_SCALARS: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArciumDomainHashParts {
    pub lo: u128,
    pub hi: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArciumGrantDomainHashes {
    pub authorize_budget: ArciumDomainHashParts,
    pub authorize_withdrawal: ArciumDomainHashParts,
}

#[derive(Clone)]
pub struct ArciumGrantDecryptor {
    tee_private_key: [u8; 32],
    tee_public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArciumBudgetGrantView {
    pub approved: bool,
    pub budget_id: u64,
    pub request_nonce: u64,
    pub amount: u64,
    pub remaining: u64,
    pub expires_at: u64,
    pub state_version: u64,
    pub domain_hash_lo: u128,
    pub domain_hash_hi: u128,
    pub vault_config_lo: u128,
    pub vault_config_hi: u128,
    pub client_lo: u128,
    pub client_hi: u128,
    pub budget_grant_lo: u128,
    pub budget_grant_hi: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArciumWithdrawalGrantView {
    pub approved: bool,
    pub withdrawal_id: u64,
    pub amount: u64,
    pub expires_at: u64,
    pub state_version: u64,
    pub domain_hash_lo: u128,
    pub domain_hash_hi: u128,
    pub vault_config_lo: u128,
    pub vault_config_hi: u128,
    pub client_lo: u128,
    pub client_hi: u128,
    pub withdrawal_grant_lo: u128,
    pub withdrawal_grant_hi: u128,
    pub recipient_lo: u128,
    pub recipient_hi: u128,
}

impl ArciumGrantDecryptor {
    pub fn from_env() -> Result<Option<Self>, String> {
        let private_key = match env::var("SUBLY402_ARCIUM_TEE_X25519_PRIVATE_KEY_HEX")
            .ok()
            .or_else(|| env::var("SUBLY402_ARCIUM_TEE_X25519_PRIVATE_KEY_B64").ok())
        {
            Some(value) => decode_key_bytes("SUBLY402_ARCIUM_TEE_X25519_PRIVATE_KEY", &value)?,
            None => return Ok(None),
        };
        Self::new(private_key).map(Some)
    }

    pub fn new(tee_private_key: [u8; 32]) -> Result<Self, String> {
        let tee_public_key = public_key_from_private_key(tee_private_key);
        Ok(Self {
            tee_private_key,
            tee_public_key,
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.tee_public_key
    }

    pub fn decrypt_budget_grant_view(
        &self,
        tee_public_key: [u8; 32],
        mxe_public_key: [u8; 32],
        ciphertexts: &[[u8; 32]],
        nonce: [u8; 16],
    ) -> Result<ArciumBudgetGrantView, String> {
        self.require_expected_public_key(tee_public_key)?;
        let values = self.decrypt_scalars(
            mxe_public_key,
            ciphertexts,
            nonce,
            BUDGET_GRANT_VIEW_SCALARS,
        )?;
        Ok(ArciumBudgetGrantView {
            approved: field_to_bool(values[0], "approved")?,
            budget_id: field_to_u64(values[1], "budgetId")?,
            request_nonce: field_to_u64(values[2], "requestNonce")?,
            amount: field_to_u64(values[3], "amount")?,
            remaining: field_to_u64(values[4], "remaining")?,
            expires_at: field_to_u64(values[5], "expiresAt")?,
            state_version: field_to_u64(values[6], "stateVersion")?,
            domain_hash_lo: field_to_u128(values[7], "domainHashLo")?,
            domain_hash_hi: field_to_u128(values[8], "domainHashHi")?,
            vault_config_lo: field_to_u128(values[9], "vaultConfigLo")?,
            vault_config_hi: field_to_u128(values[10], "vaultConfigHi")?,
            client_lo: field_to_u128(values[11], "clientLo")?,
            client_hi: field_to_u128(values[12], "clientHi")?,
            budget_grant_lo: field_to_u128(values[13], "budgetGrantLo")?,
            budget_grant_hi: field_to_u128(values[14], "budgetGrantHi")?,
        })
    }

    pub fn decrypt_withdrawal_grant_view(
        &self,
        tee_public_key: [u8; 32],
        mxe_public_key: [u8; 32],
        ciphertexts: &[[u8; 32]],
        nonce: [u8; 16],
    ) -> Result<ArciumWithdrawalGrantView, String> {
        self.require_expected_public_key(tee_public_key)?;
        let values = self.decrypt_scalars(
            mxe_public_key,
            ciphertexts,
            nonce,
            WITHDRAWAL_GRANT_VIEW_SCALARS,
        )?;
        Ok(ArciumWithdrawalGrantView {
            approved: field_to_bool(values[0], "approved")?,
            withdrawal_id: field_to_u64(values[1], "withdrawalId")?,
            amount: field_to_u64(values[2], "amount")?,
            expires_at: field_to_u64(values[3], "expiresAt")?,
            state_version: field_to_u64(values[4], "stateVersion")?,
            domain_hash_lo: field_to_u128(values[5], "domainHashLo")?,
            domain_hash_hi: field_to_u128(values[6], "domainHashHi")?,
            vault_config_lo: field_to_u128(values[7], "vaultConfigLo")?,
            vault_config_hi: field_to_u128(values[8], "vaultConfigHi")?,
            client_lo: field_to_u128(values[9], "clientLo")?,
            client_hi: field_to_u128(values[10], "clientHi")?,
            withdrawal_grant_lo: field_to_u128(values[11], "withdrawalGrantLo")?,
            withdrawal_grant_hi: field_to_u128(values[12], "withdrawalGrantHi")?,
            recipient_lo: field_to_u128(values[13], "recipientLo")?,
            recipient_hi: field_to_u128(values[14], "recipientHi")?,
        })
    }

    fn decrypt_scalars(
        &self,
        mxe_public_key: [u8; 32],
        ciphertexts: &[[u8; 32]],
        nonce: [u8; 16],
        expected_len: usize,
    ) -> Result<Vec<BaseField>, String> {
        if ciphertexts.len() != expected_len {
            return Err(format!(
                "expected {expected_len} Arcium ciphertexts, got {}",
                ciphertexts.len()
            ));
        }
        let peer_public_key = X25519PublicKey::<CurvePoint>::from_le_bytes(mxe_public_key)
            .ok_or_else(|| "invalid Arcium MXE x25519 public key".to_string())?;
        let private_key = X25519PrivateKey::<ScalarField>::from_le_bytes(self.tee_private_key);
        let cipher = RescueCipher::<BaseField, BaseField>::new_with_client_from_keys::<
            BaseField,
            ScalarField,
            CurvePoint,
        >(private_key, peer_public_key);
        let fields = ciphertexts
            .iter()
            .enumerate()
            .map(|(index, ciphertext)| {
                BaseField::from_le_bytes_checked(*ciphertext)
                    .ok_or_else(|| format!("ciphertexts[{index}] is not a valid field element"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(cipher.decrypt(fields, field_from_u128(u128::from_le_bytes(nonce))))
    }

    fn require_expected_public_key(&self, expected: [u8; 32]) -> Result<(), String> {
        if self.tee_public_key != expected {
            return Err("TEE x25519 public key does not match enclave private key".to_string());
        }
        Ok(())
    }
}

pub fn mxe_public_key_from_env() -> Result<Option<[u8; 32]>, String> {
    match env::var("SUBLY402_ARCIUM_MXE_PUBLIC_KEY_HEX")
        .ok()
        .or_else(|| env::var("SUBLY402_ARCIUM_MXE_PUBLIC_KEY_B64").ok())
    {
        Some(value) => decode_key_bytes("SUBLY402_ARCIUM_MXE_PUBLIC_KEY", &value).map(Some),
        None => Ok(None),
    }
}

pub fn grant_domain_hashes_from_env() -> Result<Option<ArciumGrantDomainHashes>, String> {
    let authorize_budget =
        domain_hash_parts_from_env("SUBLY402_ARCIUM_AUTHORIZE_BUDGET_DOMAIN_HASH")?;
    let authorize_withdrawal =
        domain_hash_parts_from_env("SUBLY402_ARCIUM_AUTHORIZE_WITHDRAWAL_DOMAIN_HASH")?;
    match (authorize_budget, authorize_withdrawal) {
        (None, None) => Ok(None),
        (Some(authorize_budget), Some(authorize_withdrawal)) => Ok(Some(ArciumGrantDomainHashes {
            authorize_budget,
            authorize_withdrawal,
        })),
        _ => Err(
            "SUBLY402_ARCIUM_AUTHORIZE_BUDGET_DOMAIN_HASH_* and SUBLY402_ARCIUM_AUTHORIZE_WITHDRAWAL_DOMAIN_HASH_* must be configured together"
                .to_string(),
        ),
    }
}

fn decode_key_bytes(name: &str, value: &str) -> Result<[u8; 32], String> {
    let normalized = value.trim();
    let bytes = if normalized.len() == 64 && normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        hex::decode(normalized).map_err(|error| format!("invalid {name} hex: {error}"))?
    } else {
        BASE64
            .decode(normalized)
            .map_err(|error| format!("invalid {name} base64: {error}"))?
    };
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{name} must decode to 32 bytes, got {}", bytes.len()))
}

fn domain_hash_parts_from_env(prefix: &str) -> Result<Option<ArciumDomainHashParts>, String> {
    let lo_name = format!("{prefix}_LO");
    let hi_name = format!("{prefix}_HI");
    match (env::var(&lo_name).ok(), env::var(&hi_name).ok()) {
        (None, None) => Ok(None),
        (Some(lo), Some(hi)) => Ok(Some(ArciumDomainHashParts {
            lo: parse_u128_env(&lo_name, &lo)?,
            hi: parse_u128_env(&hi_name, &hi)?,
        })),
        _ => Err(format!(
            "{lo_name} and {hi_name} must be configured together"
        )),
    }
}

fn parse_u128_env(name: &str, value: &str) -> Result<u128, String> {
    let normalized = value.trim();
    if let Some(hex) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
    {
        return u128::from_str_radix(hex, 16).map_err(|error| format!("invalid {name}: {error}"));
    }
    normalized
        .parse::<u128>()
        .map_err(|error| format!("invalid {name}: {error}"))
}

fn public_key_from_private_key(private_key: [u8; 32]) -> [u8; 32] {
    X25519PublicKey::<CurvePoint>::new_from_private_key(
        X25519PrivateKey::<ScalarField>::from_le_bytes(private_key),
    )
    .to_le_bytes()
}

fn field_from_u128(value: u128) -> BaseField {
    BaseField::from(Number::from(value))
}

fn field_to_bool(value: BaseField, field: &str) -> Result<bool, String> {
    match field_to_u64(value, field)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(format!("{field} must be 0 or 1, got {other}")),
    }
}

fn field_to_u64(value: BaseField, field: &str) -> Result<u64, String> {
    let bytes = value.to_le_bytes();
    if bytes[8..].iter().any(|byte| *byte != 0) {
        return Err(format!("{field} is out of u64 range"));
    }
    Ok(u64::from_le_bytes(
        bytes[..8].try_into().expect("u64 byte slice length"),
    ))
}

fn field_to_u128(value: BaseField, field: &str) -> Result<u128, String> {
    let bytes = value.to_le_bytes();
    if bytes[16..].iter().any(|byte| *byte != 0) {
        return Err(format!("{field} is out of u128 range"));
    }
    Ok(u128::from_le_bytes(
        bytes[..16].try_into().expect("u128 byte slice length"),
    ))
}

#[cfg(test)]
pub fn public_key_from_private_key_for_test(private_key: [u8; 32]) -> [u8; 32] {
    public_key_from_private_key(private_key)
}

#[cfg(test)]
pub fn encrypt_shared_scalars_for_test(
    sender_private_key: [u8; 32],
    receiver_public_key: [u8; 32],
    plaintexts: &[u128],
    nonce: [u8; 16],
) -> Vec<[u8; 32]> {
    let receiver_public_key = X25519PublicKey::<CurvePoint>::from_le_bytes(receiver_public_key)
        .expect("receiver public key must be valid");
    let sender_private_key = X25519PrivateKey::<ScalarField>::from_le_bytes(sender_private_key);
    let cipher = RescueCipher::<BaseField, BaseField>::new_with_client_from_keys::<
        BaseField,
        ScalarField,
        CurvePoint,
    >(sender_private_key, receiver_public_key);
    cipher
        .encrypt(
            plaintexts.iter().copied().map(field_from_u128).collect(),
            field_from_u128(u128::from_le_bytes(nonce)),
        )
        .into_iter()
        .map(|field| field.to_le_bytes())
        .collect()
}
