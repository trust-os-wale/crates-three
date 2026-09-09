use common::errors::{GrcError, Result};
use hmac::{Hmac, Mac};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

pub struct SovereignCrypto;

impl SovereignCrypto {
    pub fn generate_key(length: usize) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut key = vec![0u8; length];
        rng.fill(&mut key)
            .map_err(|e| GrcError::CryptoError(format!("RNG failure: {}", e)))?;
        Ok(key)
    }

    pub fn sha256(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    pub fn sha512(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| GrcError::CryptoError(format!("HMAC key error: {}", e)))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha512::new_from_slice(key)
            .map_err(|e| GrcError::CryptoError(format!("HMAC key error: {}", e)))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

pub struct Aes256GcmEncryptor {
    key: LessSafeKey,
}

impl Aes256GcmEncryptor {
    pub fn new(key_bytes: &[u8]) -> Result<Self> {
        let unbound = UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|e| GrcError::CryptoError(format!("Key setup failed: {}", e)))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|e| GrcError::CryptoError(format!("Nonce generation failed: {}", e)))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| GrcError::CryptoError(format!("Encryption failed: {}", e)))?;

        Ok((nonce_bytes.to_vec(), in_out))
    }

    pub fn decrypt(&self, nonce_bytes: &[u8], ciphertext: &mut [u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::assume_unique_for_key(
            nonce_bytes
                .try_into()
                .map_err(|_| GrcError::CryptoError("Invalid nonce length".into()))?,
        );

        self.key
            .open_in_place(nonce, Aad::empty(), ciphertext)
            .map_err(|e| GrcError::CryptoError(format!("Decryption failed: {}", e)))
            .map(|plaintext| plaintext.to_vec())
    }
}

pub struct KeyDerivation;

impl KeyDerivation {
    pub fn derive_tenant_key(tenant_id: &str, master_key: &[u8]) -> Result<Vec<u8>> {
        SovereignCrypto::hmac_sha256(master_key, tenant_id.as_bytes())
    }

    pub fn derive_entity_key(
        tenant_id: &str,
        entity_id: &str,
        master_key: &[u8],
    ) -> Result<Vec<u8>> {
        let combined = format!("{}:{}", tenant_id, entity_id);
        SovereignCrypto::hmac_sha256(master_key, combined.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = SovereignCrypto::generate_key(32).unwrap();
        let encryptor = Aes256GcmEncryptor::new(&key).unwrap();
        let plaintext = b"sensitive governance data";
        let (nonce, mut ciphertext) = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&nonce, &mut ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hmac_deterministic() {
        let key = b"test-key";
        let data = b"governance-event";
        let hash1 = SovereignCrypto::hmac_sha256(key, data).unwrap();
        let hash2 = SovereignCrypto::hmac_sha256(key, data).unwrap();
        assert_eq!(hash1, hash2);
    }
}
