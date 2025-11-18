use aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use rand_core::{OsRng, TryRngCore};
use sha2::Sha256;
use thiserror::Error;
use x_wing::{generate_key_pair_from_os_rng, Ciphertext, DecapsulationKey, EncapsulationKey};

#[derive(Error, Debug)]
pub enum HybridCryptoError {
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("KEM encapsulation failed: {0}")]
    KemEncapsulation(String),
    #[error("KEM decapsulation failed: {0}")]
    KemDecapsulation(String),
}

pub struct HybridCrypto {
    decap_key: DecapsulationKey,
    encap_key: EncapsulationKey,
}

pub struct EncryptedMessage {
    kem_ciphertext: Vec<u8>,
    aead_ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    tag: Vec<u8>,
}

impl HybridCrypto {
    pub fn generate_keypair() -> Result<Self, HybridCryptoError> {
        let (decap_key, encap_key) = generate_key_pair_from_os_rng();

        Ok(Self {
            decap_key,
            encap_key,
        })
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedMessage, HybridCryptoError> {
        let mut rng = OsRng;

        let (kem_ciphertext, shared_secret) = self
            .encap_key
            .encapsulate(&mut rng)
            .map_err(|e| HybridCryptoError::KemEncapsulation(format!("{:?}", e)))?;

        let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut aead_key_bytes = [0u8; 32]; // ChaCha20Poly1305 uses 256-bit keys
        hkdf.expand(b"X-Wing ChaCha20Poly1305 AEAD Key", &mut aead_key_bytes)
            .map_err(|e| HybridCryptoError::Encryption(format!("HKDF error: {:?}", e)))?;

        let aead_key = chacha20poly1305::Key::from_slice(&aead_key_bytes);
        let cipher = ChaCha20Poly1305::new(&aead_key);

        let mut nonce_bytes = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|e| HybridCryptoError::Encryption(format!("RNG error: {:?}", e)))?;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
        let aead_ciphertext_with_tag = cipher
            .encrypt(
                &nonce,
                aead::Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|e| HybridCryptoError::Encryption(e.to_string()))?;

        let tag_size = 16;
        let ciphertext_len = aead_ciphertext_with_tag.len();
        if ciphertext_len < tag_size {
            return Err(HybridCryptoError::InvalidFormat);
        }
        let (aead_ciphertext, tag) = aead_ciphertext_with_tag.split_at(ciphertext_len - tag_size);

        Ok(EncryptedMessage {
            kem_ciphertext: kem_ciphertext.to_bytes().to_vec(),
            aead_ciphertext: aead_ciphertext.to_vec(),
            nonce: nonce.to_vec(),
            tag: tag.to_vec(),
        })
    }

    pub fn decrypt(
        &self,
        encrypted_message: &EncryptedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, HybridCryptoError> {
        let kem_bytes: &[u8; 1120] = encrypted_message
            .kem_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| HybridCryptoError::InvalidFormat)?;
        let kem_ciphertext = Ciphertext::from(kem_bytes);

        let shared_secret = self
            .decap_key
            .decapsulate(&kem_ciphertext)
            .map_err(|e| HybridCryptoError::KemDecapsulation(format!("{:?}", e)))?;

        let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut aead_key_bytes = [0u8; 32]; // ChaCha20Poly1305 uses 256-bit keys
        hkdf.expand(b"X-Wing ChaCha20Poly1305 AEAD Key", &mut aead_key_bytes)
            .map_err(|e| HybridCryptoError::Decryption(format!("HKDF error: {:?}", e)))?;

        let aead_key = chacha20poly1305::Key::from_slice(&aead_key_bytes);
        let cipher = ChaCha20Poly1305::new(&aead_key);

        let nonce = chacha20poly1305::Nonce::from_slice(&encrypted_message.nonce);
        let mut full_ciphertext = encrypted_message.aead_ciphertext.clone();
        full_ciphertext.extend_from_slice(&encrypted_message.tag);

        let plaintext = cipher
            .decrypt(
                &nonce,
                aead::Payload {
                    msg: &full_ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| HybridCryptoError::AuthenticationFailed)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_encryption() {
        let alice = HybridCrypto::generate_keypair().unwrap();
        let plaintext = b"Secret message";
        let associated_data = b"Auth data";

        let encrypted = alice.encrypt(plaintext, associated_data).unwrap();
        let decrypted = alice.decrypt(&encrypted, associated_data).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_tampering_detection() {
        let alice = HybridCrypto::generate_keypair().unwrap();
        let plaintext = b"Important message";
        let aad = b"Auth data";

        let mut encrypted = alice.encrypt(plaintext, aad).unwrap();
        encrypted.aead_ciphertext[0] ^= 0x01;

        assert!(alice.decrypt(&encrypted, aad).is_err());
    }
}

fn main() {
    println!("Hybrid Encryption Demo (X-Wing Concept)");
    println!("==========================================");

    let alice = HybridCrypto::generate_keypair().expect("Failed to generate key pair");
    println!("✓ Generated key pair");

    let message = "Hello, post-quantum world! This demonstrates X-Wing hybrid encryption.";
    let associated_data = "Message metadata";

    println!("\nOriginal message: {}", message);
    println!("Associated data: {}", associated_data);

    let encrypted = alice
        .encrypt(message.as_bytes(), associated_data.as_bytes())
        .expect("Failed to encrypt message");

    println!("✓ Encrypted message");
    println!(
        "  - X-Wing ciphertext: {} bytes",
        encrypted.kem_ciphertext.len()
    );
    println!(
        "  - AEAD ciphertext: {} bytes",
        encrypted.aead_ciphertext.len()
    );
    println!("  - Nonce: {} bytes", encrypted.nonce.len());
    println!("  - Tag: {} bytes", encrypted.tag.len());

    let decrypted = alice
        .decrypt(&encrypted, associated_data.as_bytes())
        .expect("Failed to decrypt message");

    let decrypted_message = String::from_utf8(decrypted).expect("Invalid UTF-8");
    println!("\nDecrypted message: {}", decrypted_message);

    assert_eq!(message, decrypted_message);
    println!("✓ Message integrity verified!");
}
