//! Envelope encryption for multi-recipient secret sharing.
//!
//! This implements a hybrid cryptographic approach that combines symmetric and asymmetric
//! encryption for efficient secret sharing with multiple recipients.
//!
//! ## Encryption (Sender Side)
//!
//! 1. Generate a random 256-bit AES symmetric key
//! 2. Encrypt the secret payload with AES-256-GCM (authenticated encryption)
//! 3. For each recipient:
//!    - Wrap the AES key using crypto_box (X25519 + XSalsa20-Poly1305)
//!    - This creates an encrypted copy of the symmetric key that only that recipient can unwrap
//!
//! Result: One ciphertext (shared by all) + one wrapped key per recipient
//!
//! ## Decryption (Recipient Side)
//!
//! 1. Unwrap the symmetric key using recipient's secret key + sender's public key
//! 2. Decrypt the payload using the recovered AES key
//!
//! ## Why Envelope Encryption?
//!
//! - **Efficiency**: Large payloads are encrypted once with fast symmetric crypto (AES-256-GCM)
//! - **Scalability**: Adding recipients only requires wrapping the 32-byte key, not re-encrypting the payload
//! - **Security**: Combines AES (speed) with public-key crypto (key distribution)
//! - **Authenticity**: Both AES-GCM and crypto_box provide authenticated encryption (tamper detection)

use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use anyhow::{Result, anyhow};
use crypto_box::{PublicKey, SalsaBox, SecretKey};

/// The result of encrypting a secret for multiple recipients.
/// Contains the encrypted payload and per-recipient wrapped keys.
pub struct EncryptedDrop {
    /// The encrypted secret payload (same for all recipients)
    pub ciphertext: Vec<u8>,
    /// Nonce for AES-256-GCM decryption (96 bits)
    pub aes_nonce: [u8; 12],
    /// One wrapped key per recipient (order matches recipient_public_keys in encrypt_drop)
    pub wrapped_keys: Vec<WrappedKey>,
}

/// A symmetric key wrapped (encrypted) for a specific recipient.
/// Only that recipient can unwrap it using their secret key.
pub struct WrappedKey {
    /// Nonce for crypto_box decryption (192 bits)
    pub nonce: [u8; 24],
    /// The AES symmetric key, encrypted with the recipient's public key
    pub wrapped_key: Vec<u8>,
}

/// Encrypts a secret for multiple recipients using envelope encryption.
///
/// The payload is encrypted once with AES-256-GCM. The AES key is then wrapped
/// (encrypted) for each recipient using their public key. Each recipient can
/// independently unwrap the key and decrypt the payload.
///
/// The sender's secret key is used to sign the key wrapping, proving the sender's identity.
pub fn encrypt_drop(
    input: &[u8],
    sender_secret_key: &SecretKey,
    recipient_public_keys: &[PublicKey],
) -> Result<EncryptedDrop> {
    // Step 1: Encrypt the payload with a random symmetric key
    let (ciphertext, symmetric_key, aes_nonce) = encrypt_payload(input)?;

    // Step 2: Wrap the symmetric key for each recipient
    let mut wrapped_keys = Vec::new();

    for recipient_pub in recipient_public_keys {
        let (box_nonce, wrapped) = wrap_key(recipient_pub, sender_secret_key, &symmetric_key)?;

        wrapped_keys.push(WrappedKey {
            nonce: box_nonce,
            wrapped_key: wrapped,
        });
    }

    Ok(EncryptedDrop {
        ciphertext,
        aes_nonce,
        wrapped_keys,
    })
}

/// Decrypts a drop that was encrypted for this recipient.
///
/// First unwraps the symmetric key using the recipient's secret key and sender's
/// public key, then decrypts the payload with the recovered key.
///
/// The sender's public key is required to verify the sender's identity during unwrapping.
pub fn decrypt_drop(
    drop: &EncryptedDrop,
    sender_public_key: &PublicKey,
    recipient_secret_key: &SecretKey,
    my_wrapped_key: &WrappedKey,
) -> Result<Vec<u8>> {
    // Step 1: Unwrap (decrypt) the symmetric key
    let symmetric_key = unwrap_key(
        sender_public_key,
        recipient_secret_key,
        &my_wrapped_key.nonce,
        &my_wrapped_key.wrapped_key,
    )?;

    // Step 2: Decrypt the payload with the recovered key
    decrypt_payload(&drop.ciphertext, &symmetric_key, &drop.aes_nonce)
}

/// Encrypts a payload with AES-256-GCM using a randomly generated key.
/// Returns (ciphertext, symmetric_key, nonce). The symmetric key is what gets wrapped per-recipient.
fn encrypt_payload(input: &[u8]) -> Result<(Vec<u8>, [u8; 32], [u8; 12])> {
    // Generate random 256-bit symmetric key
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);

    // Generate random 96-bit nonce (unique per encryption)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AES-GCM provides authenticated encryption (confidentiality + integrity)
    let ciphertext = cipher
        .encrypt(nonce, input)
        .map_err(|e| anyhow!("encryption failed: {}", e))?;

    Ok((ciphertext, key_bytes, nonce_bytes))
}

/// Decrypts an AES-256-GCM ciphertext using the provided key and nonce.
/// Fails if the ciphertext has been tampered with (authentication check).
fn decrypt_payload(
    ciphertext: &[u8],
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
) -> Result<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce_bytes);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // AES-GCM verifies integrity - decryption fails if data was tampered with
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("decryption failed: {}", e))
}

/// Wraps (encrypts) a symmetric key for a specific recipient using crypto_box.
///
/// Uses X25519 Diffie-Hellman to derive a shared secret between sender and recipient,
/// then encrypts the key with XSalsa20-Poly1305. Only the recipient can unwrap it.
fn wrap_key(
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
    key_to_wrap: &[u8; 32],
) -> Result<([u8; 24], Vec<u8>)> {
    // Generate random 192-bit nonce for crypto_box
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = crypto_box::Nonce::from_slice(&nonce_bytes);

    // SalsaBox derives a shared secret via X25519 DH, then encrypts with XSalsa20-Poly1305
    let the_box = SalsaBox::new(recipient_public_key, sender_secret_key);
    let wrapped = the_box
        .encrypt(nonce, &key_to_wrap[..])
        .map_err(|e| anyhow!("key wrapping failed: {}", e))?;

    Ok((nonce_bytes, wrapped))
}

/// Unwraps (decrypts) a symmetric key that was wrapped for this recipient.
///
/// Uses the sender's public key and recipient's secret key to derive the same shared
/// secret that was used during wrapping, then decrypts the wrapped key.
fn unwrap_key(
    sender_public_key: &PublicKey,
    recipient_secret_key: &SecretKey,
    nonce_bytes: &[u8; 24],
    wrapped_key: &[u8],
) -> Result<[u8; 32]> {
    let nonce = crypto_box::Nonce::from_slice(nonce_bytes);

    // Note the argument order flip from wrap_key - same shared secret is derived
    let the_box = SalsaBox::new(sender_public_key, recipient_secret_key);
    let unwrapped = the_box
        .decrypt(nonce, wrapped_key)
        .map_err(|e| anyhow!("key unwrapping failed: {}", e))?;

    // Verify the unwrapped key is the expected length (32 bytes for AES-256)
    unwrapped
        .try_into()
        .map_err(|_| anyhow!("unwrapped key has incorrect length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let input = b"Hello, world!";
        let (ciphertext, key_bytes, nonce_bytes) = encrypt_payload(input).unwrap();
        let decrypted = decrypt_payload(&ciphertext, &key_bytes, &nonce_bytes).unwrap();

        assert_eq!(&input[..], &decrypted[..]);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let input = b"Hello, world!";
        let (ciphertext, _, nonce_bytes) = encrypt_payload(input).unwrap();

        let mut wrong_key = [0u8; 32];
        OsRng.fill_bytes(&mut wrong_key);

        let result = decrypt_payload(&ciphertext, &wrong_key, &nonce_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let input = b"Hello, world!";
        let (mut ciphertext, key_bytes, nonce_bytes) = encrypt_payload(input).unwrap();

        // Flip a bit in the ciphertext
        ciphertext[0] ^= 0x01;

        let result = decrypt_payload(&ciphertext, &key_bytes, &nonce_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_unwrap_key() {
        let sender_secret = SecretKey::generate(&mut OsRng);
        let sender_public = sender_secret.public_key();

        let recipient_secret = SecretKey::generate(&mut OsRng);
        let recipient_public = recipient_secret.public_key();

        let mut key_to_wrap = [0u8; 32];
        OsRng.fill_bytes(&mut key_to_wrap);

        let (nonce, wrapped) = wrap_key(&recipient_public, &sender_secret, &key_to_wrap).unwrap();
        let unwrapped = unwrap_key(&sender_public, &recipient_secret, &nonce, &wrapped).unwrap();

        assert_eq!(key_to_wrap, unwrapped);
    }

    #[test]
    fn test_unwrap_wrong_recipient_fails() {
        let sender_secret = SecretKey::generate(&mut OsRng);
        let sender_public = sender_secret.public_key();

        let recipient_secret = SecretKey::generate(&mut OsRng);
        let recipient_public = recipient_secret.public_key();

        let wrong_recipient_secret = SecretKey::generate(&mut OsRng);

        let mut key_to_wrap = [0u8; 32];
        OsRng.fill_bytes(&mut key_to_wrap);

        let (nonce, wrapped) = wrap_key(&recipient_public, &sender_secret, &key_to_wrap).unwrap();

        // Try to unwrap with the wrong recipient's key
        let result = unwrap_key(&sender_public, &wrong_recipient_secret, &nonce, &wrapped);
        assert!(result.is_err());
    }

    #[test]
    fn test_unwrap_wrong_sender_fails() {
        let sender_secret = SecretKey::generate(&mut OsRng);

        let recipient_secret = SecretKey::generate(&mut OsRng);
        let recipient_public = recipient_secret.public_key();

        let wrong_sender_public = SecretKey::generate(&mut OsRng).public_key();

        let mut key_to_wrap = [0u8; 32];
        OsRng.fill_bytes(&mut key_to_wrap);

        let (nonce, wrapped) = wrap_key(&recipient_public, &sender_secret, &key_to_wrap).unwrap();

        // Try to unwrap with the wrong sender's public key
        let result = unwrap_key(&wrong_sender_public, &recipient_secret, &nonce, &wrapped);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_drop() {
        let sender_secret = SecretKey::generate(&mut OsRng);
        let sender_public = sender_secret.public_key();

        let recipient_secret = SecretKey::generate(&mut OsRng);
        let recipient_public = recipient_secret.public_key();

        let input = b"Hello, world!";

        let encrypted = encrypt_drop(input, &sender_secret, &[recipient_public]).unwrap();

        let decrypted = decrypt_drop(
            &encrypted,
            &sender_public,
            &recipient_secret,
            &encrypted.wrapped_keys[0],
        )
        .unwrap();

        assert_eq!(&input[..], &decrypted[..]);
    }

    #[test]
    fn test_decrypt_drop_wrong_recipient_fails() {
        let sender_secret = SecretKey::generate(&mut OsRng);
        let sender_public = sender_secret.public_key();

        let recipient_secret = SecretKey::generate(&mut OsRng);
        let recipient_public = recipient_secret.public_key();

        let wrong_recipient_secret = SecretKey::generate(&mut OsRng);

        let input = b"Hello, world!";

        let encrypted = encrypt_drop(input, &sender_secret, &[recipient_public]).unwrap();

        // Try to decrypt with the wrong recipient's key
        let result = decrypt_drop(
            &encrypted,
            &sender_public,
            &wrong_recipient_secret,
            &encrypted.wrapped_keys[0],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_recipient_isolation() {
        let sender_secret = SecretKey::generate(&mut OsRng);
        let sender_public = sender_secret.public_key();

        let recipient1_secret = SecretKey::generate(&mut OsRng);
        let recipient1_public = recipient1_secret.public_key();

        let recipient2_secret = SecretKey::generate(&mut OsRng);
        let recipient2_public = recipient2_secret.public_key();

        let input = b"Hello, world!";

        let encrypted = encrypt_drop(
            input,
            &sender_secret,
            &[recipient1_public, recipient2_public],
        )
        .unwrap();

        // Recipient 1 can decrypt with their wrapped key
        let decrypted1 = decrypt_drop(
            &encrypted,
            &sender_public,
            &recipient1_secret,
            &encrypted.wrapped_keys[0],
        )
        .unwrap();
        assert_eq!(&input[..], &decrypted1[..]);

        // Recipient 2 can decrypt with their wrapped key
        let decrypted2 = decrypt_drop(
            &encrypted,
            &sender_public,
            &recipient2_secret,
            &encrypted.wrapped_keys[1],
        )
        .unwrap();
        assert_eq!(&input[..], &decrypted2[..]);

        // Recipient 1 cannot use recipient 2's wrapped key
        let result = decrypt_drop(
            &encrypted,
            &sender_public,
            &recipient1_secret,
            &encrypted.wrapped_keys[1],
        );
        assert!(result.is_err());
    }
}
