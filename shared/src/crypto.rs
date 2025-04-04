use ring::{aead, digest, rand as ring_rand, signature};
use std::convert::TryInto;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("Signature error: {0}")]
    SignatureError(String),
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
}

pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Using Ed25519 for keys
    let rng = ring_rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| CryptoError::KeyGenerationError("Failed to generate key pair".into()))?;

    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|_| CryptoError::KeyGenerationError("Failed to parse key pair".into()))?;

    let public_key = key_pair.public_key().as_ref().to_vec();
    
    Ok((pkcs8_bytes.as_ref().to_vec(), public_key))
}

pub fn encrypt_message(message: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| CryptoError::EncryptionError("Invalid key for AES-256-GCM".into()))?;

    let rng = ring_rand::SystemRandom::new();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce)
        .map_err(|_| CryptoError::EncryptionError("Failed to generate nonce".into()))?;

    let sealing_key = aead::SealingKey::new(key, aead::Nonce::assume_unique_for_key(nonce));
    
    // Combine nonce and message for output
    let mut output = Vec::with_capacity(nonce.len() + message.len() + 16); // 16 bytes for tag
    output.extend_from_slice(&nonce);
    output.extend_from_slice(message);
    
    // In-place encryption on the message part
    let tag = sealing_key.seal_in_place_separate_tag(
        aead::Aad::from(&[]),
        &mut output[nonce.len()..nonce.len() + message.len()]
    ).map_err(|_| CryptoError::EncryptionError("Failed to encrypt message".into()))?;
    
    output.extend_from_slice(tag.as_ref());
    Ok(output)
}

pub fn decrypt_message(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if encrypted.len() < 12 + 16 { // nonce + tag minimum size
        return Err(CryptoError::DecryptionError("Invalid encrypted message".into()));
    }
    
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| CryptoError::DecryptionError("Invalid key for AES-256-GCM".into()))?;

    let nonce = &encrypted[..12];
    let ciphertext_and_tag = &encrypted[12..];
    
    let opening_key = aead::OpeningKey::new(
        key, 
        aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| CryptoError::DecryptionError("Invalid nonce".into()))?
    );

    let mut ciphertext = ciphertext_and_tag.to_vec();
    let plaintext = opening_key.open_in_place(aead::Aad::from(&[]), &mut ciphertext)
        .map_err(|_| CryptoError::DecryptionError("Failed to decrypt message".into()))?;
    
    Ok(plaintext.to_vec())
}

pub fn sign_message(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(private_key)
        .map_err(|_| CryptoError::SignatureError("Invalid private key".into()))?;
    
    Ok(key_pair.sign(message).as_ref().to_vec())
}

pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), CryptoError> {
    let peer_public_key = signature::UnparsedPublicKey::new(
        &signature::ED25519,
        public_key,
    );
    
    peer_public_key.verify(message, signature)
        .map_err(|_| CryptoError::SignatureError("Invalid signature".into()))?;
    
    Ok(())
}