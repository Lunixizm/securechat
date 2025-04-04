use shared::crypto::{decrypt_message, encrypt_message, verify_signature};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerCryptoError {
    #[error("Crypto error: {0}")]
    CryptoError(#[from] shared::crypto::CryptoError),
    #[error("Invalid message format")]
    InvalidMessageFormat,
}

pub fn process_incoming_message(
    encrypted_content: &[u8],
    signature: &[u8],
    sender_public_key: &[u8],
    server_key: &[u8],
) -> Result<Vec<u8>, ServerCryptoError> {
    // First verify the signature
    verify_signature(encrypted_content, signature, sender_public_key)
        .map_err(ServerCryptoError::CryptoError)?;
    
    // Decrypt the message using server key
    let decrypted = decrypt_message(encrypted_content, server_key)
        .map_err(ServerCryptoError::CryptoError)?;
    
    // Log the message content (in a real app, you'd save to DB or monitoring system)
    tracing::info!("Decrypted message: {}", String::from_utf8_lossy(&decrypted));
    
    Ok(decrypted)
}

pub fn process_outgoing_message(
    message_content: &[u8],
    recipient_public_key: &[u8],
) -> Result<Vec<u8>, ServerCryptoError> {
    // Encrypt the message for the recipient
    let encrypted = encrypt_message(message_content, recipient_public_key)
        .map_err(ServerCryptoError::CryptoError)?;
    
    Ok(encrypted)
}