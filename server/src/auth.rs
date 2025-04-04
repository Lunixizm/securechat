use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use once_cell::sync::Lazy;

pub static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    env::var("JWT_SECRET").unwrap_or_else(|_| "secret_key_please_change_in_production".to_string())
});

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User ID
    pub exp: u64,    // Expiration time
    pub iat: u64,    // Issued at
}

pub fn generate_token(user_id: Uuid) -> Result<String, jsonwebtoken::errors::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    
    let claims = Claims {
        sub: user_id.to_string(),
        exp: now + Duration::from_secs(60 * 60 * 24).as_secs(), // 24 hours
        iat: now,
    };
    
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
}

pub fn validate_token(token: &str) -> Result<Uuid, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )?;
    
    let user_id = Uuid::parse_str(&token_data.claims.sub)
        .map_err(|_| jsonwebtoken::errors::ErrorKind::InvalidToken)?;
    
    Ok(user_id)
}