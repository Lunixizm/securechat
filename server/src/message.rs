use std::fs::OpenOptions;
use std::io::Write;
use chrono::Utc;
use uuid::Uuid;

pub fn log_message(sender_id: Uuid, recipient_id: Uuid, message: &str) {
    let now = Utc::now();
    let log_entry = format!(
        "[{}] From: {} To: {} | {}\n",
        now.format("%Y-%m-%d %H:%M:%S"),
        sender_id,
        recipient_id,
        message
    );
    
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("messages.log")
    {
        let _ = file.write_all(log_entry.as_bytes());
    } else {
        // If can't write to file, log to console
        println!("Failed to write to log file: {}", log_entry);
    }
}

// server/src/api.rs
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json, Router,
    routing::{get, post},
    middleware,
};
use serde::{Deserialize, Serialize};
use shared::models::{Command, Response, User};
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use crate::{
    auth::{generate_token, validate_token},
    db::{self, DbPool},
    encryption::{process_incoming_message, process_outgoing_message},
    message::log_message,
};

// Middleware for authentication
async fn auth_middleware(
    token: String,
    State(pool): State<DbPool>,
) -> Result<Uuid, (StatusCode, Json<Response>)> {
    match validate_token(&token) {
        Ok(user_id) => Ok(user_id),
        Err(_) => Err((
            StatusCode::UNAUTHORIZED,
            Json(Response::Error("Invalid token".to_string())),
        )),
    }
}

pub fn create_router(pool: DbPool) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/users", get(get_users))
        .route("/messages", get(get_messages).post(send_message))
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::permissive())
        )
        .with_state(pool)
}

async fn health_check() -> &'static str {
    "Server is running"
}

async fn register(
    State(pool): State<DbPool>,
    Json(command): Json<Command>,
) -> Result<Json<Response>, (StatusCode, Json<Response>)> {
    if let Command::Register { username, public_key } = command {
        // Check if username already exists
        if let Ok(Some(_)) = db::get_user_by_username(&pool, &username).await {
            return Err((
                StatusCode::CONFLICT,
                Json(Response::Error("Username already exists".to_string())),
            ));
        }
        
        // Create new user
        match db::create_user(&pool, &username, &public_key).await {
            Ok(user) => {
                // Generate auth token
                let token = generate_token(user.id)
                    .map_err(|_| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(Response::Error("Failed to generate token".to_string())),
                        )
                    })?;
                
                Ok(Json(Response::UserRegistered {
                    user_id: user.id,
                    token,
                }))
            }
            Err(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Response::Error("Failed to create user".to_string())),
            )),
        }
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(Response::Error("Invalid command".to_string())),
        ))
    }
}

async fn login(
    State(pool): State<DbPool>,
    Json(command): Json<Command>,
) -> Result<Json<Response>, (StatusCode, Json<Response>)> {
    if let Command::Login { username, signature } = command {
        // Get user by username
        let user = match db::get_user_by_username(&pool, &username).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(Response::Error("User not found".to_string())),
                ));
            }
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Response::Error("Database error".to_string())),
                ));
            }
        };
        
        // Verify signature (in real app, we'd need a challenge-response mechanism)
        // For simplicity, we're just checking that signature exists
        if signature.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(Response::Error("Invalid signature".to_string())),
            ));
        }
        
        // Generate token
        let token = generate_token(user.id)
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Response::Error("Failed to generate token".to_string())),
                )
            })?;
        
        Ok(Json(Response::LoggedIn {
            user_id: user.id,
            token,
        }))
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(Response::Error("Invalid command".to_string())),
        ))
    }
}

async fn get_users(
    State(pool): State<DbPool>,
) -> Result<Json<Response>, (StatusCode, Json<Response>)> {
    match db::get_all_users(&pool).await {
        Ok(users) => Ok(Json(Response::Users(users))),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Response::Error("Failed to get users".to_string())),
        )),
    }
}

async fn get_messages(
    State(pool): State<DbPool>,
    token: String,
) -> Result<Json<Response>, (StatusCode, Json<Response>)> {
    // Validate token
    let user_id = auth_middleware(token, State(pool.clone())).await?;
    
    // Get messages for user
    match db::get_messages_for_user(&pool, user_id).await {
        Ok(messages) => Ok(Json(Response::Messages(messages))),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Response::Error("Failed to get messages".to_string())),
        )),
    }
}

async fn send_message(
    State(pool): State<DbPool>,
    token: String,
    Json(command): Json<Command>,
) -> Result<Json<Response>, (StatusCode, Json<Response>)> {
    // Validate token
    let sender_id = auth_middleware(token, State(pool.clone())).await?;
    
    if let Command::SendMessage { recipient, content, signature } = command {
        // Get recipient user by username
        let recipient_user = match db::get_user_by_username(&pool, &recipient).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(Response::Error("Recipient not found".to_string())),
                ));
            }
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Response::Error("Database error".to_string())),
                ));
            }
        };
        
        // Get sender user info to verify signature
        let sender = match db::get_user_by_username(&pool, &recipient).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(Response::Error("Sender not found".to_string())),
                ));
            }
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Response::Error("Database error".to_string())),
                ));
            }
        };
        
        // Server key (in a real application, would be properly managed)
        let server_key = b"server_encryption_key_please_change_me_and_manage_properly";
        
        // Process message (decrypt, log, re-encrypt)
        match process_incoming_message(&content, &signature, &sender.public_key, server_key) {
            Ok(decrypted) => {
                // Log the message
                log_message(sender_id, recipient_user.id, &String::from_utf8_lossy(&decrypted));
                
                // Re-encrypt for recipient
                match process_outgoing_message(&decrypted, &recipient_user.public_key) {
                    Ok(encrypted_for_recipient) => {
                        // Save message to database
                        match db::save_message(
                            &pool,
                            sender_id,
                            recipient_user.id,
                            &encrypted_for_recipient,
                            &signature,
                        ).await {
                            Ok(message) => Ok(Json(Response::MessageSent {
                                message_id: message.id,
                            })),
                            Err(_) => Err((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(Response::Error("Failed to save message".to_string())),
                            )),
                        }
                    }
                    Err(_) => Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(Response::Error("Failed to process message for recipient".to_string())),
                    )),
                }
            }
            Err(_) => Err((
                StatusCode::BAD_REQUEST,
                Json(Response::Error("Invalid message".to_string())),
            )),
        }
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(Response::Error("Invalid command".to_string())),
        ))
    }
}