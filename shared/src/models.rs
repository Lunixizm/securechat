use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: Uuid,
    pub sender_id: Uuid,
    pub recipient_id: Uuid,
    pub content: Vec<u8>, // Encrypted content
    pub timestamp: DateTime<Utc>,
    pub signature: Vec<u8>, // Digital signature
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    Register { username: String, public_key: Vec<u8> },
    Login { username: String, signature: Vec<u8> },
    SendMessage { recipient: String, content: Vec<u8>, signature: Vec<u8> },
    GetMessages,
    GetUsers,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Success,
    Error(String),
    UserRegistered { user_id: Uuid, token: String },
    LoggedIn { user_id: Uuid, token: String },
    MessageSent { message_id: Uuid },
    Messages(Vec<Message>),
    Users(Vec<User>),
}