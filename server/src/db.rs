use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use shared::models::{User, Message};
use uuid::Uuid;
use std::env;

pub type DbPool = Pool<Postgres>;

pub async fn init_db() -> Result<DbPool, sqlx::Error> {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    
    // Run migrations to set up database schema
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await?;
    
    Ok(pool)
}

pub async fn create_user(
    pool: &DbPool,
    username: &str,
    public_key: &[u8],
) -> Result<User, sqlx::Error> {
    let now = chrono::Utc::now();
    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (username, public_key, created_at, last_seen)
        VALUES ($1, $2, $3, $4)
        RETURNING id, username, public_key, created_at, last_seen
        "#,
        username,
        public_key,
        now,
        now
    )
    .fetch_one(pool)
    .await?;
    
    Ok(user)
}

pub async fn get_user_by_username(
    pool: &DbPool,
    username: &str,
) -> Result<Option<User>, sqlx::Error> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT id, username, public_key, created_at, last_seen
        FROM users
        WHERE username = $1
        "#,
        username
    )
    .fetch_optional(pool)
    .await?;
    
    Ok(user)
}

pub async fn save_message(
    pool: &DbPool,
    sender_id: Uuid,
    recipient_id: Uuid,
    content: &[u8],
    signature: &[u8],
) -> Result<Message, sqlx::Error> {
    let message = sqlx::query_as!(
        Message,
        r#"
        INSERT INTO messages (sender_id, recipient_id, content, timestamp, signature)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, sender_id, recipient_id, content, timestamp, signature
        "#,
        sender_id,
        recipient_id,
        content,
        chrono::Utc::now(),
        signature
    )
    .fetch_one(pool)
    .await?;
    
    Ok(message)
}

pub async fn get_messages_for_user(
    pool: &DbPool,
    user_id: Uuid,
) -> Result<Vec<Message>, sqlx::Error> {
    let messages = sqlx::query_as!(
        Message,
        r#"
        SELECT id, sender_id, recipient_id, content, timestamp, signature
        FROM messages
        WHERE recipient_id = $1
        ORDER BY timestamp DESC
        "#,
        user_id
    )
    .fetch_all(pool)
    .await?;
    
    Ok(messages)
}

pub async fn get_all_users(
    pool: &DbPool,
) -> Result<Vec<User>, sqlx::Error> {
    let users = sqlx::query_as!(
        User,
        r#"
        SELECT id, username, public_key, created_at, last_seen
        FROM users
        ORDER BY username
        "#
    )
    .fetch_all(pool)
    .await?;
    
    Ok(users)
}