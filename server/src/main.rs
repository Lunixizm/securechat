mod api;
mod auth;
mod db;
mod encryption;
mod message;

use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenv::dotenv().ok();
    
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "server=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    // Initialize database
    let db_pool = db::init_db().await.expect("Failed to initialize database");
    
    // Build application with routes
    let app = api::create_router(db_pool);
    
    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    tracing::info!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
