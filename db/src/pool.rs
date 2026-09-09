use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use tracing::info;

/// Create a new PostgreSQL connection pool
pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .min_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))
        .connect(database_url)
        .await?;

    info!("PostgreSQL connection pool created");
    Ok(pool)
}

/// Create a pool with custom configuration
pub async fn create_pool_with_config(
    database_url: &str,
    max_connections: u32,
    min_connections: u32,
) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))
        .connect(database_url)
        .await?;

    info!(
        max_connections,
        min_connections, "PostgreSQL connection pool created"
    );
    Ok(pool)
}

/// Health check for database connection
pub async fn check_health(pool: &PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query("SELECT 1").execute(pool).await?;
    Ok(true)
}

/// Get database URL from environment
pub fn database_url_from_env() -> Result<String, std::env::VarError> {
    let host = std::env::var("DB_HOST").unwrap_or_else(|_| "localhost".into());
    let port = std::env::var("DB_PORT").unwrap_or_else(|_| "5432".into());
    let name = std::env::var("DB_NAME")?;
    let user = std::env::var("DB_USER")?;
    let password = std::env::var("DB_PASSWORD")?;

    Ok(format!(
        "postgres://{}:{}@{}:{}/{}",
        user, password, host, port, name
    ))
}
