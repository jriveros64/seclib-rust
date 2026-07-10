use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error, Clone)]
pub enum StoreError {
    #[error("Clave no encontrada")]
    NotFound,
    #[error("Error de base de datos: {0}")]
    Database(String),
    #[error("Error de Redis: {0}")]
    Redis(String),
    #[error("Error de serialización: {0}")]
    Serialization(String),
    #[error("Error al parsear número: {0}")]
    Parse(String),
}

// SessionStore trait for decoupled key-value store
#[async_trait]
pub trait SessionStore: Send + Sync + std::fmt::Debug {
    async fn get(&self, key: &str) -> Result<Option<String>, StoreError>;
    async fn set(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> Result<(), StoreError>;
    async fn delete(&self, key: &str) -> Result<(), StoreError>;
    async fn compare_and_set(
        &self,
        key: &str,
        expected: Option<&str>,
        desired: Option<&str>,
        ttl_secs: Option<u64>,
    ) -> Result<bool, StoreError>;
}

// RateLimitStore trait for generic rate-limiting counter
#[async_trait]
pub trait RateLimitStore: Send + Sync + std::fmt::Debug {
    async fn increment(&self, key: &str, window_secs: u64) -> Result<u64, StoreError>;
}

// --- In-Memory Implementations ---

#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    data: Arc<Mutex<HashMap<String, (String, Instant)>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for MemoryStore {
    async fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let mut data = self.data.lock().await;
        if let Some((value, expires_at)) = data.get(key) {
            if Instant::now() < *expires_at {
                return Ok(Some(value.clone()));
            }
        }
        data.remove(key);
        Ok(None)
    }

    async fn set(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> Result<(), StoreError> {
        let mut data = self.data.lock().await;
        // Bounded GC cleanup on write
        data.retain(|_, (_, expires_at)| Instant::now() < *expires_at);

        let expires_at = match ttl_secs {
            Some(secs) => Instant::now() + Duration::from_secs(secs),
            None => Instant::now() + Duration::from_secs(365 * 24 * 3600), // ~1 year
        };
        data.insert(key.to_string(), (value.to_string(), expires_at));
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let mut data = self.data.lock().await;
        data.remove(key);
        Ok(())
    }

    async fn compare_and_set(
        &self,
        key: &str,
        expected: Option<&str>,
        desired: Option<&str>,
        ttl_secs: Option<u64>,
    ) -> Result<bool, StoreError> {
        let mut data = self.data.lock().await;
        // Bounded GC cleanup on write
        data.retain(|_, (_, expires_at)| Instant::now() < *expires_at);

        let current = if let Some((value, expires_at)) = data.get(key) {
            if Instant::now() < *expires_at {
                Some(value.clone())
            } else {
                None
            }
        } else {
            None
        };

        if current.as_deref() == expected {
            match desired {
                Some(val) => {
                    let expires_at = match ttl_secs {
                        Some(secs) => Instant::now() + Duration::from_secs(secs),
                        None => Instant::now() + Duration::from_secs(365 * 24 * 3600),
                    };
                    data.insert(key.to_string(), (val.to_string(), expires_at));
                }
                None => {
                    data.remove(key);
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemoryRateLimitStore {
    data: Arc<Mutex<HashMap<String, (u64, Instant)>>>,
}

impl MemoryRateLimitStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RateLimitStore for MemoryRateLimitStore {
    async fn increment(&self, key: &str, window_secs: u64) -> Result<u64, StoreError> {
        let mut data = self.data.lock().await;
        // Bounded GC cleanup on write
        data.retain(|_, (_, expires_at)| Instant::now() < *expires_at);

        let now = Instant::now();
        if let Some((count, expires_at)) = data.get_mut(key) {
            if now < *expires_at {
                *count += 1;
                return Ok(*count);
            }
        }
        let expires_at = now + Duration::from_secs(window_secs);
        data.insert(key.to_string(), (1, expires_at));
        Ok(1)
    }
}

// --- Postgres Implementations ---

#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: sqlx::PgPool,
}

impl PostgresStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    // Lazy initialization of database schema
    pub async fn init_db(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS seclib_store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL
            );",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl SessionStore for PostgresStore {
    async fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let row: Option<String> = sqlx::query_scalar(
            "SELECT value FROM seclib_store WHERE key = $1 AND expires_at > CURRENT_TIMESTAMP",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(row)
    }

    async fn set(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> Result<(), StoreError> {
        // GC cleanup of expired entries on write
        let _ = sqlx::query("DELETE FROM seclib_store WHERE expires_at < CURRENT_TIMESTAMP")
            .execute(&self.pool)
            .await;

        let ttl = ttl_secs.unwrap_or(365 * 24 * 3600);
        let expires_at: DateTime<Utc> = Utc::now() + chrono::Duration::seconds(ttl as i64);

        sqlx::query(
            "INSERT INTO seclib_store (key, value, expires_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at"
        )
        .bind(key)
        .bind(value)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM seclib_store WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn compare_and_set(
        &self,
        key: &str,
        expected: Option<&str>,
        desired: Option<&str>,
        ttl_secs: Option<u64>,
    ) -> Result<bool, StoreError> {
        // GC cleanup of expired entries on write
        let _ = sqlx::query("DELETE FROM seclib_store WHERE expires_at < CURRENT_TIMESTAMP")
            .execute(&self.pool)
            .await;

        let ttl = ttl_secs.unwrap_or(365 * 24 * 3600);
        let expires_at: DateTime<Utc> = Utc::now() + chrono::Duration::seconds(ttl as i64);

        match (expected, desired) {
            (None, Some(val)) => {
                let rows = sqlx::query(
                    "INSERT INTO seclib_store (key, value, expires_at)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (key) DO NOTHING",
                )
                .bind(key)
                .bind(val)
                .bind(expires_at)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

                Ok(rows.rows_affected() > 0)
            }
            (Some(exp), Some(val)) => {
                let rows = sqlx::query(
                    "UPDATE seclib_store SET value = $1, expires_at = $2
                     WHERE key = $3 AND value = $4 AND expires_at > CURRENT_TIMESTAMP",
                )
                .bind(val)
                .bind(expires_at)
                .bind(key)
                .bind(exp)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

                Ok(rows.rows_affected() > 0)
            }
            (Some(exp), None) => {
                let rows = sqlx::query(
                    "DELETE FROM seclib_store
                     WHERE key = $1 AND value = $2 AND expires_at > CURRENT_TIMESTAMP",
                )
                .bind(key)
                .bind(exp)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

                Ok(rows.rows_affected() > 0)
            }
            (None, None) => {
                let exists = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM seclib_store WHERE key = $1 AND expires_at > CURRENT_TIMESTAMP)"
                )
                .bind(key)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

                Ok(!exists)
            }
        }
    }
}

#[async_trait]
impl RateLimitStore for PostgresStore {
    async fn increment(&self, key: &str, window_secs: u64) -> Result<u64, StoreError> {
        // GC cleanup of expired entries on write
        let _ = sqlx::query("DELETE FROM seclib_store WHERE expires_at < CURRENT_TIMESTAMP")
            .execute(&self.pool)
            .await;

        let expires_at: DateTime<Utc> = Utc::now() + chrono::Duration::seconds(window_secs as i64);

        let count_str: String = sqlx::query_scalar(
            "INSERT INTO seclib_store (key, value, expires_at)
             VALUES ($1, '1', $2)
             ON CONFLICT (key) DO UPDATE
             SET value = CASE
                 WHEN seclib_store.expires_at > CURRENT_TIMESTAMP THEN (seclib_store.value::bigint + 1)::text
                 ELSE '1'
             END,
             expires_at = CASE
                 WHEN seclib_store.expires_at > CURRENT_TIMESTAMP THEN seclib_store.expires_at
                 ELSE $2
             END
             RETURNING value"
        )
        .bind(key)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        let count: u64 = count_str
            .parse()
            .map_err(|e| StoreError::Parse(format!("Invalid stored integer: {e}")))?;
        Ok(count)
    }
}

// --- Redis Implementations ---

#[derive(Debug, Clone)]
pub struct RedisStore {
    client: redis::Client,
}

impl RedisStore {
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl SessionStore for RedisStore {
    async fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| StoreError::Redis(e.to_string()))?;

        let val: Option<String> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(|e| StoreError::Redis(e.to_string()))?;

        Ok(val)
    }

    async fn set(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> Result<(), StoreError> {
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| StoreError::Redis(e.to_string()))?;

        if let Some(secs) = ttl_secs {
            let _: () = redis::cmd("SETEX")
                .arg(key)
                .arg(secs)
                .arg(value)
                .query_async(&mut conn)
                .await
                .map_err(|e| StoreError::Redis(e.to_string()))?;
        } else {
            let _: () = redis::cmd("SET")
                .arg(key)
                .arg(value)
                .query_async(&mut conn)
                .await
                .map_err(|e| StoreError::Redis(e.to_string()))?;
        }

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| StoreError::Redis(e.to_string()))?;

        let _: () = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(|e| StoreError::Redis(e.to_string()))?;

        Ok(())
    }

    async fn compare_and_set(
        &self,
        key: &str,
        expected: Option<&str>,
        desired: Option<&str>,
        ttl_secs: Option<u64>,
    ) -> Result<bool, StoreError> {
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| StoreError::Redis(e.to_string()))?;

        let script = r#"
            local val = redis.call('GET', KEYS[1])
            local expected_exists = tonumber(ARGV[1])
            local expected_val = ARGV[2]
            local desired_exists = tonumber(ARGV[3])
            local desired_val = ARGV[4]
            local ttl = tonumber(ARGV[5])

            local current_exists = 0
            if val then
                current_exists = 1
            end

            if current_exists ~= expected_exists then
                return 0
            end

            if expected_exists == 1 and val ~= expected_val then
                return 0
            end

            -- Match! Perform update/delete
            if desired_exists == 1 then
                if ttl and ttl > 0 then
                    redis.call('SETEX', KEYS[1], ttl, desired_val)
                else
                    redis.call('SET', KEYS[1], desired_val)
                end
            else
                redis.call('DEL', KEYS[1])
            end
            return 1
        "#;

        let expected_exists = if expected.is_some() { 1 } else { 0 };
        let expected_val = expected.unwrap_or("");
        let desired_exists = if desired.is_some() { 1 } else { 0 };
        let desired_val = desired.unwrap_or("");
        let ttl = ttl_secs.unwrap_or(0);

        let res: u32 = redis::Script::new(script)
            .key(key)
            .arg(expected_exists)
            .arg(expected_val)
            .arg(desired_exists)
            .arg(desired_val)
            .arg(ttl)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| StoreError::Redis(e.to_string()))?;

        Ok(res == 1)
    }
}

#[async_trait]
impl RateLimitStore for RedisStore {
    async fn increment(&self, key: &str, window_secs: u64) -> Result<u64, StoreError> {
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| StoreError::Redis(e.to_string()))?;

        let script = r#"
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return count
        "#;

        let count: u64 = redis::Script::new(script)
            .key(key)
            .arg(window_secs)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| StoreError::Redis(e.to_string()))?;

        Ok(count)
    }
}
