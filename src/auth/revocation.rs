use deadpool_redis::Pool;
use deadpool_redis::redis::AsyncCommands;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Redis-backed store for access-token revocation entries (`jti` values).
///
/// Keys are stored as:
/// - `token-revocation:jti:{uuid}`
///
/// Values are a static marker (`"1"`) with a TTL equal to the remaining token
/// lifetime. This keeps memory usage bounded and naturally expires stale
/// revocations.
#[derive(Clone, Debug)]
pub struct TokenRevocationStore {
    pool: Pool,
    key_prefix: String,
}

impl TokenRevocationStore {
    const DEFAULT_KEY_PREFIX: &'static str = "token-revocation:jti:";

    /// Create a new revocation store with the default key prefix.
    pub fn new(pool: Pool) -> Self {
        Self {
            pool,
            key_prefix: Self::DEFAULT_KEY_PREFIX.to_owned(),
        }
    }

    /// Create a new revocation store with a custom key prefix.
    pub fn with_prefix(pool: Pool, key_prefix: impl Into<String>) -> Self {
        Self {
            pool,
            key_prefix: key_prefix.into(),
        }
    }

    /// Add a token `jti` to the revocation set until `expires_at`.
    ///
    /// If `expires_at` is already in the past (or effectively now), this is a
    /// no-op.
    pub async fn revoke_jti_until(&self, jti: Uuid, expires_at: OffsetDateTime) -> Result<(), RevocationError> {
        let Some(ttl_seconds) = ttl_seconds_until(expires_at) else {
            return Ok(());
        };

        self.revoke_jti_for(jti, ttl_seconds).await
    }

    /// Add a token `jti` to the revocation set for `ttl_seconds`.
    ///
    /// A `ttl_seconds` of `0` is treated as a no-op.
    pub async fn revoke_jti_for(&self, jti: Uuid, ttl_seconds: u64) -> Result<(), RevocationError> {
        if ttl_seconds == 0 {
            return Ok(());
        }

        let key = self.key_for_jti(jti);
        let mut conn = self.pool.get().await?;
        let _: () = conn.set_ex(key, "1", ttl_seconds).await?;
        Ok(())
    }

    /// Check whether a token `jti` is currently revoked.
    pub async fn is_jti_revoked(&self, jti: Uuid) -> Result<bool, RevocationError> {
        let key = self.key_for_jti(jti);
        let mut conn = self.pool.get().await?;
        let exists: bool = conn.exists(key).await?;
        Ok(exists)
    }

    /// Remove a `jti` from the revocation set (best-effort/manual un-revoke).
    pub async fn clear_jti(&self, jti: Uuid) -> Result<(), RevocationError> {
        let key = self.key_for_jti(jti);
        let mut conn = self.pool.get().await?;
        let _: usize = conn.del(key).await?;
        Ok(())
    }

    fn key_for_jti(&self, jti: Uuid) -> String {
        format!("{}{}", self.key_prefix, jti)
    }
}

#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("failed to get Redis connection from pool: {0}")]
    Pool(#[from] deadpool_redis::PoolError),

    #[error("Redis command failed: {0}")]
    Redis(#[from] deadpool_redis::redis::RedisError),
}

/// Compute the whole-second TTL from now until `expires_at`.
///
/// Returns `None` when the timestamp is in the past or less than one second
/// from now.
fn ttl_seconds_until(expires_at: OffsetDateTime) -> Option<u64> {
    let remaining = expires_at - OffsetDateTime::now_utc();
    duration_to_ttl_seconds(remaining)
}

fn duration_to_ttl_seconds(duration: Duration) -> Option<u64> {
    let secs = duration.whole_seconds();
    if secs <= 0 {
        return None;
    }

    u64::try_from(secs).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_is_none_for_non_positive_duration() {
        assert_eq!(duration_to_ttl_seconds(Duration::ZERO), None);
        assert_eq!(duration_to_ttl_seconds(Duration::seconds(-1)), None);
    }

    #[test]
    fn ttl_is_some_for_positive_duration() {
        assert_eq!(duration_to_ttl_seconds(Duration::seconds(1)), Some(1));
        assert_eq!(duration_to_ttl_seconds(Duration::seconds(300)), Some(300));
    }
}
