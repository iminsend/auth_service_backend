//! Redis 캐시 클라이언트 구현

use redis::{AsyncCommands, Client};
use serde::{Serialize, de::DeserializeOwned};
use std::env;
use log::info;

/// Redis 캐시 클라이언트
///
/// 멀티플렉싱된 연결을 사용하여 Redis 서버와 상호작용하며,
/// JSON 기반 자동 직렬화를 지원합니다.
#[derive(Clone)]
pub struct RedisClient {
    client: Client,
}

impl RedisClient {
    /// 새 Redis 클라이언트를 생성합니다.
    ///
    /// `REDIS_URL` 환경 변수를 사용하며, 설정되지 않은 경우 
    /// `redis://localhost:6379`를 기본값으로 사용합니다.
    ///
    /// # Returns
    ///
    /// Redis 클라이언트 인스턴스를 반환합니다.
    ///
    /// # Errors
    ///
    /// - Redis 서버 연결 실패
    /// - 잘못된 URL 형식
    /// - 네트워크 오류
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let redis = RedisClient::new().await?;
    /// ```
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let redis_url = env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string());
            
        let client = Client::open(redis_url)?;
        
        // 연결 테스트
        let mut conn = client.get_multiplexed_async_connection().await?;
        redis::cmd("PING").query_async::<()>(&mut conn).await?;
        
        info!("✅ Redis 연결 성공");
        
        Ok(Self { client })
    }
    
    /// 지정된 키에서 값을 조회합니다.
    ///
    /// # Arguments
    ///
    /// * `key` - 조회할 Redis 키
    ///
    /// # Returns
    ///
    /// - `Ok(Some(T))` - 키가 존재하고 역직렬화 성공
    /// - `Ok(None)` - 키가 존재하지 않음
    ///
    /// # Errors
    ///
    /// Redis 연결 오류 또는 JSON 역직렬화 실패 시 에러를 반환합니다.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let user: Option<User> = redis.get("user:123").await?;
    /// ```
    pub async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, redis::RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let value: Option<String> = conn.get(key).await?;
        
        match value {
            Some(json) => {
                let deserialized = serde_json::from_str(&json)
                    .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "Deserialization failed", e.to_string())))?;
                Ok(Some(deserialized))
            }
            None => Ok(None),
        }
    }
    
    /// 지정된 키에 값을 저장합니다.
    ///
    /// # Arguments
    ///
    /// * `key` - 저장할 Redis 키
    /// * `value` - 저장할 값
    ///
    /// # Errors
    ///
    /// Redis 연결 오류 또는 JSON 직렬화 실패 시 에러를 반환합니다.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// redis.set("user:123", &user_data).await?;
    /// ```
    pub async fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<(), redis::RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let json = serde_json::to_string(value)
            .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "Serialization failed", e.to_string())))?;
        conn.set(key, json).await
    }
    
    /// 만료 시간과 함께 값을 저장합니다.
    ///
    /// # Arguments
    ///
    /// * `key` - 저장할 Redis 키
    /// * `value` - 저장할 값
    /// * `seconds` - 만료 시간 (초 단위)
    ///
    /// # Errors
    ///
    /// Redis 연결 오류 또는 JSON 직렬화 실패 시 에러를 반환합니다.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // 1시간 후 만료
    /// redis.set_with_expiry("session:abc", &session, 3600).await?;
    /// ```
    pub async fn set_with_expiry<T: Serialize>(&self, key: &str, value: &T, seconds: usize) -> Result<(), redis::RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let json = serde_json::to_string(value)
            .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "Serialization failed", e.to_string())))?;
        conn.set_ex(key, json, seconds as u64).await
    }
    
    /// 지정된 키를 삭제합니다.
    ///
    /// # Arguments
    ///
    /// * `key` - 삭제할 Redis 키
    ///
    /// # Errors
    ///
    /// Redis 연결 오류 시 에러를 반환합니다. 키가 존재하지 않아도 성공으로 처리됩니다.
    pub async fn del(&self, key: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        conn.del(key).await
    }
    
    /// 여러 키를 한 번에 삭제합니다.
    ///
    /// # Arguments
    ///
    /// * `keys` - 삭제할 Redis 키들의 슬라이스
    ///
    /// # Errors
    ///
    /// Redis 연결 오류 시 에러를 반환합니다.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let keys = vec!["user:123".to_string(), "user:456".to_string()];
    /// redis.del_multiple(&keys).await?;
    /// ```
    pub async fn del_multiple(&self, keys: &[String]) -> Result<(), redis::RedisError> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        conn.del(keys).await
    }
    
    /// 패턴과 일치하는 키들을 검색합니다.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Redis 패턴 문자열 (와일드카드 지원)
    ///
    /// # Returns
    ///
    /// 패턴과 일치하는 키 목록을 반환합니다.
    ///
    /// # Errors
    ///
    /// Redis 연결 오류 시 에러를 반환합니다.
    ///
    /// # Performance
    ///
    /// KEYS 명령은 블로킹 연산입니다. 프로덕션에서는 SCAN 사용을 권장합니다.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let user_keys = redis.keys("user:*").await?;
    /// ```
    pub async fn keys(&self, pattern: &str) -> Result<Vec<String>, redis::RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        conn.keys(pattern).await
    }
}

impl Default for RedisClient {
    /// 기본 설정으로 RedisClient를 생성합니다.
    ///
    /// # Panics
    ///
    /// Redis 클라이언트 생성에 실패하면 패닉이 발생합니다.
    ///
    /// # Note
    ///
    /// 실제 Redis 연결 테스트를 수행하지 않습니다.
    /// 프로덕션에서는 `RedisClient::new().await`를 사용하세요.
    fn default() -> Self {
        let redis_url = env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string());
        
        let client = Client::open(redis_url)
            .expect("Failed to create Redis client with default configuration");
            
        Self { client }
    }
}
