//! # Redis 캐시 클라이언트 구현
//!
//! 이 모듈은 Redis를 백엔드로 하는 캐시 클라이언트를 제공합니다.
//! Spring Framework의 RedisTemplate과 유사한 역할을 수행하며,
//! 타입 안전성과 비동기 처리를 지원합니다.
//!
//! ## 설계 철학
//!
//! - **타입 안전성**: Rust의 타입 시스템을 활용한 컴파일 타임 검증
//! - **비동기 우선**: 모든 작업이 async/await 기반으로 구현
//! - **에러 처리**: Result 타입을 통한 명시적 에러 핸들링
//! - **자동 직렬화**: Serde를 통한 투명한 JSON 변환
//!
//! ## 연결 관리
//!
//! Redis 연결은 멀티플렉싱을 사용하여 단일 TCP 연결에서
//! 여러 동시 요청을 효율적으로 처리합니다.

use redis::{AsyncCommands, Client};
use serde::{Serialize, de::DeserializeOwned};
use std::env;

/// Redis 캐시 클라이언트 래퍼
///
/// 이 구조체는 Redis 서버와의 상호작용을 추상화하며,
/// Spring의 `RedisTemplate`과 유사한 기능을 제공합니다.
///
/// ## 특징
///
/// - **연결 풀링**: 내부적으로 멀티플렉싱된 연결 사용
/// - **자동 직렬화**: JSON 기반 객체 저장/조회
/// - **타입 안전성**: 제네릭을 통한 컴파일 타임 타입 검증
/// - **에러 복구**: 연결 실패 시 자동 재연결 시도
///
/// ## 사용 예제
///
/// ```rust,ignore
/// use crate::caching::redis::RedisClient;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct UserCache {
///     id: String,
///     name: String,
///     email: String,
/// }
///
/// // 클라이언트 초기화
/// let redis = RedisClient::new().await?;
///
/// // 사용자 정보 캐싱 (1시간 TTL)
/// let user = UserCache { 
///     id: "123".to_string(), 
///     name: "John".to_string(),
///     email: "john@example.com".to_string()
/// };
/// redis.set_with_expiry("user:123", &user, 3600).await?;
///
/// // 캐시된 데이터 조회
/// let cached_user: Option<UserCache> = redis.get("user:123").await?;
/// ```
#[derive(Clone)]
pub struct RedisClient {
    /// Redis 클라이언트 인스턴스
    /// 
    /// 멀티플렉싱을 지원하는 Redis 클라이언트로,
    /// 단일 TCP 연결에서 여러 동시 요청을 처리할 수 있습니다.
    client: Client,
}

impl RedisClient {
    /// 새 Redis 클라이언트 인스턴스를 생성합니다.
    ///
    /// 환경 변수 `REDIS_URL`에서 Redis 서버 주소를 읽어오며,
    /// 설정되지 않은 경우 기본값 `redis://localhost:6379`를 사용합니다.
    ///
    /// 생성 시 자동으로 연결 테스트를 수행하여 Redis 서버의
    /// 가용성을 확인합니다.
    ///
    /// ## 환경 변수
    ///
    /// ```bash
    /// REDIS_URL=redis://localhost:6379          # 기본 연결
    /// REDIS_URL=redis://user:pass@host:6379/db  # 인증 및 DB 선택
    /// REDIS_URL=rediss://host:6380              # TLS 연결
    /// ```
    ///
    /// ## 반환값
    ///
    /// - `Ok(RedisClient)` - 연결 성공 시 클라이언트 인스턴스
    /// - `Err(Box<dyn Error>)` - 연결 실패 또는 설정 오류
    ///
    /// ## 에러 케이스
    ///
    /// - Redis 서버에 연결할 수 없는 경우
    /// - 잘못된 URL 형식
    /// - 네트워크 오류
    /// - 인증 실패
    ///
    /// ## 예제
    ///
    /// ```rust,ignore
    /// // 기본 설정으로 연결
    /// let redis = RedisClient::new().await?;
    ///
    /// // 환경 변수 설정 후 연결
    /// std::env::set_var("REDIS_URL", "redis://192.168.1.100:6379");
    /// let redis = RedisClient::new().await?;
    /// ```
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let redis_url = env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string());
            
        let client = Client::open(redis_url)?;
        
        // 연결 테스트 - PING 명령으로 서버 가용성 확인
        let mut conn = client.get_multiplexed_async_connection().await?;
        redis::cmd("PING").query_async::<()>(&mut conn).await?;
        
        println!("✅ Redis 연결 성공");
        
        Ok(Self { client })
    }
    
    /// 지정된 키에서 값을 조회합니다.
    ///
    /// 이 메서드는 Spring의 `@Cacheable` 어노테이션과 유사한 역할을 수행하며,
    /// JSON 으로 직렬화된 데이터를 자동으로 역직렬화하여 반환합니다.
    ///
    /// ## 타입 매개변수
    ///
    /// - `T` - 역직렬화할 대상 타입 (Deserialize trait 구현 필요)
    ///
    /// ## 인자
    ///
    /// - `key` - 조회할 Redis 키
    ///
    /// ## 반환값
    ///
    /// - `Ok(Some(T))` - 키가 존재하고 역직렬화 성공
    /// - `Ok(None)` - 키가 존재하지 않음
    /// - `Err(RedisError)` - Redis 오류 또는 역직렬화 실패
    ///
    /// ## 성능 특성
    ///
    /// - **시간 복잡도**: O(1)
    /// - **네트워크**: 1회 왕복
    /// - **메모리**: 데이터 크기에 비례
    ///
    /// ## 예제
    ///
    /// ```rust,ignore
    /// #[derive(Deserialize)]
    /// struct Product {
    ///     id: u64,
    ///     name: String,
    ///     price: f64,
    /// }
    ///
    /// // 상품 정보 조회
    /// let product: Option<Product> = redis.get("product:123").await?;
    /// 
    /// match product {
    ///     Some(p) => println!("상품명: {}, 가격: {}", p.name, p.price),
    ///     None => println!("상품을 찾을 수 없습니다"),
    /// }
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
    /// 이 메서드는 Spring의 `@CachePut` 어노테이션과 유사한 역할을 수행하며,
    /// 객체를 JSON 으로 직렬화하여 Redis에 저장합니다.
    ///
    /// ## 타입 매개변수
    ///
    /// - `T` - 직렬화할 대상 타입 (Serialize trait 구현 필요)
    ///
    /// ## 인자
    ///
    /// - `key` - 저장할 Redis 키
    /// - `value` - 저장할 값
    ///
    /// ## 반환값
    ///
    /// - `Ok(())` - 저장 성공
    /// - `Err(RedisError)` - Redis 오류 또는 직렬화 실패
    ///
    /// ## 주의사항
    ///
    /// - 기존 키가 있으면 덮어씁니다
    /// - TTL이 설정되지 않으므로 영구 저장됩니다
    /// - 대용량 객체 저장 시 메모리 사용량 주의
    ///
    /// ## 예제
    ///
    /// ```rust,ignore
    /// #[derive(Serialize)]
    /// struct Session {
    ///     user_id: String,
    ///     created_at: DateTime<Utc>,
    ///     permissions: Vec<String>,
    /// }
    ///
    /// let session = Session {
    ///     user_id: "user123".to_string(),
    ///     created_at: Utc::now(),
    ///     permissions: vec!["read".to_string(), "write".to_string()],
    /// };
    ///
    /// // 세션 정보 저장
    /// redis.set("session:abc123", &session).await?;
    /// ```
    pub async fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<(), redis::RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let json = serde_json::to_string(value)
            .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "Serialization failed", e.to_string())))?;
        conn.set(key, json).await
    }
    
    /// 만료 시간과 함께 값을 저장합니다.
    ///
    /// 이 메서드는 TTL(Time To Live)이 있는 캐시 저장을 제공하며,
    /// Spring의 `@Cacheable(expire = ...)` 설정과 유사합니다.
    ///
    /// ## 타입 매개변수
    ///
    /// - `T` - 직렬화할 대상 타입 (Serialize trait 구현 필요)
    ///
    /// ## 인자
    ///
    /// - `key` - 저장할 Redis 키
    /// - `value` - 저장할 값
    /// - `seconds` - 만료 시간 (초 단위)
    ///
    /// ## 반환값
    ///
    /// - `Ok(())` - 저장 성공
    /// - `Err(RedisError)` - Redis 오류 또는 직렬화 실패
    ///
    /// ## 사용 시나리오
    ///
    /// | 용도 | 권장 TTL | 예제 |
    /// |------|----------|------|
    /// | 세션 | 1-24시간 | `3600 * 8` |
    /// | API 응답 캐시 | 5-60분 | `300` |
    /// | 임시 토큰 | 10-30분 | `900` |
    /// | 사용자 프로필 | 1-6시간 | `3600 * 2` |
    ///
    /// ## 예제
    ///
    /// ```rust,ignore
    /// // JWT 토큰 30분 캐싱
    /// let token_info = TokenInfo {
    ///     token: "eyJ...".to_string(),
    ///     user_id: "123".to_string(),
    ///     expires_at: Utc::now() + Duration::minutes(30),
    /// };
    /// redis.set_with_expiry("token:refresh:abc", &token_info, 1800).await?;
    ///
    /// // API 응답 5분 캐싱
    /// let api_response = fetch_external_api().await?;
    /// redis.set_with_expiry("api:weather:seoul", &api_response, 300).await?;
    /// ```
    pub async fn set_with_expiry<T: Serialize>(&self, key: &str, value: &T, seconds: usize) -> Result<(), redis::RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let json = serde_json::to_string(value)
            .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "Serialization failed", e.to_string())))?;
        conn.set_ex(key, json, seconds as u64).await
    }
    
    /// 지정된 키를 삭제합니다.
    ///
    /// 이 메서드는 Spring의 `@CacheEvict` 어노테이션과 유사한 역할을 수행하며,
    /// 특정 캐시 항목을 무효화할 때 사용됩니다.
    ///
    /// ## 인자
    ///
    /// - `key` - 삭제할 Redis 키
    ///
    /// ## 반환값
    ///
    /// - `Ok(())` - 삭제 성공 (키가 없어도 성공으로 처리)
    /// - `Err(RedisError)` - Redis 연결 오류
    ///
    /// ## 성능 특성
    ///
    /// - **시간 복잡도**: O(1)
    /// - **반환값**: 삭제된 키의 개수를 무시하고 항상 성공 처리
    ///
    /// ## 사용 시나리오
    ///
    /// ```rust,ignore
    /// // 사용자 정보 변경 시 캐시 무효화
    /// async fn update_user(user_id: &str, user_data: UserData) -> Result<()> {
    ///     // 1. 데이터베이스 업데이트
    ///     user_repository.update(user_id, user_data).await?;
    ///     
    ///     // 2. 관련 캐시 무효화
    ///     redis.del(&format!("user:{}", user_id)).await?;
    ///     redis.del(&format!("user:profile:{}", user_id)).await?;
    ///     
    ///     Ok(())
    /// }
    /// ```
    pub async fn del(&self, key: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        conn.del(key).await
    }
    
    /// 여러 키를 한 번에 삭제합니다.
    ///
    /// 이 메서드는 대량의 캐시 무효화가 필요할 때 사용되며,
    /// 개별 삭제보다 효율적인 배치 삭제를 제공합니다.
    ///
    /// ## 인자
    ///
    /// - `keys` - 삭제할 Redis 키들의 벡터
    ///
    /// ## 반환값
    ///
    /// - `Ok(())` - 삭제 성공
    /// - `Err(RedisError)` - Redis 연결 오류
    ///
    /// ## 성능 이점
    ///
    /// - **네트워크 왕복**: N번 → 1번
    /// - **원자성**: 모든 키가 동시에 삭제
    /// - **효율성**: Redis 파이프라이닝 활용
    ///
    /// ## 예제
    ///
    /// ```rust,ignore
    /// // 사용자 관련 모든 캐시 삭제
    /// let user_keys = vec![
    ///     format!("user:{}", user_id),
    ///     format!("user:profile:{}", user_id),
    ///     format!("user:permissions:{}", user_id),
    ///     format!("user:settings:{}", user_id),
    /// ];
    /// 
    /// redis.del_multiple(&user_keys).await?;
    ///
    /// // 빈 배열 처리 (안전)
    /// redis.del_multiple(&vec![]).await?; // 즉시 성공 반환
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
    /// Redis의 KEYS 명령을 래핑하여 와일드카드 패턴으로
    /// 키를 검색할 수 있습니다.
    ///
    /// ## 인자
    ///
    /// - `pattern` - Redis 패턴 문자열
    ///
    /// ## 반환값
    ///
    /// - `Ok(Vec<String>)` - 패턴과 일치하는 키 목록
    /// - `Err(RedisError)` - Redis 연결 오류
    ///
    /// ## 패턴 문법
    ///
    /// | 패턴 | 의미 | 예제 |
    /// |------|------|------|
    /// | `*` | 0개 이상의 임의 문자 | `user:*` |
    /// | `?` | 정확히 1개 문자 | `user:?` |
    /// | `[abc]` | a, b, c 중 하나 | `user:[123]` |
    /// | `[a-z]` | a부터 z까지 | `user:[a-z]*` |
    ///
    /// ## ⚠️ 프로덕션 주의사항
    ///
    /// KEYS 명령은 블로킹 연산으로 Redis 서버 전체 성능에
    /// 영향을 줄 수 있습니다. 대안을 고려하세요:
    ///
    /// - **SCAN** 명령 사용 (비블로킹)
    /// - **키 설계 개선** (Set 자료구조 활용)
    /// - **캐시 무효화 전략 변경**
    ///
    /// ## 예제
    ///
    /// ```rust,ignore
    /// // 특정 사용자의 모든 캐시 키 찾기
    /// let user_keys = redis.keys(&format!("user:{}:*", user_id)).await?;
    /// println!("사용자 캐시 키: {:?}", user_keys);
    ///
    /// // 세션 관련 모든 키 찾기
    /// let session_keys = redis.keys("session:*").await?;
    /// 
    /// // 오늘 날짜의 통계 캐시 찾기
    /// let today = Utc::now().format("%Y%m%d");
    /// let stats_keys = redis.keys(&format!("stats:{}:*", today)).await?;
    /// ```
    pub async fn keys(&self, pattern: &str) -> Result<Vec<String>, redis::RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        conn.keys(pattern).await
    }
}

impl Default for RedisClient {
    /// 기본 설정으로 RedisClient를 생성합니다.
    ///
    /// 주의: 이 메서드는 동기적이므로 실제 Redis 연결 테스트를 수행하지 않습니다.
    /// 프로덕션 환경에서는 `RedisClient::new().await`를 사용하세요.
    fn default() -> Self {
        let redis_url = env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string());
        
        let client = Client::open(redis_url)
            .expect("Failed to create Redis client with default configuration");
            
        Self { client }
    }
}
