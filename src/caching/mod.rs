//! 캐싱 계층 모듈
//!
//! Redis를 백엔드로 하는 분산 캐시 지원과 JSON 기반 객체 직렬화를 제공합니다.
//!
//! # 주요 기능
//!
//! - Redis 통합 및 연결 풀링
//! - JSON 기반 자동 직렬화/역직렬화
//! - TTL 지원 및 패턴 기반 캐시 무효화
//!
//! # 사용 예제
//!
//! ```rust,ignore
//! use crate::caching::redis::RedisClient;
//!
//! let cache = RedisClient::new().await?;
//! cache.set("user:123", &user_data).await?;
//! cache.set_with_expiry("session:abc", &session, 3600).await?;
//!
//! let cached_user: Option<User> = cache.get("user:123").await?;
//! cache.invalidate_pattern_cache("user:*").await?;
//! ```
//!
//! # 환경 설정
//!
//! ```bash
//! REDIS_URL=redis://localhost:6379  # 기본값
//! ```

pub mod redis;
