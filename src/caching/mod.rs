//! # 캐싱 모듈
//! 이 모듈은 백엔드 서비스의 캐싱 계층을 제공합니다.
//! Spring Framework의 Cache Abstraction과 유사한 역할을 수행하며,
//! 데이터베이스 조회 성능 최적화와 응답 시간 단축을 목적으로 합니다.
//!
//! ## 주요 기능
//! - **Redis 통합**: Redis를 백엔드로 하는 분산 캐시 지원
//! - **직렬화/역직렬화**: JSON 기반 자동 객체 변환
//! - **TTL 지원**: 키별 만료 시간 설정
//! - **패턴 기반 삭제**: 와일드카드를 사용한 일괄 캐시 무효화
//! - **연결 풀링**: 멀티플렉싱을 통한 효율적인 연결 관리
//!
//! ## 아키텍처 설계
//! ```text
//! Service Layer
//!      ↓
//! Cache Abstraction (RedisClient)
//!      ↓  
//! Redis Server
//! ```
//!
//! ## 사용 예제
//! ```rust,ignore
//! use crate::caching::redis::RedisClient;
//!
//! // 캐시 클라이언트 초기화
//! let cache = RedisClient::new().await?;
//!
//! // 데이터 캐싱
//! cache.set("user:123", &user_data).await?;
//!
//! // 만료 시간과 함께 캐싱 (3600초 = 1시간)
//! cache.set_with_expiry("session:abc", &session, 3600).await?;
//!
//! // 캐시 조회
//! let cached_user: Option<User> = cache.get("user:123").await?;
//!
//! // 패턴 기반 캐시 무효화
//! cache.invalidate_pattern_cache("user:*").await?;
//! ```
//!
//! ## 성능 고려사항
//!
//! - Redis 연결은 멀티플렉싱되어 동시 요청을 효율적으로 처리
//! - JSON 직렬화 오버헤드는 네트워크 I/O 절약으로 상쇄
//! - 캐시 키 네이밍 전략은 Repository 매크로에서 자동 관리
//! - KEYS 명령 사용 시 프로덕션 환경에서 주의 필요
//!
//! ## 환경 설정
//! Redis 연결은 .env 환경 변수를 통해 설정됩니다:
//! ```bash
//! # 기본값: redis://localhost:6379
//! REDIS_URL=redis://your-redis-server:6379
//! ```

pub mod redis;
