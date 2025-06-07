//! # 사용자 리포지토리 모듈
//! 
//! 사용자 엔티티의 데이터 액세스 계층을 담당하는 리포지토리 구현체들을 제공합니다.
//! Spring Framework의 JPA Repository 패턴을 참고하여 Rust 생태계에 맞게 구현되었습니다.
//! 
//! ## 주요 컴포넌트
//! 
//! - [`UserRepository`](user_repo::UserRepository) - 사용자 데이터 액세스 및 캐싱을 담당하는 메인 리포지토리
//! 
//! ## 아키텍처 특징
//! 
//! ### 싱글톤 패턴
//! 
//! 모든 리포지토리는 `#[repository]` 매크로를 통해 자동으로 싱글톤으로 관리됩니다.
//! 이를 통해 메모리 효율성을 높이고 일관된 데이터 액세스를 보장합니다.
//! 
//! ### 멀티 레이어 캐싱
//! 
//! - **L1 Cache**: Redis를 사용한 분산 캐시
//! - **L2 Storage**: MongoDB 기반 영구 저장소
//! 
//! ### 의존성 주입
//! 
//! - `Database` 컴포넌트 자동 주입
//! - `RedisClient` 컴포넌트 자동 주입
//! - 전역 서비스 레지스트리를 통한 관리
//! 
//! ## 사용 예제
//! 
//! ```rust,ignore
//! use crate::repositories::users::user_repo::UserRepository;
//! 
//! async fn example_usage() -> Result<(), AppError> {
//!     // 싱글톤 인스턴스 가져오기
//!     let user_repo = UserRepository::instance();
//!     
//!     // 사용자 생성
//!     let mut new_user = User {
//!         email: "user@example.com".to_string(),
//!         username: "john_doe".to_string(),
//!         // ... 기타 필드
//!     };
//!     
//!     let created_user = user_repo.create(new_user).await?;
//!     
//!     // 이메일로 사용자 조회 (캐시 우선)
//!     let found_user = user_repo
//!         .find_by_email("user@example.com")
//!         .await?;
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ## 성능 최적화
//! 
//! - **인덱스 기반 조회**: 이메일, 사용자명에 대한 유니크 인덱스 활용
//! - **스마트 캐싱**: 자주 조회되는 데이터의 Redis 캐싱
//! - **캐시 무효화**: 데이터 변경 시 자동 캐시 갱신
//! 
//! ## 에러 처리
//! 
//! 모든 메서드는 [`AppError`](crate::core::errors::AppError)를 통해 일관된 에러 처리를 제공합니다:
//! 
//! - `DatabaseError` - MongoDB 관련 오류
//! - `ValidationError` - 입력값 검증 오류  
//! - `ConflictError` - 중복 데이터 관련 오류
//! 
//! ## 설정 요구사항
//! 
//! 이 모듈을 사용하려면 다음 컴포넌트들이 서비스 레지스트리에 등록되어 있어야 합니다:
//! 
//! - `Database` - MongoDB 연결 관리자
//! - `RedisClient` - Redis 캐시 클라이언트
//! 
//! ```rust,ignore
//! // 애플리케이션 초기화 시
//! ServiceLocator::register(Database::new().await?);
//! ServiceLocator::register(RedisClient::new().await?);
//! ```

pub mod user_repo;
