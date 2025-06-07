//! # Core Framework Module
//!
//! 백엔드 서비스를 위한 핵심 프레임워크 기능을 제공하는 모듈입니다.
//! Spring Framework의 핵심 컨테이너 기능을 Rust 생태계에 맞게 구현하여,
//! 타입 안전성과 성능을 모두 만족하는 의존성 주입 시스템을 제공합니다.
//!
//! ## 모듈 구성
//!
//! ### [`registry`] - 의존성 주입 컨테이너
//! - **ServiceLocator**: Spring의 ApplicationContext + BeanFactory 역할
//! - **자동 레지스트리**: `inventory` 기반 컴파일 타임 서비스 등록
//! - **싱글톤 관리**: Thread-safe한 인스턴스 생명주기 관리
//! - **의존성 해결**: Arc<T> 타입 기반 자동 의존성 주입
//!
//! ### [`errors`] - 통합 에러 처리
//! - **AppError**: 애플리케이션 전역 에러 타입 정의
//! - **HTTP 통합**: Actix-Web ResponseError 자동 구현
//! - **계층화된 에러**: 도메인별 세분화된 에러 분류
//! - **자동 변환**: thiserror 기반 에러 체인 관리
//!
//! ## Spring Framework와의 비교
//!
//! | Spring | 이 프레임워크 |
//! |--------|---------------|
//! | `@Component` | `#[service]` / `#[repository]` |
//! | `ApplicationContext` | `ServiceLocator` |
//! | `@Autowired` | `Arc<T>` 필드 자동 주입 |
//! | `@Service` | `#[service]` 매크로 |
//! | `@Repository` | `#[repository]` 매크로 |
//! | `@ExceptionHandler` | `AppError::error_response()` |
//! | Bean 생명주기 | Singleton + Lazy 초기화 |
//!
//! ## 핵심 설계 원칙
//!
//! ### 1. Zero-Cost Abstractions
//! - 컴파일 타임 최적화를 통한 런타임 오버헤드 최소화
//! - 매크로 기반 코드 생성으로 동적 디스패치 제거
//! - 타입 소거 없는 완전한 타입 안전성
//!
//! ### 2. Thread Safety by Design
//! - `Arc<T>` + `RwLock`을 통한 동시성 안전성
//! - 불변성 우선 설계로 데이터 레이스 방지
//! - Lock-free 자료구조 활용으로 성능 최적화
//!
//! ### 3. Fail-Fast Philosophy
//! - 컴파일 타임 에러 검출 우선
//! - 명시적 에러 처리로 런타임 안정성 보장
//! - 순환 참조 등 설계 문제의 조기 발견
//!
//! ## 사용 패턴
//!
//! ### 기본 서비스 정의
//!
//! ```rust
//! use std::sync::Arc;
//! use crate::core::registry::ServiceLocator;
//!
//! // 리포지토리 정의
//! #[repository(collection = "users")]
//! struct UserRepository {
//!     db: Arc<Database>,
//!     redis: Arc<RedisClient>,
//! }
//!
//! // 서비스 정의 (자동 의존성 주입)
//! #[service]
//! struct UserService {
//!     user_repo: Arc<UserRepository>,  // 자동 주입
//!     email_service: Arc<EmailService>, // 자동 주입
//! }
//!
//! // 사용
//! let user_service = UserService::instance();
//! ```
//!
//! ### 애플리케이션 초기화
//!
//! ```rust
//! use crate::core::registry::ServiceLocator;
//! use crate::core::errors::AppError;
//!
//! #[actix_web::main]
//! async fn main() -> Result<(), AppError> {
//!     // 1. 인프라 컴포넌트 등록
//!     let database = Database::connect("mongodb://localhost").await?;
//!     let redis = RedisClient::connect("redis://localhost").await?;
//!     
//!     ServiceLocator::set(database);
//!     ServiceLocator::set(redis);
//!     
//!     // 2. 모든 서비스/리포지토리 초기화
//!     ServiceLocator::initialize_all().await?;
//!     
//!     // 3. 웹 서버 시작
//!     HttpServer::new(|| {
//!         App::new()
//!             .route("/users", web::get().to(get_users))
//!             .route("/users", web::post().to(create_user))
//!     })
//!     .bind("0.0.0.0:8080")?
//!     .run()
//!     .await
//! }
//! ```
//!
//! ### 에러 처리
//!
//! ```rust
//! use crate::core::errors::AppError;
//!
//! // 서비스 메서드에서 에러 발생
//! async fn create_user(data: UserData) -> Result<User, AppError> {
//!     if data.email.is_empty() {
//!         return Err(AppError::ValidationError("Email is required".to_string()));
//!     }
//!     
//!     let user = self.user_repo.create(data).await
//!         .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!     
//!     Ok(user)
//! }
//!
//! // 핸들러에서 자동 HTTP 응답 변환
//! async fn create_user_handler(
//!     data: web::Json<UserData>
//! ) -> Result<web::Json<User>, AppError> {
//!     let user_service = UserService::instance();
//!     let user = user_service.create_user(data.into_inner()).await?;
//!     Ok(web::Json(user))
//! }
//! ```
//!
//! ## 메모리 관리 및 성능
//!
//! ### 싱글톤 패턴의 이점
//! - **메모리 효율성**: 각 타입당 하나의 인스턴스만 생성
//! - **초기화 비용 절약**: 비싼 리소스(DB 연결 등)의 재사용
//! - **캐시 활용**: 인스턴스 수준 캐싱으로 성능 향상
//!
//! ### 지연 초기화 (Lazy Loading)
//! - **빠른 시작**: 필요한 컴포넌트만 초기화
//! - **메모리 절약**: 사용하지 않는 서비스는 생성하지 않음
//! - **오류 격리**: 특정 서비스 초기화 실패가 전체에 영향 없음
//!
//! ## 확장성 고려사항
//!
//! ### 새로운 서비스 추가
//! 1. 구조체 정의 + `#[service]` 매크로 적용
//! 2. 의존성은 `Arc<T>` 필드로 선언 (자동 주입)
//! 3. 비즈니스 로직 구현
//! 4. 컴파일 시 자동으로 레지스트리에 등록됨
//!
//! ### 외부 라이브러리 통합
//! 1. 래퍼 구조체 생성
//! 2. `ServiceLocator::set()` 으로 수동 등록
//! 3. 다른 서비스에서 `Arc<WrapperType>` 으로 주입
//!
//! ## 트러블슈팅
//!
//! ### 순환 참조 감지
//! ```text
//! ❌ Circular dependency detected for type: UserService
//! panic: Circular dependency detected: UserService is already being initialized
//! ```
//! **해결**: 서비스 계층 구조를 재설계하여 단방향 의존성으로 변경
//!
//! ### 미등록 타입 에러
//! ```text
//! panic: Service not found: EmailService. Make sure it's registered...
//! ```
//! **해결**: `#[service]` 매크로 적용 또는 `ServiceLocator::set()` 으로 수동 등록

pub mod errors;
pub mod registry;

pub use errors::*;
pub use registry::*;
