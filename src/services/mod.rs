//! # 비즈니스 로직 서비스 모듈
//! 
//! 애플리케이션의 핵심 비즈니스 로직을 담당하는 서비스 계층입니다.
//! Spring Framework의 Service Layer 패턴을 참고하여 설계되었으며,
//! 도메인별로 모듈화된 서비스들을 제공합니다.
//! 
//! ## 아키텍처 개요
//! 
//! ```text
//! ┌─────────────────┐
//! │   Controllers   │ ← HTTP 요청/응답 처리
//! └─────────────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │    Services     │ ← 비즈니스 로직 (이 모듈)
//! └─────────────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  Repositories   │ ← 데이터 액세스
//! └─────────────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │   Database      │ ← 영구 저장소
//! └─────────────────┘
//! ```
//! 
//! ## 도메인별 서비스 모듈
//! 
//! ### 사용자 관리 ([`users`])
//! - **사용자 생명주기 관리**: 생성, 조회, 수정, 삭제
//! - **비밀번호 관리**: bcrypt 해싱 및 검증
//! - **프로필 관리**: 사용자 정보 업데이트 및 관리
//! - **데이터 변환**: Entity ↔ DTO 변환 로직
//! 
//! ### 인증 및 보안 ([`auth`])
//! - **JWT 토큰 관리**: 액세스/리프레시 토큰 생성 및 검증
//! - **OAuth 통합**: Google OAuth 2.0 인증 플로우
//! - **보안 정책**: 토큰 만료, 권한 검증, CSRF 방지
//! - **세션 관리**: 사용자 인증 상태 관리
//! 
//! ## 핵심 설계 원칙
//! 
//! ### 1. 싱글톤 패턴 (Singleton Pattern)
//! 
//! 모든 서비스는 `#[service]` 매크로를 통해 자동으로 싱글톤으로 관리됩니다:
//! 
//! ```rust,ignore
//! #[service]
//! pub struct UserService {
//!     user_repo: Arc<UserRepository>,
//! }
//! 
//! // 사용법
//! let user_service = UserService::instance(); // 항상 동일한 인스턴스
//! ```
//! 
//! **이점:**
//! - 메모리 효율성 향상
//! - 일관된 상태 관리
//! - 스레드 안전성 보장 (`Arc<T>` 기반)
//! 
//! ### 2. 의존성 주입 (Dependency Injection)
//! 
//! Spring의 `@Autowired`와 유사하게 자동 의존성 주입을 지원합니다:
//! 
//! ```rust,ignore
//! #[service]
//! pub struct AuthService {
//!     user_repo: Arc<UserRepository>,     // 자동 주입
//!     token_service: Arc<TokenService>,   // 자동 주입
//!     config: AuthConfig,                 // Default::default()
//! }
//! ```
//! 
//! **주입 규칙:**
//! - `Arc<T>` 타입: `ServiceLocator::get::<T>()`로 자동 주입
//! - 기타 타입: `Default::default()` 사용
//! 
//! ### 3. 트랜잭션 관리 (Transaction Management)
//! 
//! 비즈니스 로직의 원자성을 보장하기 위한 트랜잭션 경계 설정:
//! 
//! ```rust,ignore
//! impl UserService {
//!     pub async fn create_user(&self, request: CreateUserRequest) -> Result<CreateUserResponse, AppError> {
//!         // 1. 입력값 검증
//!         // 2. 비즈니스 규칙 적용 (중복 확인 등)
//!         // 3. 데이터 변환 (DTO → Entity)
//!         // 4. Repository를 통한 영구 저장
//!         // 5. 응답 DTO 생성
//!     }
//! }
//! ```
//! 
//! ### 4. 에러 처리 및 로깅
//! 
//! 일관된 에러 처리와 상세한 로깅을 통한 디버깅 지원:
//! 
//! ```rust,ignore
//! pub async fn verify_password(&self, email: &str, password: &str) -> Result<User, AppError> {
//!     let start_time = std::time::Instant::now();
//!     
//!     // 비즈니스 로직 수행
//!     let result = self.perform_authentication(email, password).await?;
//!     
//!     let duration = start_time.elapsed();
//!     log::info!("Password verification took: {:?}", duration);
//!     
//!     Ok(result)
//! }
//! ```
//! 
//! ## 성능 최적화 전략
//! 
//! ### 1. 비동기 처리 (Async/Await)
//! 
//! 모든 I/O 작업은 비동기로 처리하여 높은 동시성을 달성합니다:
//! 
//! ```rust,ignore
//! // 동시 실행으로 성능 향상
//! let (user_result, auth_result) = tokio::join!(
//!     user_service.get_user_by_id(id),
//!     auth_service.verify_token(token)
//! );
//! ```
//! 
//! ### 2. 스마트 캐싱
//! 
//! Repository 레이어와 협력하여 효율적인 캐싱을 활용합니다:
//! 
//! ```rust,ignore
//! // Repository의 캐시를 활용한 빠른 조회
//! let user = self.user_repo.find_by_email(email).await?; // Redis 캐시 우선
//! ```
//! 
//! ### 3. 배치 처리
//! 
//! 대량 데이터 처리 시 배치 작업으로 성능을 최적화합니다.
//! 
//! ## 보안 고려사항
//! 
//! ### 1. 비밀번호 보안
//! 
//! - **bcrypt 해싱**: 환경별 cost 설정으로 보안 강도 조절
//! - **솔트 자동 생성**: 레인보우 테이블 공격 방지
//! - **타이밍 공격 방지**: 일정한 검증 시간 유지
//! 
//! ### 2. JWT 토큰 보안
//! 
//! - **짧은 액세스 토큰 수명**: 탈취 위험 최소화
//! - **리프레시 토큰 순환**: 장기간 사용 시 보안 강화
//! - **서명 검증**: 토큰 무결성 보장
//! 
//! ### 3. OAuth 보안
//! 
//! - **State 매개변수**: CSRF 공격 방지
//! - **Nonce 검증**: 재생 공격 방지
//! - **HTTPS 강제**: 민감 정보 전송 보호
//! 
//! ## 사용 예제
//! 
//! ### 사용자 생성 플로우
//! 
//! ```rust,ignore
//! use crate::services::{users::UserService, auth::TokenService};
//! 
//! async fn register_user() -> Result<(), AppError> {
//!     // 1. 서비스 인스턴스 가져오기
//!     let user_service = UserService::instance();
//!     let token_service = TokenService::instance();
//!     
//!     // 2. 사용자 생성 요청
//!     let request = CreateUserRequest {
//!         email: "user@example.com".to_string(),
//!         username: "john_doe".to_string(),
//!         password: "secure_password".to_string(),
//!         display_name: "John Doe".to_string(),
//!     };
//!     
//!     // 3. 사용자 생성 (비즈니스 로직 실행)
//!     let response = user_service.create_user(request).await?;
//!     
//!     // 4. 인증 토큰 생성
//!     let user = User::from(response.user);
//!     let token_pair = token_service.generate_token_pair(&user)?;
//!     
//!     println!("사용자 생성 완료: {}", response.message);
//!     println!("액세스 토큰: {}", token_pair.access_token);
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ### OAuth 인증 플로우
//! 
//! ```rust,ignore
//! use crate::services::auth::GoogleAuthService;
//! 
//! async fn google_oauth_flow() -> Result<(), AppError> {
//!     let google_auth = GoogleAuthService::instance();
//!     
//!     // 1. 로그인 URL 생성
//!     let login_response = google_auth.get_login_url()?;
//!     println!("로그인 URL: {}", login_response.login_url);
//!     
//!     // 2. 콜백 처리 (Authorization Code 받음)
//!     let auth_code = "received_from_google";
//!     let state = login_response.state;
//!     
//!     // 3. 사용자 인증 및 등록/로그인
//!     let user = google_auth.authenticate_with_code(auth_code, &state).await?;
//!     
//!     println!("Google 인증 완료: {}", user.email);
//!     Ok(())
//! }
//! ```
//! 
//! ## 설정 및 의존성
//! 
//! ### 필수 컴포넌트
//! 
//! 서비스 계층이 정상 작동하려면 다음 컴포넌트들이 ServiceLocator에 등록되어야 합니다:
//! 
//! ```rust,ignore
//! // 애플리케이션 초기화 시
//! use crate::core::registry::ServiceLocator;
//! 
//! async fn initialize_services() -> Result<(), AppError> {
//!     // 데이터베이스 및 캐시 클라이언트
//!     ServiceLocator::register(Database::new().await?);
//!     ServiceLocator::register(RedisClient::new().await?);
//!     
//!     // 리포지토리 등록 (자동 등록됨)
//!     // 서비스 등록 (자동 등록됨)
//!     
//!     println!("서비스 초기화 완료");
//!     Ok(())
//! }
//! ```
//! 
//! ### 환경 설정
//! 
//! - `JWT_SECRET`: JWT 토큰 서명용 비밀키
//! - `BCRYPT_COST`: 비밀번호 해싱 강도
//! - `GOOGLE_CLIENT_ID`: Google OAuth 클라이언트 ID
//! - `GOOGLE_CLIENT_SECRET`: Google OAuth 클라이언트 시크릿
//! 
//! ## 확장 가능성
//! 
//! ### 새로운 서비스 추가
//! 
//! ```rust,ignore
//! // 새로운 도메인 서비스 추가
//! pub mod orders;     // 주문 관리
//! pub mod payments;   // 결제 처리
//! pub mod notifications; // 알림 서비스
//! ```
//! 
//! ### 추가 인증 프로바이더
//! 
//! ```rust,ignore
//! // auth 모듈에 새로운 OAuth 프로바이더 추가
//! pub mod github_auth_service;
//! pub mod facebook_auth_service;
//! pub mod apple_auth_service;
//! ```
//! 
//! ## 성능 모니터링
//! 
//! 모든 서비스는 성능 메트릭을 수집하며, 다음과 같은 지표를 추적합니다:
//! 
//! - **응답 시간**: 각 메서드의 실행 시간
//! - **처리량**: 초당 요청 처리 수
//! - **에러율**: 실패한 요청의 비율
//! - **리소스 사용량**: 메모리, CPU 사용률
//! 
//! 이러한 메트릭을 통해 병목 지점을 식별하고 성능을 지속적으로 개선할 수 있습니다.

pub mod users;
pub mod auth;
