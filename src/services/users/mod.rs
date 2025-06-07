//! # 사용자 관리 서비스 모듈
//! 
//! 사용자 생명주기와 관련된 모든 비즈니스 로직을 담당하는 서비스들을 제공합니다.
//! Spring Framework의 UserDetailsService와 UserService 패턴을 참고하여 설계되었으며,
//! 사용자 등록, 인증, 프로필 관리, 계정 상태 관리 등의 핵심 기능을 구현합니다.
//! 
//! ## 아키텍처 개요
//! 
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        User Service Layer                       │
//! ├─────────────────┬─────────────────┬─────────────────────────────┤
//! │  User Lifecycle │  Authentication │      Profile Management     │
//! │                 │                 │                             │
//! │ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────────────────┐ │
//! │ │   CREATE    │ │ │  PASSWORD   │ │ │       UPDATE            │ │
//! │ │             │ │ │             │ │ │                         │ │
//! │ │ • 회원가입    │ │ │ • 로컬 인증   │ │ │ • 프로필 수정              │ │
//! │ │ • 검증       │ │ │ • bcrypt    │ │ │ • 권한 관리               │ │
//! │ │ • 해싱       │ │ │ • 타이밍      │ │ │ • 상태 변경               │ │
//! │ └─────────────┘ │ └─────────────┘ │ └─────────────────────────┘ │
//! │                 │                 │                             │
//! │ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────────────────┐ │
//! │ │    READ     │ │ │   VERIFY    │ │ │        DELETE           │ │
//! │ │             │ │ │             │ │ │                         │ │
//! │ │ • ID 조회    │ │ │ • 계정 상태   │ │ │ • 계정 비활성화             │ │
//! │ │ • 이메일 조회  │ │ │ • OAuth 체크│ │ │ • 데이터 정리               │ │
//! │ │ • DTO 변환   │ │ │ • 로그인 로그│ │ │ • 연관 데이터 처리            │ │
//! │ └─────────────┘ │ └─────────────┘ │ └─────────────────────────┘ │
//! └─────────────────┴─────────────────┴─────────────────────────────┘
//!                                 │
//!                                 ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Repository Layer                             │
//! │                                                                 │
//! │  • MongoDB 영구 저장                                              │
//! │  • Redis 캐싱                                                    │
//! │  • 인덱스 최적화                                                   │
//! │  • 트랜잭션 관리                                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//! 
//! ## 제공 서비스
//! 
//! ### 사용자 서비스 ([`UserService`](user_service::UserService))
//! 
//! 사용자 계정의 전체 생명주기를 관리하는 핵심 서비스입니다.
//! Spring Security의 UserDetailsService와 유사한 역할을 수행하며,
//! 추가로 사용자 등록 및 프로필 관리 기능을 제공합니다.
//! 
//! **주요 기능:**
//! 
//! - **사용자 등록**: 로컬 계정 생성 및 비밀번호 해싱
//! - **사용자 조회**: ID, 이메일 기반 사용자 정보 검색
//! - **인증 지원**: 비밀번호 검증 및 계정 상태 확인
//! - **계정 관리**: 사용자 삭제 및 비활성화
//! - **보안 강화**: bcrypt 해싱, 타이밍 공격 방지
//! 
//! ## 비즈니스 로직 패턴
//! 
//! ### 1. 사용자 등록 플로우
//! 
//! ```text
//! 클라이언트 요청 (CreateUserRequest)
//!           │
//!           ▼
//! ┌─────────────────────────────────────┐
//! │        입력 검증                      │
//! │ • 이메일 형식 확인                      │
//! │ • 비밀번호 복잡도 검증                   │
//! │ • 사용자명 규칙 확인                     │
//! └─────────────────────────────────────┘
//!           │
//!           ▼
//! ┌─────────────────────────────────────┐
//! │        중복 검사                      │
//! │ • 이메일 중복 확인                      │
//! │ • 사용자명 중복 확인                    │
//! │ • Repository 계층 호출               │
//! └─────────────────────────────────────┘
//!           │
//!           ▼
//! ┌─────────────────────────────────────┐
//! │      비밀번호 해싱                   │
//! │ • bcrypt 알고리즘 사용               │
//! │ • 환경별 cost 설정                  │
//! │ • 솔트 자동 생성                    │
//! └─────────────────────────────────────┘
//!           │
//!           ▼
//! ┌─────────────────────────────────────┐
//! │       엔티티 생성                    │
//! │ • User::new_local() 호출            │
//! │ • 기본값 설정                       │
//! │ • 메타데이터 추가                   │
//! └─────────────────────────────────────┘
//!           │
//!           ▼
//! ┌─────────────────────────────────────┐
//! │       영구 저장                      │
//! │ • Repository::create() 호출         │
//! │ • MongoDB 저장                      │
//! │ • 캐시 무효화                       │
//! └─────────────────────────────────────┘
//!           │
//!           ▼
//! ┌─────────────────────────────────────┐
//! │       응답 생성                      │
//! │ • Entity → DTO 변환                 │
//! │ • 민감 정보 제거                    │
//! │ • CreateUserResponse 반환           │
//! └─────────────────────────────────────┘
//! ```
//! 
//! ### 2. 인증 플로우
//! 
//! ```text
//! 로그인 요청 (email, password)
//!           │
//!           ▼
//! ┌─────────────────────────────────────┐
//! │      사용자 조회                     │
//! │ • 이메일 기반 검색                   │
//! │ • 캐시 우선 조회                    │
//! │ • 존재하지 않으면 실패               │
//! └─────────────────────────────────────┘
//!           │
//!           ▼
//! ┌─────────────────────────────────────┐
//! │    인증 방식 확인                    │
//! │ • OAuth vs 로컬 계정 구분            │
//! │ • 비밀번호 해시 존재 여부            │
//! │ • 로컬 계정만 처리                   │
//! └─────────────────────────────────────┘
//!           │
//!           ▼
//! ┌─────────────────────────────────────┐
//! │     비밀번호 검증                       │
//! │ • bcrypt::verify() 호출             │
//! │ • 타이밍 공격 방지                  │
//! │ • 검증 시간 로깅                    │
//! └─────────────────────────────────────┘
//!           │
//!           ▼
//! ┌─────────────────────────────────────┐
//! │     계정 상태 확인                     │
//! │ • is_active 플래그 검사                │
//! │ • 계정 잠금 여부 확인                    │
//! │ • 활성 계정만 로그인 허용                 │
//! └─────────────────────────────────────┘
//!           │
//!           ▼
//!         인증 성공
//! ```
//! 
//! ## 보안 특징
//! 
//! ### 1. 비밀번호 보안
//! 
//! - **bcrypt 해싱**: 적응형 해시 함수로 무차별 대입 공격 방지
//! - **환경별 Cost**: 개발(낮음) vs 운영(높음) 환경별 보안 강도 조절
//! - **솔트 자동 생성**: 레인보우 테이블 공격 방지
//! - **타이밍 공격 방지**: 일정한 검증 시간 유지
//! 
//! ### 2. 입력 검증
//! 
//! - **이메일 형식**: RFC 5322 표준 준수
//! - **비밀번호 복잡도**: 최소 길이, 특수문자, 대소문자 조합
//! - **사용자명 규칙**: 영숫자, 언더스코어만 허용
//! - **SQL 인젝션 방지**: 매개변수화된 쿼리 사용
//! 
//! ### 3. 계정 보안
//! 
//! - **중복 방지**: 이메일, 사용자명 유니크 제약
//! - **계정 상태 관리**: 활성/비활성 플래그
//! - **인증 제한**: OAuth 계정은 비밀번호 인증 차단
//! - **감사 로그**: 중요 작업 로깅
//! 
//! ## 성능 최적화
//! 
//! ### 1. 캐싱 전략
//! 
//! - **Repository 캐싱**: 사용자 조회 시 Redis 캐시 활용
//! - **해싱 최적화**: 환경별 bcrypt cost 조절
//! - **배치 처리**: 대량 사용자 처리 시 배치 작업
//! 
//! ### 2. 비동기 처리
//! 
//! - **I/O 최적화**: 모든 DB 작업 비동기 처리
//! - **동시성**: 다중 요청 병렬 처리
//! - **백프레셔**: 부하 제어 메커니즘
//! 
//! ### 3. 메트릭 수집
//! 
//! - **처리 시간**: 각 작업별 소요 시간 측정
//! - **성공률**: 인증 성공/실패 비율
//! - **리소스 사용량**: 메모리, CPU 사용량 모니터링
//! 
//! ## 사용 예제
//! 
//! ### 사용자 등록
//! 
//! ```rust,ignore
//! use crate::services::users::UserService;
//! use crate::domain::dto::users::request::CreateUserRequest;
//! 
//! async fn register_user() -> Result<(), AppError> {
//!     let user_service = UserService::instance();
//!     
//!     let request = CreateUserRequest {
//!         email: "alice@example.com".to_string(),
//!         username: "alice_doe".to_string(),
//!         display_name: "Alice Doe".to_string(),
//!         password: "SecurePassword123!".to_string(),
//!     };
//!     
//!     let response = user_service.create_user(request).await?;
//!     
//!     println!("사용자 생성 완료: {}", response.message);
//!     println!("사용자 ID: {}", response.user.id);
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ### 사용자 인증
//! 
//! ```rust,ignore
//! async fn authenticate_user() -> Result<(), AppError> {
//!     let user_service = UserService::instance();
//!     
//!     // 비밀번호 검증
//!     let user = user_service
//!         .verify_password("alice@example.com", "SecurePassword123!")
//!         .await?;
//!     
//!     println!("인증 성공: {} ({})", user.username, user.email);
//!     
//!     // JWT 토큰 생성 (인증 서비스와 연계)
//!     let token_service = TokenService::instance();
//!     let tokens = token_service.generate_token_pair(&user)?;
//!     
//!     println!("액세스 토큰: {}", tokens.access_token);
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ### 사용자 프로필 조회
//! 
//! ```rust,ignore
//! async fn get_user_profile(user_id: &str) -> Result<(), AppError> {
//!     let user_service = UserService::instance();
//!     
//!     let user_response = user_service.get_user_by_id(user_id).await?;
//!     
//!     println!("사용자 프로필:");
//!     println!("  이메일: {}", user_response.email);
//!     println!("  사용자명: {}", user_response.username);
//!     println!("  표시명: {}", user_response.display_name);
//!     println!("  가입일: {}", user_response.created_at);
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ## 에러 처리
//! 
//! 모든 서비스 메서드는 `Result<T, AppError>` 타입을 반환하며,
//! 다음과 같은 에러 상황을 처리합니다:
//! 
//! | 에러 유형 | 원인 | 대처 방안 |
//! |-----------|------|-----------|
//! | `ValidationError` | 입력값 검증 실패 | 클라이언트 입력 수정 |
//! | `ConflictError` | 중복 데이터 | 다른 값으로 재시도 |
//! | `NotFound` | 존재하지 않는 사용자 | 404 응답 |
//! | `AuthenticationError` | 인증 실패 | 로그인 정보 재확인 |
//! | `InternalError` | 시스템 오류 | 서버 로그 확인 |
//! 
//! ## 확장 가능성
//! 
//! ### 추가 기능
//! 
//! ```rust,ignore
//! // 향후 추가 가능한 기능들
//! impl UserService {
//!     pub async fn update_profile(&self, id: &str, update: UpdateProfileRequest) -> Result<UserResponse, AppError>;
//!     pub async fn change_password(&self, id: &str, old_password: &str, new_password: &str) -> Result<(), AppError>;
//!     pub async fn reset_password(&self, email: &str) -> Result<(), AppError>;
//!     pub async fn activate_account(&self, token: &str) -> Result<(), AppError>;
//!     pub async fn deactivate_account(&self, id: &str, reason: &str) -> Result<(), AppError>;
//!     pub async fn get_user_list(&self, filter: UserFilter, pagination: Pagination) -> Result<PagedUserResponse, AppError>;
//! }
//! ```
//! 
//! ### 통합 모듈
//! 
//! ```rust,ignore
//! pub mod profile_service;      // 프로필 관리 전담
//! pub mod notification_service; // 사용자 알림
//! pub mod preferences_service;  // 사용자 설정
//! pub mod avatar_service;       // 프로필 이미지 관리
//! ```
//! 
//! ## 설정 요구사항
//! 
//! ### 환경 변수
//! 
//! ```bash
//! # 비밀번호 해싱 설정
//! BCRYPT_COST=12  # 운영환경: 12-15, 개발환경: 4-8
//! 
//! # 사용자 검증 규칙
//! MIN_PASSWORD_LENGTH=8
//! MAX_USERNAME_LENGTH=30
//! REQUIRE_EMAIL_VERIFICATION=true
//! ```
//! 
//! ### 필수 의존성
//! 
//! ```toml
//! [dependencies]
//! bcrypt = "0.14"           # 비밀번호 해싱
//! regex = "1.0"             # 입력 검증
//! validator = "0.16"        # 데이터 검증
//! chrono = "0.4"            # 시간 처리
//! ```
//! 
//! 이 모듈은 안전하고 확장 가능한 사용자 관리 시스템의 기반을 제공하며,
//! Spring Framework의 검증된 패턴을 Rust 생태계에 맞게 구현하여
//! 현대적인 웹 애플리케이션의 사용자 관리 요구사항을 충족합니다.

pub mod user_service;
