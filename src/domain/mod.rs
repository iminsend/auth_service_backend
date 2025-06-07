//! # Domain Layer Module
//!
//! 도메인 계층을 구성하는 핵심 모듈로, 비즈니스 로직과 도메인 규칙을 담당합니다.
//! Spring Framework의 Domain Layer와 동일한 역할을 수행하며,
//! Domain-Driven Design (DDD) 원칙에 따라 설계되었습니다.
//!
//! ## 아키텍처 개요
//!
//! ```text
//! Domain Layer (이 모듈)
//! ├── Entities      - 핵심 비즈니스 객체 (JPA Entity와 유사)
//! ├── DTOs         - 데이터 전송 객체 (Request/Response)  
//! └── Models       - 외부 시스템 통합 모델 (OAuth, API 등)
//!      │
//!      ▼
//! Application Layer (Services)
//!      │
//!      ▼  
//! Infrastructure Layer (Repositories, DB)
//! ```
//!
//! ## Spring Framework와의 비교
//!
//! | Spring | 이 시스템 | 역할 |
//! |--------|-----------|------|
//! | `@Entity` | `entities` 모듈 | 비즈니스 핵심 객체 |
//! | `@RequestBody` / `@ResponseBody` | `dto` 모듈 | API 계약 정의 |
//! | Domain Models | `models` 모듈 | 외부 시스템 통합 |
//! | `@Embeddable` | Struct 컴포지션 | 값 객체 표현 |
//! | `@Valid` | `serde` 검증 | 데이터 유효성 검사 |
//!
//! ## 모듈 구성
//!
//! ### [`entities`] - 핵심 도메인 엔티티
//! 
//! 비즈니스의 핵심 개념을 나타내는 영속 가능한 객체들입니다.
//! Spring JPA의 `@Entity` 클래스와 동일한 역할을 수행합니다.
//!
//! #### 특징:
//! - **영속성**: MongoDB에 저장되는 도메인 객체
//! - **비즈니스 규칙**: 도메인 로직과 제약 사항 포함
//! - **불변성**: 가능한 한 불변 객체로 설계
//! - **식별성**: 고유 ID를 통한 객체 식별
//!
//! #### 예제:
//! ```rust,ignore
//! use serde::{Deserialize, Serialize};
//! use mongodb::bson::oid::ObjectId;
//! 
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! pub struct User {
//!     #[serde(rename = "_id")]
//!     pub id: ObjectId,
//!     pub email: String,
//!     pub name: String,
//!     pub provider: AuthProvider,
//!     pub created_at: chrono::DateTime<chrono::Utc>,
//!     pub updated_at: chrono::DateTime<chrono::Utc>,
//! }
//! 
//! impl User {
//!     /// 새 사용자 생성 (팩토리 메서드)
//!     pub fn new(email: String, name: String, provider: AuthProvider) -> Self {
//!         let now = chrono::Utc::now();
//!         Self {
//!             id: ObjectId::new(),
//!             email,
//!             name,
//!             provider,
//!             created_at: now,
//!             updated_at: now,
//!         }
//!     }
//!     
//!     /// 도메인 비즈니스 로직
//!     pub fn update_profile(&mut self, name: String) {
//!         self.name = name;
//!         self.updated_at = chrono::Utc::now();
//!     }
//! }
//! ```
//!
//! ### [`dto`] - 데이터 전송 객체
//!
//! API 경계에서 데이터를 전송하기 위한 객체들입니다.
//! Spring의 `@RequestBody`/`@ResponseBody`와 동일한 역할을 수행합니다.
//!
//! #### 설계 원칙:
//! - **API 계약**: 외부 시스템과의 명확한 인터페이스 정의
//! - **유효성 검증**: 입력 데이터의 형식과 제약 조건 검증
//! - **버전 관리**: API 버전별 호환성 유지
//! - **문서화**: API 문서 자동 생성을 위한 메타데이터
//!
//! #### 구조:
//! ```text
//! dto/
//! ├── users/
//! │   ├── request/     - 사용자 관련 요청 DTO
//! │   │   ├── create_user_request.rs
//! │   │   ├── update_user_request.rs
//! │   │   └── login_request.rs
//! │   └── response/    - 사용자 관련 응답 DTO  
//! │       ├── user_response.rs
//! │       ├── auth_response.rs
//! │       └── profile_response.rs
//! └── common/         - 공통 DTO (페이지네이션 등)
//! ```
//!
//! #### 예제:
//! ```rust,ignore
//! use serde::{Deserialize, Serialize};
//! use validator::Validate;
//! 
//! /// 사용자 생성 요청 DTO
//! #[derive(Debug, Deserialize, Validate)]
//! pub struct CreateUserRequest {
//!     #[validate(email(message = "유효한 이메일 주소를 입력하세요"))]
//!     pub email: String,
//!     
//!     #[validate(length(min = 2, max = 50, message = "이름은 2-50자 사이여야 합니다"))]
//!     pub name: String,
//!     
//!     #[validate(length(min = 8, message = "비밀번호는 최소 8자 이상이어야 합니다"))]
//!     pub password: String,
//! }
//! 
//! /// 사용자 응답 DTO (민감한 정보 제외)
//! #[derive(Debug, Serialize)]
//! pub struct UserResponse {
//!     pub id: String,
//!     pub email: String,
//!     pub name: String,
//!     pub provider: String,
//!     pub created_at: String,
//! }
//! 
//! impl From<User> for UserResponse {
//!     fn from(user: User) -> Self {
//!         Self {
//!             id: user.id.to_hex(),
//!             email: user.email,
//!             name: user.name,
//!             provider: user.provider.as_str().to_string(),
//!             created_at: user.created_at.to_rfc3339(),
//!         }
//!     }
//! }
//! ```
//!
//! ### [`models`] - 외부 시스템 통합 모델
//!
//! 외부 API나 서비스와의 통합을 위한 데이터 모델들입니다.
//! Spring의 외부 API 클라이언트 모델과 유사한 역할을 수행합니다.
//!
//! #### 용도:
//! - **OAuth 통합**: Google, GitHub 등 OAuth 프로바이더 모델
//! - **외부 API**: 써드파티 서비스 연동 모델
//! - **메시지 큐**: RabbitMQ, Kafka 등 메시지 모델
//! - **캐시**: Redis 저장용 임시 모델
//!
//! #### 구조:
//! ```text
//! models/
//! ├── oauth/
//! │   ├── google_oauth_model/
//! │   │   ├── token_response.rs
//! │   │   ├── user_info.rs
//! │   │   └── auth_request.rs
//! │   ├── github_oauth_model/   (향후 확장)
//! │   └── facebook_oauth_model/ (향후 확장)
//! ├── external_api/
//! │   ├── payment_gateway/
//! │   └── email_service/
//! └── cache/
//!     ├── session_model.rs
//!     └── user_cache.rs
//! ```
//!
//! #### 예제:
//! ```rust,ignore
//! use serde::{Deserialize, Serialize};
//! 
//! /// Google OAuth 토큰 응답 모델
//! #[derive(Debug, Deserialize)]
//! pub struct GoogleTokenResponse {
//!     pub access_token: String,
//!     pub expires_in: u64,
//!     pub refresh_token: Option<String>,
//!     pub scope: String,
//!     pub token_type: String,
//!     pub id_token: Option<String>,
//! }
//! 
//! /// Google 사용자 정보 모델
//! #[derive(Debug, Deserialize)]
//! pub struct GoogleUserInfo {
//!     pub id: String,
//!     pub email: String,
//!     pub verified_email: bool,
//!     pub name: String,
//!     pub given_name: String,
//!     pub family_name: String,
//!     pub picture: String,
//!     pub locale: String,
//! }
//! 
//! impl From<GoogleUserInfo> for User {
//!     fn from(google_user: GoogleUserInfo) -> Self {
//!         User::new(
//!             google_user.email,
//!             google_user.name,
//!             AuthProvider::Google,
//!         )
//!     }
//! }
//! ```
//!
//! ## 설계 패턴 및 원칙
//!
//! ### 1. Domain-Driven Design (DDD)
//!
//! - **유비쿼터스 언어**: 도메인 전문가와 개발자가 공통으로 사용하는 용어
//! - **경계 컨텍스트**: 명확한 도메인 경계 설정
//! - **애그리게이트**: 관련 엔티티들의 논리적 그룹핑
//! - **값 객체**: 식별자가 없는 불변 객체
//!
//! ### 2. Clean Architecture
//!
//! - **의존성 규칙**: 외부 계층이 내부 계층에 의존 (역방향 의존성 금지)
//! - **인터페이스 분리**: 각 모듈간 명확한 인터페이스 정의
//! - **단일 책임**: 각 모듈이 하나의 책임만 가지도록 설계
//!
//! ### 3. 타입 안전성
//!
//! - **컴파일 타임 검증**: Rust의 타입 시스템 활용
//! - **Null Safety**: Option<T>를 통한 안전한 null 처리
//! - **에러 핸들링**: Result<T, E>를 통한 명시적 에러 처리
//!
//! ## 실제 사용 예제
//!
//! ### 사용자 등록 플로우
//!
//! ```rust,ignore
//! use crate::domain::{entities::User, dto::CreateUserRequest};
//! use crate::core::errors::AppError;
//! 
//! // 1. DTO로 입력 받기
//! let request = CreateUserRequest {
//!     email: "user@example.com".to_string(),
//!     name: "John Doe".to_string(),
//!     password: "securepass123".to_string(),
//! };
//! 
//! // 2. 유효성 검증
//! request.validate()?;
//! 
//! // 3. 도메인 엔티티 생성
//! let user = User::new(
//!     request.email,
//!     request.name,
//!     AuthProvider::Local,
//! );
//! 
//! // 4. 리포지토리를 통한 영속화
//! let saved_user = user_repository.create(user).await?;
//! 
//! // 5. 응답 DTO로 변환
//! let response = UserResponse::from(saved_user);
//! ```
//!
//! ### Google OAuth 통합 플로우
//!
//! ```rust,ignore
//! use crate::domain::models::oauth::GoogleUserInfo;
//! 
//! // 1. Google에서 사용자 정보 받기
//! let google_user: GoogleUserInfo = oauth_service
//!     .get_user_info(access_token).await?;
//! 
//! // 2. 도메인 엔티티로 변환
//! let user = User::from(google_user);
//! 
//! // 3. 기존 사용자 확인 또는 새 사용자 생성
//! let existing_user = user_repository
//!     .find_by_email(&user.email).await?;
//! 
//! let final_user = match existing_user {
//!     Some(existing) => existing,
//!     None => user_repository.create(user).await?,
//! };
//! ```
//!
//! ## 확장성 고려사항
//!
//! ### 1. 새로운 엔티티 추가
//!
//! ```rust,ignore
//! // entities/posts/post.rs
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! pub struct Post {
//!     #[serde(rename = "_id")]
//!     pub id: ObjectId,
//!     pub title: String,
//!     pub content: String,
//!     pub author_id: ObjectId,  // User와의 관계
//!     pub created_at: DateTime<Utc>,
//! }
//! ```
//!
//! ### 2. 새로운 외부 서비스 통합
//!
//! ```rust,ignore
//! // models/payment/stripe_model.rs
//! #[derive(Debug, Deserialize)]
//! pub struct StripePaymentIntent {
//!     pub id: String,
//!     pub amount: u64,
//!     pub currency: String,
//!     pub status: String,
//! }
//! ```
//!
//! ### 3. API 버전 관리
//!
//! ```text
//! dto/
//! ├── v1/
//! │   └── users/
//! │       ├── request/
//! │       └── response/
//! └── v2/
//!     └── users/
//!         ├── request/
//!         └── response/
//! ```
//!
//! ## 트러블슈팅
//!
//! ### 일반적인 문제들
//!
//! #### 1. 직렬화/역직렬화 오류
//! ```text
//! Error: missing field `created_at`
//! 해결: #[serde(default)] 또는 Option<T> 사용
//! ```
//!
//! #### 2. 순환 참조
//! ```text
//! Error: cycle detected when computing layout
//! 해결: Arc<T> 또는 참조 타입으로 관계 표현
//! ```
//!
//! #### 3. 타입 변환 오류
//! ```text
//! Error: the trait `From<X>` is not implemented for `Y`
//! 해결: 적절한 From/Into trait 구현
//! ```
//!
//! ## 베스트 프랙티스
//!
//! 1. **작은 인터페이스**: 각 DTO는 특정 용도에만 최적화
//! 2. **불변성 우선**: 가능한 한 불변 객체로 설계
//! 3. **명시적 변환**: From/Into trait을 통한 타입 변환
//! 4. **문서화**: 각 필드와 메서드에 명확한 문서 제공
//! 5. **테스트 작성**: 도메인 로직에 대한 충분한 단위 테스트

pub mod entities;
pub mod dto;
pub mod models;

pub use entities::*;
pub use dto::*;
pub use models::*;
