//! # Domain Entities Module
//!
//! 이 모듈은 비즈니스 도메인의 핵심 엔티티들을 정의합니다.
//! Spring Framework의 JPA Entity와 유사한 역할을 하며, MongoDB 문서와 직접 매핑되는
//! 데이터 구조체들을 포함합니다.
//!
//! ## 주요 역할
//!
//! - **도메인 모델링**: 비즈니스 도메인의 핵심 개념들을 Rust 구조체로 표현
//! - **데이터베이스 매핑**: MongoDB 컬렉션과 1:1 대응되는 문서 구조 정의
//! - **타입 안전성**: 컴파일 타임에 데이터 일관성 보장
//! - **직렬화/역직렬화**: JSON ↔ Rust 구조체 변환 지원
//!
//! ## 아키텍처 특징
//!
//! ### DDD(Domain Driven Design) 적용
//! ```text
//! Domain Layer
//! ├── entities/     ← 이 모듈 (핵심 비즈니스 엔티티)
//! ├── models/       ← 도메인 모델 및 값 객체
//! └── dto/          ← 데이터 전송 객체
//! ```
//!
//! ### MongoDB 통합
//! 모든 엔티티는 다음 특징을 가집니다:
//! - **BSON 직렬화**: `serde`와 `bson` 크레이트를 통한 자동 변환
//! - **ObjectId 지원**: MongoDB의 `_id` 필드와 매핑
//! - **인덱스 설정**: 성능 최적화를 위한 복합 인덱스 지원
//! - **스키마 검증**: Rust 타입 시스템을 통한 데이터 무결성 보장
//!
//! ### 싱글톤 매크로 연동
//! 이 엔티티들은 프로젝트의 `#[repository]` 매크로와 함께 사용됩니다:
//! ```rust,ignore
//! use crate::domain::entities::users::User;
//! 
//! #[repository(collection = "users")]
//! struct UserRepository {
//!     db: Arc<Database>,
//!     cache: Arc<RedisClient>,
//! }
//! 
//! impl UserRepository {
//!     async fn find_by_email(&self, email: &str) -> Option<User> {
//!         self.collection::<User>()
//!             .find_one(doc! { "email": email }, None)
//!             .await
//!             .ok()
//!             .flatten()
//!     }
//! }
//! ```
//!
//! ## 엔티티 설계 원칙
//!
//! ### 1. 불변성 우선
//! ```rust,ignore
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! pub struct User {
//!     #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
//!     pub id: Option<ObjectId>,
//!     pub email: String,           // 변경 불가능한 식별자
//!     pub created_at: DateTime<Utc>, // 생성 시점 고정
//!     // ...
//! }
//! ```
//!
//! ### 2. 타입 안전성
//! ```rust,ignore
//! // 원시 타입 대신 명확한 도메인 타입 사용
//! pub struct UserId(ObjectId);
//! pub struct Email(String);
//! pub struct HashedPassword(String);
//! ```
//!
//! ### 3. 비즈니스 규칙 캡슐화
//! ```rust,ignore
//! impl User {
//!     pub fn new(email: String, password: String) -> Result<Self, ValidationError> {
//!         // 이메일 형식 검증
//!         if !is_valid_email(&email) {
//!             return Err(ValidationError::InvalidEmail);
//!         }
//!         
//!         // 비밀번호 강도 검증
//!         if !is_strong_password(&password) {
//!             return Err(ValidationError::WeakPassword);
//!         }
//!         
//!         Ok(User {
//!             id: None,
//!             email,
//!             password_hash: hash_password(&password)?,
//!             created_at: Utc::now(),
//!             updated_at: Utc::now(),
//!         })
//!     }
//! }
//! ```
//!
//! ## Spring Framework와의 비교
//!
//! | Spring JPA Entity | Rust Domain Entity |
//! |------------------|-------------------|
//! | `@Entity` | `#[derive(Serialize, Deserialize)]` |
//! | `@Id` | `#[serde(rename = "_id")]` |
//! | `@Column` | `#[serde(rename = "field_name")]` |
//! | `@CreatedDate` | `created_at: DateTime<Utc>` |
//! | `@Transactional` | MongoDB Transaction API |
//! | Bean Validation | Rust 타입 시스템 + 커스텀 검증 |
//!
//! ## 성능 고려사항
//!
//! ### 메모리 효율성
//! - **Arc 공유**: 불변 엔티티는 `Arc`로 감싸서 메모리 복사 최소화
//! - **지연 로딩**: 필요한 경우에만 관련 엔티티 로딩
//! - **부분 업데이트**: 전체 문서가 아닌 변경된 필드만 업데이트
//!
//! ### 캐싱 전략
//! ```rust,ignore
//! // Repository 레벨에서 자동 캐싱
//! let user = user_repo.find_by_id("user123").await?; // DB 조회
//! let same_user = user_repo.find_by_id("user123").await?; // 캐시에서 조회
//! ```
//!
//! ## 모듈 구조
//!
//! ```text
//! entities/
//! ├── mod.rs          ← 이 파일 (전체 엔티티 모듈 문서)
//! ├── users/          ← 사용자 관련 엔티티
//! │   ├── mod.rs
//! │   ├── user.rs     ← User 엔티티
//! │   └── profile.rs  ← UserProfile 엔티티
//! ├── auth/           ← 인증 관련 엔티티  
//! │   ├── session.rs  ← Session 엔티티
//! │   └── token.rs    ← RefreshToken 엔티티
//! └── shared/         ← 공통 엔티티 및 타입
//!     ├── base.rs     ← BaseEntity trait
//!     └── types.rs    ← 공통 도메인 타입
//! ```
//!
//! ## 예제: 전체 워크플로우
//!
//! ```rust,ignore
//! use crate::domain::entities::users::User;
//! use crate::repositories::users::UserRepository;
//! use crate::services::users::UserService;
//!
//! // 1. 엔티티 생성
//! let user = User::new("user@example.com".to_string(), "strong_password".to_string())?;
//!
//! // 2. Repository를 통한 저장 (싱글톤)
//! let user_repo = UserRepository::instance();
//! let saved_user = user_repo.save(user).await?;
//!
//! // 3. Service에서 비즈니스 로직 수행 (싱글톤)
//! let user_service = UserService::instance();
//! let updated_user = user_service.update_profile(saved_user.id, profile_data).await?;
//!
//! // 4. 자동 캐싱으로 성능 최적화
//! let cached_user = user_repo.find_by_id(saved_user.id).await?; // 캐시에서 조회
//! ```
//!
//! ## 마이그레이션 및 스키마 진화
//!
//! MongoDB의 스키마리스 특성을 활용하면서도 타입 안전성을 유지:
//! ```rust,ignore
//! #[derive(Serialize, Deserialize)]
//! pub struct User {
//!     #[serde(skip_serializing_if = "Option::is_none")]
//!     pub legacy_field: Option<String>, // 기존 필드 호환성
//!     
//!     #[serde(default)]
//!     pub new_field: bool, // 새로운 필드 (기본값 적용)
//! }
//! ```
//!
//! ## 주의사항
//!
//! - **순환 참조 금지**: 엔티티 간 직접 참조보다는 ID 참조 사용
//! - **크기 제한**: MongoDB 문서 크기 제한(16MB) 고려
//! - **인덱스 설계**: 쿼리 패턴에 맞는 복합 인덱스 설계 필수
//! - **데이터 일관성**: 트랜잭션이 필요한 작업은 명시적 처리

pub mod users;