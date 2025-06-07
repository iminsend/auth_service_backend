//! # Data Transfer Objects (DTO) Module
//!
//! API 경계에서 데이터를 전송하기 위한 객체들을 정의하는 모듈입니다.
//! Spring Framework의 `@RequestBody`, `@ResponseBody`와 동일한 역할을 수행하며,
//! 클라이언트와 서버 간의 데이터 계약(Contract)을 명확히 정의합니다.
//!
//! ## Spring Framework와의 비교
//!
//! | Spring | 이 시스템 | 역할 |
//! |--------|-----------|------|
//! | `@RequestBody` | `request` 모듈 | HTTP 요청 본문 매핑 |
//! | `@ResponseBody` | `response` 모듈 | HTTP 응답 본문 매핑 |
//! | `@Valid` | `validator` crate | 입력값 유효성 검증 |
//! | `@JsonProperty` | `serde` annotations | JSON 필드 매핑 |
//! | `@ApiModel` | rustdoc comments | API 문서 생성 |
//! | `ResponseEntity<T>` | `Result<T, AppError>` | 상태 코드와 함께 응답 |
//!
//! ## 설계 원칙
//!
//! ### 1. API 계약 우선 (API Contract First)
//! - **명시적 인터페이스**: 클라이언트가 기대할 수 있는 명확한 데이터 구조
//! - **버전 호환성**: API 변경 시 하위 호환성 유지
//! - **문서화**: 자동 생성되는 API 문서의 기반
//!
//! ### 2. 유효성 검증 내장 (Built-in Validation)
//! - **타입 안전성**: 컴파일 타임 타입 검증
//! - **런타임 검증**: validator crate를 통한 비즈니스 규칙 검증
//! - **에러 메시지**: 사용자 친화적인 검증 실패 메시지
//!
//! ### 3. 도메인 분리 (Domain Separation)
//! - **내부 표현 vs 외부 표현**: Entity와 DTO의 명확한 분리
//! - **보안**: 민감한 정보의 노출 방지
//! - **진화 가능성**: 내부 구조 변경이 API에 미치는 영향 최소화
//!
//! ## 모듈 구조
//!
//! ```text
//! dto/
//! ├── users/              # 사용자 관련 DTO
//! │   ├── request/        # 요청 DTO (클라이언트 → 서버)
//! │   │   ├── create_user.rs
//! │   │   ├── update_user.rs
//! │   │   └── login_request.rs
//! │   └── response/       # 응답 DTO (서버 → 클라이언트)
//! │       ├── user_response.rs
//! │       ├── auth_response.rs
//! │       └── google_oauth_response.rs
//! ├── posts/              # 게시물 관련 DTO (향후 확장)
//! ├── comments/           # 댓글 관련 DTO (향후 확장)
//! └── common/             # 공통 DTO
//!     ├── pagination.rs   # 페이지네이션
//!     ├── error_response.rs
//!     └── success_response.rs
//! ```
//!
//! ## Spring Boot Controller와의 비교
//!
//! ### Spring Boot 예제
//! ```java
//! @RestController
//! @RequestMapping("/api/v1/users")
//! public class UserController {
//!     
//!     @PostMapping
//!     public ResponseEntity<UserResponse> createUser(
//!         @Valid @RequestBody CreateUserRequest request
//!     ) {
//!         User user = userService.createUser(request);
//!         UserResponse response = UserResponse.from(user);
//!         return ResponseEntity.ok(response);
//!     }
//!     
//!     @GetMapping("/{id}")
//!     public ResponseEntity<UserResponse> getUser(@PathVariable String id) {
//!         User user = userService.findById(id);
//!         return ResponseEntity.ok(UserResponse.from(user));
//!     }
//! }
//! 
//! // Request DTO
//! public class CreateUserRequest {
//!     @NotBlank(message = "이메일은 필수입니다")
//!     @Email(message = "유효한 이메일 형식이 아닙니다")
//!     private String email;
//!     
//!     @NotBlank(message = "이름은 필수입니다")
//!     @Size(min = 2, max = 50, message = "이름은 2-50자 사이여야 합니다")
//!     private String name;
//!     
//!     // getters, setters...
//! }
//! 
//! // Response DTO
//! public class UserResponse {
//!     private String id;
//!     private String email;
//!     private String name;
//!     private String createdAt;
//!     
//!     public static UserResponse from(User user) {
//!         return UserResponse.builder()
//!             .id(user.getId())
//!             .email(user.getEmail())
//!             .name(user.getName())
//!             .createdAt(user.getCreatedAt().toString())
//!             .build();
//!     }
//! }
//! ```
//!
//! ### 이 시스템 예제
//! ```rust,ignore
//! use actix_web::{web, HttpResponse, Result};
//! use crate::domain::dto::users::{CreateUserRequest, UserResponse};
//! use crate::core::errors::AppError;
//! 
//! // Handler (Controller 역할)
//! pub async fn create_user(
//!     request: web::Json<CreateUserRequest>  // @RequestBody와 동일
//! ) -> Result<HttpResponse, AppError> {
//!     // 유효성 검증 (자동)
//!     let validated_request = request.into_inner();
//!     
//!     // 서비스 호출
//!     let user = user_service.create_user(validated_request).await?;
//!     
//!     // 응답 DTO로 변환
//!     let response = UserResponse::from(user);
//!     
//!     // JSON 응답 (ResponseEntity와 동일)
//!     Ok(HttpResponse::Created().json(response))
//! }
//! 
//! pub async fn get_user(
//!     path: web::Path<String>  // @PathVariable과 동일
//! ) -> Result<HttpResponse, AppError> {
//!     let user_id = path.into_inner();
//!     let user = user_service.find_by_id(&user_id).await?;
//!     let response = UserResponse::from(user);
//!     
//!     Ok(HttpResponse::Ok().json(response))
//! }
//! ```
//!
//! ## DTO 작성 가이드
//!
//! ### 1. Request DTO 작성
//!
//! ```rust,ignore
//! use serde::Deserialize;
//! use validator::Validate;
//! 
//! /// 사용자 생성 요청 DTO
//! /// 
//! /// Spring의 @RequestBody CreateUserRequest와 동일한 역할
//! #[derive(Debug, Deserialize, Validate)]
//! pub struct CreateUserRequest {
//!     /// 사용자 이메일 (고유해야 함)
//!     #[validate(email(message = "유효한 이메일 주소를 입력하세요"))]
//!     pub email: String,
//!     
//!     /// 사용자 표시 이름
//!     #[validate(length(
//!         min = 2, 
//!         max = 50, 
//!         message = "이름은 2-50자 사이여야 합니다"
//!     ))]
//!     pub name: String,
//!     
//!     /// 비밀번호 (평문, 서버에서 해싱됨)
//!     #[validate(length(
//!         min = 8, 
//!         message = "비밀번호는 최소 8자 이상이어야 합니다"
//!     ))]
//!     #[validate(regex(
//!         path = "STRONG_PASSWORD_REGEX",
//!         message = "비밀번호는 영문, 숫자, 특수문자를 포함해야 합니다"
//!     ))]
//!     pub password: String,
//!     
//!     /// 선택적 프로필 이미지 URL
//!     #[validate(url(message = "유효한 URL 형식이 아닙니다"))]
//!     pub profile_image: Option<String>,
//! }
//! 
//! impl CreateUserRequest {
//!     /// DTO를 도메인 엔티티로 변환
//!     /// Spring의 ModelMapper.map()과 유사한 역할
//!     pub fn to_entity(self) -> User {
//!         User::new(
//!             self.email,
//!             self.name,
//!             AuthProvider::Local,
//!         )
//!     }
//! }
//! ```
//!
//! ### 2. Response DTO 작성
//!
//! ```rust,ignore
//! use serde::Serialize;
//! use chrono::{DateTime, Utc};
//! 
//! /// 사용자 응답 DTO
//! /// 
//! /// Spring의 @ResponseBody UserResponse와 동일한 역할
//! /// 민감한 정보(비밀번호, 내부 ID 등)는 제외
//! #[derive(Debug, Serialize)]
//! pub struct UserResponse {
//!     /// 사용자 공개 ID (MongoDB ObjectId를 문자열로 변환)
//!     pub id: String,
//!     
//!     /// 사용자 이메일
//!     pub email: String,
//!     
//!     /// 사용자 표시 이름
//!     pub name: String,
//!     
//!     /// 인증 공급자 (local, google, etc.)
//!     pub provider: String,
//!     
//!     /// 계정 생성 시각 (ISO 8601 형식)
//!     pub created_at: String,
//!     
//!     /// 마지막 업데이트 시각 (ISO 8601 형식)
//!     pub updated_at: String,
//!     
//!     /// 프로필 이미지 URL (선택적)
//!     pub profile_image: Option<String>,
//! }
//! 
//! impl From<User> for UserResponse {
//!     /// 도메인 엔티티를 응답 DTO로 변환
//!     /// Spring의 @JsonView나 ModelMapper와 유사한 역할
//!     fn from(user: User) -> Self {
//!         Self {
//!             id: user.id.to_hex(),
//!             email: user.email,
//!             name: user.name,
//!             provider: user.provider.as_str().to_string(),
//!             created_at: user.created_at.to_rfc3339(),
//!             updated_at: user.updated_at.to_rfc3339(),
//!             profile_image: user.profile_image,
//!         }
//!     }
//! }
//! ```
//!
//! ### 3. 컬렉션 응답 DTO
//!
//! ```rust,ignore
//! use serde::Serialize;
//! 
//! /// 페이지네이션된 사용자 목록 응답
//! /// Spring Data의 Page<T>와 유사한 역할
//! #[derive(Debug, Serialize)]
//! pub struct UserListResponse {
//!     /// 사용자 목록
//!     pub users: Vec<UserResponse>,
//!     
//!     /// 페이지네이션 정보
//!     pub pagination: PaginationInfo,
//! }
//! 
//! #[derive(Debug, Serialize)]
//! pub struct PaginationInfo {
//!     /// 현재 페이지 번호 (0부터 시작)
//!     pub page: u32,
//!     
//!     /// 페이지당 아이템 수
//!     pub size: u32,
//!     
//!     /// 전체 아이템 수
//!     pub total: u64,
//!     
//!     /// 전체 페이지 수
//!     pub total_pages: u32,
//!     
//!     /// 다음 페이지 존재 여부
//!     pub has_next: bool,
//!     
//!     /// 이전 페이지 존재 여부
//!     pub has_previous: bool,
//! }
//! ```
//!
//! ## 유효성 검증 (Validation)
//!
//! ### Spring Validation vs Rust Validator
//!
//! | Spring | Rust | 설명 |
//! |--------|------|------|
//! | `@NotNull` | 기본 동작 | Option<T>가 아닌 필드는 필수 |
//! | `@NotBlank` | `#[validate(length(min = 1))]` | 빈 문자열 방지 |
//! | `@Email` | `#[validate(email)]` | 이메일 형식 검증 |
//! | `@Size(min, max)` | `#[validate(length(min, max))]` | 문자열 길이 검증 |
//! | `@Pattern` | `#[validate(regex)]` | 정규표현식 검증 |
//! | `@Valid` | `#[validate]` | 중첩 객체 검증 |
//!
//! ### 검증 사용 예제
//!
//! ```rust,ignore
//! use actix_web::{web, HttpResponse, Result};
//! use validator::Validate;
//! use crate::core::errors::AppError;
//! 
//! pub async fn create_user(
//!     request: web::Json<CreateUserRequest>
//! ) -> Result<HttpResponse, AppError> {
//!     // 1. 유효성 검증 (Spring의 @Valid와 동일)
//!     if let Err(validation_errors) = request.validate() {
//!         return Err(AppError::ValidationError(
//!             format!("입력값 검증 실패: {:?}", validation_errors)
//!         ));
//!     }
//!     
//!     // 2. 비즈니스 로직 실행
//!     let user = user_service.create_user(request.into_inner()).await?;
//!     
//!     // 3. 응답 생성
//!     Ok(HttpResponse::Created().json(UserResponse::from(user)))
//! }
//! ```
//!
//! ## 에러 응답 처리
//!
//! ### Spring의 @ExceptionHandler vs 이 시스템
//!
//! ```rust
//! use serde::Serialize;
//! use actix_web::http::StatusCode;
//! 
//! /// API 에러 응답 DTO
//! /// Spring의 ErrorResponse와 동일한 역할
//! #[derive(Debug, Serialize)]
//! pub struct ErrorResponse {
//!     /// 에러 코드 (HTTP 상태 코드)
//!     pub status: u16,
//!     
//!     /// 에러 메시지 (사용자에게 표시)
//!     pub message: String,
//!     
//!     /// 상세 에러 정보 (개발 환경에서만)
//!     pub details: Option<String>,
//!     
//!     /// 에러 발생 시각
//!     pub timestamp: String,
//!     
//!     /// 요청 경로
//!     pub path: String,
//! }
//! 
//! impl ErrorResponse {
//!     pub fn new(
//!         status: StatusCode,
//!         message: String,
//!         path: String,
//!     ) -> Self {
//!         Self {
//!             status: status.as_u16(),
//!             message,
//!             details: None,
//!             timestamp: chrono::Utc::now().to_rfc3339(),
//!             path,
//!         }
//!     }
//! }
//! ```
//!
//! ## 베스트 프랙티스
//!
//! ### 1. 명명 규칙
//! - **Request DTO**: `{Action}{Entity}Request` (예: `CreateUserRequest`)
//! - **Response DTO**: `{Entity}Response` (예: `UserResponse`)
//! - **List Response**: `{Entity}ListResponse` (예: `UserListResponse`)
//!
//! ### 2. 필드 설계
//! - **필수 필드**: 기본 타입 사용 (`String`, `i32` 등)
//! - **선택적 필드**: `Option<T>` 사용
//! - **민감한 정보**: Response DTO에서 제외
//! - **날짜/시간**: ISO 8601 문자열 형식 사용
//!
//! ### 3. 변환 패턴
//! - **Request → Entity**: `impl From<Request> for Entity`
//! - **Entity → Response**: `impl From<Entity> for Response`
//! - **복잡한 변환**: 별도 mapper 함수 구현
//!
//! ### 4. 문서화
//! - **필드 설명**: 각 필드의 목적과 제약사항 명시
//! - **예제**: API 문서 생성을 위한 예제 제공
//! - **변경 로그**: API 변경 시 호환성 정보 기록
//!
//! ## 향후 확장 계획
//!
//! ```text
//! dto/
//! ├── users/           ✅ 구현 완료
//! ├── posts/           🔄 구현 예정
//! ├── comments/        📋 계획 중
//! ├── auth/            📋 계획 중 (토큰 갱신, 로그아웃 등)
//! ├── admin/           📋 계획 중 (관리자 기능)
//! └── common/          📋 계획 중 (공통 DTO)
//!     ├── pagination.rs
//!     ├── search.rs
//!     └── bulk_operations.rs
//! ```

pub mod users;

// 향후 확장을 위한 모듈 선언
// pub mod posts;
// pub mod comments;
// pub mod auth;
// pub mod admin;
// pub mod common;

// 공통 re-exports
pub use users::*;
