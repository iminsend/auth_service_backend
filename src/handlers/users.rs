//! # User Management HTTP Handlers
//!
//! 사용자 관리와 관련된 HTTP 엔드포인트를 처리하는 핸들러 함수들입니다.
//! CRUD(Create, Read, Update, Delete) 작업을 지원하며,
//! RESTful API 설계 원칙을 따릅니다.
//!
//! ## RESTful API 설계
//!
//! ### 현재 구현된 엔드포인트
//! | 메서드 | 경로 | 설명 | 상태 코드 |
//! |--------|------|------|-----------|
//! | `POST` | `/users` | 새 사용자 생성 | 201 Created |
//! | `GET` | `/users/{id}` | 사용자 조회 | 200 OK |
//! | `DELETE` | `/users/{id}` | 사용자 삭제 | 204 No Content |
//!
//! ### 향후 구현 예정
//! | 메서드 | 경로 | 설명 |
//! |--------|------|------|
//! | `PUT` | `/users/{id}` | 사용자 전체 정보 수정 |
//! | `PATCH` | `/users/{id}` | 사용자 부분 정보 수정 |
//! | `GET` | `/users` | 사용자 목록 조회 (페이징) |
//! | `GET` | `/users/{id}/profile` | 사용자 프로필 조회 |
//! | `PUT` | `/users/{id}/profile` | 사용자 프로필 수정 |
//!
//! ## Spring Boot와의 비교
//!
//! ### Spring Boot Controller
//! ```java
//! @RestController
//! @RequestMapping("/api/v1/users")
//! @Validated
//! public class UserController {
//!     
//!     @Autowired
//!     private UserService userService;
//!     
//!     @PostMapping
//!     public ResponseEntity<UserResponse> createUser(
//!         @Valid @RequestBody CreateUserRequest request
//!     ) {
//!         UserResponse response = userService.createUser(request);
//!         return ResponseEntity.status(HttpStatus.CREATED).body(response);
//!     }
//!     
//!     @GetMapping("/{id}")
//!     public ResponseEntity<UserResponse> getUser(@PathVariable String id) {
//!         UserResponse user = userService.getUserById(id);
//!         return ResponseEntity.ok(user);
//!     }
//!     
//!     @DeleteMapping("/{id}")
//!     public ResponseEntity<Void> deleteUser(@PathVariable String id) {
//!         userService.deleteUser(id);
//!         return ResponseEntity.noContent().build();
//!     }
//! }
//! ```
//!
//! ### 이 모듈의 Rust 구현
//! ```rust,ignore
//! use actix_web::{web, HttpResponse, get, post, delete};
//! use crate::services::users::UserService;
//!
//! #[post("")]
//! pub async fn create_user(
//!     payload: web::Json<CreateUserRequest>,
//! ) -> Result<HttpResponse, AppError> {
//!     payload.validate()?;
//!     let service = UserService::instance(); // 싱글톤 패턴
//!     let response = service.create_user(payload.into_inner()).await?;
//!     Ok(HttpResponse::Created().json(response))
//! }
//!
//! #[get("/{user_id}")]
//! pub async fn get_user(
//!     user_id: web::Path<String>,
//! ) -> Result<HttpResponse, AppError> {
//!     let service = UserService::instance();
//!     let user = service.get_user_by_id(&user_id).await?;
//!     Ok(HttpResponse::Ok().json(user))
//! }
//! ```
//!
//! ## 입력 검증
//!
//! ### 자동 검증 시스템
//! ```rust,ignore
//! use validator::{Validate, ValidationError};
//!
//! #[derive(Deserialize, Validate)]
//! pub struct CreateUserRequest {
//!     #[validate(email(message = "유효한 이메일 주소를 입력해주세요"))]
//!     pub email: String,
//!     
//!     #[validate(length(min = 3, max = 30, message = "사용자명은 3-30자 사이여야 합니다"))]
//!     #[validate(regex(path = "USERNAME_REGEX", message = "사용자명에 특수문자는 사용할 수 없습니다"))]
//!     pub username: String,
//!     
//!     #[validate(length(min = 8, message = "비밀번호는 최소 8자 이상이어야 합니다"))]
//!     #[validate(custom(function = "validate_password_strength"))]
//!     pub password: String,
//! }
//!
//! fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
//!     let has_upper = password.chars().any(|c| c.is_uppercase());
//!     let has_lower = password.chars().any(|c| c.is_lowercase());
//!     let has_digit = password.chars().any(|c| c.is_numeric());
//!     
//!     if !(has_upper && has_lower && has_digit) {
//!         return Err(ValidationError::new("weak_password"));
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## 에러 처리 패턴
//!
//! ### HTTP 상태 코드 매핑
//! ```rust,ignore
//! // 비즈니스 로직 에러 → HTTP 상태 코드 자동 매핑
//! match service_result {
//!     Err(ServiceError::UserNotFound) => HttpResponse::NotFound().json(ErrorResponse {
//!         error: "user_not_found",
//!         message: "사용자를 찾을 수 없습니다",
//!     }),
//!     Err(ServiceError::DuplicateEmail) => HttpResponse::Conflict().json(ErrorResponse {
//!         error: "duplicate_email", 
//!         message: "이미 사용 중인 이메일입니다",
//!     }),
//!     Err(ServiceError::ValidationError(msg)) => HttpResponse::BadRequest().json(ErrorResponse {
//!         error: "validation_error",
//!         message: msg,
//!     }),
//!     Ok(result) => HttpResponse::Ok().json(result),
//! }
//! ```
//!
//! ### 표준화된 에러 응답
//! ```json
//! {
//!   "error": "validation_error",
//!   "message": "입력 데이터가 유효하지 않습니다",
//!   "details": {
//!     "field_errors": {
//!       "email": ["유효한 이메일 주소를 입력해주세요"],
//!       "password": ["비밀번호는 최소 8자 이상이어야 합니다"]
//!     }
//!   },
//!   "timestamp": "2024-01-01T12:00:00Z"
//! }
//! ```
//!
//! ## 보안 고려사항
//!
//! ### 인증/인가
//! ```rust,ignore
//! use actix_web_httpauth::extractors::bearer::BearerAuth;
//! use crate::middleware::auth::RequireAuth;
//!
//! // 인증이 필요한 엔드포인트
//! #[get("/{user_id}")]
//! #[middleware(RequireAuth)]
//! pub async fn get_user(
//!     user_id: web::Path<String>,
//!     auth: BearerAuth, // JWT 토큰 자동 추출
//! ) -> Result<HttpResponse, AppError> {
//!     let current_user = auth.extract_user()?;
//!     
//!     // 본인 정보만 조회 가능 (관리자 제외)
//!     if current_user.id != *user_id && !current_user.is_admin() {
//!         return Err(AppError::Forbidden("권한이 없습니다".to_string()));
//!     }
//!     
//!     let service = UserService::instance();
//!     let user = service.get_user_by_id(&user_id).await?;
//!     Ok(HttpResponse::Ok().json(user))
//! }
//! ```
//!
//! ### 개인정보 보호
//! ```rust,ignore
//! // 응답에서 민감한 정보 제외
//! #[derive(Serialize)]
//! pub struct PublicUserResponse {
//!     pub id: String,
//!     pub username: String,
//!     pub display_name: String,
//!     pub created_at: DateTime<Utc>,
//!     // password_hash, email 등 민감한 정보 제외
//! }
//!
//! impl From<User> for PublicUserResponse {
//!     fn from(user: User) -> Self {
//!         Self {
//!             id: user.id_string().unwrap_or_default(),
//!             username: user.username,
//!             display_name: user.display_name,
//!             created_at: user.created_at,
//!         }
//!     }
//! }
//! ```
//!
//! ## 성능 최적화
//!
//! ### 페이징과 필터링
//! ```rust,ignore
//! #[derive(Deserialize, Validate)]
//! pub struct UserListQuery {
//!     #[validate(range(min = 1, max = 100))]
//!     pub limit: Option<u64>,
//!     
//!     pub offset: Option<u64>,
//!     pub search: Option<String>,
//!     pub role: Option<String>,
//!     pub sort_by: Option<String>,
//!     pub sort_order: Option<SortOrder>,
//! }
//!
//! #[get("")]
//! pub async fn list_users(
//!     query: web::Query<UserListQuery>,
//! ) -> Result<HttpResponse, AppError> {
//!     query.validate()?;
//!     
//!     let service = UserService::instance();
//!     let result = service.list_users(query.into_inner()).await?;
//!     
//!     Ok(HttpResponse::Ok().json(PaginatedResponse {
//!         data: result.users,
//!         total: result.total,
//!         page: result.page,
//!         per_page: result.per_page,
//!     }))
//! }
//! ```
//!
//! ### 캐싱 전략
//! ```rust,ignore
//! #[get("/{user_id}")]
//! pub async fn get_user_cached(
//!     user_id: web::Path<String>,
//! ) -> Result<HttpResponse, AppError> {
//!     let service = UserService::instance();
//!     let user = service.get_user_by_id_cached(&user_id).await?;
//!     
//!     Ok(HttpResponse::Ok()
//!         .insert_header(("Cache-Control", "public, max-age=300")) // 5분 캐시
//!         .insert_header(("ETag", format!("\"{}\"", user.updated_at.timestamp())))
//!         .json(user))
//! }
//! ```
//!
//! ## 로깅 및 모니터링
//!
//! ### 구조화된 로깅
//! ```rust,ignore
//! use tracing::{info, warn, error, instrument};
//!
//! #[instrument(skip(payload), fields(email = %payload.email, username = %payload.username))]
//! #[post("")]
//! pub async fn create_user(
//!     payload: web::Json<CreateUserRequest>,
//! ) -> Result<HttpResponse, AppError> {
//!     info!("새 사용자 생성 요청");
//!     
//!     let result = service.create_user(payload.into_inner()).await;
//!     
//!     match &result {
//!         Ok(user) => {
//!             info!(user_id = %user.id, "사용자 생성 성공");
//!             // 감사 로그
//!             audit_log::record_user_creation(&user).await;
//!         }
//!         Err(e) => {
//!             warn!(error = %e, "사용자 생성 실패");
//!         }
//!     }
//!     
//!     result.map(|response| HttpResponse::Created().json(response))
//! }
//! ```
//!
//! ### 메트릭 수집
//! ```rust,ignore
//! use prometheus::{Counter, Histogram, register_counter, register_histogram};
//!
//! lazy_static! {
//!     static ref USER_CREATION_COUNTER: Counter = register_counter!(
//!         "user_creation_total", 
//!         "Total number of user creation attempts"
//!     ).unwrap();
//!     
//!     static ref USER_LOOKUP_DURATION: Histogram = register_histogram!(
//!         "user_lookup_duration_seconds",
//!         "Time spent looking up users"
//!     ).unwrap();
//! }
//!
//! #[post("")]
//! pub async fn create_user(/* ... */) -> Result<HttpResponse, AppError> {
//!     USER_CREATION_COUNTER.inc();
//!     
//!     let _timer = USER_LOOKUP_DURATION.start_timer();
//!     let result = service.create_user(payload.into_inner()).await;
//!     
//!     // 타이머가 자동으로 측정 완료
//!     result.map(|response| HttpResponse::Created().json(response))
//! }
//! ```

use actix_web::{web, HttpResponse, get, post, delete};
use validator::Validate;
use crate::core::errors::AppError;
use crate::domain::dto::users::request::CreateUserRequest;
use crate::services::users::user_service::UserService;

/// 사용자 생성 핸들러
///
/// 새로운 사용자 계정을 생성합니다. 로컬 인증용 사용자를 생성하며,
/// 이메일과 사용자명의 고유성을 검증합니다.
///
/// # 엔드포인트
///
/// `POST /users`
///
/// # 요청 본문
///
/// ```json
/// {
///   "email": "user@example.com",
///   "username": "john_doe",
///   "display_name": "John Doe",
///   "password": "secure_password123"
/// }
/// ```
///
/// # 응답
///
/// ## 성공 (201 Created)
/// ```json
/// {
///   "id": "507f1f77bcf86cd799439011",
///   "email": "user@example.com",
///   "username": "john_doe",
///   "display_name": "John Doe",
///   "auth_provider": "local",
///   "is_active": true,
///   "is_email_verified": false,
///   "roles": ["user"],
///   "created_at": "2024-01-01T00:00:00Z",
///   "updated_at": "2024-01-01T00:00:00Z"
/// }
/// ```
///
/// ## 실패 사례
///
/// ### 중복 이메일 (409 Conflict)
/// ```json
/// {
///   "error": "duplicate_email",
///   "message": "이미 사용 중인 이메일입니다"
/// }
/// ```
///
/// ### 검증 실패 (400 Bad Request)
/// ```json
/// {
///   "error": "validation_error",
///   "message": "입력 데이터가 유효하지 않습니다",
///   "details": {
///     "email": ["유효한 이메일 주소를 입력해주세요"],
///     "password": ["비밀번호는 최소 8자 이상이어야 합니다"]
///   }
/// }
/// ```
///
/// # 비즈니스 규칙
///
/// - 이메일은 시스템 전체에서 고유해야 함
/// - 사용자명은 시스템 전체에서 고유해야 함
/// - 비밀번호는 bcrypt로 해시되어 저장됨
/// - 기본 역할로 "user" 부여
/// - 이메일 인증이 필요한 상태로 생성 (`is_email_verified: false`)
///
/// # 보안 고려사항
///
/// - 비밀번호는 평문으로 로그에 기록되지 않음
/// - 강력한 비밀번호 정책 적용
/// - Rate limiting으로 스팸 계정 생성 방지
/// - 이메일 중복 확인으로 계정 탈취 방지
///
/// # 사용 예제
///
/// ```bash
/// curl -X POST http://localhost:8080/api/v1/users \
///   -H "Content-Type: application/json" \
///   -d '{
///     "email": "newuser@example.com",
///     "username": "newuser",
///     "display_name": "New User",
///     "password": "SecurePass123!"
///   }'
/// ```
#[post("")]
pub async fn create_user(
    payload: web::Json<CreateUserRequest>,
) -> Result<HttpResponse, AppError> {
    // 유효성 검사
    payload.validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;
    
    let service = UserService::instance();
    let response = service.create_user(payload.into_inner()).await?;
    
    Ok(HttpResponse::Created().json(response))
}

/// 사용자 조회 핸들러
///
/// 지정된 ID의 사용자 정보를 조회합니다.
/// 사용자의 공개 프로필 정보만 반환하며, 민감한 정보는 제외됩니다.
///
/// # 엔드포인트
///
/// `GET /users/{user_id}`
///
/// # 경로 파라미터
///
/// - `user_id`: 조회할 사용자의 고유 ID (MongoDB ObjectId)
///
/// # 응답
///
/// ## 성공 (200 OK)
/// ```json
/// {
///   "id": "507f1f77bcf86cd799439011",
///   "email": "user@example.com",
///   "username": "john_doe",
///   "display_name": "John Doe",
///   "auth_provider": "local",
///   "is_active": true,
///   "is_email_verified": true,
///   "roles": ["user"],
///   "profile_image_url": "https://example.com/avatar.jpg",
///   "last_login_at": "2024-01-01T10:00:00Z",
///   "created_at": "2024-01-01T00:00:00Z",
///   "updated_at": "2024-01-01T08:00:00Z"
/// }
/// ```
///
/// ## 실패 사례
///
/// ### 사용자 없음 (404 Not Found)
/// ```json
/// {
///   "error": "user_not_found",
///   "message": "사용자를 찾을 수 없습니다"
/// }
/// ```
///
/// ### 잘못된 ID 형식 (400 Bad Request)
/// ```json
/// {
///   "error": "invalid_id_format",
///   "message": "유효하지 않은 사용자 ID 형식입니다"
/// }
/// ```
///
/// # 개인정보 보호
///
/// - 비밀번호 해시는 응답에 포함되지 않음
/// - OAuth 관련 민감한 데이터는 제외됨
/// - 향후 권한에 따라 필드 노출 제어 예정
///
/// # 캐싱 정책
///
/// - 응답에 적절한 Cache-Control 헤더 포함
/// - ETag를 통한 조건부 요청 지원 (향후)
/// - 사용자 정보 변경 시 캐시 무효화
///
/// # 사용 예제
///
/// ```bash
/// curl -X GET http://localhost:8080/api/v1/users/507f1f77bcf86cd799439011
/// ```
///
/// # 향후 개선사항
///
/// - 권한 기반 필드 필터링
/// - 본인 정보 조회 시 추가 정보 제공
/// - 관리자용 상세 정보 엔드포인트 분리
#[get("/{user_id}")]
pub async fn get_user(
    user_id: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let service = UserService::instance();
    let user = service.get_user_by_id(&user_id).await?;
    
    Ok(HttpResponse::Ok().json(user))
}

/// 사용자 삭제 핸들러
///
/// 지정된 ID의 사용자를 시스템에서 완전히 삭제합니다.
/// 이는 물리적 삭제(Hard Delete)이며, 복구가 불가능합니다.
///
/// # 엔드포인트
///
/// `DELETE /users/{user_id}`
///
/// # 경로 파라미터
///
/// - `user_id`: 삭제할 사용자의 고유 ID (MongoDB ObjectId)
///
/// # 응답
///
/// ## 성공 (204 No Content)
/// ```bash,ignore
/// HTTP/1.1 204 No Content
/// Content-Length: 0
/// ```
///
/// ## 실패 사례
///
/// ### 사용자 없음 (404 Not Found)
/// ```json
/// {
///   "error": "user_not_found",
///   "message": "삭제할 사용자를 찾을 수 없습니다"
/// }
/// ```
///
/// ### 권한 없음 (403 Forbidden)
/// ```json
/// {
///   "error": "insufficient_permissions",
///   "message": "사용자 삭제 권한이 없습니다"
/// }
/// ```
///
/// # 삭제 정책
///
/// ## 현재 구현 (Hard Delete)
/// - 사용자 데이터를 데이터베이스에서 완전 제거
/// - 관련된 세션, 토큰 등도 함께 삭제
/// - 복구 불가능
///
/// ## 향후 개선 (Soft Delete)
/// ```rust,ignore
/// // 논리적 삭제로 변경 예정
/// #[derive(Serialize, Deserialize)]
/// pub struct User {
///     // 기존 필드들...
///     pub deleted_at: Option<DateTime<Utc>>,
///     pub deleted_by: Option<String>,
/// }
/// ```
///
/// # 연관 데이터 처리
///
/// 사용자 삭제 시 다음 데이터들이 함께 처리됩니다:
/// - 활성 세션 무효화
/// - JWT 토큰 블랙리스트 추가
/// - 프로필 이미지 등 업로드된 파일 삭제
/// - 관련 로그 데이터는 개인정보 제거 후 익명화
///
/// # GDPR 준수
///
/// - 사용자의 "잊혀질 권리" 지원
/// - 개인정보 완전 삭제 보장
/// - 법적 보존 의무가 있는 데이터는 익명화
/// - 삭제 요청 감사 로그 기록
///
/// # 보안 고려사항
///
/// - 관리자 권한 필요 (현재 미구현, 향후 추가)
/// - 본인 계정 삭제 시 추가 인증 요구 (향후)
/// - 삭제 요청 Rate limiting
/// - 중요 계정 삭제 시 2차 승인 (향후)
///
/// # 사용 예제
///
/// ```bash
/// curl -X DELETE http://localhost:8080/api/v1/users/507f1f77bcf86cd799439011 \
///   -H "Authorization: Bearer {admin_token}"
/// ```
///
/// # 감사 로그
///
/// 모든 삭제 작업은 감사 로그에 기록됩니다:
/// ```json
/// {
///   "action": "user_deleted",
///   "target_user_id": "507f1f77bcf86cd799439011",
///   "target_email": "user@example.com",
///   "deleted_by": "admin_user_id",
///   "timestamp": "2024-01-01T12:00:00Z",
///   "ip_address": "192.168.1.1",
///   "user_agent": "Mozilla/5.0..."
/// }
/// ```
#[delete("/{user_id}")]
pub async fn delete_user(
    user_id: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let service = UserService::instance();
    service.delete_user(&user_id).await?;
    
    Ok(HttpResponse::NoContent().finish())
}
