//! # User Management HTTP Handlers
//!
//! 사용자 관리와 관련된 HTTP 엔드포인트를 처리하는 핸들러 함수들입니다.
//! CRUD(Create, Read, Update, Delete) 작업을 지원하며, RESTful API 설계 원칙을 따릅니다.
//!
//! ## 캐싱 전략
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

use actix_web::{web, HttpResponse, get, post, delete};
use validator::Validate;
use crate::errors::errors::AppError;
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
/// - Rate limiting 으로 스팸 계정 생성 방지
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
    payload.validate()
        .map_err(
            |e| AppError::ValidationError(e.to_string())
        )?;
    
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
/// `GET /api/vi/users/{user_id}`
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
#[delete("/{user_id}")]
pub async fn delete_user(
    user_id: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let service = UserService::instance();
    service.delete_user(&user_id).await?;
    
    Ok(HttpResponse::NoContent().finish())
}
