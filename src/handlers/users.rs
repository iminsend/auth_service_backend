//! 사용자 관리 CRUD 작업을 위한 HTTP 핸들러

use actix_web::{web, HttpResponse, post, get, delete};
use validator::Validate;
use crate::errors::errors::AppError;
use crate::domain::dto::users::request::CreateUserRequest;
use crate::services::users::user_service::UserService;

/// 새로운 사용자 계정을 생성합니다.
///
/// # Endpoint
/// `POST /users`
///
/// 이메일과 사용자명의 고유성을 검증하고 새 사용자를 생성합니다.
/// 비밀번호는 bcrypt로 해시되어 저장됩니다.
///
/// # Request Body
///
/// 이메일, 사용자명, 표시명, 비밀번호가 포함된 `CreateUserRequest`를 요구합니다.
///
/// # Errors
///
/// 입력 데이터가 유효하지 않은 경우 `AppError::ValidationError`를 반환합니다.
/// 중복된 이메일이나 사용자명이 있는 경우 적절한 오류를 반환합니다.
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

/// ID로 사용자 정보를 조회합니다.
///
/// # Endpoint
/// `GET /users/{user_id}`
///
/// 지정된 사용자의 공개 프로필 정보를 반환합니다.
/// 비밀번호 해시 등의 민감한 정보는 응답에서 제외됩니다.
///
/// # Path Parameters
///
/// - `user_id`: 조회할 사용자의 MongoDB ObjectId
#[get("/{user_id}")]
pub async fn get_user(
    user_id: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let service = UserService::instance();
    let user = service.get_user_by_id(&user_id).await?;
    
    Ok(HttpResponse::Ok().json(user))
}

/// ID로 사용자를 삭제합니다.
///
/// # Endpoint
/// `DELETE /users/{user_id}`
///
/// 시스템에서 사용자를 영구적으로 제거합니다 (물리적 삭제).
/// 이 작업은 되돌릴 수 없습니다.
///
/// # Path Parameters
///
/// - `user_id`: 삭제할 사용자의 MongoDB ObjectId
///
/// # Returns
///
/// 성공적으로 삭제되면 `204 No Content`를 반환합니다.
#[delete("/{user_id}")]
pub async fn delete_user(
    user_id: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let service = UserService::instance();
    service.delete_user(&user_id).await?;
    
    Ok(HttpResponse::NoContent().finish())
}
