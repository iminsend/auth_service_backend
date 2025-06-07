use actix_web::{web, HttpResponse, get, post, delete};
use validator::Validate;
use crate::core::errors::AppError;
use crate::domain::dto::users::request::CreateUserRequest;
use crate::services::users::user_service::UserService;

/// 사용자 생성 핸들러
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
#[get("/{user_id}")]
pub async fn get_user(
    user_id: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let service = UserService::instance();
    let user = service.get_user_by_id(&user_id).await?;
    
    Ok(HttpResponse::Ok().json(user))
}

/// 사용자 삭제 핸들러
#[delete("/{user_id}")]
pub async fn delete_user(
    user_id: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let service = UserService::instance();
    service.delete_user(&user_id).await?;
    
    Ok(HttpResponse::NoContent().finish())
}
