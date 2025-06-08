//! 애플리케이션 전역에서 사용하는 에러 시스템
//!
//! 백엔드 서비스를 위한 통합 에러 처리 시스템입니다.
//! `thiserror`와 `actix_web::ResponseError`를 사용하여 타입 안전하고 
//! 일관된 에러 처리를 제공합니다.
//!
//! ## 사용 예제
//!
//! ```rust,ignore
//! use crate::errors::AppError;
//!
//! async fn create_user(data: CreateUserRequest) -> Result<User, AppError> {
//!     if data.email.is_empty() {
//!         return Err(AppError::ValidationError("Email is required".to_string()));
//!     }
//!     
//!     let user = user_repo.create(data).await
//!         .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!     
//!     Ok(user)
//! }
//! ```

use thiserror::Error;

/// 애플리케이션 전역 에러 타입
///
/// 백엔드 서비스에서 발생할 수 있는 모든 종류의 에러를 포괄하는 열거형입니다.
/// 자동으로 HTTP 응답으로 변환되어 클라이언트에게 전달됩니다.
#[derive(Error, Debug)]
pub enum AppError {
    /// 데이터베이스 관련 에러 (500 Internal Server Error)
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    /// Redis 캐시 관련 에러 (500 Internal Server Error)
    #[error("Redis error: {0}")]
    RedisError(String),
    
    /// 입력값 검증 에러 (400 Bad Request)
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    /// 리소스 찾을 수 없음 에러 (404 Not Found)
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// 충돌/중복 에러 (409 Conflict)
    #[error("Conflict error: {0}")]
    ConflictError(String),
    
    /// 인증 실패 에러 (401 Unauthorized)
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    
    /// 권한 부족 에러 (403 Forbidden)
    #[error("Authorization error: {0}")]
    AuthorizationError(String),
    
    /// 외부 서비스 에러 (500 Internal Server Error)
    #[error("External service error: {0}")]
    ExternalServiceError(String),
    
    /// 내부 서버 에러 (500 Internal Server Error)
    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl actix_web::ResponseError for AppError {
    /// HTTP 에러 응답을 생성합니다.
    ///
    /// 각 에러 타입을 적절한 HTTP 상태 코드와 JSON 응답으로 변환합니다.
    fn error_response(&self) -> actix_web::HttpResponse {
        use actix_web::http::StatusCode;
        
        let status = match self {
            AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::ConflictError(_) => StatusCode::CONFLICT,
            AppError::AuthenticationError(_) => StatusCode::UNAUTHORIZED,
            AppError::AuthorizationError(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        
        actix_web::HttpResponse::build(status)
            .json(serde_json::json!({
                "error": self.to_string()
            }))
    }
}

/// 편의성을 위한 Result 타입 별칭
pub type AppResult<T> = Result<T, AppError>;

/// 외부 라이브러리 에러를 AppError로 변환하는 확장 trait
pub trait ErrorContext<T> {
    /// 컨텍스트 정보와 함께 에러를 변환합니다.
    fn context(self, msg: &str) -> AppResult<T>;
    
    /// 클로저를 사용하여 지연 평가된 컨텍스트를 제공합니다.
    fn with_context<F>(self, f: F) -> AppResult<T>
    where
        F: FnOnce() -> String;
}

impl<T, E> ErrorContext<T> for Result<T, E>
where
    E: std::fmt::Display,
{
    fn context(self, msg: &str) -> AppResult<T> {
        self.map_err(|e| AppError::InternalError(format!("{}: {}", msg, e)))
    }
    
    fn with_context<F>(self, f: F) -> AppResult<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| AppError::InternalError(format!("{}: {}", f(), e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::ResponseError;

    #[test]
    fn test_validation_error_response() {
        let error = AppError::ValidationError("Email is required".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_not_found_error_response() {
        let error = AppError::NotFound("User not found".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), actix_web::http::StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_authentication_error_response() {
        let error = AppError::AuthenticationError("Invalid token".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_authorization_error_response() {
        let error = AppError::AuthorizationError("Insufficient permissions".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), actix_web::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_internal_error_response() {
        let error = AppError::InternalError("Something went wrong".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_error_context_trait() {
        let result: Result<(), &str> = Err("original error");
        let app_result = result.context("Additional context");
        
        assert!(app_result.is_err());
        if let Err(AppError::InternalError(msg)) = app_result {
            assert!(msg.contains("Additional context"));
            assert!(msg.contains("original error"));
        } else {
            panic!("Expected InternalError");
        }
    }
}
