//! # Application Error Handling System
//!
//! 백엔드 서비스를 위한 통합 에러 처리 시스템입니다.
//! Spring Framework의 `@ExceptionHandler`와 글로벌 에러 처리 메커니즘을
//! Rust의 타입 시스템과 결합하여 안전하고 일관된 에러 처리를 제공합니다.
//!
//! ## 설계 철학
//!
//! ### 1. 계층화된 에러 분류
//! - **도메인별 분류**: 각 계층(데이터, 비즈니스, 프레젠테이션)별 에러 타입
//! - **의미론적 분류**: HTTP 상태 코드와 직접 매핑되는 의미있는 에러
//! - **컨텍스트 보존**: 원본 에러 정보를 손실 없이 전달
//!
//! ### 2. 자동 HTTP 응답 변환
//! - **ResponseError 구현**: Actix-Web과 완전 통합
//! - **일관된 응답 형식**: 모든 에러에 대한 표준화된 JSON 응답
//! - **적절한 상태 코드**: 에러 타입에 따른 자동 HTTP 상태 코드 매핑
//!
//! ### 3. 개발자 친화적 디버깅
//! - **상세한 에러 메시지**: 문제 해결에 필요한 충분한 정보 제공
//! - **에러 체인 추적**: `thiserror`를 통한 근본 원인 추적
//! - **타입 안전성**: 컴파일 타임 에러 타입 검증
//!
//! ## Spring과의 비교
//!
//! | Spring | 이 시스템 |
//! |--------|-----------|
//! | `@ExceptionHandler` | `ResponseError::error_response()` |
//! | `ResponseEntity<ErrorResponse>` | `HttpResponse::build().json()` |
//! | `@ResponseStatus` | 자동 상태 코드 매핑 |
//! | Global Exception Handler | `AppError` 전역 구현 |
//! | Custom Exception | `AppError` 열거형 변형 |
//!
//! ## 사용 패턴
//!
//! ### 서비스 계층에서의 에러 처리
//!
//! ```rust,ignore
//! use crate::core::errors::AppError;
//!
//! impl UserService {
//!     async fn create_user(&self, data: CreateUserRequest) -> Result<User, AppError> {
//!         // 1. 입력 검증
//!         if data.email.is_empty() {
//!             return Err(AppError::ValidationError(
//!                 "Email is required".to_string()
//!             ));
//!         }
//!         
//!         // 2. 중복 검사
//!         if self.user_repo.exists_by_email(&data.email).await? {
//!             return Err(AppError::ConflictError(
//!                 format!("User with email {} already exists", data.email)
//!             ));
//!         }
//!         
//!         // 3. 데이터베이스 작업
//!         let user = self.user_repo.create(data).await
//!             .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!         
//!         Ok(user)
//!     }
//! }
//! ```
//!
//! ### 핸들러에서의 에러 처리
//!
//! ```rust,ignore
//! use actix_web::{web, HttpResponse, Result};
//! use crate::core::errors::AppError;
//!
//! async fn create_user_handler(
//!     data: web::Json<CreateUserRequest>
//! ) -> Result<HttpResponse, AppError> {
//!     let user_service = UserService::instance();
//!     
//!     match user_service.create_user(data.into_inner()).await {
//!         Ok(user) => Ok(HttpResponse::Created().json(user)),
//!         Err(e) => Err(e), // 자동으로 적절한 HTTP 응답으로 변환됨
//!     }
//! }
//! ```
//!
//! ## HTTP 응답 매핑
//!
//! | AppError | HTTP Status | 사용 시나리오 |
//! |----------|-------------|---------------|
//! | `ValidationError` | 400 Bad Request | 입력값 검증 실패 |
//! | `NotFound` | 404 Not Found | 리소스 없음 |
//! | `ConflictError` | 409 Conflict | 중복 데이터, 비즈니스 규칙 위반 |
//! | `AuthenticationError` | 401 Unauthorized | 인증 실패 |
//! | `AuthorizationError` | 403 Forbidden | 권한 부족 |
//! | `DatabaseError` | 500 Internal Server Error | 데이터베이스 오류 |
//! | `RedisError` | 500 Internal Server Error | 캐시 오류 |
//! | `ExternalServiceError` | 500 Internal Server Error | 외부 API 오류 |
//! | `InternalError` | 500 Internal Server Error | 예상치 못한 오류 |

use thiserror::Error;

/// 애플리케이션 전역 에러 타입
///
/// 백엔드 서비스에서 발생할 수 있는 모든 종류의 에러를 포괄하는 열거형입니다.
/// `thiserror` 크레이트를 사용하여 자동으로 `Error` trait을 구현하고,
/// `actix_web::ResponseError`를 구현하여 HTTP 응답으로 자동 변환됩니다.
///
/// ## 에러 카테고리
///
/// ### 1. 인프라 계층 에러
/// - `DatabaseError`: MongoDB, PostgreSQL 등 데이터베이스 관련 오류
/// - `RedisError`: Redis 캐시 시스템 관련 오류
/// - `ExternalServiceError`: 외부 API 호출 실패
///
/// ### 2. 비즈니스 계층 에러
/// - `ValidationError`: 입력값 검증 실패
/// - `ConflictError`: 비즈니스 규칙 위반 (중복 생성 등)
/// - `NotFound`: 요청된 리소스가 존재하지 않음
///
/// ### 3. 보안 계층 에러
/// - `AuthenticationError`: 인증 실패 (로그인 실패, 토큰 만료 등)
/// - `AuthorizationError`: 권한 부족 (접근 권한 없음)
///
/// ### 4. 시스템 계층 에러
/// - `InternalError`: 예상하지 못한 시스템 오류
///
/// ## 에러 변환 패턴
///
/// ```rust,ignore
/// // MongoDB 에러 변환
/// user_collection.find_one(filter, None).await
///     .map_err(|e| AppError::DatabaseError(e.to_string()))?;
///
/// // Redis 에러 변환
/// redis_client.get::<String>("key").await
///     .map_err(|e| AppError::RedisError(e.to_string()))?;
///
/// // 외부 API 에러 변환
/// reqwest::get("https://api.example.com").await
///     .map_err(|e| AppError::ExternalServiceError(e.to_string()))?;
/// ```
#[derive(Error, Debug)]
pub enum AppError {
    /// 데이터베이스 관련 에러
    ///
    /// MongoDB, PostgreSQL 등 데이터베이스 연산 중 발생하는 오류를 나타냅니다.
    /// 일반적으로 500 Internal Server Error로 응답됩니다.
    ///
    /// # 발생 시나리오
    /// - 연결 타임아웃
    /// - 쿼리 문법 오류
    /// - 제약 조건 위반
    /// - 트랜잭션 롤백
    ///
    /// # 예제
    /// ```rust,ignore
    /// // MongoDB 삽입 실패
    /// collection.insert_one(doc, None).await
    ///     .map_err(|e| AppError::DatabaseError(
    ///         format!("Failed to insert user: {}", e)
    ///     ))?;
    /// ```
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    /// Redis 캐시 관련 에러
    ///
    /// Redis 서버와의 통신 오류나 캐시 연산 실패를 나타냅니다.
    /// 일반적으로 500 Internal Server Error로 응답됩니다.
    ///
    /// # 발생 시나리오
    /// - Redis 서버 연결 실패
    /// - 메모리 부족
    /// - 키 타입 불일치
    /// - 네트워크 타임아웃
    ///
    /// # 예제
    /// ```rust,ignore
    /// // 캐시 조회 실패
    /// redis_client.get::<String>("user:123").await
    ///     .map_err(|e| AppError::RedisError(
    ///         format!("Failed to get cached user: {}", e)
    ///     ))?;
    /// ```
    #[error("Redis error: {0}")]
    RedisError(String),
    
    /// 입력값 검증 에러
    ///
    /// 클라이언트가 제공한 데이터가 비즈니스 규칙이나 형식 요구사항을
    /// 만족하지 않을 때 발생합니다. 400 Bad Request로 응답됩니다.
    ///
    /// # 발생 시나리오
    /// - 필수 필드 누락
    /// - 이메일 형식 오류
    /// - 비밀번호 복잡성 미달
    /// - 숫자 범위 초과
    /// - 문자열 길이 제한 위반
    ///
    /// # 예제
    /// ```rust,ignore
    /// // 이메일 검증
    /// if !is_valid_email(&user_data.email) {
    ///     return Err(AppError::ValidationError(
    ///         "Invalid email format".to_string()
    ///     ));
    /// }
    ///
    /// // 필수 필드 검증
    /// if user_data.name.trim().is_empty() {
    ///     return Err(AppError::ValidationError(
    ///         "Name is required".to_string()
    ///     ));
    /// }
    /// ```
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    /// 리소스 찾을 수 없음 에러
    ///
    /// 클라이언트가 요청한 리소스(사용자, 게시물 등)가 존재하지 않을 때
    /// 발생합니다. 404 Not Found로 응답됩니다.
    ///
    /// # 발생 시나리오
    /// - 존재하지 않는 사용자 ID로 조회
    /// - 삭제된 리소스에 접근
    /// - 잘못된 URL 경로
    /// - 권한이 없는 리소스 접근 (일부 경우)
    ///
    /// # 예제
    /// ```rust,ignore
    /// // 사용자 조회 실패
    /// let user = user_repo.find_by_id(&user_id).await?
    ///     .ok_or_else(|| AppError::NotFound(
    ///         format!("User with id {} not found", user_id)
    ///     ))?;
    /// ```
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// 충돌/중복 에러
    ///
    /// 비즈니스 규칙 위반이나 중복 데이터 생성 시도 시 발생합니다.
    /// 409 Conflict로 응답됩니다.
    ///
    /// # 발생 시나리오
    /// - 중복 이메일로 회원가입 시도
    /// - 동일한 이름의 리소스 생성
    /// - 동시성 충돌 (optimistic locking)
    /// - 비즈니스 상태 제약 위반
    ///
    /// # 예제
    /// ```rust,ignore
    /// // 중복 이메일 검사
    /// if user_repo.exists_by_email(&email).await? {
    ///     return Err(AppError::ConflictError(
    ///         format!("User with email {} already exists", email)
    ///     ));
    /// }
    ///
    /// // 상태 변경 제약 검사
    /// if order.status == OrderStatus::Completed {
    ///     return Err(AppError::ConflictError(
    ///         "Cannot modify completed order".to_string()
    ///     ));
    /// }
    /// ```
    #[error("Conflict error: {0}")]
    ConflictError(String),
    
    /// 인증 실패 에러
    ///
    /// 사용자의 신원을 확인할 수 없을 때 발생합니다.
    /// 401 Unauthorized로 응답됩니다.
    ///
    /// # 발생 시나리오
    /// - 잘못된 로그인 정보
    /// - 만료된 JWT 토큰
    /// - 유효하지 않은 토큰 서명
    /// - OAuth 인증 실패
    /// - 세션 만료
    ///
    /// # 예제
    /// ```rust,ignore
    /// // JWT 토큰 검증
    /// let claims = jwt::decode_token(&token)
    ///     .map_err(|e| AppError::AuthenticationError(
    ///         format!("Invalid token: {}", e)
    ///     ))?;
    ///
    /// // 비밀번호 검증
    /// if !bcrypt::verify(&password, &user.password_hash)? {
    ///     return Err(AppError::AuthenticationError(
    ///         "Invalid password".to_string()
    ///     ));
    /// }
    /// ```
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    
    /// 권한 부족 에러
    ///
    /// 인증된 사용자가 특정 작업을 수행할 권한이 없을 때 발생합니다.
    /// 403 Forbidden으로 응답됩니다.
    ///
    /// # 발생 시나리오
    /// - 관리자 전용 기능에 일반 사용자 접근
    /// - 다른 사용자의 개인 정보 접근
    /// - 리소스 소유권 없음
    /// - 역할 기반 접근 제어 위반
    ///
    /// # 예제
    /// ```rust,ignore
    /// // 소유권 검사
    /// if post.author_id != current_user.id && !current_user.is_admin() {
    ///     return Err(AppError::AuthorizationError(
    ///         "Not authorized to edit this post".to_string()
    ///     ));
    /// }
    ///
    /// // 역할 기반 검사
    /// if !current_user.has_role(Role::Admin) {
    ///     return Err(AppError::AuthorizationError(
    ///         "Admin role required".to_string()
    ///     ));
    /// }
    /// ```
    #[error("Authorization error: {0}")]
    AuthorizationError(String),
    
    /// 외부 서비스 에러
    ///
    /// 써드파티 API나 외부 서비스 호출 실패 시 발생합니다.
    /// 일반적으로 500 Internal Server Error로 응답됩니다.
    ///
    /// # 발생 시나리오
    /// - 결제 게이트웨이 API 오류
    /// - 이메일 서비스 장애
    /// - 소셜 로그인 API 실패
    /// - 외부 데이터 소스 접근 불가
    /// - 네트워크 타임아웃
    ///
    /// # 예제
    /// ```rust,ignore
    /// // 외부 API 호출
    /// let response = reqwest::get("https://api.payment-gateway.com/charge")
    ///     .await
    ///     .map_err(|e| AppError::ExternalServiceError(
    ///         format!("Payment service unavailable: {}", e)
    ///     ))?;
    ///
    /// // 이메일 발송 실패
    /// email_service.send_verification(&email).await
    ///     .map_err(|e| AppError::ExternalServiceError(
    ///         format!("Failed to send email: {}", e)
    ///     ))?;
    /// ```
    #[error("External service error: {0}")]
    ExternalServiceError(String),
    
    /// 내부 서버 에러
    ///
    /// 예상하지 못한 시스템 오류나 프로그래밍 오류 시 발생합니다.
    /// 500 Internal Server Error로 응답됩니다.
    ///
    /// # 발생 시나리오
    /// - 메모리 부족
    /// - 파일 시스템 오류
    /// - 설정 파일 손상
    /// - 의존성 주입 실패
    /// - 예상치 못한 panic 복구
    ///
    /// # 예제
    /// ```rust,ignore
    /// // 설정 파일 읽기 실패
    /// let config = std::fs::read_to_string("config.toml")
    ///     .map_err(|e| AppError::InternalError(
    ///         format!("Failed to read config: {}", e)
    ///     ))?;
    ///
    /// // 의존성 주입 실패
    /// let service = ServiceLocator::try_get::<PaymentService>()
    ///     .ok_or_else(|| AppError::InternalError(
    ///         "PaymentService not registered".to_string()
    ///     ))?;
    /// ```
    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl actix_web::ResponseError for AppError {
    /// HTTP 에러 응답을 생성합니다.
    ///
    /// 각 `AppError` 변형을 적절한 HTTP 상태 코드와 JSON 응답으로 변환합니다.
    /// Spring의 `@ExceptionHandler`와 동일한 역할을 수행하여 일관된 에러 응답을 보장합니다.
    ///
    /// # 응답 형식
    ///
    /// 모든 에러 응답은 다음과 같은 표준 JSON 형식을 따릅니다:
    ///
    /// ```json
    /// {
    ///   "error": "Human readable error message"
    /// }
    /// ```
    ///
    /// # 상태 코드 매핑
    ///
    /// - `ValidationError` → 400 Bad Request
    /// - `NotFound` → 404 Not Found  
    /// - `ConflictError` → 409 Conflict
    /// - `AuthenticationError` → 401 Unauthorized
    /// - `AuthorizationError` → 403 Forbidden
    /// - 나머지 모든 에러 → 500 Internal Server Error
    ///
    /// # 로깅 고려사항
    ///
    /// 5xx 에러의 경우 서버 로그에 자세한 정보를 기록하되,
    /// 클라이언트에는 민감한 내부 정보를 노출하지 않도록 주의해야 합니다.
    ///
    /// # 확장 예제
    ///
    /// ```rust,ignore
    /// // 더 상세한 에러 응답이 필요한 경우
    /// impl actix_web::ResponseError for AppError {
    ///     fn error_response(&self) -> actix_web::HttpResponse {
    ///         let (status, error_code, message) = match self {
    ///             AppError::ValidationError(msg) => (
    ///                 StatusCode::BAD_REQUEST,
    ///                 "VALIDATION_ERROR",
    ///                 msg
    ///             ),
    ///             // ... 다른 에러들
    ///         };
    ///         
    ///         actix_web::HttpResponse::build(status).json(json!({
    ///             "error": {
    ///                 "code": error_code,
    ///                 "message": message,
    ///                 "timestamp": chrono::Utc::now().to_rfc3339()
    ///             }
    ///         }))
    ///     }
    /// }
    /// ```
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
///
/// 애플리케이션 전체에서 자주 사용되는 `Result<T, AppError>` 패턴을
/// 간소화하기 위한 타입 별칭입니다.
///
/// # 사용 예제
///
/// ```rust,ignore
/// use crate::core::errors::AppResult;
///
/// // Before: Result<User, AppError>
/// // After: AppResult<User>
/// async fn create_user(data: CreateUserRequest) -> AppResult<User> {
///     // 구현...
/// }
/// ```
pub type AppResult<T> = Result<T, AppError>;

/// 외부 라이브러리 에러를 AppError로 변환하는 확장 trait
///
/// 다양한 외부 라이브러리의 에러 타입을 `AppError`로 쉽게 변환할 수 있도록
/// 도와주는 확장 trait입니다.
///
/// # 예제
///
/// ```rust,ignore
/// use crate::core::errors::{AppError, ErrorContext};
///
/// // MongoDB 에러 변환
/// let result = collection.find_one(filter, None).await
///     .context("Failed to find user")?;
///
/// // Redis 에러 변환  
/// let cached_data = redis_client.get::<String>("key").await
///     .context("Failed to get cached data")?;
/// ```
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
