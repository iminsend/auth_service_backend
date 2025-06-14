//! API 라우트 설정 모듈
//!
//! RESTful API 엔드포인트들을 기능별로 그룹화하여 제공합니다.
//! 사용자, 인증 관련 라우트와 헬스체크 엔드포인트를 포함합니다.
//!
//! # Features
//!
//! - 사용자 CRUD API 엔드포인트
//! - 로컬/OAuth 인증 API 엔드포인트  
//! - 역할 기반 접근 제어 미들웨어 적용
//! - 헬스체크 엔드포인트
//!
//! # Auth Middleware Usage
//!
//! 라우트에 따라 다른 인증 레벨을 적용할 수 있습니다:
//!
//! ## 인증 불필요 (Public 라우트)
//! ```rust,ignore
//! cfg.service(
//!     web::scope("/api/v1/public")
//!         .service(handlers::auth::local_login)  // 로그인 자체는 인증 불필요
//!         .service(handlers::users::create_user) // 회원가입은 인증 불필요
//! );
//! ```
//!
//! ## 인증 필요 + 역할 기반 권한 검증
//! ```rust,ignore
//! cfg.service(
//!     web::scope("/api/v1/users")
//!         .wrap(AuthMiddleware::required_with_roles(vec!["user", "admin"]))
//!         .service(handlers::users::get_user)     // user 또는 admin 역할 필요
//! );
//! ```
//!
//! ## 관리자 전용 라우트
//! ```rust,ignore
//! cfg.service(
//!     web::scope("/api/v1/admin")
//!         .wrap(AuthMiddleware::required_with_roles(vec!["admin"]))
//!         .service(handlers::admin::manage_users) // admin 역할만 허용
//! );
//! ```
//!
//! # Examples
//!
//! ```rust,ignore
//! use actix_web::web;
//! 
//! let mut cfg = web::ServiceConfig::new();
//! configure_all_routes(&mut cfg);
//! ```

use crate::handlers;
use crate::middlewares::AuthMiddleware;
use actix_web::web;
use chrono;
use serde_json::json;

/// 모든 라우트를 설정합니다
///
/// 기능별로 분할된 라우트들을 통합하여 애플리케이션에 등록합니다.
///
/// # Arguments
///
/// * `cfg` - Actix-web 서비스 설정 객체
///
/// # Examples
///
/// ```rust,ignore
/// use actix_web::{web, App};
///
/// let app = App::new().configure(configure_all_routes);
/// ```
pub fn configure_all_routes(cfg: &mut web::ServiceConfig) {
    // Health check endpoint
    cfg.service(health_check);

    // Feature-specific routes
    configure_user_routes(cfg);
    configure_auth_routes(cfg);
    
    // RSA routes
    configure_rsa_routes(cfg);
}

/// 사용자 관련 라우트를 설정합니다
///
/// 사용자 생성, 조회, 삭제 API 엔드포인트를 등록합니다.
/// 보안 레벨에 따라 라우트를 분리하여 구성합니다.
///
/// # Route Groups
///
/// ## Public 라우트 (인증 불필요)
/// - `POST /api/v1/users` - 사용자 생성 (회원가입)
/// - `DELETE /api/v1/users` - 사용자 삭제
///
/// ## Protected 라우트 (인증 + 권한 필요)
/// - `GET /api/v1/users` - 사용자 조회 (user 또는 admin 역할)
///
/// # Arguments
///
/// * `cfg` - Actix-web 서비스 설정 객체
///
/// # Examples
///
/// ```bash
/// # Public - 인증 없이 접근 가능
/// curl -X POST http://localhost:8080/api/v1/users \
///   -H "Content-Type: application/json" \
///   -d '{"email":"user@example.com","username":"newuser"}'
///
/// # Protected - Bearer 토큰 필요
/// curl -X GET http://localhost:8080/api/v1/users \
///   -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
/// ```
fn configure_user_routes(cfg: &mut web::ServiceConfig) {
    // Public routes
    cfg.service(
        web::scope("/api/v1/users")
            .service(handlers::users::create_user)
            .service(handlers::users::delete_user)
    );
    
    // Protected routes - 명확한 이름 사용
    cfg.service(
        web::scope("/api/v1/me")  // 간단하고 명확
            .wrap(AuthMiddleware::required_with_roles(vec!["user", "admin"]))
            .service(handlers::users::get_user)
    );
}

/// 인증 관련 라우트를 설정합니다
///
/// 로컬 로그인, OAuth 인증 API 엔드포인트를 등록합니다.
/// 모든 인증 라우트는 Public 접근이 가능합니다 (인증을 위한 엔드포인트이므로).
///
/// # Available Routes
///
/// ## 로컬 인증
/// - `POST /api/v1/auth/login` - 이메일/비밀번호 로그인
/// - `POST /api/v1/auth/verify` - JWT 토큰 검증
/// - `GET /api/v1/auth/me` - 현재 사용자 정보 조회
/// - `POST /api/v1/auth/refresh` - 토큰 갱신
///
/// ## OAuth (Google)
/// - `GET /api/v1/auth/google` - Google OAuth 로그인 URL 생성
/// - `POST /api/v1/auth/google/callback` - Google OAuth 콜백 처리
///
/// # Arguments
///
/// * `cfg` - Actix-web 서비스 설정 객체
///
/// # Examples
///
/// ```bash
/// # 로컬 로그인
/// curl -X POST http://localhost:8080/api/v1/auth/login \
///   -H "Content-Type: application/json" \
///   -d '{"email":"user@example.com","password":"password123"}'
///
/// # Google OAuth 시작
/// curl http://localhost:8080/api/v1/auth/google
/// ```
fn configure_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1/auth")
            // 로컬 인증
            .service(handlers::auth::local_login)
            .service(handlers::auth::verify_token)
            .service(handlers::auth::get_current_user)
            .service(handlers::auth::refresh_tokens)
            // Google OAuth
            .service(handlers::auth::google_login_url)
            .service(handlers::auth::google_oauth_callback)
    );

    // 인증이 필요한 사용자 라우트들
    cfg.service(
        web::scope("/api/v1/token")
            .wrap(AuthMiddleware::required_with_roles(vec!["user", "admin"]))
            .service(handlers::token_handlers::refresh_token_handler)
            .service(handlers::token_handlers::logout_handler)
            .service(handlers::token_handlers::revoke_all_tokens_handler)
    );
}

fn configure_rsa_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1/rsa")
            .service(handlers::rsa::jwks_handler)
            .service(handlers::rsa::register_public_key)
            .service(handlers::rsa::get_registered_services)
            .service(handlers::rsa::get_all_keys_admin)
            .service(handlers::rsa::deactivate_key)
            .service(handlers::rsa::activate_key)
            .service(handlers::rsa::get_jwt_secret)
    );
}

/// 서비스 상태를 확인하는 헬스체크 엔드포인트
///
/// 로드밸런서나 모니터링 시스템에서 서비스 상태를 확인하는 데 사용됩니다.
///
/// # Returns
///
/// * `HttpResponse` - 서비스 상태 정보를 포함한 JSON 응답
///   - `status`: 서비스 상태 ("healthy")
///   - `service`: 서비스 이름
///   - `version`: 현재 버전
///   - `timestamp`: 응답 시각
///   - `features`: 사용 중인 기술 스택
///
/// # Examples
///
/// ```bash
/// curl http://localhost:8080/health
/// ```
///
/// Response:
/// ```json
/// {
///   "status": "healthy",
///   "service": "insend_auth_service",
///   "version": "0.1.0",
///   "timestamp": "2023-01-01T00:00:00Z",
///   "features": {
///     "database": "MongoDB",
///     "cache": "Redis",
///     "dependency_injection": "Singleton Macro"
///   }
/// }
/// ```
#[actix_web::get("/health")]
async fn health_check() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().json(json!({
        "status": "healthy",
        "service": "insend_auth_service",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "features": {
            "database": "MongoDB",
            "cache": "Redis",
            "dependency_injection": "Singleton Macro"
        }
    }))
}
