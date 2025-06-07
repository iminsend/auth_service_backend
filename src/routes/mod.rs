//! 라우트 설정 모듈
//! 
//! 모든 API 엔드포인트의 라우트 설정을 관리합니다.
//! RESTful API 엔드포인트들을 기능별로 그룹화하여 제공합니다.

use actix_web::web;
use crate::handlers;

/// All Routes
/// 
/// 각 기능별로 분할된 route를 본 라우트에서 통합해서 제공합니다.
pub fn configure_all_routes(cfg: &mut web::ServiceConfig) {
    // Health check endpoint
    cfg.service(health_check);
    
    // Feature-specific routes
    configure_user_routes(cfg);
    configure_auth_routes(cfg);
}

/// User Routes - RESTful API
/// 
/// 사용자의 생성, 조회, 삭제에 대한 API 모음입니다.
fn configure_user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1/users")
            .service(handlers::users::create_user)
            .service(handlers::users::get_user)
            .service(handlers::users::delete_user),
    );
}

/// Auth Routes - 인증 관련 API
/// 
/// 로컬 로그인, OAuth 인증에 대한 API 모음입니다.
fn configure_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1/auth")
            // 로컬 인증
            .service(handlers::auth::local_login)
            .service(handlers::auth::verify_token)
            
            // Google OAuth
            .service(handlers::auth::google_login_url)
            .service(handlers::auth::google_oauth_callback)
            
            // 일반 OAuth (확장용)
            .service(handlers::auth::oauth_login_url)
            .service(handlers::auth::oauth_callback)
    );
}

/// 헬스체크 엔드포인트
/// 
/// 서비스 상태를 확인하는 엔드포인트입니다.
/// 로드밸런서나 모니터링 시스템에서 사용됩니다.
#[actix_web::get("/health")]
async fn health_check() -> actix_web::HttpResponse {
    use serde_json::json;
    use chrono;
    
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
