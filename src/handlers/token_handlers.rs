use actix_web::{web, HttpRequest, HttpResponse, Result, get, post, HttpMessage};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use serde::{Deserialize, Serialize};
use crate::services::auth::TokenService;
use crate::domain::models::token::token::TokenClaims;
use chrono;

/// 토큰 갱신 요청 DTO
#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// 로그아웃 요청 DTO (Header의 Authorization에서 access_token 추출)
#[derive(Deserialize)]
pub struct LogoutRequest {
    // 필요시 추가 정보
}

/// API 응답 래퍼
#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
        }
    }

    pub fn error(message: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            message: Some(message),
        }
    }
}

/// 토큰 갱신 API 핸들러
#[post("/refresh")]
pub async fn refresh_token_handler(
    req: HttpRequest,
    refresh_req: web::Json<RefreshRequest>,
) -> Result<HttpResponse> {
    // 1. 현재 사용자 ID 추출 (Authorization 헤더에서)
    let user_id = match extract_user_id_from_request(&req).await {
        Some(id) => id,
        None => {
            return Ok(HttpResponse::Unauthorized().json(
                ApiResponse::<()>::error("Invalid or missing access token".to_string())
            ));
        }
    };

    // 2. 토큰 갱신
    let token_service = TokenService::instance();
    match token_service.refresh_access_token(&user_id, &refresh_req.refresh_token).await {
        Ok(token_pair) => {
            Ok(HttpResponse::Ok().json(ApiResponse::success(token_pair)))
        }
        Err(e) => {
            log::error!("Token refresh failed: {}", e);
            Ok(HttpResponse::Unauthorized().json(
                ApiResponse::<()>::error("Failed to refresh token".to_string())
            ))
        }
    }
}

#[post("/test")]
pub async fn test_token(
    req: HttpRequest,
) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(ApiResponse::success("test")))
}

/// 로그아웃 API 핸들러
#[post("/logout")]
pub async fn logout_handler(
    req: HttpRequest,
    _logout_req: web::Json<LogoutRequest>,  // _를 붙여서 사용 안함을 명시
) -> Result<HttpResponse> {
    // 1. Authorization 헤더에서 사용자 ID 추출
    let user_id = match extract_user_id_from_request(&req).await {
        Some(id) => id,
        None => {
            return Ok(HttpResponse::Unauthorized().json(
                ApiResponse::<()>::error("Invalid or missing access token".to_string())
            ));
        }
    };

    // 2. 로그아웃 처리 (올바른 단일 인자)
    let token_service = TokenService::instance();
    match token_service.logout(&user_id).await {
        Ok(_) => {
            Ok(HttpResponse::Ok().json(
                ApiResponse::<()> {
                    success: true,
                    data: None,
                    message: Some("Logged out successfully".to_string()),
                }
            ))
        }
        Err(e) => {
            log::error!("Logout failed: {}", e);
            Ok(HttpResponse::InternalServerError().json(
                ApiResponse::<()>::error("Failed to logout".to_string())
            ))
        }
    }
}

/// 모든 세션 강제 종료 API (보안 강화)
#[post("/revoke-all")]
pub async fn revoke_all_tokens_handler(
    req: HttpRequest,
) -> Result<HttpResponse> {
    let user_id = match extract_user_id_from_request(&req).await {
        Some(id) => id,
        None => {
            return Ok(HttpResponse::Unauthorized().json(
                ApiResponse::<()>::error("Invalid or missing access token".to_string())
            ));
        }
    };

    let token_service = TokenService::instance();
    match token_service.revoke_all_tokens(&user_id).await {
        Ok(_) => {
            Ok(HttpResponse::Ok().json(
                ApiResponse::<()> {
                    success: true,
                    data: None,
                    message: Some("All tokens revoked successfully".to_string()),
                }
            ))
        }
        Err(e) => {
            log::error!("Token revocation failed: {}", e);
            Ok(HttpResponse::InternalServerError().json(
                ApiResponse::<()>::error("Failed to revoke tokens".to_string())
            ))
        }
    }
}

/// JWT 인증 미들웨어
pub async fn jwt_auth_middleware(
    req: ServiceRequest,
    next: Next<impl actix_web::body::MessageBody>,
) -> Result<ServiceResponse<impl actix_web::body::MessageBody>, actix_web::Error> {
    // Authorization 헤더에서 토큰 추출
    let auth_header = req.headers().get("Authorization");
    
    let token = match auth_header {
        Some(header) => {
            let auth_str = header.to_str().map_err(|_| {
                actix_web::error::ErrorUnauthorized("Invalid Authorization header")
            })?;
            
            if !auth_str.starts_with("Bearer ") {
                return Err(actix_web::error::ErrorUnauthorized("Invalid token format"));
            }
            
            &auth_str[7..] // "Bearer " 제거
        }
        None => {
            return Err(actix_web::error::ErrorUnauthorized("Missing Authorization header"));
        }
    };

    // 토큰 검증
    let token_service = TokenService::instance();
    let validation = token_service.validate_access_token(token).await;
    
    if !validation.is_valid {
        let error_msg = validation.error_message.unwrap_or("Invalid token".to_string());
        return Err(actix_web::error::ErrorUnauthorized(error_msg));
    }

    // 검증된 사용자 정보를 request extensions에 저장
    if let Some(claims) = validation.claims {
        req.extensions_mut().insert(claims);
    }

    // 다음 미들웨어/핸들러로 진행
    next.call(req).await
}

// ===== 헬퍼 함수들 =====

/// Request에서 사용자 ID 추출
async fn extract_user_id_from_request(req: &HttpRequest) -> Option<String> {
    // Authorization 헤더에서 토큰 추출 후 검증
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;
    
    if !auth_str.starts_with("Bearer ") {
        return None;
    }
    
    let token = &auth_str[7..];
    
    let token_service = TokenService::instance();
    let validation = token_service.validate_access_token(token).await;
    
    if validation.is_valid {
        validation.claims.map(|claims| claims.user_id)
    } else {
        None
    }
}

/// 테스트용 간단한 핸들러
#[get("/test")]
pub async fn test_handler() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Test handler working!",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// 보호된 API 핸들러 예제  
#[get("/profile")]
pub async fn get_profile_handler(req: HttpRequest) -> Result<HttpResponse> {
    // JWT 미들웨어에서 검증된 사용자 정보 추출
    let extensions = req.extensions();
    let claims = extensions.get::<TokenClaims>()
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("No user info"))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user_id": claims.user_id,
        "email": claims.email.as_ref().unwrap_or(&String::new()),
        "message": "Profile retrieved successfully"
    })))
}

/// 라우터 설정 함수
pub fn configure_token_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .service(refresh_token_handler)
            .service(logout_handler)
            .service(revoke_all_tokens_handler)
            .service(get_profile_handler)
    );
}
