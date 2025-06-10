use actix_web::{web, HttpRequest, HttpResponse, Result, get, post, HttpMessage};
use crate::services::auth::TokenService;
use crate::domain::models::token::token::TokenClaims;
use chrono;
use crate::domain::{ApiResponse, LogoutRequest, RefreshRequest};

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

/// 로그아웃 API 핸들러 (상세 블랙리스트 지원)
#[post("/logout")]
pub async fn logout_handler(
    req: HttpRequest,
    _logout_req: web::Json<LogoutRequest>,  // _를 붙여서 사용 안함을 명시
) -> Result<HttpResponse> {
    // 1. Authorization 헤더에서 access token 추출
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            actix_web::error::ErrorUnauthorized("Authorization 헤더가 없습니다")
        })?;

    let token_service = TokenService::instance();
    
    // 2. Bearer 토큰 추출
    let access_token = match token_service.extract_bearer_token(auth_header) {
        Ok(token) => token,
        Err(_) => {
            return Ok(HttpResponse::Unauthorized().json(
                ApiResponse::<()>::error("유효하지 않은 토큰 형식입니다".to_string())
            ));
        }
    };

    // 3. 토큰에서 사용자 ID 추출 (블랙리스트 확인 포함)
    let user_id = match token_service.extract_user_id(access_token).await {
        Ok(id) => id,
        Err(_) => {
            return Ok(HttpResponse::Unauthorized().json(
                ApiResponse::<()>::error("유효하지 않거나 만료된 토큰입니다".to_string())
            ));
        }
    };

    // 4. IP 주소 추출
    let ip_address = extract_client_ip(&req);
    
    // 5. User-Agent 추출
    let user_agent = req.headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // 6. 로그아웃 처리 (세션 삭제 + 상세 블랙리스트 추가)
    match token_service.logout_with_blacklist_detailed(
        &user_id, 
        access_token, 
        ip_address.clone(),
        user_agent.clone()
    ).await {
        Ok(_) => {
            log::info!("사용자 로그아웃 성공 - user_id: {}, IP: {:?}, UA: {:?}", 
                       user_id, ip_address, user_agent.as_deref().unwrap_or("Unknown"));
            Ok(HttpResponse::Ok().json(
                ApiResponse::<()> {
                    success: true,
                    data: None,
                    message: Some("로그아웃이 성공적으로 처리되었습니다".to_string()),
                }
            ))
        }
        Err(e) => {
            log::error!("로그아웃 실패 - user_id: {}, 에러: {}", user_id, e);
            Ok(HttpResponse::InternalServerError().json(
                ApiResponse::<()>::error("로그아웃 처리 중 오류가 발생했습니다".to_string())
            ))
        }
    }
}

/// HTTP 요청에서 클라이언트 IP 주소 추출
/// 
/// 프록시나 로드 밸런서를 고려하여 다양한 헤더에서 실제 클라이언트 IP를 추출합니다.
/// 
/// # 우선순위
/// 1. `X-Forwarded-For` (첫 번째 IP)
/// 2. `X-Real-IP`
/// 3. `X-Client-IP`
/// 4. `CF-Connecting-IP` (Cloudflare)
/// 5. 연결 정보에서 peer 주소
fn extract_client_ip(req: &HttpRequest) -> Option<String> {
    // X-Forwarded-For 헤더 확인 (프록시 환경에서 가장 일반적)
    if let Some(forwarded_for) = req.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // 첫 번째 IP만 사용 (체인의 첫 번째가 원본 클라이언트)
            if let Some(first_ip) = forwarded_str.split(',').next() {
                let trimmed_ip = first_ip.trim();
                if !trimmed_ip.is_empty() {
                    return Some(trimmed_ip.to_string());
                }
            }
        }
    }
    
    // X-Real-IP 헤더 확인
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }
    
    // X-Client-IP 헤더 확인
    if let Some(client_ip) = req.headers().get("X-Client-IP") {
        if let Ok(ip_str) = client_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }
    
    // CF-Connecting-IP 헤더 확인 (Cloudflare)
    if let Some(cf_ip) = req.headers().get("CF-Connecting-IP") {
        if let Ok(ip_str) = cf_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }
    
    // 마지막 수단: 연결 정보에서 peer 주소
    if let Some(peer_addr) = req.peer_addr() {
        return Some(peer_addr.ip().to_string());
    }
    
    None
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


/// Request에서 사용자 ID 추출 (블랙리스트 확인 포함)
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

/// 사용자의 모든 블랙리스트된 토큰 조회 API (관리자용)
#[get("/blacklist/{user_id}")]
pub async fn get_user_blacklisted_tokens_handler(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    
    // 관리자 권한 확인 (JWT에서 roles 확인)
    let extensions = req.extensions();
    if let Some(claims) = extensions.get::<TokenClaims>() {
        if !claims.roles.contains(&"admin".to_string()) {
            return Ok(HttpResponse::Forbidden().json(
                ApiResponse::<()>::error("관리자 권한이 필요합니다".to_string())
            ));
        }
    } else {
        return Ok(HttpResponse::Unauthorized().json(
            ApiResponse::<()>::error("인증이 필요합니다".to_string())
        ));
    }

    let token_service = TokenService::instance();
    
    match token_service.get_user_blacklisted_tokens(&user_id).await {
        Ok(blacklisted_tokens) => {
            log::info!("관리자 블랙리스트 조회 - user_id: {}, 토큰 개수: {}", user_id, blacklisted_tokens.len());
            Ok(HttpResponse::Ok().json(ApiResponse::success(blacklisted_tokens)))
        }
        Err(e) => {
            log::error!("블랙리스트 조회 실패 - user_id: {}, 에러: {}", user_id, e);
            Ok(HttpResponse::InternalServerError().json(
                ApiResponse::<()>::error("블랙리스트 조회 중 오류가 발생했습니다".to_string())
            ))
        }
    }
}

/// 라우터 설정 함수
pub fn configure_token_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .service(refresh_token_handler)
            .service(logout_handler)
            .service(revoke_all_tokens_handler)
            .service(get_user_blacklisted_tokens_handler)
    );
}
