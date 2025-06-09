//! Authentication HTTP Handlers
//!
//! 사용자 인증과 관련된 HTTP 엔드포인트를 처리하는 핸들러 함수들입니다.
//! 로컬 인증과 OAuth 2.0 인증을 모두 지원하며, JWT 토큰 기반의 상태 없는 인증을 구현합니다.
//!
//! # Auth Providers
//!
//! - **로컬 인증**: 이메일/패스워드 방식 (`POST /auth/login`)
//! - **OAuth 2.0**: Google OAuth 인증 (`GET /auth/google/login`, `/callback`)
//! - **토큰 검증**: JWT 토큰 유효성 확인 (`POST /auth/verify`)
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde_json::json;
use validator::Validate;
use crate::{
    services::{
        auth::{GoogleAuthService, TokenService},
        users::user_service::UserService,
    },
};
use crate::domain::{LocalLoginRequest, OAuthCallbackQuery, RefreshTokenRequest};
use crate::errors::errors::AppError;

/// 로컬 로그인 핸들러
///
/// 이메일과 패스워드를 사용한 전통적인 로그인을 처리합니다.
/// 새로운 JWT 토큰 관리 시스템(refresh token + blacklist)을 사용합니다.
/// 
/// # Endpoint
/// `POST /auth/login`
#[post("/login")]
pub async fn local_login(
    payload: web::Json<LocalLoginRequest>,
) -> Result<HttpResponse, AppError> {
    // 유효성 검사
    payload.validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let user_service = UserService::instance();
    let token_service = TokenService::instance();

    // 사용자 인증
    let user = user_service
        .verify_password(&payload.email, &payload.password)
        .await?;

    let user_id = user.id_string().unwrap_or_default();
    
    log::info!("로컬 로그인 시도 - 사용자: {}, ID: {}", payload.email, user_id);

    // JWT 토큰 쌍 생성 (Google 로그인과 동일한 방식) + Redis 세션 저장
    let token_pair = token_service
        .generate_token_pair(&user)
        .await
        .map_err(|e| {
            log::error!("토큰 생성 실패 - 사용자: {}, 에러: {}", payload.email, e);
            AppError::InternalError(format!("토큰 생성 실패: {}", e))
        })?;

    // 응답 생성 (Google 로그인과 동일한 구조)
    let response = serde_json::json!({
        "user": {
            "id": user_id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "auth_provider": user.auth_provider,
            "is_active": user.is_active,
            "created_at": user.created_at,
            "updated_at": user.updated_at
        },
        "access_token": token_pair.access_token,
        "refresh_token": token_pair.refresh_token.unwrap_or_default(),
        "expires_in": token_pair.expires_in,
        "token_type": "Bearer"
    });

    Ok(HttpResponse::Ok().json(response))
}

/// Google OAuth 로그인 URL 생성 핸들러
///
/// Google OAuth 2.0 인증을 시작하기 위한 인증 URL을 생성합니다.
/// 
/// # Endpoint
/// `GET /auth/google/login`
#[get("/google/login")]
pub async fn google_login_url() -> Result<HttpResponse, AppError> {
    let google_service = GoogleAuthService::instance();
    let url_response = google_service.get_login_url()?;
    
    Ok(HttpResponse::Ok().json(url_response))
}

/// Google OAuth 콜백 처리 핸들러
///
/// Google OAuth 인증 완료 후 리다이렉트되는 콜백을 처리합니다.
/// 새로운 JWT 토큰 관리 시스템(refresh token + blacklist)을 사용합니다.
/// 
/// # Endpoint
/// `GET /auth/google/callback?code={code}&state={state}`
#[get("/google/callback")]
pub async fn google_oauth_callback(
    query: web::Query<OAuthCallbackQuery>,
) -> Result<HttpResponse, AppError> {
    // 에러 체크 (사용자가 거부했거나 에러 발생)
    if let Some(error) = &query.error {
        let error_msg = query.error_description
            .as_deref()
            .unwrap_or("OAuth 인증이 취소되었거나 실패했습니다");
        log::warn!("Google OAuth 에러: {} - {}", error, error_msg);
        return Err(AppError::AuthenticationError(error_msg.to_string()));
    }

    // 유효성 검사
    query.validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let google_service = GoogleAuthService::instance();
    let token_service = TokenService::instance(); // 새로운 토큰 서비스 사용

    // Google OAuth 인증 처리
    let user = google_service
        .authenticate_with_code(&query.code, &query.state)
        .await?;

    // JWT 토큰 쌍 생성 (Local 로그인과 동일한 방식) + Redis 세션 저장
    let token_pair = token_service
        .generate_token_pair(&user)
        .await
        .map_err(|e| AppError::InternalError(format!("토큰 생성 실패: {}", e)))?;

    // 응답 생성 (Local 로그인과 동일한 구조)
    let response = serde_json::json!({
        "user": {
            "id": user.id_string().unwrap_or_default(),
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "auth_provider": user.auth_provider,
            "is_active": user.is_active,
            "created_at": user.created_at,
            "updated_at": user.updated_at
        },
        "access_token": token_pair.access_token,
        "refresh_token": token_pair.refresh_token.unwrap_or_default(),
        "expires_in": token_pair.expires_in,
        "token_type": "Bearer"
    });

    log::info!("Google OAuth 로그인 성공 (JWT 토큰 방식): {}", user.email);
    Ok(HttpResponse::Ok().json(response))
}

/// 토큰 검증 엔드포인트
///
/// 클라이언트가 보유한 JWT 토큰의 유효성을 검증합니다.
/// 
/// # Endpoint
/// `POST /auth/verify`
#[post("/verify")]
pub async fn verify_token(
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let token_service = TokenService::instance();
    
    // Authorization 헤더에서 토큰 추출
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::AuthenticationError("Authorization 헤더가 없습니다".to_string()))?;
    
    let token = token_service.extract_bearer_token(auth_header)?;
    let claims = token_service.verify_token(token)?;
    
    Ok(HttpResponse::Ok().json(json!({
        "valid": true,
        "user_id": claims.sub,
        "auth_provider": claims.auth_provider
    })))
}

/// 현재 인증된 사용자 정보 조회 엔드포인트
///
/// JWT 토큰을 검증하고 데이터베이스에서 최신 사용자 정보를 조회하여 반환합니다.
/// 
/// # Endpoint
/// `GET /auth/me`
#[get("/me")]
pub async fn get_current_user(
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let token_service = TokenService::instance();
    let user_service = UserService::instance();

    // Authorization 헤더에서 토큰 추출
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::AuthenticationError("Authorization 헤더가 없습니다".to_string()))?;

    // Bearer 토큰 추출
    let token = token_service.extract_bearer_token(auth_header)?;

    // 토큰 검증 및 사용자 ID 추출
    let user_id = token_service.extract_user_id(token)?;

    // 데이터베이스에서 최신 사용자 정보 조회
    let user = user_service.find_by_id(&user_id).await
        .map_err(|_| AppError::AuthenticationError("사용자 조회 중 오류가 발생했습니다".to_string()))?
        .ok_or_else(|| AppError::AuthenticationError("사용자를 찾을 수 없습니다".to_string()))?;

    // 응답 생성
    Ok(HttpResponse::Ok().json(json!({
        "id": user.id_string().unwrap_or_default(),
        "username": user.username,
        "email": user.email,
        "roles": user.roles,
        "auth_provider": user.auth_provider,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "updated_at": user.updated_at
    })))
}

/// 토큰 갱신 엔드포인트
///
/// 만료된 액세스 토큰을 리프레시 토큰을 사용하여 갱신합니다.
/// 
/// # Endpoint
/// `POST /auth/refresh`
#[post("/refresh")]
pub async fn refresh_tokens(
    req: HttpRequest,
    body: Option<web::Json<RefreshTokenRequest>>,
) -> Result<HttpResponse, AppError> {
    let token_service = TokenService::instance();
    let user_service = UserService::instance();

    // 리프레시 토큰을 쿠키 또는 요청 본문에서 추출
    let rt = extract_refresh_token(&req, body.as_deref())?;

    // 리프레시 토큰 검증
    let claims = token_service.verify_token(&rt)
        .map_err(|_| AppError::AuthenticationError("리프레시 토큰이 만료되었거나 유효하지 않습니다".to_string()))?;

    // 사용자 정보 조회
    let user = user_service.find_by_id(&claims.sub).await
        .map_err(|_| AppError::InternalError("사용자 조회 중 오류가 발생했습니다".to_string()))?
        .ok_or_else(|| AppError::AuthenticationError("사용자를 찾을 수 없습니다".to_string()))?;

    // 사용자 계정 상태 확인
    if !user.is_active {
        log::warn!("비활성 사용자의 토큰 갱신 시도: {}", claims.sub);
        return Err(AppError::AuthenticationError("계정이 비활성화되었습니다".to_string()));
    }

    // 새로운 토큰 쌍 생성
    let token_pair = token_service.generate_token_pair(&user).await?;

    log::info!("토큰 갱신 성공: 사용자 ID {}", claims.sub);

    // 응답 생성
    Ok(HttpResponse::Ok().json(json!({
        "access_token": token_pair.access_token,
        "refresh_token": token_pair.refresh_token,
        "expires_in": token_pair.expires_in,
        "token_type": "Bearer"
    })))
}


/// HTTP 요청에서 리프레시 토큰 추출
fn extract_refresh_token(
    req: &HttpRequest,
    body: Option<&RefreshTokenRequest>,
) -> Result<String, AppError> {
    // 1. 쿠키에서 리프레시 토큰 찾기
    if let Some(cookie_header) = req.headers().get("Cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie_pair in cookie_str.split(';') {
                let cookie_pair = cookie_pair.trim();
                if let Some((name, value)) = cookie_pair.split_once('=') {
                    if name.trim() == "refresh_token" {
                        let token = value.trim();
                        if !token.is_empty() {
                            return Ok(token.to_string());
                        }
                    }
                }
            }
        }
    }

    // 2. 요청 본문에서 리프레시 토큰 찾기
    if let Some(body) = body {
        if !body.refresh_token.is_empty() {
            return Ok(body.refresh_token.clone());
        }
    }

    // 3. 토큰을 찾을 수 없음
    Err(AppError::AuthenticationError(
        "리프레시 토큰이 제공되지 않았습니다".to_string()
    ))
}
