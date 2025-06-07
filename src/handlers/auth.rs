use actix_web::{web, HttpResponse, get, post};
use serde::{Deserialize};
use validator::Validate;
use crate::{
    core::errors::AppError,
    config::AuthProvider,
    services::{
        users::user_service::UserService,
        auth::{GoogleAuthService, TokenService},
    },
    domain::dto::users::response::LoginResponse,
};

/// 로컬 로그인 요청
#[derive(Debug, Deserialize, Validate)]
pub struct LocalLoginRequest {
    #[validate(email(message = "유효한 이메일 주소를 입력해주세요"))]
    pub email: String,
    
    #[validate(length(min = 1, message = "비밀번호를 입력해주세요"))]
    pub password: String,
}

/// OAuth 콜백 쿼리 파라미터
#[derive(Debug, Deserialize, Validate)]
pub struct OAuthCallbackQuery {
    #[validate(length(min = 1, message = "Authorization code가 필요합니다"))]
    pub code: String,
    
    #[validate(length(min = 1, message = "State가 필요합니다"))]
    pub state: String,
    
    /// 에러가 있을 경우 (사용자가 거부했거나 에러 발생)
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// 로컬 로그인 핸들러
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

    // JWT 토큰 생성
    let token_pair = token_service.generate_token_pair(&user)?;

    // 응답 생성
    let response = match token_pair.refresh_token {
        Some(refresh_token) => LoginResponse::with_refresh_token(
            user,
            token_pair.access_token,
            token_pair.expires_in,
            refresh_token,
        ),
        None => LoginResponse::new(
            user,
            token_pair.access_token,
            token_pair.expires_in,
        ),
    };

    log::info!("사용자 로컬 로그인 성공: {}", payload.email);
    Ok(HttpResponse::Ok().json(response))
}

/// Google OAuth 로그인 URL 생성
#[get("/google/login")]
pub async fn google_login_url() -> Result<HttpResponse, AppError> {
    let google_service = GoogleAuthService::instance();
    let url_response = google_service.get_login_url()?;
    
    Ok(HttpResponse::Ok().json(url_response))
}

/// Google OAuth 콜백 처리
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
    let token_service = TokenService::instance();

    // Google OAuth 인증 처리
    let user = google_service
        .authenticate_with_code(&query.code, &query.state)
        .await?;

    // JWT 토큰 생성
    let token_pair = token_service.generate_token_pair(&user)?;

    // 응답 생성
    let response = match token_pair.refresh_token {
        Some(refresh_token) => LoginResponse::with_refresh_token(
            user,
            token_pair.access_token,
            token_pair.expires_in,
            refresh_token,
        ),
        None => LoginResponse::new(
            user,
            token_pair.access_token,
            token_pair.expires_in,
        ),
    };

    log::info!("Google OAuth 로그인 성공");
    Ok(HttpResponse::Ok().json(response))
}

/// 일반적인 OAuth 로그인 URL 생성 (향후 확장용)
#[get("/{provider}/login")]
pub async fn oauth_login_url(
    provider: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let auth_provider = AuthProvider::from_str(&provider)
        .map_err(|e| AppError::ValidationError(e))?;

    match auth_provider {
        AuthProvider::Google => {
            let google_service = GoogleAuthService::instance();
            let url_response = google_service.get_login_url()?;
            Ok(HttpResponse::Ok().json(url_response))
        },
        AuthProvider::Local => {
            Err(AppError::ValidationError("로컬 인증은 OAuth를 지원하지 않습니다".to_string()))
        },
        _ => {
            Err(AppError::ValidationError(format!("{}는 아직 지원되지 않는 OAuth 프로바이더입니다", provider)))
        }
    }
}

/// 일반적인 OAuth 콜백 처리 (향후 확장용)
#[get("/{provider}/callback")]
pub async fn oauth_callback(
    provider: web::Path<String>,
    query: web::Query<OAuthCallbackQuery>,
) -> Result<HttpResponse, AppError> {
    // 에러 체크
    if let Some(error) = &query.error {
        let error_msg = query.error_description
            .as_deref()
            .unwrap_or("OAuth 인증이 취소되었거나 실패했습니다");
        log::warn!("{} OAuth 에러: {} - {}", provider, error, error_msg);
        return Err(AppError::AuthenticationError(error_msg.to_string()));
    }

    // 유효성 검사
    query.validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let auth_provider = AuthProvider::from_str(&provider)
        .map_err(|e| AppError::ValidationError(e))?;

    let token_service = TokenService::instance();

    let user = match auth_provider {
        AuthProvider::Google => {
            let google_service = GoogleAuthService::instance();
            google_service
                .authenticate_with_code(&query.code, &query.state)
                .await?
        },
        AuthProvider::Local => {
            return Err(AppError::ValidationError("로컬 인증은 OAuth를 지원하지 않습니다".to_string()));
        },
        _ => {
            return Err(AppError::ValidationError(format!("{}는 아직 지원되지 않는 OAuth 프로바이더입니다", provider)));
        }
    };

    // JWT 토큰 생성
    let token_pair = token_service.generate_token_pair(&user)?;

    // 응답 생성
    let response = match token_pair.refresh_token {
        Some(refresh_token) => LoginResponse::with_refresh_token(
            user,
            token_pair.access_token,
            token_pair.expires_in,
            refresh_token,
        ),
        None => LoginResponse::new(
            user,
            token_pair.access_token,
            token_pair.expires_in,
        ),
    };

    log::info!("{} OAuth 로그인 성공", auth_provider.as_str());
    Ok(HttpResponse::Ok().json(response))
}

/// 토큰 검증 엔드포인트 (선택사항)
#[post("/verify")]
pub async fn verify_token(
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    let token_service = TokenService::instance();
    
    // Authorization 헤더에서 토큰 추출
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::AuthenticationError("Authorization 헤더가 없습니다".to_string()))?;
    
    let token = token_service.extract_bearer_token(auth_header)?;
    let claims = token_service.verify_token(token)?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "valid": true,
        "user_id": claims.sub,
        "email": claims.email,
        "auth_provider": claims.auth_provider
    })))
}
