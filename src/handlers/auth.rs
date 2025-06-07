//! # Authentication HTTP Handlers
//!
//! 사용자 인증과 관련된 HTTP 엔드포인트를 처리하는 핸들러 함수들입니다.
//! Spring Security와 유사한 방식으로 로컬 인증과 OAuth 2.0 인증을 모두 지원하며,
//! JWT 토큰 기반의 상태 없는(stateless) 인증을 구현합니다.
//!
//! ## 지원하는 인증 방식
//!
//! ### 1. 로컬 인증 (이메일/패스워드)
//! ```text
//! POST /auth/login
//! {
//!   "email": "user@example.com",
//!   "password": "secure_password"
//! }
//! ```
//!
//! ### 2. OAuth 2.0 인증
//! ```text
//! GET  /auth/{provider}/login     ← 인증 URL 생성
//! GET  /auth/{provider}/callback  ← OAuth 콜백 처리
//! ```
//!
//! ### 3. 토큰 검증
//! ```text
//! POST /auth/verify
//! Authorization: Bearer {jwt_token}
//! ```
//!
//! ## Spring Security와의 비교
//!
//! ### Spring Security 구성
//! ```java
//! @Configuration
//! @EnableWebSecurity
//! public class SecurityConfig {
//!     
//!     @Bean
//!     public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//!         http
//!             .oauth2Login(oauth2 -> oauth2
//!                 .loginPage("/login")
//!                 .defaultSuccessUrl("/dashboard")
//!                 .userInfoEndpoint(userInfo -> userInfo
//!                     .userService(customOAuth2UserService)
//!                 )
//!             )
//!             .formLogin(form -> form
//!                 .loginPage("/login")
//!                 .defaultSuccessUrl("/dashboard")
//!             );
//!         return http.build();
//!     }
//! }
//!
//! @RestController
//! public class AuthController {
//!     
//!     @PostMapping("/api/auth/login")
//!     public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
//!         // 로컬 인증 처리
//!     }
//! }
//! ```
//!
//! ### 이 모듈의 Rust 구현
//! ```rust,ignore
//! // OAuth 2.0 플로우
//! #[get("/google/login")]
//! pub async fn google_login_url() -> Result<HttpResponse, AppError> {
//!     let google_service = GoogleAuthService::instance();
//!     let url_response = google_service.get_login_url()?;
//!     Ok(HttpResponse::Ok().json(url_response))
//! }
//!
//! #[get("/google/callback")]
//! pub async fn google_oauth_callback(
//!     query: web::Query<OAuthCallbackQuery>,
//! ) -> Result<HttpResponse, AppError> {
//!     let google_service = GoogleAuthService::instance();
//!     let user = google_service.authenticate_with_code(&query.code, &query.state).await?;
//!     // JWT 토큰 생성 및 응답
//! }
//! ```
//!
//! ## 인증 플로우
//!
//! ### 로컬 인증 플로우
//! ```text
//! 1. 클라이언트 → POST /auth/login (이메일, 패스워드)
//! 2. 서버 → 이메일/패스워드 검증
//! 3. 서버 → JWT 토큰 생성
//! 4. 서버 → 토큰과 사용자 정보 응답
//! 5. 클라이언트 → Authorization: Bearer {token}으로 후속 요청
//! ```
//!
//! ### OAuth 2.0 인증 플로우
//! ```text
//! 1. 클라이언트 → GET /auth/google/login (인증 URL 요청)
//! 2. 서버 → Google 인증 URL 응답
//! 3. 클라이언트 → Google 인증 페이지로 리다이렉트
//! 4. 사용자 → Google에서 인증 수행
//! 5. Google → GET /auth/google/callback?code=...&state=... 리다이렉트
//! 6. 서버 → 인증 코드를 액세스 토큰으로 교환
//! 7. 서버 → Google에서 사용자 정보 조회
//! 8. 서버 → JWT 토큰 생성 및 응답
//! ```
//!
//! ## 보안 고려사항
//!
//! ### CSRF 보호
//! ```rust,ignore
//! // OAuth state 파라미터로 CSRF 공격 방지
//! let csrf_token = Uuid::new_v4().to_string();
//! let auth_url = format!(
//!     "https://accounts.google.com/o/oauth2/v2/auth?state={}",
//!     csrf_token
//! );
//! 
//! // 콜백에서 state 검증
//! if received_state != stored_state {
//!     return Err(AppError::AuthenticationError("Invalid state parameter"));
//! }
//! ```
//!
//! ### 토큰 보안
//! ```rust,ignore
//! // JWT 토큰 생성 시 보안 강화
//! let token_claims = TokenClaims {
//!     sub: user.id.clone(),
//!     email: user.email.clone(),
//!     auth_provider: user.auth_provider.clone(),
//!     roles: user.roles.clone(),
//!     exp: (Utc::now() + Duration::hours(1)).timestamp() as usize, // 1시간 만료
//!     iat: Utc::now().timestamp() as usize,
//!     iss: "auth-service".to_string(), // 발행자
//! };
//! ```
//!
//! ### Rate Limiting
//! ```rust,ignore
//! // 로그인 시도 제한
//! use actix_web_lab::middleware::from_fn;
//!
//! async fn rate_limit_middleware(
//!     req: ServiceRequest,
//!     next: Next<impl MessageBody>,
//! ) -> Result<ServiceResponse<impl MessageBody>, Error> {
//!     let ip = req.peer_addr().map(|addr| addr.ip());
//!     
//!     if let Some(ip) = ip {
//!         let attempts = get_login_attempts(ip).await?;
//!         if attempts > 5 {
//!             return Err(ErrorTooManyRequests("Too many login attempts"));
//!         }
//!     }
//!     
//!     next.call(req).await
//! }
//! ```
//!
//! ## 에러 처리 전략
//!
//! ### 표준화된 에러 응답
//! ```rust,ignore
//! // 인증 실패 시 표준 에러 응답
//! {
//!   "error": "authentication_failed",
//!   "message": "잘못된 이메일 또는 비밀번호입니다",
//!   "details": null,
//!   "timestamp": "2024-01-01T12:00:00Z"
//! }
//!
//! // OAuth 에러 시 상세 정보 포함
//! {
//!   "error": "oauth_error",
//!   "message": "Google OAuth 인증이 실패했습니다",
//!   "details": {
//!     "provider": "google",
//!     "error_code": "access_denied",
//!     "error_description": "User denied access"
//!   }
//! }
//! ```
//!
//! ### 로깅 및 모니터링
//! ```rust,ignore
//! use tracing::{info, warn, error, instrument};
//!
//! #[instrument(skip(payload), fields(email = %payload.email))]
//! pub async fn local_login(
//!     payload: web::Json<LocalLoginRequest>,
//! ) -> Result<HttpResponse, AppError> {
//!     info!("로컬 로그인 시도");
//!     
//!     match user_service.verify_password(&payload.email, &payload.password).await {
//!         Ok(user) => {
//!             info!("로그인 성공: user_id={}", user.id_string().unwrap_or_default());
//!             // 성공 처리
//!         }
//!         Err(e) => {
//!             warn!("로그인 실패: {}", e);
//!             // 실패 처리
//!         }
//!     }
//! }
//! ```
//!
//! ## 응답 형식
//!
//! ### 성공적인 로그인 응답
//! ```json
//! {
//!   "user": {
//!     "id": "507f1f77bcf86cd799439011",
//!     "email": "user@example.com",
//!     "username": "john_doe",
//!     "display_name": "John Doe",
//!     "auth_provider": "google",
//!     "is_active": true,
//!     "roles": ["user"],
//!     "created_at": "2024-01-01T00:00:00Z"
//!   },
//!   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//!   "expires_in": 3600,
//!   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//!   "token_type": "Bearer"
//! }
//! ```
//!
//! ### OAuth 로그인 URL 응답
//! ```json
//! {
//!   "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&state=...",
//!   "state": "uuid-v4-csrf-token",
//!   "expires_in": 600
//! }
//! ```

use actix_web::{get, post, web, HttpResponse};
use serde::Deserialize;
use validator::Validate;
use crate::{
    config::AuthProvider,
    domain::dto::users::response::LoginResponse,
    services::{
        auth::{GoogleAuthService, TokenService},
        users::user_service::UserService,
    },
};
use crate::errors::errors::AppError;

/// 로컬 로그인 요청 구조체
///
/// 이메일과 패스워드를 사용한 전통적인 인증 방식의 요청 데이터입니다.
/// validator 크레이트를 사용하여 입력 데이터의 유효성을 검증합니다.
///
/// # 검증 규칙
///
/// - `email`: 유효한 이메일 형식이어야 함
/// - `password`: 최소 1자 이상 (빈 값 방지)
///
/// # 예제
///
/// ```json
/// {
///   "email": "user@example.com",
///   "password": "secure_password123"
/// }
/// ```
#[derive(Debug, Deserialize, Validate)]
pub struct LocalLoginRequest {
    #[validate(email(message = "유효한 이메일 주소를 입력해주세요"))]
    pub email: String,
    
    #[validate(length(min = 1, message = "비밀번호를 입력해주세요"))]
    pub password: String,
}

/// OAuth 콜백 쿼리 파라미터 구조체
///
/// OAuth 2.0 Authorization Code Flow에서 인증 서버가 리다이렉트할 때
/// 전달하는 쿼리 파라미터들을 파싱하기 위한 구조체입니다.
///
/// # 필수 파라미터
///
/// - `code`: 액세스 토큰으로 교환할 인증 코드
/// - `state`: CSRF 공격 방지를 위한 상태 토큰
///
/// # 선택적 파라미터
///
/// - `error`: 인증 실패 시 에러 코드
/// - `error_description`: 에러에 대한 상세 설명
///
/// # 예제
///
/// 성공 시: `?code=4/0AdQt8qh...&state=uuid-csrf-token`
/// 실패 시: `?error=access_denied&error_description=User+denied+access&state=uuid-csrf-token`
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
///
/// 이메일과 패스워드를 사용한 전통적인 로그인을 처리합니다.
/// 사용자 인증 성공 시 JWT 토큰을 발급하고 사용자 정보와 함께 응답합니다.
///
/// # 엔드포인트
///
/// `POST /auth/login`
///
/// # 요청 본문
///
/// ```json
/// {
///   "email": "user@example.com",
///   "password": "user_password"
/// }
/// ```
///
/// # 응답
///
/// ## 성공 (200 OK)
/// ```json
/// {
///   "user": { /* 사용자 정보 */ },
///   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
///   "expires_in": 3600,
///   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
///   "token_type": "Bearer"
/// }
/// ```
///
/// ## 실패 (400/401/500)
/// ```json
/// {
///   "error": "authentication_failed",
///   "message": "잘못된 이메일 또는 비밀번호입니다"
/// }
/// ```
///
/// # 보안 고려사항
///
/// - 비밀번호는 bcrypt로 해시되어 저장됨
/// - 로그인 실패 시 구체적인 실패 이유를 노출하지 않음
/// - Rate limiting으로 무차별 대입 공격 방지
/// - 감사 로그에 로그인 시도 기록
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

/// Google OAuth 로그인 URL 생성 핸들러
///
/// Google OAuth 2.0 인증을 시작하기 위한 인증 URL을 생성합니다.
/// 클라이언트는 이 URL로 사용자를 리다이렉트하여 Google 인증을 시작할 수 있습니다.
///
/// # 엔드포인트
///
/// `GET /auth/google/login`
///
/// # 응답
///
/// ```json
/// {
///   "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&state=...",
///   "state": "uuid-v4-csrf-token",
///   "expires_in": 600
/// }
/// ```
///
/// # 사용법
///
/// 1. 클라이언트가 이 엔드포인트를 호출
/// 2. 서버가 Google 인증 URL과 CSRF 토큰 응답
/// 3. 클라이언트가 사용자를 auth_url로 리다이렉트
/// 4. 사용자가 Google에서 인증 수행
/// 5. Google이 콜백 URL로 리다이렉트 (code와 state 파라미터 포함)
///
/// # 보안 기능
///
/// - CSRF 보호를 위한 state 파라미터 포함
/// - 인증 URL 만료 시간 설정
/// - 필요한 OAuth 스코프만 요청
#[get("/google/login")]
pub async fn google_login_url() -> Result<HttpResponse, AppError> {
    let google_service = GoogleAuthService::instance();
    let url_response = google_service.get_login_url()?;
    
    Ok(HttpResponse::Ok().json(url_response))
}

/// Google OAuth 콜백 처리 핸들러
///
/// Google OAuth 인증 완료 후 리다이렉트되는 콜백을 처리합니다.
/// 인증 코드를 액세스 토큰으로 교환하고, 사용자 정보를 조회하여
/// JWT 토큰을 발급합니다.
///
/// # 엔드포인트
///
/// `GET /auth/google/callback?code={code}&state={state}`
///
/// # 쿼리 파라미터
///
/// - `code`: Google에서 제공한 인증 코드
/// - `state`: CSRF 방지용 상태 토큰
/// - `error`: 인증 실패 시 에러 코드 (선택적)
/// - `error_description`: 에러 설명 (선택적)
///
/// # 응답
///
/// ## 성공 시
/// ```json
/// {
///   "user": { /* 사용자 정보 */ },
///   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
///   "expires_in": 3600,
///   "token_type": "Bearer"
/// }
/// ```
///
/// ## 에러 시
/// ```json
/// {
///   "error": "oauth_error",
///   "message": "OAuth 인증이 취소되었거나 실패했습니다"
/// }
/// ```
///
/// # 처리 흐름
///
/// 1. 쿼리 파라미터 검증 (에러, 코드, 상태 확인)
/// 2. CSRF 상태 토큰 검증
/// 3. 인증 코드를 액세스 토큰으로 교환
/// 4. Google에서 사용자 정보 조회
/// 5. 기존 사용자 확인 또는 신규 사용자 생성
/// 6. JWT 토큰 생성 및 응답
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

/// 범용 OAuth 로그인 URL 생성 핸들러 (향후 확장용)
///
/// 다양한 OAuth 프로바이더를 지원하기 위한 확장 가능한 엔드포인트입니다.
/// 현재는 Google만 지원하지만, 향후 GitHub, Microsoft 등을 추가할 수 있습니다.
///
/// # 엔드포인트
///
/// `GET /auth/{provider}/login`
///
/// # 경로 파라미터
///
/// - `provider`: OAuth 프로바이더 이름 (`google`, `github`, `microsoft` 등)
///
/// # 지원 프로바이더
///
/// - `google`: Google OAuth 2.0
/// - `github`: GitHub OAuth (향후 구현)
/// - `microsoft`: Microsoft OAuth (향후 구현)
///
/// # 응답
///
/// 각 프로바이더별 인증 URL과 메타데이터를 포함한 JSON 응답
///
/// # 예제
///
/// `GET /auth/google/login` → Google 인증 URL 응답
/// `GET /auth/github/login` → GitHub 인증 URL 응답 (향후)
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

/// 범용 OAuth 콜백 처리 핸들러 (향후 확장용)
///
/// 다양한 OAuth 프로바이더의 콜백을 처리하는 확장 가능한 엔드포인트입니다.
/// 프로바이더별로 적절한 서비스를 선택하여 인증을 처리합니다.
///
/// # 엔드포인트
///
/// `GET /auth/{provider}/callback`
///
/// # 경로 파라미터
///
/// - `provider`: OAuth 프로바이더 이름
///
/// # 쿼리 파라미터
///
/// 표준 OAuth 2.0 콜백 파라미터들 (프로바이더별로 동일)
///
/// # 처리 흐름
///
/// 1. 프로바이더 식별 및 검증
/// 2. 해당 프로바이더 서비스 선택
/// 3. OAuth 인증 코드 처리
/// 4. 사용자 정보 조회 및 계정 처리
/// 5. JWT 토큰 생성 및 응답
///
/// # 확장성
///
/// 새로운 OAuth 프로바이더 추가 시:
/// 1. AuthProvider enum에 새 variant 추가
/// 2. 해당 프로바이더 서비스 구현
/// 3. match 구문에 케이스 추가
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

/// 토큰 검증 엔드포인트
///
/// 클라이언트가 보유한 JWT 토큰의 유효성을 검증합니다.
/// 토큰이 유효한 경우 토큰에 포함된 사용자 정보를 응답합니다.
///
/// # 엔드포인트
///
/// `POST /auth/verify`
///
/// # 헤더
///
/// ```bash.ignore
/// Authorization: Bearer {jwt_token}
/// ```
///
/// # 응답
///
/// ## 유효한 토큰
/// ```json
/// {
///   "valid": true,
///   "user_id": "507f1f77bcf86cd799439011",
///   "email": "user@example.com",
///   "auth_provider": "google"
/// }
/// ```
///
/// ## 무효한 토큰
/// ```json
/// {
///   "error": "authentication_error",
///   "message": "Invalid or expired token"
/// }
/// ```
///
/// # 사용 사례
///
/// - SPA에서 페이지 로드 시 토큰 유효성 확인
/// - 마이크로서비스 간 토큰 검증
/// - 토큰 갱신 전 유효성 확인
/// - 보안이 중요한 작업 전 재검증
///
/// # 보안 고려사항
///
/// - 토큰 만료 시간 엄격 확인
/// - 토큰 서명 검증
/// - 블랙리스트 토큰 확인 (향후 구현)
/// - Rate limiting 적용 권장
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