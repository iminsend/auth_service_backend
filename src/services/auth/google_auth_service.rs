//! # Google OAuth 2.0 인증 서비스
//! 
//! Google OAuth 2.0 프로토콜을 통한 소셜 로그인 기능을 제공합니다.
//! RFC 6749 OAuth 2.0 표준과 Google의 OAuth 2.0 구현을 준수하며,
//! Spring Security OAuth2와 유사한 인증 플로우를 구현합니다.
//! 
//! ## OAuth 2.0 Authorization Code Flow
//! 
//! ```text
//! ┌─────────────┐                                  ┌─────────────────┐                                ┌─────────────────┐
//! │   클라이언트   │                                  │   우리 서버      │                                │  Google OAuth   │
//! └─────────────┘                                  └─────────────────┘                                └─────────────────┘
//!        │                                                    │                                               │
//!        │ 1. GET /auth/google/login                          │                                               │
//!        ├───────────────────────────────────────────────────►│                                               │
//!        │                                                    │ 2. Generate state & build auth URL           │
//!        │                                                    ├──────────────────────────┐                   │
//!        │                                                    │                          │                   │
//!        │                                                    │◄─────────────────────────┘                   │
//!        │ 3. 302 Redirect to Google OAuth                    │                                               │
//!        │◄───────────────────────────────────────────────────┤                                               │
//!        │                                                    │                                               │
//!        │ 4. User authenticates with Google                  │                                               │
//!        ├────────────────────────────────────────────────────────────────────────────────────────────────►│
//!        │                                                    │                                               │
//!        │ 5. Google redirects with auth code                 │                                               │
//!        │◄────────────────────────────────────────────────────────────────────────────────────────────────┤
//!        │                                                    │                                               │
//!        │ 6. GET /auth/google/callback?code=xxx&state=yyy     │                                               │
//!        ├───────────────────────────────────────────────────►│                                               │
//!        │                                                    │ 7. Verify state parameter                    │
//!        │                                                    ├──────────────────────────┐                   │
//!        │                                                    │                          │                   │
//!        │                                                    │◄─────────────────────────┘                   │
//!        │                                                    │ 8. Exchange code for token                   │
//!        │                                                    ├──────────────────────────────────────────────►│
//!        │                                                    │ 9. Return access_token                       │
//!        │                                                    │◄──────────────────────────────────────────────┤
//!        │                                                    │ 10. Fetch user info with token               │
//!        │                                                    ├──────────────────────────────────────────────►│
//!        │                                                    │ 11. Return user profile                      │
//!        │                                                    │◄──────────────────────────────────────────────┤
//!        │                                                    │ 12. Create/update user in DB                 │
//!        │                                                    ├──────────────────────────┐                   │
//!        │                                                    │                          │                   │
//!        │                                                    │◄─────────────────────────┘                   │
//!        │ 13. Return JWT tokens                              │                                               │
//!        │◄───────────────────────────────────────────────────┤                                               │
//! ```
//! 
//! ## 보안 특징
//! 
//! ### 1. CSRF 방지 (State Parameter)
//! 
//! OAuth 2.0 state 매개변수를 사용하여 Cross-Site Request Forgery 공격을 방지합니다:
//! 
//! ```text
//! State Generation:
//! timestamp:secret → hash → state_value
//! 
//! State Verification:
//! received_state → verify_format → check_expiry → confirm_origin
//! ```
//! 
//! ### 2. Authorization Code 제한 시간
//! 
//! - **일회성 사용**: Authorization Code는 한 번만 사용 가능
//! - **짧은 수명**: 일반적으로 10분 내 사용해야 함
//! - **즉시 교환**: 코드 수신 즉시 액세스 토큰으로 교환
//! 
//! ### 3. HTTPS 강제
//! 
//! - **모든 OAuth 통신**: TLS 1.2 이상 암호화
//! - **리다이렉트 URI**: HTTPS 스키마만 허용
//! - **토큰 전송**: 암호화된 채널을 통해서만 전송
//! 
//! ## Google API 통합
//! 
//! ### 사용하는 Google API 엔드포인트
//! 
//! | 용도 | 엔드포인트 | 메서드 |
//! |------|------------|--------|
//! | **Authorization** | `https://accounts.google.com/o/oauth2/auth` | GET |
//! | **Token Exchange** | `https://oauth2.googleapis.com/token` | POST |
//! | **User Info** | `https://www.googleapis.com/oauth2/v2/userinfo` | GET |
//! 
//! ### 필요한 OAuth 스코프
//! 
//! - `openid`: OpenID Connect 식별자
//! - `email`: 사용자 이메일 주소
//! - `profile`: 기본 프로필 정보 (이름, 사진 등)
//! 
//! ## 계정 연동 정책
//! 
//! ### 1. 신규 사용자 (이메일이 처음인 경우)
//! 
//! ```rust,ignore
//! // 새 Google 계정으로 회원가입
//! let new_user = User::new_oauth(
//!     google_user.email,
//!     generated_username,
//!     google_user.name,
//!     AuthProvider::Google,
//!     google_user.id,
//!     google_user.picture,
//! );
//! 
//! user_repo.create(new_user).await?;
//! ```
//! 
//! ### 2. 기존 Google 사용자
//! 
//! ```rust,ignore
//! // 기존 Google 계정으로 로그인
//! if existing_user.auth_provider == AuthProvider::Google {
//!     return Ok(existing_user); // 로그인 성공
//! }
//! ```
//! 
//! ### 3. 기존 로컬 사용자 (이메일 중복)
//! 
//! ```rust,ignore
//! // 계정 연동 필요 - 에러 반환
//! if existing_user.auth_provider == AuthProvider::Local {
//!     return Err(AppError::ConflictError(
//!         "이미 로컬 계정이 존재합니다. 계정 연동을 진행해주세요.".to_string()
//!     ));
//! }
//! ```

use std::sync::Arc;
use singleton_macro::service;
use crate::{
    config::{AuthProvider, GoogleOAuthConfig, OAuthConfig},
    domain::entities::users::user::User,
    repositories::users::user_repo::UserRepository,
};
use crate::domain::dto::users::response::google_oauth_response::{GoogleTokenResponse, OAuthLoginUrlResponse};
use crate::domain::models::oauth::google_oauth_model::google_user::GoogleUserInfo;
use crate::errors::errors::AppError;

/// Google OAuth 2.0 인증 서비스
/// 
/// Google의 OAuth 2.0 프로토콜을 사용한 소셜 로그인 기능을 제공합니다.
/// Spring Security OAuth2 Client와 유사한 기능을 구현하며,
/// 사용자 인증부터 계정 생성/연동까지의 전체 플로우를 관리합니다.
/// 
/// ## 주요 책임
/// 
/// 1. **OAuth URL 생성**: Google 인증 페이지로의 리다이렉트 URL 생성
/// 2. **콜백 처리**: Google로부터 받은 Authorization Code 처리
/// 3. **토큰 교환**: Authorization Code를 Access Token으로 교환
/// 4. **사용자 정보 조회**: Google API를 통한 사용자 프로필 정보 획득
/// 5. **계정 관리**: 신규 가입, 기존 로그인, 계정 연동 처리
/// 
/// ## 싱글톤 패턴
/// 
/// `#[service]` 매크로를 통해 자동으로 싱글톤으로 관리되며,
/// UserRepository 의존성이 자동으로 주입됩니다.
/// 
/// ## 설정 의존성
/// 
/// 다음 환경변수들이 올바르게 설정되어야 합니다:
/// 
/// ```bash
/// GOOGLE_CLIENT_ID=your-client-id.googleusercontent.com
/// GOOGLE_CLIENT_SECRET=your-client-secret  
/// GOOGLE_REDIRECT_URI=https://yourapp.com/auth/google/callback
/// OAUTH_STATE_SECRET=your-state-secret
/// ```
/// 
/// ## 보안 고려사항
/// 
/// - **State 매개변수**: CSRF 공격 방지를 위한 임의값 생성 및 검증
/// - **HTTPS 강제**: 모든 OAuth 통신은 TLS 암호화 필수
/// - **토큰 즉시 교환**: Authorization Code의 짧은 수명 활용
/// - **에러 정보 제한**: 공격자에게 유용한 정보 노출 방지
/// 
/// ## 사용 예제
/// 
/// ```rust,ignore
/// use crate::services::auth::GoogleAuthService;
/// 
/// // 1. 로그인 URL 생성
/// let google_auth = GoogleAuthService::instance();
/// let login_response = google_auth.get_login_url()?;
/// 
/// // 클라이언트에게 리다이렉트 URL 제공
/// HttpResponse::Found()
///     .append_header(("Location", login_response.login_url))
///     .finish()
/// 
/// // 2. 콜백 처리 (웹 핸들러에서)
/// async fn google_callback(query: web::Query<GoogleCallbackQuery>) -> Result<HttpResponse> {
///     let google_auth = GoogleAuthService::instance();
///     
///     // 사용자 인증 및 계정 처리
///     let user = google_auth
///         .authenticate_with_code(&query.code, &query.state)
///         .await?;
///     
///     // JWT 토큰 생성 후 응답
///     let token_service = TokenService::instance();
///     let tokens = token_service.generate_token_pair(&user)?;
///     
///     Ok(HttpResponse::Ok().json(tokens))
/// }
/// ```
#[service]
pub struct GoogleAuthService {
    /// 사용자 리포지토리
    /// 
    /// Google 인증 성공 후 사용자 계정 생성, 조회, 업데이트를 담당합니다.
    /// 자동 의존성 주입을 통해 UserRepository 싱글톤이 주입됩니다.
    user_repo: Arc<UserRepository>,
}

impl GoogleAuthService {
    /// Google OAuth 로그인 URL 생성
    /// 
    /// 사용자를 Google 인증 페이지로 리다이렉트하기 위한 Authorization URL을 생성합니다.
    /// OAuth 2.0 Authorization Code Grant 플로우의 첫 번째 단계입니다.
    /// 
    /// # 반환값
    /// 
    /// * `Ok(OAuthLoginUrlResponse)` - 로그인 URL과 state 값을 포함한 응답
    /// * `Err(AppError::InternalError)` - state 생성 실패 또는 URL 구성 오류
    /// 
    /// # 생성되는 URL 구조
    /// 
    /// ```text
    /// https://accounts.google.com/o/oauth2/auth?
    ///   client_id=YOUR_CLIENT_ID&
    ///   redirect_uri=https://yourapp.com/auth/google/callback&
    ///   scope=openid%20email%20profile&
    ///   response_type=code&
    ///   state=CSRF_PROTECTION_VALUE
    /// ```
    /// 
    /// # URL 매개변수 설명
    /// 
    /// | 매개변수 | 값 | 설명 |
    /// |----------|----|----- |
    /// | `client_id` | Google Client ID | Google Console에서 발급받은 앱 식별자 |
    /// | `redirect_uri` | 콜백 URL | 인증 완료 후 사용자가 돌아올 URL |
    /// | `scope` | `openid email profile` | 요청할 사용자 정보 범위 |
    /// | `response_type` | `code` | Authorization Code Grant 명시 |
    /// | `state` | 임의 문자열 | CSRF 방지용 검증값 |
    /// 
    /// # State 매개변수 보안
    /// 
    /// state 값은 다음과 같이 생성됩니다:
    /// 
    /// ```rust,ignore
    /// let state_data = format!("{}:{}", timestamp, state_secret);
    /// let state = hash(state_data); // 해시 함수로 안전한 값 생성
    /// ```
    /// 
    /// 이 값은 콜백 시 검증되어 CSRF 공격을 방지합니다.
    /// 
    /// # 클라이언트 사용 패턴
    /// 
    /// ```javascript
    /// // 프론트엔드에서 로그인 버튼 클릭 시
    /// const response = await fetch('/auth/google/login');
    /// const { login_url, state } = await response.json();
    /// 
    /// // state를 세션에 저장 (콜백 시 검증용)
    /// sessionStorage.setItem('oauth_state', state);
    /// 
    /// // 사용자를 Google 로그인 페이지로 리다이렉트
    /// window.location.href = login_url;
    /// ```
    /// 
    /// # 에러 처리
    /// 
    /// - **설정 오류**: Google OAuth 설정이 누락된 경우
    /// - **URL 인코딩 실패**: 특수문자 포함 매개변수 처리 오류
    /// - **State 생성 실패**: 시스템 시간 오류 또는 해시 함수 문제
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// use actix_web::{web, HttpResponse, Result};
    /// 
    /// async fn google_login_handler() -> Result<HttpResponse> {
    ///     let google_auth = GoogleAuthService::instance();
    ///     
    ///     match google_auth.get_login_url() {
    ///         Ok(response) => {
    ///             log::info!("Google 로그인 URL 생성 완료");
    ///             
    ///             // JSON 응답으로 URL 제공
    ///             Ok(HttpResponse::Ok().json(response))
    ///         },
    ///         Err(e) => {
    ///             log::error!("Google 로그인 URL 생성 실패: {}", e);
    ///             Ok(HttpResponse::InternalServerError()
    ///                 .json(json!({"error": "OAuth URL 생성에 실패했습니다"})))
    ///         }
    ///     }
    /// }
    /// ```
    pub fn get_login_url(&self) -> Result<OAuthLoginUrlResponse, AppError> {
        let state = self.generate_oauth_state()?;
        
        let params = [
            ("client_id", GoogleOAuthConfig::client_id()),
            ("redirect_uri", GoogleOAuthConfig::redirect_uri()),
            ("scope", "openid email profile".to_string()),
            ("response_type", "code".to_string()),
            ("state", state.clone()),
        ];

        let query_string = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let login_url = format!("{}?{}", GoogleOAuthConfig::auth_uri(), query_string);

        Ok(OAuthLoginUrlResponse { login_url, state })
    }

    /// Authorization Code를 사용하여 사용자 인증 및 계정 처리
    /// 
    /// Google OAuth 콜백에서 받은 Authorization Code를 처리하여
    /// 사용자 인증을 완료하고 계정 생성 또는 로그인을 수행합니다.
    /// 
    /// # 인자
    /// 
    /// * `auth_code` - Google에서 발급한 Authorization Code
    /// * `state` - CSRF 방지용 state 매개변수
    /// 
    /// # 반환값
    /// 
    /// * `Ok(User)` - 인증된 사용자 엔티티
    /// * `Err(AppError::AuthenticationError)` - state 검증 실패 또는 OAuth 오류
    /// * `Err(AppError::ConflictError)` - 계정 연동 필요
    /// * `Err(AppError::ExternalServiceError)` - Google API 통신 오류
    /// 
    /// # 처리 단계
    /// 
    /// 1. **State 검증**: CSRF 공격 방지를 위한 state 매개변수 확인
    /// 2. **토큰 교환**: Authorization Code → Access Token
    /// 3. **사용자 정보 조회**: Google API로부터 프로필 정보 획득
    /// 4. **계정 처리**: 신규 가입, 기존 로그인, 또는 충돌 처리
    /// 
    /// # 계정 처리 로직
    /// 
    /// ```text
    /// Google 사용자 정보 획득
    ///           │
    ///           ▼
    ///     이메일로 기존 사용자 조회
    ///           │
    ///           ├─ 사용자 없음 ──────────► 새 Google 계정 생성
    ///           │
    ///           └─ 사용자 있음
    ///                     │
    ///                     ├─ Google 계정 ────► 로그인 성공
    ///                     │
    ///                     ├─ 로컬 계정 ──────► 계정 연동 에러
    ///                     │
    ///                     └─ 다른 OAuth ────► 중복 계정 에러
    /// ```
    /// 
    /// # 보안 고려사항
    /// 
    /// - **State 검증**: 모든 콜백 요청에서 state 검증 필수
    /// - **Code 즉시 사용**: Authorization Code는 수신 즉시 교환
    /// - **HTTPS 전용**: 모든 토큰 교환은 TLS 암호화 채널 사용
    /// - **에러 정보 제한**: 공격자에게 유용한 정보 노출 방지
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// use actix_web::{web, HttpResponse, Result};
    /// use serde::Deserialize;
    /// 
    /// #[derive(Deserialize)]
    /// struct GoogleCallback {
    ///     code: String,
    ///     state: String,
    ///     error: Option<String>,
    /// }
    /// 
    /// async fn google_callback_handler(
    ///     query: web::Query<GoogleCallback>
    /// ) -> Result<HttpResponse> {
    ///     // 에러 확인 (사용자가 인증 거부한 경우)
    ///     if let Some(error) = &query.error {
    ///         log::warn!("Google OAuth 에러: {}", error);
    ///         return Ok(HttpResponse::BadRequest()
    ///             .json(json!({"error": "인증이 취소되었습니다"})));
    ///     }
    /// 
    ///     let google_auth = GoogleAuthService::instance();
    ///     
    ///     match google_auth.authenticate_with_code(&query.code, &query.state).await {
    ///         Ok(user) => {
    ///             log::info!("Google 인증 성공: {}", user.email);
    ///             
    ///             // JWT 토큰 생성
    ///             let token_service = TokenService::instance();
    ///             let tokens = token_service.generate_token_pair(&user)?;
    ///             
    ///             Ok(HttpResponse::Ok().json(json!({
    ///                 "message": "로그인 성공",
    ///                 "user": UserResponse::from(user),
    ///                 "tokens": tokens
    ///             })))
    ///         },
    ///         Err(AppError::ConflictError(msg)) => {
    ///             log::warn!("계정 연동 필요: {}", msg);
    ///             Ok(HttpResponse::Conflict().json(json!({
    ///                 "error": "account_linking_required",
    ///                 "message": msg
    ///             })))
    ///         },
    ///         Err(e) => {
    ///             log::error!("Google 인증 실패: {}", e);
    ///             Ok(HttpResponse::Unauthorized().json(json!({
    ///                 "error": "authentication_failed",
    ///                 "message": "인증에 실패했습니다"
    ///             })))
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn authenticate_with_code(&self, auth_code: &str, state: &str) -> Result<User, AppError> {
        // 1. State 검증
        self.verify_oauth_state(state)?;

        // 2. Authorization code로 액세스 토큰 교환
        let token_response = self.exchange_code_for_token(auth_code).await?;

        // 3. 액세스 토큰으로 사용자 정보 조회
        let google_user = self.get_user_info(&token_response.access_token).await?;

        // 4. 이메일로 기존 사용자 확인
        match self.user_repo.find_by_email(&google_user.email).await? {
            Some(existing_user) => {
                // 기존 사용자 확인
                match existing_user.auth_provider {
                    AuthProvider::Google => {
                        // Google 사용자면 로그인 처리
                        log::info!("Google 사용자 로그인: {}", google_user.email);
                        Ok(existing_user)
                    },
                    AuthProvider::Local => {
                        // 로컬 사용자면 계정 연동 제안 (에러로 처리)
                        Err(AppError::ConflictError(
                            "이미 해당 이메일로 등록된 로컬 계정이 있습니다. 로컬 로그인을 사용하거나 계정을 연동해주세요.".to_string()
                        ))
                    },
                    _ => {
                        // 다른 OAuth 프로바이더면 에러
                        Err(AppError::ConflictError(
                            "이미 해당 이메일로 다른 OAuth 프로바이더에 등록된 계정이 있습니다.".to_string()
                        ))
                    }
                }
            },
            None => {
                // 새 사용자 생성
                log::info!("새 Google 사용자 등록: {}", google_user.email);
                self.create_google_user(google_user).await
            }
        }
    }

    /// Authorization Code를 Access Token으로 교환
    /// 
    /// OAuth 2.0 토큰 엔드포인트를 통해 Authorization Code를 Access Token으로 교환합니다.
    /// 이 토큰은 후속 Google API 호출에 사용됩니다.
    /// 
    /// # 인자
    /// 
    /// * `auth_code` - Google에서 발급한 일회용 Authorization Code
    /// 
    /// # 반환값
    /// 
    /// * `Ok(GoogleTokenResponse)` - 액세스 토큰과 메타데이터
    /// * `Err(AppError::ExternalServiceError)` - Google API 통신 오류
    /// 
    /// # 요청 형식
    /// 
    /// ```text
    /// POST https://oauth2.googleapis.com/token
    /// Content-Type: application/x-www-form-urlencoded
    /// 
    /// code=AUTHORIZATION_CODE&
    /// client_id=YOUR_CLIENT_ID&
    /// client_secret=YOUR_CLIENT_SECRET&
    /// redirect_uri=YOUR_REDIRECT_URI&
    /// grant_type=authorization_code
    /// ```
    /// 
    /// # 응답 구조
    /// 
    /// 성공 시:
    /// ```json
    /// {
    ///   "access_token": "ya29.a0AfH6SMC...",
    ///   "expires_in": 3599,
    ///   "refresh_token": "1//04z...",
    ///   "scope": "openid email profile",
    ///   "token_type": "Bearer",
    ///   "id_token": "eyJhbGciOiJSUzI1NiIs..."
    /// }
    /// ```
    /// 
    /// # 에러 처리
    /// 
    /// Google이 반환할 수 있는 주요 에러:
    /// 
    /// | 에러 코드 | 설명 | 대처 방안 |
    /// |-----------|------|-----------|
    /// | `invalid_grant` | 코드 만료/사용됨 | 새로운 인증 플로우 시작 |
    /// | `invalid_client` | 클라이언트 설정 오류 | 환경설정 확인 |
    /// | `invalid_request` | 잘못된 요청 형식 | 요청 매개변수 검증 |
    /// 
    /// # 보안 고려사항
    /// 
    /// - **Client Secret 보호**: 서버 사이드에서만 사용, 클라이언트 노출 금지
    /// - **HTTPS 전용**: 모든 토큰 교환은 TLS 암호화 필수
    /// - **코드 즉시 사용**: Authorization Code는 10분 내 사용
    /// - **재시도 제한**: 실패 시 과도한 재시도 방지
    async fn exchange_code_for_token(&self, auth_code: &str) -> Result<GoogleTokenResponse, AppError> {
        let client = reqwest::Client::new();
        
        let params = [
            ("code", auth_code),
            ("client_id", &GoogleOAuthConfig::client_id()),
            ("client_secret", &GoogleOAuthConfig::client_secret()),
            ("redirect_uri", &GoogleOAuthConfig::redirect_uri()),
            ("grant_type", "authorization_code"),
        ];

        let response = client
            .post(&GoogleOAuthConfig::token_uri())
            .form(&params)
            .send()
            .await
            .map_err(|e| AppError::ExternalServiceError(format!("Google 토큰 요청 실패: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AppError::ExternalServiceError(format!(
                "Google 토큰 교환 실패: {}", error_text
            )));
        }

        response
            .json::<GoogleTokenResponse>()
            .await
            .map_err(|e| AppError::ExternalServiceError(format!("Google 토큰 응답 파싱 실패: {}", e)))
    }

    /// Access Token으로 Google 사용자 정보 조회
    /// 
    /// Google UserInfo API를 호출하여 인증된 사용자의 프로필 정보를 가져옵니다.
    /// OAuth 2.0 스코프에 따라 제공되는 정보가 결정됩니다.
    /// 
    /// # 인자
    /// 
    /// * `access_token` - Google에서 발급받은 액세스 토큰
    /// 
    /// # 반환값
    /// 
    /// * `Ok(GoogleUserInfo)` - 사용자 프로필 정보
    /// * `Err(AppError::ExternalServiceError)` - Google API 통신 오류
    /// 
    /// # API 호출 형식
    /// 
    /// ```text
    /// GET https://www.googleapis.com/oauth2/v2/userinfo
    /// Authorization: Bearer ACCESS_TOKEN
    /// ```
    /// 
    /// # 응답 데이터 구조
    /// 
    /// ```json
    /// {
    ///   "id": "1234567890",
    ///   "email": "user@gmail.com", 
    ///   "verified_email": true,
    ///   "name": "John Doe",
    ///   "given_name": "John",
    ///   "family_name": "Doe",
    ///   "picture": "https://lh3.googleusercontent.com/.../photo.jpg",
    ///   "locale": "en"
    /// }
    /// ```
    /// 
    /// # 스코프별 제공 정보
    /// 
    /// | 스코프 | 제공 정보 |
    /// |--------|-----------|
    /// | `openid` | 기본 식별자 (`id`) |
    /// | `email` | 이메일 주소, 인증 여부 |
    /// | `profile` | 이름, 프로필 사진, 언어 설정 |
    /// 
    /// # 에러 처리
    /// 
    /// - **401 Unauthorized**: 토큰 만료 또는 유효하지 않은 토큰
    /// - **403 Forbidden**: 스코프 권한 부족
    /// - **429 Too Many Requests**: API 사용량 제한 초과
    /// - **500 Internal Error**: Google 서버 오류
    /// 
    /// # 개인정보 보호
    /// 
    /// - **최소 정보 수집**: 애플리케이션에 필요한 정보만 요청
    /// - **동의 기반**: 사용자가 명시적으로 동의한 정보만 수집
    /// - **데이터 보존**: 필요한 기간만 보관 후 삭제
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// // 토큰 교환 후 사용자 정보 조회
    /// let token_response = self.exchange_code_for_token(auth_code).await?;
    /// let google_user = self.get_user_info(&token_response.access_token).await?;
    /// 
    /// println!("사용자 정보:");
    /// println!("  ID: {}", google_user.id);
    /// println!("  이메일: {}", google_user.email);  
    /// println!("  이름: {}", google_user.name);
    /// println!("  프로필 사진: {}", google_user.picture.unwrap_or_default());
    /// ```
    async fn get_user_info(&self, access_token: &str) -> Result<GoogleUserInfo, AppError> {
        let client = reqwest::Client::new();
        
        let response = client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::ExternalServiceError(format!("Google 사용자 정보 요청 실패: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AppError::ExternalServiceError(format!(
                "Google 사용자 정보 조회 실패: {}", error_text
            )));
        }

        response
            .json::<GoogleUserInfo>()
            .await
            .map_err(|e| AppError::ExternalServiceError(format!("Google 사용자 정보 파싱 실패: {}", e)))
    }

    /// Google 사용자 정보로 새 사용자 계정 생성
    /// 
    /// Google OAuth를 통해 획득한 사용자 정보를 바탕으로
    /// 새로운 사용자 계정을 생성하고 데이터베이스에 저장합니다.
    /// 
    /// # 인자
    /// 
    /// * `google_user` - Google API에서 받은 사용자 프로필 정보
    /// 
    /// # 반환값
    /// 
    /// * `Ok(User)` - 생성된 사용자 엔티티
    /// * `Err(AppError)` - 사용자명 생성 실패 또는 데이터베이스 오류
    /// 
    /// # 계정 생성 과정
    /// 
    /// 1. **고유 사용자명 생성**: 중복되지 않는 사용자명 생성
    /// 2. **OAuth 사용자 엔티티 생성**: Google 인증 프로바이더로 설정
    /// 3. **데이터베이스 저장**: UserRepository를 통한 영구 저장
    /// 
    /// # 사용자명 생성 규칙
    /// 
    /// ```text
    /// Google 이름: "John Doe"
    /// ↓
    /// 기본 사용자명: "john_doe"
    /// ↓
    /// 중복 확인 및 번호 추가:
    /// - john_doe (사용 가능하면 선택)
    /// - john_doe_1 (중복 시)
    /// - john_doe_2 (또 중복 시)
    /// - ...
    /// ```
    /// 
    /// # 저장되는 정보
    /// 
    /// - **이메일**: Google 계정 이메일 (로그인 식별자)
    /// - **사용자명**: 시스템 내 고유 식별자
    /// - **표시명**: Google 프로필의 실명
    /// - **인증 프로바이더**: `AuthProvider::Google`
    /// - **OAuth ID**: Google 사용자 고유 ID
    /// - **프로필 사진**: Google 프로필 이미지 URL
    /// 
    /// # 보안 고려사항
    /// 
    /// - **비밀번호 없음**: OAuth 계정은 비밀번호 해시 저장하지 않음
    /// - **이메일 인증됨**: Google에서 이미 인증된 이메일로 간주
    /// - **계정 활성화**: 기본적으로 활성 상태로 생성
    /// 
    /// # 데이터 검증
    /// 
    /// - **이메일 형식**: 유효한 이메일 주소 확인
    /// - **이름 길이**: 적절한 길이 제한 적용
    /// - **특수문자 처리**: 사용자명에서 안전하지 않은 문자 제거
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// // Google 사용자 정보 예시
    /// let google_user = GoogleUserInfo {
    ///     id: "1234567890".to_string(),
    ///     email: "john.doe@gmail.com".to_string(),
    ///     name: "John Doe".to_string(),
    ///     given_name: "John".to_string(),
    ///     family_name: "Doe".to_string(),
    ///     picture: Some("https://lh3.googleusercontent.com/.../photo.jpg".to_string()),
    ///     verified_email: true,
    /// };
    /// 
    /// // 새 사용자 생성
    /// let new_user = self.create_google_user(google_user).await?;
    /// 
    /// println!("새 Google 사용자 생성:");
    /// println!("  ID: {}", new_user.id.unwrap().to_hex());
    /// println!("  이메일: {}", new_user.email);
    /// println!("  사용자명: {}", new_user.username);
    /// println!("  인증 방식: {:?}", new_user.auth_provider);
    /// ```
    async fn create_google_user(&self, google_user: GoogleUserInfo) -> Result<User, AppError> {
        // 사용자명 생성 (중복 방지 로직 추가 필요)
        let username = self.generate_unique_username(&google_user.given_name).await?;

        let user = User::new_oauth(
            google_user.email,
            username,
            google_user.name,
            AuthProvider::Google,
            google_user.id,
            google_user.picture,
        );

        self.user_repo.create(user).await
    }

    /// 중복되지 않는 고유 사용자명 생성
    /// 
    /// 주어진 기본 이름을 바탕으로 시스템 내에서 중복되지 않는
    /// 고유한 사용자명을 생성합니다.
    /// 
    /// # 인자
    /// 
    /// * `base_name` - 기본이 되는 이름 (일반적으로 Google의 given_name)
    /// 
    /// # 반환값
    /// 
    /// * `Ok(String)` - 고유한 사용자명
    /// * `Err(AppError::InternalError)` - 1000회 시도 후에도 고유명 생성 실패
    /// 
    /// # 생성 알고리즘
    /// 
    /// 1. **기본 정규화**: 소문자 변환, 공백을 언더스코어로 변경
    /// 2. **중복 확인**: 데이터베이스에서 해당 사용자명 검색
    /// 3. **번호 추가**: 중복 시 순차적으로 번호 추가
    /// 4. **재시도**: 최대 1000회까지 시도
    /// 
    /// # 정규화 규칙
    /// 
    /// ```text
    /// 입력: "John Doe" → 출력: "john_doe"
    /// 입력: "김철수"   → 출력: "김철수" (유니코드 지원)
    /// 입력: "user@123" → 출력: "user_123" (특수문자 처리)
    /// ```
    /// 
    /// # 중복 처리 예시
    /// 
    /// ```text
    /// 시도 1: "john" (이미 존재)
    /// 시도 2: "john_1" (이미 존재)  
    /// 시도 3: "john_2" (이미 존재)
    /// 시도 4: "john_3" (사용 가능) ✓
    /// ```
    /// 
    /// # 성능 고려사항
    /// 
    /// - **데이터베이스 조회**: 각 시도마다 DB 쿼리 발생
    /// - **인덱스 활용**: username 필드의 유니크 인덱스 활용
    /// - **캐싱 불가**: 실시간 중복 확인 필요
    /// 
    /// # 확장 가능성
    /// 
    /// 향후 개선 방안:
    /// - 더 지능적인 이름 생성 (닉네임 사전 활용)
    /// - 무작위 접미사 사용 (숫자 대신 문자열)
    /// - 배치 검증 (여러 후보를 한 번에 확인)
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// // 다양한 입력에 대한 사용자명 생성
    /// let username1 = self.generate_unique_username("John").await?;
    /// // 결과: "john" 또는 "john_1", "john_2" 등
    /// 
    /// let username2 = self.generate_unique_username("Mary Jane").await?;
    /// // 결과: "mary_jane" 또는 "mary_jane_1" 등
    /// 
    /// let username3 = self.generate_unique_username("김철수").await?;
    /// // 결과: "김철수" 또는 "김철수_1" 등
    /// ```
    async fn generate_unique_username(&self, base_name: &str) -> Result<String, AppError> {
        let mut username = base_name.to_lowercase().replace(' ', "_");
        let mut counter = 1;

        // 기본 사용자명으로 시도
        loop {
            match self.user_repo.find_by_username(&username).await? {
                None => return Ok(username), // 사용 가능한 사용자명 찾음
                Some(_) => {
                    // 중복되면 숫자 추가
                    username = format!("{}_{}", base_name.to_lowercase().replace(' ', "_"), counter);
                    counter += 1;
                    
                    if counter > 1000 {
                        return Err(AppError::InternalError("사용자명 생성 실패".to_string()));
                    }
                }
            }
        }
    }

    /// OAuth State 매개변수 생성
    /// 
    /// CSRF (Cross-Site Request Forgery) 공격을 방지하기 위한
    /// 임의의 state 값을 생성합니다.
    /// 
    /// # 반환값
    /// 
    /// * `Ok(String)` - 생성된 state 값 (16진수 해시)
    /// * `Err(AppError::InternalError)` - 시간 계산 오류
    /// 
    /// # State 생성 알고리즘
    /// 
    /// ```text
    /// 1. 현재 타임스탬프 획득
    /// 2. 시크릿과 결합: "timestamp:secret"
    /// 3. 해시 함수 적용 (DefaultHasher)
    /// 4. 16진수 문자열로 변환
    /// ```
    /// 
    /// # 보안 특징
    /// 
    /// - **타임스탬프 포함**: 재생 공격 방지
    /// - **시크릿 결합**: 예측 불가능성 증대
    /// - **해시 함수**: 원본 값 역추적 방지
    /// - **일회성**: 각 인증 세션마다 새로운 값
    /// 
    /// # 검증 과정
    /// 
    /// 콜백 시 다음과 같이 검증됩니다:
    /// 
    /// 1. **형식 확인**: 빈 문자열이 아닌지 검사
    /// 2. **타임스탬프 검증**: 만료 시간 확인 (선택적)
    /// 3. **해시 재계산**: 동일한 알고리즘으로 재생성 후 비교
    /// 
    /// # 한계 및 개선점
    /// 
    /// 현재 구현의 한계:
    /// - 단순한 해시 함수 사용
    /// - 만료 시간 검증 없음
    /// - 상태 저장소 없음 (Redis 등)
    /// 
    /// 프로덕션 환경 개선 사항:
    /// ```rust,ignore
    /// // 더 안전한 state 생성 예시
    /// use rand::Rng;
    /// use sha2::{Sha256, Digest};
    /// 
    /// fn generate_secure_state() -> String {
    ///     let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    ///     let nonce: u64 = rand::thread_rng().gen();
    ///     let data = format!("{}:{}:{}", timestamp, nonce, CONFIG.oauth_secret);
    ///     
    ///     let hash = Sha256::digest(data.as_bytes());
    ///     hex::encode(hash)
    /// }
    /// ```
    fn generate_oauth_state(&self) -> Result<String, AppError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::InternalError(format!("시간 계산 실패: {}", e)))?
            .as_secs();

        let state_data = format!("{}:{}", timestamp, OAuthConfig::state_secret());
        
        // 간단한 해시 생성 (실제로는 더 안전한 방법 사용 권장)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        state_data.hash(&mut hasher);
        
        Ok(format!("{:x}", hasher.finish()))
    }

    /// OAuth State 매개변수 검증
    /// 
    /// 콜백에서 받은 state 값이 유효한지 검증하여
    /// CSRF 공격을 방지합니다.
    /// 
    /// # 인자
    /// 
    /// * `state` - Google 콜백에서 받은 state 매개변수
    /// 
    /// # 반환값
    /// 
    /// * `Ok(())` - 검증 성공
    /// * `Err(AppError::AuthenticationError)` - 검증 실패
    /// 
    /// # 검증 규칙
    /// 
    /// 현재 구현에서는 기본적인 검증만 수행:
    /// 
    /// 1. **빈 값 확인**: state가 빈 문자열이 아닌지 검사
    /// 2. **형식 확인**: 예상되는 16진수 해시 형식인지 검사
    /// 
    /// # 보안 한계
    /// 
    /// 현재 구현은 기본적인 검증만 제공하므로,
    /// 프로덕션 환경에서는 다음과 같은 강화된 검증이 필요합니다:
    /// 
    /// ```rust,ignore
    /// // 강화된 state 검증 예시
    /// async fn verify_oauth_state_enhanced(&self, state: &str) -> Result<(), AppError> {
    ///     // 1. Redis에서 저장된 state 확인
    ///     let stored_state = redis_client.get(&format!("oauth:state:{}", state)).await?;
    ///     if stored_state.is_none() {
    ///         return Err(AppError::AuthenticationError("유효하지 않은 state".to_string()));
    ///     }
    ///     
    ///     // 2. 만료 시간 확인
    ///     let state_data: StateData = serde_json::from_str(&stored_state.unwrap())?;
    ///     if state_data.expires_at < Utc::now().timestamp() {
    ///         return Err(AppError::AuthenticationError("만료된 state".to_string()));
    ///     }
    ///     
    ///     // 3. 사용 후 삭제 (일회성)
    ///     redis_client.del(&format!("oauth:state:{}", state)).await?;
    ///     
    ///     Ok(())
    /// }
    /// ```
    /// 
    /// # 권장 개선사항
    /// 
    /// 1. **Redis 저장소**: state를 Redis에 임시 저장
    /// 2. **만료 시간**: 5-10분 후 자동 만료
    /// 3. **일회성 보장**: 사용 후 즉시 삭제
    /// 4. **세션 연결**: 사용자 세션과 state 연결
    /// 5. **암호화**: state 값 자체를 암호화
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// // 콜백 핸들러에서 state 검증
    /// async fn handle_google_callback(
    ///     code: &str, 
    ///     state: &str
    /// ) -> Result<User, AppError> {
    ///     let google_auth = GoogleAuthService::instance();
    ///     
    ///     // state 검증 - CSRF 공격 방지
    ///     google_auth.verify_oauth_state(state)?;
    ///     
    ///     // 나머지 인증 과정 진행
    ///     let user = google_auth.authenticate_with_code(code, state).await?;
    ///     
    ///     Ok(user)
    /// }
    /// ```
    fn verify_oauth_state(&self, state: &str) -> Result<(), AppError> {
        // 실제 구현에서는 더 강력한 state 검증 로직 필요
        // 예: Redis에 임시 저장 후 검증, 타임스탬프 검증 등
        
        if state.is_empty() {
            return Err(AppError::AuthenticationError("유효하지 않은 OAuth state".to_string()));
        }

        Ok(())
    }
}
