//! # Authentication Configuration Module
//! 
//! OAuth 프로바이더, JWT 토큰, 세션 관리 등 인증 관련 설정을 관리하는 모듈입니다.
//! Spring Security의 OAuth2 및 JWT 설정과 유사한 역할을 수행하며,
//! 다양한 인증 방식을 지원합니다.
//!
//! ## 지원하는 인증 방식
//!
//! 1. **로컬 인증**: 이메일/패스워드 기반 전통적인 인증
//! 2. **Google OAuth 2.0**: Google 계정을 통한 소셜 로그인
//! 3. **JWT 토큰**: Stateless 인증을 위한 JSON Web Token
//! 4. **확장 가능한 OAuth**: GitHub, Facebook 등 추가 프로바이더 지원 준비
//!
//! ## Spring Security 와의 비교
//!
//! | Spring Security | 이 모듈 |
//! |-----------------|---------|
//! | `@EnableOAuth2Login` | `GoogleOAuthConfig` |
//! | `jwt.secret` | `JwtConfig::secret()` |
//! | `oauth2.client.registration.google` | `GoogleOAuthConfig` |
//! | `spring.security.oauth2.client.provider` | `AuthProvider` |
//!
//! ## 필수 환경 변수 설정
//!
//! ### Google OAuth 설정
//! ```bash
//! export GOOGLE_CLIENT_ID="your-google-client-id"
//! export GOOGLE_CLIENT_SECRET="your-google-client-secret"
//! export GOOGLE_REDIRECT_URI="http://localhost:8080/auth/google/callback"
//! export GOOGLE_PROJECT_ID="your-google-project-id"
//! ```
//!
//! ### JWT 토큰 설정
//! ```bash
//! export JWT_SECRET="your-super-secret-jwt-key"
//! export JWT_EXPIRATION_HOURS="24"
//! export JWT_REFRESH_EXPIRATION_DAYS="7"
//! ```
//!
//! ### OAuth 보안 설정
//! ```bash
//! export OAUTH_STATE_SECRET="your-oauth-state-secret"
//! export OAUTH_SESSION_TIMEOUT_MINUTES="10"
//! ```
//!
//! ## 사용 예제
//!
//! ```rust,ignore
//! use crate::config::{GoogleOAuthConfig, JwtConfig, AuthProvider};
//!
//! // Google OAuth 설정 사용
//! let client_id = GoogleOAuthConfig::client_id();
//! let auth_uri = GoogleOAuthConfig::auth_uri();
//!
//! // JWT 토큰 생성 설정
//! let secret = JwtConfig::secret();
//! let expiration = JwtConfig::expiration_hours();
//!
//! // 인증 프로바이더 처리
//! let provider = AuthProvider::from_str("google")?;
//! ```

use std::env;

/// Google OAuth 2.0 설정을 관리하는 구조체
///
/// Google Cloud Console 에서 생성한 OAuth 2.0 클라이언트 정보를 관리합니다.
/// Spring Security의 `spring.security.oauth2.client.registration.google` 설정과 동일한 역할을 합니다.
///
/// ## Google Cloud Console 설정 가이드
///
/// 1. [Google Cloud Console](https://console.cloud.google.com/) 접속
/// 2. 프로젝트 생성 또는 선택
/// 3. APIs & Services > Credentials로 이동
/// 4. OAuth 2.0 Client IDs 생성
/// 5. 승인된 리디렉션 URI 추가: `http://localhost:8080/auth/google/callback`
///
/// ## 보안 고려사항
///
/// - `client_secret`은 절대 클라이언트 사이드에 노출되어서는 안 됩니다
/// - 프로덕션에서는 HTTPS redirect URI만 사용하세요
/// - JavaScript 오리진을 정확히 설정하여 CORS 정책을 준수하세요
pub struct GoogleOAuthConfig;

impl GoogleOAuthConfig {
    /// Google OAuth Client ID를 반환합니다.
    ///
    /// Google Cloud Console 에서 생성한 OAuth 2.0 클라이언트의 Client ID 입니다.
    /// 이 값은 클라이언트 사이드에서도 사용될 수 있으므로 공개되어도 안전합니다.
    ///
    /// # Panics
    ///
    /// `GOOGLE_CLIENT_ID` 환경 변수가 설정되지 않은 경우 패닉이 발생합니다.
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::GoogleOAuthConfig;
    ///
    /// let client_id = GoogleOAuthConfig::client_id();
    /// println!("Google Client ID: {}", client_id);
    /// ```
    ///
    /// # 환경 변수
    ///
    /// ```bash
    /// export GOOGLE_CLIENT_ID="123456789-abcdefghijklmnop.apps.googleusercontent.com"
    /// ```
    pub fn client_id() -> String {
        env::var("GOOGLE_CLIENT_ID")
            .expect("GOOGLE_CLIENT_ID must be set")
    }
    
    /// Google OAuth Client Secret을 반환합니다.
    ///
    /// 이 값은 절대 클라이언트 사이드에 노출되어서는 안 되는 민감한 정보입니다.
    /// 서버 사이드에서만 사용되며, 토큰 교환 시 사용됩니다.
    ///
    /// # Panics
    ///
    /// `GOOGLE_CLIENT_SECRET` 환경 변수가 설정되지 않은 경우 패닉이 발생합니다.
    ///
    /// # 보안 주의사항
    ///
    /// - 이 값을 로그에 출력하지 마세요
    /// - 클라이언트 사이드 코드에 하드코딩하지 마세요
    /// - 환경 변수나 보안 저장소에만 저장하세요
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::GoogleOAuthConfig;
    ///
    /// let client_secret = GoogleOAuthConfig::client_secret();
    /// // 로그에 출력하지 마세요!
    /// ```
    pub fn client_secret() -> String {
        env::var("GOOGLE_CLIENT_SECRET")
            .expect("GOOGLE_CLIENT_SECRET must be set")
    }
    
    /// OAuth 인증 완료 후 리디렉션될 URI를 반환합니다.
    ///
    /// Google OAuth 인증 프로세스가 완료된 후 사용자가 리디렉션될 URL 입니다.
    /// 이 URI는 Google Cloud Console의 승인된 리디렉션 URI 목록에 등록되어 있어야 합니다.
    ///
    /// # Panics
    ///
    /// `GOOGLE_REDIRECT_URI` 환경 변수가 설정되지 않은 경우 패닉이 발생합니다.
    ///
    /// # URI 형식
    ///
    /// - 개발: `http://localhost:8080/auth/google/callback`
    /// - 프로덕션: `https://yourdomain.com/auth/google/callback`
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::GoogleOAuthConfig;
    ///
    /// let redirect_uri = GoogleOAuthConfig::redirect_uri();
    /// println!("OAuth Redirect URI: {}", redirect_uri);
    /// ```
    pub fn redirect_uri() -> String {
        env::var("GOOGLE_REDIRECT_URI")
            .expect("GOOGLE_REDIRECT_URI must be set")
    }
    
    /// Google OAuth 인증 서버의 인증 엔드포인트 URI를 반환합니다.
    ///
    /// 사용자를 Google 로그인 페이지로 리디렉션할 때 사용되는 URL 입니다.
    /// 일반적으로 변경할 필요가 없으므로 기본값을 제공합니다.
    ///
    /// # 기본값
    ///
    /// `https://accounts.google.com/o/oauth2/auth`
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::GoogleOAuthConfig;
    ///
    /// let auth_uri = GoogleOAuthConfig::auth_uri();
    /// let auth_url = format!("{}?client_id={}&redirect_uri={}", 
    ///     auth_uri, 
    ///     GoogleOAuthConfig::client_id(),
    ///     GoogleOAuthConfig::redirect_uri()
    /// );
    /// ```
    pub fn auth_uri() -> String {
        env::var("GOOGLE_AUTH_URI")
            .unwrap_or_else(|_| "https://accounts.google.com/o/oauth2/auth".to_string())
    }
    
    /// Google OAuth 토큰 교환 엔드포인트 URI를 반환합니다.
    ///
    /// 인증 코드를 액세스 토큰으로 교환할 때 사용되는 URL 입니다.
    /// 일반적으로 변경할 필요가 없으므로 기본값을 제공합니다.
    ///
    /// # 기본값
    ///
    /// `https://oauth2.googleapis.com/token`
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::GoogleOAuthConfig;
    ///
    /// let token_uri = GoogleOAuthConfig::token_uri();
    /// // HTTP POST 요청으로 토큰 교환
    /// ```
    pub fn token_uri() -> String {
        env::var("GOOGLE_TOKEN_URI")
            .unwrap_or_else(|_| "https://oauth2.googleapis.com/token".to_string())
    }

    /// Google Cloud Project ID를 반환합니다.
    ///
    /// Google Cloud Console 에서 생성한 프로젝트의 고유 식별자입니다.
    /// 일부 Google API 호출 시 필요할 수 있습니다.
    ///
    /// # Panics
    ///
    /// `GOOGLE_PROJECT_ID` 환경 변수가 설정되지 않은 경우 패닉이 발생합니다.
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::GoogleOAuthConfig;
    ///
    /// let project_id = GoogleOAuthConfig::project_id();
    /// println!("Google Project ID: {}", project_id);
    /// ```
    pub fn project_id() -> String {
        env::var("GOOGLE_PROJECT_ID")
            .expect("GOOGLE_PROJECT_ID must be set")
    }

    /// JavaScript Origin을 반환합니다.
    ///
    /// CORS 정책을 위한 JavaScript 오리진 설정입니다.
    /// 클라이언트 사이드에서 Google OAuth를 사용할 때 필요합니다.
    ///
    /// # 기본값
    ///
    /// `http://localhost:8080` (개발 환경용)
    ///
    /// # 프로덕션 설정
    ///
    /// ```bash
    /// export GOOGLE_JAVASCRIPT_ORIGIN="https://yourdomain.com"
    /// ```
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::GoogleOAuthConfig;
    ///
    /// let origin = GoogleOAuthConfig::javascript_origin();
    /// println!("JavaScript Origin: {}", origin);
    /// ```
    pub fn javascript_origin() -> String {
        env::var("GOOGLE_JAVASCRIPT_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:8080".to_string())
    }
}

/// JSON Web Token (JWT) 관련 설정을 관리하는 구조체
///
/// Spring Security JWT의 설정과 유사한 역할을 수행하며,
/// 토큰 생성, 검증, 만료 시간 등을 관리합니다.
///
/// ## JWT 보안 모범 사례
///
/// 1. **강력한 비밀키 사용**: 최소 256비트 (32바이트) 랜덤 키
/// 2. **적절한 만료 시간**: 액세스 토큰은 짧게, 리프레시 토큰은 길게
/// 3. **토큰 저장소 보안**: 클라이언트에서 안전한 저장소 사용
/// 4. **토큰 순환**: 정기적인 토큰 갱신 정책
///
/// ## 권장 설정값
///
/// - **개발**: 액세스 토큰 24시간, 리프레시 토큰 7일
/// - **프로덕션**: 액세스 토큰 15분, 리프레시 토큰 30일
pub struct JwtConfig;

impl JwtConfig {
    /// JWT 서명에 사용할 비밀키를 반환합니다.
    ///
    /// 이 키는 JWT 토큰의 무결성을 보장하는 핵심 요소입니다.
    /// 강력한 암호화 키를 사용해야 하며, 절대 노출되어서는 안 됩니다.
    ///
    /// # 보안 요구사항
    ///
    /// - 최소 256비트 (32바이트) 길이
    /// - 암호학적으로 안전한 랜덤 생성
    /// - 환경별로 다른 키 사용
    /// - 정기적인 키 순환 (권장)
    ///
    /// # 기본값
    ///
    /// 환경 변수가 설정되지 않은 경우 "your-secret-key"를 사용하지만,
    /// 이는 개발 환경에서만 안전하며 프로덕션에서는 경고 로그가 출력됩니다.
    ///
    /// # 키 생성 예제
    ///
    /// ```bash
    /// # 안전한 JWT 키 생성
    /// openssl rand -base64 32
    /// # 또는
    /// python -c "import secrets; print(secrets.token_urlsafe(32))"
    /// ```
    ///
    /// # 환경 변수 설정
    ///
    /// ```bash
    /// export JWT_SECRET="your-super-secret-256-bit-key-generated-securely"
    /// ```
    pub fn secret() -> String {
        env::var("JWT_SECRET")
            .unwrap_or_else(|_| {
                log::warn!("JWT_SECRET not set, using default (not secure for production!)");
                "your-secret-key".to_string()
            })
    }
    
    /// JWT 액세스 토큰의 만료 시간을 시간 단위로 반환합니다.
    ///
    /// 액세스 토큰의 유효 기간을 결정합니다. 보안과 사용성의 균형을 고려하여 설정해야 합니다.
    ///
    /// # 권장 설정값
    ///
    /// - **개발**: 24시간 (편의성 우선)
    /// - **스테이징**: 1시간 (프로덕션 유사)
    /// - **프로덕션**: 15분 (보안 우선)
    ///
    /// # 기본값
    ///
    /// 24시간 (1440분)
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::JwtConfig;
    /// use chrono::{Utc, Duration};
    ///
    /// let expiration_hours = JwtConfig::expiration_hours();
    /// let expires_at = Utc::now() + Duration::hours(expiration_hours);
    /// ```
    ///
    /// # 환경 변수 설정
    ///
    /// ```bash
    /// # 1시간으로 설정
    /// export JWT_EXPIRATION_HOURS="1"
    /// ```
    pub fn expiration_hours() -> i64 {
        env::var("JWT_EXPIRATION_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse()
            .unwrap_or(24)
    }
    
    /// JWT 리프레시 토큰의 만료 시간을 일 단위로 반환합니다.
    ///
    /// 리프레시 토큰은 액세스 토큰을 갱신하는 데 사용되므로,
    /// 액세스 토큰보다 훨씬 긴 유효 기간을 가져야 합니다.
    ///
    /// # 권장 설정값
    ///
    /// - **개발**: 7일 (편의성)
    /// - **스테이징**: 30일 (프로덕션 유사)
    /// - **프로덕션**: 30일 (보안과 UX 균형)
    ///
    /// # 기본값
    ///
    /// 7일
    ///
    /// # 보안 고려사항
    ///
    /// - 리프레시 토큰이 탈취되면 장기간 악용 가능
    /// - 토큰 순환 정책 구현 권장
    /// - 의심스러운 활동 감지 시 즉시 무효화
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::JwtConfig;
    /// use chrono::{Utc, Duration};
    ///
    /// let refresh_days = JwtConfig::refresh_expiration_days();
    /// let refresh_expires_at = Utc::now() + Duration::days(refresh_days);
    /// ```
    pub fn refresh_expiration_days() -> i64 {
        env::var("JWT_REFRESH_EXPIRATION_DAYS")
            .unwrap_or_else(|_| "7".to_string())
            .parse()
            .unwrap_or(7)
    }
}

/// OAuth 일반 설정을 관리하는 구조체
///
/// 모든 OAuth 프로바이더에 공통으로 적용되는 보안 설정을 관리합니다.
/// CSRF 공격 방지를 위한 state 매개변수와 세션 관리 등을 포함합니다.
///
/// ## OAuth State 매개변수
///
/// OAuth 2.0의 state 매개변수는 CSRF 공격을 방지하기 위한 중요한 보안 기능입니다.
/// 인증 요청 시 생성된 랜덤 값이 콜백에서 그대로 반환되는지 검증합니다.
pub struct OAuthConfig;

impl OAuthConfig {
    /// OAuth State 검증용 비밀키를 반환합니다.
    ///
    /// CSRF 공격 방지를 위한 state 매개변수 생성 및 검증에 사용됩니다.
    /// 이 값은 외부에 노출되어서는 안 되는 민감한 정보입니다.
    ///
    /// # State 매개변수 동작 원리
    ///
    /// 1. 인증 요청 시 랜덤 state 값 생성
    /// 2. 이 비밀키를 사용하여 state 값 서명
    /// 3. OAuth 콜백에서 state 값 검증
    /// 4. 서명이 일치하지 않으면 요청 거부
    ///
    /// # 기본값
    ///
    /// 환경 변수가 설정되지 않은 경우 "oauth-state-secret"을 사용하지만,
    /// 프로덕션에서는 경고 로그가 출력됩니다.
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::OAuthConfig;
    ///
    /// let state_secret = OAuthConfig::state_secret();
    /// // HMAC으로 state 값 서명
    /// ```
    ///
    /// # 환경 변수 설정
    ///
    /// ```bash
    /// export OAUTH_STATE_SECRET="your-oauth-state-secret-key"
    /// ```
    pub fn state_secret() -> String {
        env::var("OAUTH_STATE_SECRET")
            .unwrap_or_else(|_| {
                log::warn!("OAUTH_STATE_SECRET not set, using default (not secure for production!)");
                "oauth-state-secret".to_string()
            })
    }
    
    /// OAuth 세션 타임아웃을 분 단위로 반환합니다.
    ///
    /// OAuth 인증 프로세스 중 생성되는 임시 세션의 유효 기간입니다.
    /// 사용자가 OAuth 인증을 시작한 후 완료까지 걸리는 최대 시간을 제한합니다.
    ///
    /// # 권장 설정값
    ///
    /// - **개발**: 10분 (디버깅 여유 시간)
    /// - **프로덕션**: 5분 (보안 강화)
    ///
    /// # 기본값
    ///
    /// 10분
    ///
    /// # 용도
    ///
    /// - OAuth 인증 프로세스 제한
    /// - 세션 하이재킹 공격 완화
    /// - 메모리 사용량 제어
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::OAuthConfig;
    /// use std::time::{SystemTime, Duration};
    ///
    /// let timeout_minutes = OAuthConfig::session_timeout_minutes();
    /// let session_expires = SystemTime::now() + Duration::from_secs(timeout_minutes as u64 * 60);
    /// ```
    pub fn session_timeout_minutes() -> i64 {
        env::var("OAUTH_SESSION_TIMEOUT_MINUTES")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .unwrap_or(10)
    }
}

/// 지원하는 인증 공급자를 나타내는 열거형
///
/// Spring Security의 OAuth2 Client Registration과 유사한 개념으로,
/// 다양한 인증 방식을 추상화하여 통일된 인터페이스를 제공합니다.
///
/// ## 확장성
///
/// 새로운 OAuth 프로바이더 추가 시 이 열거형에 변형을 추가하고,
/// 해당 프로바이더의 설정 구조체를 구현하면 됩니다.
///
/// ## 직렬화 지원
///
/// `serde`를 통해 JSON 직렬화/역직렬화를 지원하므로,
/// API 응답이나 데이터베이스 저장에 사용할 수 있습니다.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AuthProvider {
    /// 로컬 이메일/패스워드 인증
    ///
    /// 전통적인 사용자명/패스워드 기반 인증 방식입니다.
    /// bcrypt를 사용한 패스워드 해싱과 이메일 인증을 지원합니다.
    ///
    /// # 특징
    ///
    /// - 외부 의존성 없음
    /// - 완전한 사용자 데이터 제어
    /// - 패스워드 복잡성 정책 적용 가능
    Local,
    
    /// Google OAuth 2.0 인증
    ///
    /// Google 계정을 통한 소셜 로그인입니다.
    /// Google의 강력한 보안 인프라를 활용할 수 있습니다.
    ///
    /// # 특징
    ///
    /// - 2단계 인증 자동 지원
    /// - 글로벌 사용자 베이스
    /// - Google API와의 연동 가능
    Google,
    
    /// GitHub OAuth 인증 (향후 확장용)
    ///
    /// 개발자 대상 서비스에 적합한 GitHub 계정 기반 인증입니다.
    ///
    /// # 구현 예정 기능
    ///
    /// - GitHub 프로필 정보 연동
    /// - Repository 접근 권한 관리
    /// - 개발자 도구와의 통합
    GitHub,
    
    /// Facebook OAuth 인증 (향후 확장용)
    ///
    /// 소셜 네트워크 기반 서비스에 적합한 Facebook 계정 인증입니다.
    ///
    /// # 구현 예정 기능
    ///
    /// - Facebook 소셜 그래프 연동
    /// - 친구 목록 기반 기능
    /// - Facebook 마케팅 API 연동
    Facebook,
}

impl AuthProvider {
    /// 문자열에서 AuthProvider를 생성합니다.
    ///
    /// API 요청이나 설정 파일에서 문자열로 전달된 인증 프로바이더를
    /// 적절한 열거형 값으로 변환합니다.
    ///
    /// # 인자
    ///
    /// * `s` - 인증 프로바이더 이름 (대소문자 무관)
    ///
    /// # 반환값
    ///
    /// * `Ok(AuthProvider)` - 유효한 프로바이더인 경우
    /// * `Err(String)` - 지원하지 않는 프로바이더인 경우
    ///
    /// # 지원되는 값
    ///
    /// - `"local"` → `AuthProvider::Local`
    /// - `"google"` → `AuthProvider::Google`
    /// - `"github"` → `AuthProvider::GitHub`
    /// - `"facebook"` → `AuthProvider::Facebook`
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::AuthProvider;
    ///
    /// let provider = AuthProvider::from_str("google")?;
    /// assert_eq!(provider, AuthProvider::Google);
    ///
    /// let invalid = AuthProvider::from_str("twitter");
    /// assert!(invalid.is_err());
    /// ```
    ///
    /// # API 사용 예제
    ///
    /// ```rust,ignore
    /// use actix_web::{web, HttpResponse, Result};
    /// use crate::config::AuthProvider;
    ///
    /// async fn login_handler(provider_name: web::Path<String>) -> Result<HttpResponse> {
    ///     match AuthProvider::from_str(&provider_name) {
    ///         Ok(AuthProvider::Google) => {
    ///             // Google OAuth 처리
    ///             Ok(HttpResponse::Ok().json("Google login"))
    ///         }
    ///         Ok(AuthProvider::Local) => {
    ///             // 로컬 로그인 처리
    ///             Ok(HttpResponse::Ok().json("Local login"))
    ///         }
    ///         Err(e) => Ok(HttpResponse::BadRequest().json(e))
    ///     }
    /// }
    /// ```
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "local" => Ok(AuthProvider::Local),
            "google" => Ok(AuthProvider::Google),
            "github" => Ok(AuthProvider::GitHub),
            "facebook" => Ok(AuthProvider::Facebook),
            _ => Err(format!("Unsupported auth provider: {}", s)),
        }
    }
    
    /// AuthProvider를 문자열로 변환합니다.
    ///
    /// 열거형 값을 문자열 표현으로 변환하여 API 응답이나
    /// 로깅에 사용할 수 있습니다.
    ///
    /// # 반환값
    ///
    /// 해당 프로바이더의 소문자 문자열 표현
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::AuthProvider;
    ///
    /// assert_eq!(AuthProvider::Google.as_str(), "google");
    /// assert_eq!(AuthProvider::Local.as_str(), "local");
    /// ```
    ///
    /// # 로깅 예제
    ///
    /// ```rust,ignore
    /// use crate::config::AuthProvider;
    ///
    /// let provider = AuthProvider::Google;
    /// log::info!("User authenticated via: {}", provider.as_str());
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthProvider::Local => "local",
            AuthProvider::Google => "google",
            AuthProvider::GitHub => "github",
            AuthProvider::Facebook => "facebook",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_provider_from_string() {
        assert_eq!(AuthProvider::from_str("local").unwrap(), AuthProvider::Local);
        assert_eq!(AuthProvider::from_str("google").unwrap(), AuthProvider::Google);
        assert_eq!(AuthProvider::from_str("github").unwrap(), AuthProvider::GitHub);
        assert_eq!(AuthProvider::from_str("facebook").unwrap(), AuthProvider::Facebook);
        
        // 대소문자 무관 테스트
        assert_eq!(AuthProvider::from_str("GOOGLE").unwrap(), AuthProvider::Google);
        assert_eq!(AuthProvider::from_str("Local").unwrap(), AuthProvider::Local);
        
        // 지원하지 않는 프로바이더 테스트
        assert!(AuthProvider::from_str("twitter").is_err());
        assert!(AuthProvider::from_str("unknown").is_err());
    }

    #[test]
    fn test_auth_provider_as_string() {
        assert_eq!(AuthProvider::Local.as_str(), "local");
        assert_eq!(AuthProvider::Google.as_str(), "google");
        assert_eq!(AuthProvider::GitHub.as_str(), "github");
        assert_eq!(AuthProvider::Facebook.as_str(), "facebook");
    }
    
    #[test]
    fn test_auth_provider_roundtrip() {
        // 문자열 → AuthProvider → 문자열 변환 테스트
        let providers = ["local", "google", "github", "facebook"];
        
        for &provider_str in &providers {
            let provider = AuthProvider::from_str(provider_str).unwrap();
            assert_eq!(provider.as_str(), provider_str);
        }
    }
    
    #[test]
    fn test_auth_provider_serialization() {
        // JSON 직렬화/역직렬화 테스트
        let provider = AuthProvider::Google;
        let json = serde_json::to_string(&provider).unwrap();
        let deserialized: AuthProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(provider, deserialized);
    }
}
