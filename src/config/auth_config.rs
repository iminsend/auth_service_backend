//! 인증 설정 관리 모듈
//!
//! OAuth 프로바이더, JWT 토큰, 세션 관리 등 인증 관련 설정을 관리합니다.

use std::env;
use std::str::FromStr;

/// Google OAuth 2.0 설정
pub struct GoogleOAuthConfig;

impl GoogleOAuthConfig {
    /// Google OAuth Client ID를 반환합니다.
    ///
    /// # Panics
    ///
    /// `GOOGLE_CLIENT_ID` 환경 변수가 설정되지 않은 경우
    pub fn client_id() -> String {
        env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set")
    }

    /// Google OAuth Client Secret을 반환합니다.
    ///
    /// # Panics
    ///
    /// `GOOGLE_CLIENT_SECRET` 환경 변수가 설정되지 않은 경우
    ///
    /// # Security
    ///
    /// 이 값을 로그나 클라이언트 사이드에 노출하지 마세요.
    pub fn client_secret() -> String {
        env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET must be set")
    }

    /// OAuth 인증 완료 후 리디렉션될 URI를 반환합니다.
    ///
    /// # Panics
    ///
    /// `GOOGLE_REDIRECT_URI` 환경 변수가 설정되지 않은 경우
    pub fn redirect_uri() -> String {
        env::var("GOOGLE_REDIRECT_URI").expect("GOOGLE_REDIRECT_URI must be set")
    }

    /// Google OAuth 인증 엔드포인트 URI를 반환합니다.
    pub fn auth_uri() -> String {
        env::var("GOOGLE_AUTH_URI")
            .unwrap_or_else(|_| "https://accounts.google.com/o/oauth2/auth".to_string())
    }

    /// Google OAuth 토큰 교환 엔드포인트 URI를 반환합니다.
    pub fn token_uri() -> String {
        env::var("GOOGLE_TOKEN_URI")
            .unwrap_or_else(|_| "https://oauth2.googleapis.com/token".to_string())
    }

    /// Google Cloud Project ID를 반환합니다.
    ///
    /// # Panics
    ///
    /// `GOOGLE_PROJECT_ID` 환경 변수가 설정되지 않은 경우
    pub fn project_id() -> String {
        env::var("GOOGLE_PROJECT_ID").expect("GOOGLE_PROJECT_ID must be set")
    }

    /// JavaScript Origin을 반환합니다.
    pub fn javascript_origin() -> String {
        env::var("GOOGLE_JAVASCRIPT_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".to_string())
    }
}

/// JWT 토큰 설정
pub struct JwtConfig;

impl JwtConfig {
    /// JWT 서명에 사용할 비밀키를 반환합니다.
    ///
    /// # Security
    ///
    /// 프로덕션에서는 최소 256비트 길이의 강력한 키를 사용하세요.
    pub fn secret() -> String {
        env::var("JWT_SECRET").unwrap_or_else(|_| {
            log::warn!("JWT_SECRET not set, using default (not secure for production!)");
            "your-secret-key".to_string()
        })
    }

    /// JWT 액세스 토큰의 만료 시간을 시간 단위로 반환합니다.
    ///
    /// # Returns
    ///
    /// 만료 시간 (시간 단위). 기본값: 1시간 (최소값 보장)
    pub fn expiration_hours() -> i64 {
        let hours = env::var("JWT_EXPIRATION_HOURS")
            .unwrap_or_else(|_| "1".to_string())
            .parse()
            .unwrap_or(1);
        
        // 최소값 보장 (최소 1시간)
        if hours <= 0 {
            log::warn!("JWT_EXPIRATION_HOURS가 0 이하입니다 ({}). 기본값 1시간을 사용합니다.", hours);
            1
        } else {
            hours
        }
    }

    /// JWT 리프레시 토큰의 만료 시간을 일 단위로 반환합니다.
    ///
    /// # Returns
    ///
    /// 만료 시간 (일 단위). 기본값: 7일 (최소값 보장)
    pub fn refresh_expiration_days() -> i64 {
        let days = env::var("JWT_REFRESH_EXPIRATION_DAYS")
            .unwrap_or_else(|_| "7".to_string())
            .parse()
            .unwrap_or(7);
            
        // 최소값 보장 (최소 1일)
        if days <= 0 {
            log::warn!("JWT_REFRESH_EXPIRATION_DAYS가 0 이하입니다 ({}). 기본값 7일을 사용합니다.", days);
            7
        } else {
            days
        }
    }
}

/// OAuth 일반 설정
pub struct OAuthConfig;

impl OAuthConfig {
    /// OAuth State 검증용 비밀키를 반환합니다.
    ///
    /// CSRF 공격 방지를 위한 state 매개변수 생성 및 검증에 사용됩니다.
    pub fn state_secret() -> String {
        env::var("OAUTH_STATE_SECRET").unwrap_or_else(|_| {
            log::warn!("OAUTH_STATE_SECRET not set, using default (not secure for production!)");
            "oauth-state-secret".to_string()
        })
    }

    /// OAuth 세션 타임아웃을 분 단위로 반환합니다.
    ///
    /// # Returns
    ///
    /// 세션 타임아웃 (분 단위). 기본값: 10분
    pub fn session_timeout_minutes() -> i64 {
        env::var("OAUTH_SESSION_TIMEOUT_MINUTES")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .unwrap_or(10)
    }
}

/// 지원하는 인증 공급자
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AuthProvider {
    /// 로컬 이메일/패스워드 인증
    Local,
    /// Google OAuth 2.0 인증
    Google,
    /// GitHub OAuth 인증 (향후 지원)
    GitHub,
    /// Facebook OAuth 인증 (향후 지원)
    Facebook,
}

impl Default for AuthProvider {
    fn default() -> Self {
        AuthProvider::Local
    }
}

impl std::fmt::Display for AuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for AuthProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "local" => Ok(AuthProvider::Local),
            "google" => Ok(AuthProvider::Google),
            "github" => Ok(AuthProvider::GitHub),
            "facebook" => Ok(AuthProvider::Facebook),
            _ => Err(format!("Unsupported auth provider: {}", s)),
        }
    }
}

impl AuthProvider {
    /// AuthProvider를 문자열로 변환합니다.
    ///
    /// # Returns
    ///
    /// 해당 프로바이더의 소문자 문자열 표현
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
        assert_eq!(
            "local".parse::<AuthProvider>().unwrap(),
            AuthProvider::Local
        );
        assert_eq!(
            "google".parse::<AuthProvider>().unwrap(),
            AuthProvider::Google
        );
        assert_eq!(
            "GOOGLE".parse::<AuthProvider>().unwrap(),
            AuthProvider::Google
        );

        assert!("twitter".parse::<AuthProvider>().is_err());
    }

    #[test]
    fn test_auth_provider_as_string() {
        assert_eq!(AuthProvider::Local.as_str(), "local");
        assert_eq!(AuthProvider::Google.as_str(), "google");
    }

    #[test]
    fn test_auth_provider_serialization() {
        let provider = AuthProvider::Google;
        let json = serde_json::to_string(&provider).unwrap();
        let deserialized: AuthProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(provider, deserialized);
    }
}
