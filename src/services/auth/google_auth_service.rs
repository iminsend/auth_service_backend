//! Google OAuth 2.0 인증 서비스 구현
//! 
//! Google OAuth 2.0 프로토콜을 통한 소셜 로그인 기능을 제공합니다.
//! Authorization Code Grant 플로우를 구현하여 안전한 인증을 보장합니다.

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
/// Google의 OAuth 2.0 프로토콜을 사용한 소셜 로그인을 제공합니다.
/// CSRF 방지를 위한 state 매개변수와 안전한 토큰 교환을 지원합니다.
#[service(name="google_auth")]
pub struct GoogleAuthService {
    /// 사용자 데이터 액세스 리포지토리
    user_repo: Arc<UserRepository>,
}

impl GoogleAuthService {
    /// Google OAuth 로그인 URL 생성
    /// 
    /// # Returns
    /// 
    /// * `Ok(OAuthLoginUrlResponse)` - 로그인 URL과 state 값
    /// 
    /// # Errors
    /// 
    /// * `AppError::InternalError` - state 생성 실패 또는 URL 구성 오류
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// let google_auth = GoogleAuthService::instance();
    /// let response = google_auth.get_login_url()?;
    /// 
    /// // 클라이언트를 Google 로그인 페이지로 리다이렉트
    /// HttpResponse::Found()
    ///     .append_header(("Location", response.login_url))
    ///     .finish()
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
    /// # Arguments
    /// 
    /// * `auth_code` - Google에서 발급한 Authorization Code
    /// * `state` - CSRF 방지용 state 매개변수
    /// 
    /// # Returns
    /// 
    /// * `Ok(User)` - 인증된 사용자 엔티티
    /// 
    /// # Errors
    /// 
    /// * `AppError::AuthenticationError` - state 검증 실패 또는 OAuth 오류
    /// * `AppError::ConflictError` - 계정 연동 필요 (로컬 계정과 이메일 중복)
    /// * `AppError::ExternalServiceError` - Google API 통신 오류
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// // 콜백 핸들러에서 사용
    /// let user = google_auth.authenticate_with_code(&query.code, &query.state).await?;
    /// 
    /// // JWT 토큰 생성
    /// let token_service = TokenService::instance();
    /// let tokens = token_service.generate_token_pair(&user)?;
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
    /// # Arguments
    /// 
    /// * `auth_code` - Google에서 발급한 일회용 Authorization Code
    /// 
    /// # Returns
    /// 
    /// * `Ok(GoogleTokenResponse)` - 액세스 토큰과 메타데이터
    /// 
    /// # Errors
    /// 
    /// * `AppError::ExternalServiceError` - Google API 통신 오류
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
    /// # Arguments
    /// 
    /// * `access_token` - Google에서 발급받은 액세스 토큰
    /// 
    /// # Returns
    /// 
    /// * `Ok(GoogleUserInfo)` - 사용자 프로필 정보
    /// 
    /// # Errors
    /// 
    /// * `AppError::ExternalServiceError` - Google API 통신 오류
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
    /// # Arguments
    /// 
    /// * `google_user` - Google API에서 받은 사용자 프로필 정보
    /// 
    /// # Returns
    /// 
    /// * `Ok(User)` - 생성된 사용자 엔티티
    /// 
    /// # Errors
    /// 
    /// * `AppError::InternalError` - 사용자명 생성 실패
    /// * `AppError::DatabaseError` - 사용자 저장 실패
    async fn create_google_user(&self, google_user: GoogleUserInfo) -> Result<User, AppError> {
        // 사용자명 생성 (중복 방지)
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
    /// # Arguments
    /// 
    /// * `base_name` - 기본이 되는 이름
    /// 
    /// # Returns
    /// 
    /// * `Ok(String)` - 고유한 사용자명
    /// 
    /// # Errors
    /// 
    /// * `AppError::InternalError` - 1000회 시도 후에도 고유명 생성 실패
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// // "John" → "john" 또는 "john_1", "john_2" 등
    /// let username = self.generate_unique_username("John").await?;
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
    /// CSRF 공격을 방지하기 위한 임의의 state 값을 생성합니다.
    /// 
    /// # Returns
    /// 
    /// * `Ok(String)` - 생성된 state 값 (16진수 해시)
    /// 
    /// # Errors
    /// 
    /// * `AppError::InternalError` - 시간 계산 오류
    fn generate_oauth_state(&self) -> Result<String, AppError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::InternalError(format!("시간 계산 실패: {}", e)))?
            .as_secs();

        let state_data = format!("{}:{}", timestamp, OAuthConfig::state_secret());
        
        // 간단한 해시 생성
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        state_data.hash(&mut hasher);
        
        Ok(format!("{:x}", hasher.finish()))
    }

    /// OAuth State 매개변수 검증
    /// 
    /// # Arguments
    /// 
    /// * `state` - Google 콜백에서 받은 state 매개변수
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - 검증 성공
    /// 
    /// # Errors
    /// 
    /// * `AppError::AuthenticationError` - 검증 실패
    /// 
    /// # Notes
    /// 
    /// 현재는 기본적인 검증만 수행합니다.
    /// 프로덕션 환경에서는 Redis 저장소와 만료 시간 검증이 필요합니다.
    fn verify_oauth_state(&self, state: &str) -> Result<(), AppError> {
        if state.is_empty() {
            return Err(AppError::AuthenticationError("유효하지 않은 OAuth state".to_string()));
        }

        Ok(())
    }
}
