use std::sync::Arc;
use singleton_macro::service;
use crate::{
    domain::entities::users::user::User,
    repositories::users::user_repo::UserRepository,
    config::{GoogleOAuthConfig, OAuthConfig, AuthProvider},
    core::errors::AppError,
};
use crate::domain::dto::users::response::google_oauth_response::{GoogleTokenResponse, OAuthLoginUrlResponse};
use crate::domain::models::oauth::google_oauth_model::google_user::GoogleUserInfo;

/// Google OAuth 인증 서비스
#[service]
pub struct GoogleAuthService {
    user_repo: Arc<UserRepository>,
}

impl GoogleAuthService {
    /// Google OAuth 로그인 URL 생성
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

    /// Authorization code를 사용하여 사용자 인증 및 등록/로그인 처리
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

    /// Authorization code를 액세스 토큰으로 교환
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

    /// 액세스 토큰으로 Google 사용자 정보 조회
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

    /// Google 사용자 정보로 새 사용자 생성
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

    /// 중복되지 않는 사용자명 생성
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

    /// OAuth state 생성 (CSRF 방지용)
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

    /// OAuth state 검증
    fn verify_oauth_state(&self, state: &str) -> Result<(), AppError> {
        // 실제 구현에서는 더 강력한 state 검증 로직 필요
        // 예: Redis에 임시 저장 후 검증, 타임스탬프 검증 등
        
        if state.is_empty() {
            return Err(AppError::AuthenticationError("유효하지 않은 OAuth state".to_string()));
        }

        Ok(())
    }
}
