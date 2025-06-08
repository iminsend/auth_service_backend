//! JWT 토큰 관리 서비스 구현
//! 
//! JSON Web Token 기반의 인증 시스템을 제공합니다.
//! 액세스 토큰과 리프레시 토큰의 생성, 검증, 갱신을 담당합니다.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use singleton_macro::service;
use crate::{
    config::JwtConfig,
    domain::entities::users::user::User,
};
use crate::domain::token::token::{TokenClaims, TokenPair};
use crate::errors::errors::AppError;

/// JWT 토큰 관리 서비스
/// 
/// HMAC-SHA256 서명을 사용하여 안전한 JWT 토큰을 생성하고 검증합니다.
/// 액세스 토큰(1시간)과 리프레시 토큰(30일)을 지원합니다.
#[service(name="token")]
pub struct TokenService {
    // 외부 의존성 없음
}

impl TokenService {
    /// 사용자를 위한 JWT 액세스 토큰 생성
    /// 
    /// # Arguments
    /// 
    /// * `user` - 토큰을 발급받을 사용자 정보
    /// 
    /// # Returns
    /// 
    /// * `Ok(String)` - 생성된 JWT 액세스 토큰
    /// 
    /// # Errors
    /// 
    /// * `AppError::InternalError` - 토큰 생성 실패 또는 사용자 ID 없음
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// let token_service = TokenService::instance();
    /// let access_token = token_service.generate_access_token(&user)?;
    /// ```
    pub fn generate_access_token(&self, user: &User) -> Result<String, AppError> {
        let now = Utc::now();
        let expiration = now + Duration::hours(JwtConfig::expiration_hours());
        
        let claims = TokenClaims {
            sub: user.id_string().ok_or_else(|| {
                AppError::InternalError("사용자 ID가 없습니다".to_string())
            })?,
            auth_provider: user.auth_provider.clone(),
            roles: user.roles.clone(),
            iat: now.timestamp(),
            exp: expiration.timestamp(),
        };

        let secret = JwtConfig::secret();
        let header = Header::default();
        let encoding_key = EncodingKey::from_secret(secret.as_ref());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| AppError::InternalError(format!("JWT 토큰 생성 실패: {}", e)))
    }

    /// 사용자를 위한 리프레시 토큰 생성
    /// 
    /// # Arguments
    /// 
    /// * `user` - 토큰을 발급받을 사용자 정보
    /// 
    /// # Returns
    /// 
    /// * `Ok(String)` - 생성된 JWT 리프레시 토큰
    /// 
    /// # Errors
    /// 
    /// * `AppError::InternalError` - 토큰 생성 실패
    /// 
    /// # Security
    /// 
    /// 리프레시 토큰은 Secure HttpOnly Cookie에 저장하는 것을 권장합니다.
    pub fn generate_refresh_token(&self, user: &User) -> Result<String, AppError> {
        let now = Utc::now();
        let expiration = now + Duration::days(JwtConfig::refresh_expiration_days());
        
        let claims = TokenClaims {
            sub: user.id_string().ok_or_else(|| {
                AppError::InternalError("사용자 ID가 없습니다".to_string())
            })?,
            auth_provider: user.auth_provider.clone(),
            roles: user.roles.clone(),
            iat: now.timestamp(),
            exp: expiration.timestamp(),
        };

        let secret = JwtConfig::secret();
        let header = Header::default();
        let encoding_key = EncodingKey::from_secret(secret.as_ref());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| AppError::InternalError(format!("리프레시 토큰 생성 실패: {}", e)))
    }

    /// 토큰 쌍 생성 (액세스 + 리프레시)
    /// 
    /// # Arguments
    /// 
    /// * `user` - 토큰을 발급받을 사용자 정보
    /// 
    /// # Returns
    /// 
    /// * `Ok(TokenPair)` - 액세스/리프레시 토큰과 만료 정보
    /// 
    /// # Errors
    /// 
    /// * `AppError::InternalError` - 토큰 생성 실패
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// let token_pair = token_service.generate_token_pair(&user)?;
    /// println!("Access token: {}", token_pair.access_token);
    /// println!("Expires in: {} seconds", token_pair.expires_in);
    /// ```
    pub fn generate_token_pair(&self, user: &User) -> Result<TokenPair, AppError> {
        let access_token = self.generate_access_token(user)?;
        let refresh_token = self.generate_refresh_token(user)?;
        let expires_in = JwtConfig::expiration_hours() * 3600; // 초 단위로 변환

        Ok(TokenPair {
            access_token,
            refresh_token: Some(refresh_token),
            expires_in,
        })
    }

    /// JWT 토큰 검증 및 클레임 추출
    /// 
    /// # Arguments
    /// 
    /// * `token` - 검증할 JWT 토큰 문자열 (Bearer 접두사 제외)
    /// 
    /// # Returns
    /// 
    /// * `Ok(TokenClaims)` - 검증된 토큰의 클레임 정보
    /// 
    /// # Errors
    /// 
    /// * `AppError::AuthenticationError` - 토큰 만료, 잘못된 형식/서명
    /// * `AppError::InternalError` - 기타 시스템 오류
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// let claims = token_service.verify_token(token)?;
    /// println!("User ID: {}", claims.sub);
    /// println!("Roles: {:?}", claims.roles);
    /// ```
    pub fn verify_token(&self, token: &str) -> Result<TokenClaims, AppError> {
        let secret = JwtConfig::secret();
        let decoding_key = DecodingKey::from_secret(secret.as_ref());
        let validation = Validation::default();

        decode::<TokenClaims>(token, &decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    AppError::AuthenticationError("토큰이 만료되었습니다".to_string())
                },
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    AppError::AuthenticationError("유효하지 않은 토큰입니다".to_string())
                },
                _ => AppError::InternalError(format!("토큰 검증 실패: {}", e))
            })
    }

    /// 액세스 토큰으로부터 사용자 ID 추출
    /// 
    /// # Arguments
    /// 
    /// * `token` - 검증할 JWT 토큰 문자열
    /// 
    /// # Returns
    /// 
    /// * `Ok(String)` - 사용자 ID (MongoDB ObjectId 문자열)
    /// 
    /// # Errors
    /// 
    /// * `AppError::AuthenticationError` - 토큰 검증 실패
    pub fn extract_user_id(&self, token: &str) -> Result<String, AppError> {
        let claims = self.verify_token(token)?;
        Ok(claims.sub)
    }

    /// Bearer 토큰에서 실제 토큰 부분 추출
    /// 
    /// HTTP Authorization 헤더의 "Bearer {token}" 형식에서 토큰 부분만을 추출합니다.
    /// 
    /// # Arguments
    /// 
    /// * `auth_header` - HTTP Authorization 헤더 값 전체
    /// 
    /// # Returns
    /// 
    /// * `Ok(&str)` - Bearer 접두사를 제거한 순수 토큰 문자열
    /// 
    /// # Errors
    /// 
    /// * `AppError::AuthenticationError` - 잘못된 헤더 형식
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// let auth_header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    /// let token = token_service.extract_bearer_token(auth_header)?;
    /// let claims = token_service.verify_token(token)?;
    /// ```
    pub fn extract_bearer_token<'a>(&self, auth_header: &'a str) -> Result<&'a str, AppError> {
        if auth_header.starts_with("Bearer ") {
            Ok(&auth_header[7..])
        } else {
            Err(AppError::AuthenticationError("유효하지 않은 인증 헤더 형식입니다".to_string()))
        }
    }
}
