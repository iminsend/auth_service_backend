use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use singleton_macro::service;
use crate::{
    domain::entities::users::user::User,
    config::{JwtConfig, AuthProvider},
    core::errors::AppError,
};

/// JWT 토큰의 클레임 구조
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    /// 사용자 ID
    pub sub: String,
    /// 사용자 이메일
    pub email: String,
    /// 사용자 이름
    pub username: String,
    /// 인증 프로바이더
    pub auth_provider: AuthProvider,
    /// 사용자 역할
    pub roles: Vec<String>,
    /// 토큰 발급 시간 (Unix timestamp)
    pub iat: i64,
    /// 토큰 만료 시간 (Unix timestamp)
    pub exp: i64,
}

/// JWT 토큰 쌍
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
}

/// JWT 토큰 관리 서비스
#[service]
pub struct TokenService {
    // 매크로가 자동으로 의존성 주입 처리
}

impl TokenService {
    /// 사용자를 위한 JWT 액세스 토큰 생성
    pub fn generate_access_token(&self, user: &User) -> Result<String, AppError> {
        let now = Utc::now();
        let expiration = now + Duration::hours(JwtConfig::expiration_hours());
        
        let claims = TokenClaims {
            sub: user.id_string().ok_or_else(|| {
                AppError::InternalError("사용자 ID가 없습니다".to_string())
            })?,
            email: user.email.clone(),
            username: user.username.clone(),
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
    pub fn generate_refresh_token(&self, user: &User) -> Result<String, AppError> {
        let now = Utc::now();
        let expiration = now + Duration::days(JwtConfig::refresh_expiration_days());
        
        let claims = TokenClaims {
            sub: user.id_string().ok_or_else(|| {
                AppError::InternalError("사용자 ID가 없습니다".to_string())
            })?,
            email: user.email.clone(),
            username: user.username.clone(),
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
    pub fn extract_user_id(&self, token: &str) -> Result<String, AppError> {
        let claims = self.verify_token(token)?;
        Ok(claims.sub)
    }

    /// Bearer 토큰에서 실제 토큰 부분 추출
    pub fn extract_bearer_token<'a>(&self, auth_header: &'a str) -> Result<&'a str, AppError> {
        if auth_header.starts_with("Bearer ") {
            Ok(&auth_header[7..])
        } else {
            Err(AppError::AuthenticationError("유효하지 않은 인증 헤더 형식입니다".to_string()))
        }
    }
}
