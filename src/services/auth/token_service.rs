//! JWT 토큰 관리 서비스 구현
//! 
//! JSON Web Token 기반의 인증 시스템을 제공합니다.
//! 액세스 토큰과 리프레시 토큰의 생성, 검증, 갱신을 담당하며,
//! Redis를 통한 세션 관리를 포함합니다.

use std::sync::Arc;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use singleton_macro::service;
use uuid::Uuid;

use crate::{
    config::JwtConfig,
    domain::entities::users::user::User,
    repositories::tokens::token_repository::TokenRepository,
};
use crate::domain::models::token::token::{TokenClaims, TokenPair};
use crate::errors::errors::AppError;

/// 토큰 검증 결과
#[derive(Debug)]
pub struct TokenValidation {
    pub is_valid: bool,
    pub claims: Option<TokenClaims>,
    pub error_message: Option<String>,
}

/// JWT 토큰 관리 서비스
/// 
/// HMAC-SHA256 서명을 사용하여 안전한 JWT 토큰을 생성하고 검증합니다.
/// 액세스 토큰(1시간)과 리프레시 토큰(7일)을 지원하며,
/// Redis를 통한 세션 관리를 제공합니다.
#[service(name="token")]
pub struct TokenService {
    token_repo: Arc<TokenRepository>,
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
            user_id: user.id_string().ok_or_else(|| {
                AppError::InternalError("사용자 ID가 없습니다".to_string())
            })?,
            email: Some(user.email.clone()),
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
            user_id: user.id_string().ok_or_else(|| {
                AppError::InternalError("사용자 ID가 없습니다".to_string())
            })?,
            email: Some(user.email.clone()),
        };

        let secret = JwtConfig::secret();
        let header = Header::default();
        let encoding_key = EncodingKey::from_secret(secret.as_ref());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| AppError::InternalError(format!("리프레시 토큰 생성 실패: {}", e)))
    }

    /// 토큰 쌍 생성 (액세스 + 리프레시) with Redis 세션 저장
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
    /// let token_pair = token_service.generate_token_pair(&user).await?;
    /// println!("Access token: {}", token_pair.access_token);
    /// println!("Expires in: {} seconds", token_pair.expires_in);
    /// ```
    pub async fn generate_token_pair(&self, user: &User) -> Result<TokenPair, AppError> {
        let access_token = self.generate_access_token(user)?;
        let refresh_token = self.generate_refresh_token(user)?;
        let expires_in = JwtConfig::expiration_hours() * 3600; // 초 단위로 변환

        // Refresh token을 Redis에도 저장 (세션 관리용)
        let user_id = user.id_string().ok_or_else(|| {
            AppError::InternalError("사용자 ID가 없습니다".to_string())
        })?;

        let refresh_days = JwtConfig::refresh_expiration_days();
        let refresh_expires_in = refresh_days * 24 * 3600; // 초 단위

        // Redis에 refresh token 세션 저장
        if let Err(e) = self.token_repo.store_refresh_token(
            &user_id,
            &user.username,
            user.auth_provider.as_str(),
            &refresh_token,
            refresh_expires_in as u64,
        ).await {
            log::warn!("Redis에 refresh token 저장 실패: {}", e);
            // Redis 저장 실패해도 JWT 토큰은 정상 반환 (Redis는 선택적)
        } else {
            log::info!("Refresh token Redis 세션 저장 완료 - user_id: {}", user_id);
        }

        Ok(TokenPair {
            access_token,
            refresh_token: Some(refresh_token),
            expires_in,
        })
    }

    /// 새로운 토큰 쌍 생성 (로그인시 사용 - Redis 세션 관리 포함)
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// * `username` - 사용자명
    /// * `email` - 사용자 이메일
    /// * `auth_provider` - 인증 방식 (Local, Google 등)
    /// 
    /// # Returns
    /// TokenPair (access_token + refresh_token) with Redis session management
    pub async fn create_token_pair(
        &self,
        user_id: &str,
        username: &str,
        email: &str,
        auth_provider: &str,
    ) -> Result<TokenPair, Box<dyn std::error::Error>> {
        // 환경변수에서 TTL 값 읽기
        let access_hours = std::env::var("JWT_EXPIRATION_HOURS")
            .unwrap_or_else(|_| "1".to_string())
            .parse::<i64>()
            .unwrap_or(1);
            
        let refresh_days = std::env::var("JWT_REFRESH_EXPIRATION_DAYS")
            .unwrap_or_else(|_| "7".to_string())
            .parse::<i64>()
            .unwrap_or(7);
        
        // TTL 값 검증 및 최소값 보장
        let access_hours = if access_hours <= 0 { 1 } else { access_hours };
        let refresh_days = if refresh_days <= 0 { 7 } else { refresh_days };
        
        let access_expires_in = access_hours * 3600; // 초 단위
        let refresh_expires_in = refresh_days * 24 * 3600; // 초 단위
        
        // 최종 TTL 검증 (디버깅 로그 추가)
        if refresh_expires_in <= 0 {
            log::error!("계산된 refresh_expires_in이 0 이하입니다: {}", refresh_expires_in);
            return Err("토큰 생성 실패: TTL cannot be zero".into());
        }
        
        log::info!("TokenService create_token_pair - access_ttl: {}초, refresh_ttl: {}초", 
                   access_expires_in, refresh_expires_in);

        // JWT Access Token 생성
        let now = Utc::now();
        let access_exp = now + Duration::seconds(access_expires_in);
        
        let claims = TokenClaims {
            sub: user_id.to_string(),
            auth_provider: auth_provider.parse().unwrap_or_default(),
            roles: vec!["user".to_string()], // 기본 역할
            iat: now.timestamp(),
            exp: access_exp.timestamp(),
            user_id: user_id.to_string(),
            email: Some(email.to_string()),
        };

        let secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "your-secret-key".to_string());
        let access_token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )?;

        // Refresh Token 생성 (UUID 방식 사용)
        let refresh_token = Uuid::new_v4().to_string();
        
        // Redis에 세션 정보 저장
        // - 사용자 등록 id
        // - 사용자 username  
        // - 인증방식
        // - 로그인 일시
        // - 사용자 refresh_token 문자열
        self.token_repo.store_refresh_token(
            user_id,
            username,
            auth_provider,
            &refresh_token,
            refresh_expires_in as u64,
        ).await?;
        
        log::info!("Redis 세션 저장 완료 - user_id: {}, username: {}, auth_provider: {}, refresh_expires_in: {}초", 
                   user_id, username, auth_provider, refresh_expires_in);

        Ok(TokenPair {
            access_token,
            refresh_token: Some(refresh_token),
            expires_in: access_expires_in,
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

    /// Refresh Token으로 새로운 Access Token 발급
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// * `refresh_token` - Refresh Token
    /// 
    /// # Returns
    /// 새로운 TokenPair
    pub async fn refresh_access_token(
        &self,
        user_id: &str,
        refresh_token: &str,
    ) -> Result<TokenPair, Box<dyn std::error::Error>> {
        // 1. Redis에서 Refresh Token 검증
        let token_info = self.token_repo.get_refresh_token(user_id, refresh_token).await?
            .ok_or("Invalid or expired refresh token")?;

        // 2. 새로운 Access Token 생성
        let access_hours = std::env::var("JWT_EXPIRATION_HOURS")
            .unwrap_or_else(|_| "1".to_string())
            .parse::<i64>()
            .unwrap_or(1);
        
        // TTL 값 검증 및 최소값 보장
        let access_hours = if access_hours <= 0 { 1 } else { access_hours };
        let access_expires_in = access_hours * 3600;

        let now = Utc::now();
        let access_exp = now + Duration::seconds(access_expires_in);
        
        let access_claims = TokenClaims {
            sub: user_id.to_string(),
            auth_provider: token_info.auth_provider.parse().unwrap_or_default(),
            roles: vec!["user".to_string()],
            iat: now.timestamp(),
            exp: access_exp.timestamp(),
            user_id: user_id.to_string(),
            email: None, // refresh 시에는 이메일 정보 없음
        };

        let secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "your-secret-key".to_string());
        let new_access_token = encode(
            &Header::default(),
            &access_claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )?;

        // 3. 기존 refresh token 유지
        let _remaining_ttl = (token_info.expires_at - Utc::now().timestamp()).max(0);

        Ok(TokenPair {
            access_token: new_access_token,
            refresh_token: Some(refresh_token.to_string()),
            expires_in: access_expires_in,
        })
    }

    /// 로그아웃 처리 (모든 세션 정보 삭제)
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// 
    /// # Note
    /// Refresh Token과 모든 관련 세션 정보를 삭제합니다.
    /// Access Token은 여전히 유효하지만 Refresh가 불가능해집니다.
    pub async fn logout(
        &self,
        user_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 모든 사용자 토큰 및 세션 정보 삭제
        self.token_repo.delete_all_user_tokens(user_id).await?;
        
        log::info!("사용자 로그아웃 완료 - user_id: {}, 모든 세션 정보 삭제됨", user_id);
        Ok(())
    }

    /// 토큰 검증 및 상세 결과 반환
    /// 
    /// # Arguments
    /// * `token` - 검증할 JWT 토큰
    /// 
    /// # Returns
    /// TokenValidation 구조체 (is_valid, claims, error_message)
    pub async fn validate_access_token(&self, token: &str) -> TokenValidation {
        // JWT 검증
        match self.verify_token(token) {
            Ok(claims) => TokenValidation {
                is_valid: true,
                claims: Some(claims),
                error_message: None,
            },
            Err(e) => TokenValidation {
                is_valid: false,
                claims: None,
                error_message: Some(e.to_string()),
            },
        }
    }

    /// 사용자의 모든 세션 강제 종료 (보안 강화)
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// 
    /// # Note
    /// 비밀번호 변경, 보안 침해 의심시 사용
    pub async fn revoke_all_tokens(
        &self,
        user_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Redis에서 모든 토큰 삭제
        self.token_repo.delete_all_user_tokens(user_id).await?;
        Ok(())
    }
}
