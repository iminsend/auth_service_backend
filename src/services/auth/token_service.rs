//! JWT 토큰 관리 서비스 구현 (블랙리스트 지원)
//! 
//! JSON Web Token 기반의 인증 시스템을 제공합니다.
//! 액세스 토큰과 리프레시 토큰의 생성, 검증, 갱신을 담당하며,
//! Redis를 통한 세션 관리와 토큰 블랙리스트 기능을 포함합니다.

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

/// JWT 토큰 관리 서비스 (블랙리스트 지원)
/// 
/// HMAC-SHA256 서명을 사용하여 안전한 JWT 토큰을 생성하고 검증합니다.
/// 액세스 토큰(1시간)과 리프레시 토큰(7일)을 지원하며,
/// Redis를 통한 세션 관리와 토큰 블랙리스트 기능을 제공합니다.
#[service(name="token")]
pub struct TokenService {
    token_repo: Arc<TokenRepository>,
}

impl TokenService {
    /// 사용자를 위한 JWT 액세스 토큰 생성 (JTI 포함)
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
        let jti = Uuid::new_v4().to_string(); // JWT ID 생성
        
        let claims = TokenClaims {
            sub: user.id_string().ok_or_else(|| {
                AppError::InternalError("사용자 ID가 없습니다".to_string())
            })?,
            jti, // JWT ID 추가
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

    /// 사용자를 위한 리프레시 토큰 생성 (JTI 포함)
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
        let jti = Uuid::new_v4().to_string(); // JWT ID 생성
        
        let claims = TokenClaims {
            sub: user.id_string().ok_or_else(|| {
                AppError::InternalError("사용자 ID가 없습니다".to_string())
            })?,
            jti, // JWT ID 추가
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

        // JWT Access Token 생성 (JTI 포함)
        let now = Utc::now();
        let access_exp = now + Duration::seconds(access_expires_in);
        let access_jti = Uuid::new_v4().to_string();
        
        let claims = TokenClaims {
            sub: user_id.to_string(),
            jti: access_jti, // JWT ID 추가
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

    /// JWT 토큰 검증 및 클레임 추출 (블랙리스트 확인 포함)
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
    /// * `AppError::AuthenticationError` - 토큰 만료, 잘못된 형식/서명, 블랙리스트에 등록됨
    /// * `AppError::InternalError` - 기타 시스템 오류
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// let claims = token_service.verify_token(token).await?;
    /// println!("User ID: {}", claims.sub);
    /// println!("Roles: {:?}", claims.roles);
    /// ```
    pub async fn verify_token(&self, token: &str) -> Result<TokenClaims, AppError> {
        // 1. 블랙리스트 확인 (JWT 파싱보다 먼저 수행)
        if let Err(e) = self.token_repo.is_token_blacklisted(token).await {
            log::warn!("블랙리스트 확인 중 오류 발생: {}", e);
            // 블랙리스트 확인 실패 시에도 토큰은 유효한 것으로 처리 (Redis 장애 대응)
        } else if self.token_repo.is_token_blacklisted(token).await.unwrap_or(false) {
            return Err(AppError::AuthenticationError("토큰이 블랙리스트에 등록되어 있습니다".to_string()));
        }

        // 2. JWT 구조 및 서명 검증
        let secret = JwtConfig::secret();
        let decoding_key = DecodingKey::from_secret(secret.as_ref());
        let validation = Validation::default();

        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    AppError::AuthenticationError("토큰이 만료되었습니다".to_string())
                },
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    AppError::AuthenticationError("유효하지 않은 토큰입니다".to_string())
                },
                _ => AppError::InternalError(format!("토큰 검증 실패: {}", e))
            })?;

        Ok(token_data.claims)
    }

    /// 동기식 토큰 검증 (블랙리스트 확인 없음 - 기존 호환성용)
    /// 
    /// # Note
    /// 
    /// 이 메서드는 기존 코드와의 호환성을 위해 유지됩니다.
    /// 새로운 코드에서는 `verify_token` (async 버전)을 사용하세요.
    pub fn verify_token_sync(&self, token: &str) -> Result<TokenClaims, AppError> {
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
    pub async fn extract_user_id(&self, token: &str) -> Result<String, AppError> {
        let claims = self.verify_token(token).await?;
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
    /// let claims = token_service.verify_token(token).await?;
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

        // 2. 새로운 Access Token 생성 (JTI 포함)
        let access_hours = std::env::var("JWT_EXPIRATION_HOURS")
            .unwrap_or_else(|_| "1".to_string())
            .parse::<i64>()
            .unwrap_or(1);
        
        // TTL 값 검증 및 최소값 보장
        let access_hours = if access_hours <= 0 { 1 } else { access_hours };
        let access_expires_in = access_hours * 3600;

        let now = Utc::now();
        let access_exp = now + Duration::seconds(access_expires_in);
        let access_jti = Uuid::new_v4().to_string(); // 새로운 JWT ID 생성
        
        let access_claims = TokenClaims {
            sub: user_id.to_string(),
            jti: access_jti, // JWT ID 추가
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

        Ok(TokenPair {
            access_token: new_access_token,
            refresh_token: Some(refresh_token.to_string()),
            expires_in: access_expires_in,
        })
    }

    /// 액세스 토큰을 블랙리스트에 추가 (상세 정보 포함)
    /// 
    /// # Arguments
    /// * `token` - 블랙리스트에 추가할 액세스 토큰
    /// * `reason` - 블랙리스트 추가 이유
    /// * `ip_address` - 요청자 IP 주소 (선택사항)
    /// * `user_agent` - 사용자 에이전트 (선택사항)
    /// 
    /// # Returns
    /// * `Ok(())` - 성공
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// // 로그아웃 시 현재 토큰을 블랙리스트에 추가
    /// use crate::repositories::tokens::token_repository::BlacklistReason;
    /// token_service.add_to_blacklist_detailed(
    ///     current_access_token, 
    ///     BlacklistReason::Logout,
    ///     Some("192.168.1.1".to_string()),
    ///     Some("Mozilla/5.0...".to_string())
    /// ).await?;
    /// ```
    pub async fn add_to_blacklist_detailed(
        &self, 
        token: &str, 
        reason: crate::repositories::tokens::token_repository::BlacklistReason,
        ip_address: Option<String>,
        user_agent: Option<String>
    ) -> Result<(), AppError> {
        // 1. 토큰에서 JTI, 사용자 ID, 만료시간 추출
        let claims = self.verify_token_sync(token)?; // 동기식 검증 사용 (블랙리스트 확인 없음)
        
        // 2. 토큰의 남은 만료시간 계산
        let now = Utc::now().timestamp();
        let ttl_seconds = (claims.exp - now).max(0) as u64; // 음수 방지
        
        if ttl_seconds == 0 {
            log::warn!("이미 만료된 토큰을 블랙리스트에 추가하려고 시도했습니다: JTI={}", claims.jti);
            return Ok(()); // 이미 만료된 토큰은 블랙리스트에 추가할 필요 없음
        }
        
        // 3. Redis 블랙리스트에 상세 정보와 함께 추가 (토큰 기반)
        self.token_repo.blacklist_token_detailed(
            token,              // 전체 토큰
            &claims.jti,        // JTI
            &claims.user_id,    // 사용자 ID
            claims.exp,         // 원래 만료시간
            reason,             // 블랙리스트 추가 이유
            ttl_seconds,        // TTL
            ip_address,         // IP 주소
            user_agent,         // User-Agent
        ).await
        .map_err(|e| AppError::InternalError(format!("토큰 블랙리스트 추가 실패: {}", e)))?;
            
        log::info!("토큰이 상세 정보와 함께 블랙리스트에 추가되었습니다: JTI={}, 사용자={}, TTL={}초", 
                   claims.jti, claims.user_id, ttl_seconds);
        Ok(())
    }

    /// 액세스 토큰을 블랙리스트에 추가 (기본 버전, 호환성 유지)
    /// 
    /// # Arguments
    /// * `token` - 블랙리스트에 추가할 액세스 토큰
    /// 
    /// # Returns
    /// * `Ok(())` - 성공
    /// 
    /// # Note
    /// 이 메서드는 기존 호환성을 위해 유지됩니다.
    /// 새로운 코드에서는 `add_to_blacklist_detailed`를 사용하세요.
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// // 로그아웃 시 현재 토큰을 블랙리스트에 추가
    /// token_service.add_to_blacklist(current_access_token).await?;
    /// ```
    pub async fn add_to_blacklist(&self, token: &str) -> Result<(), AppError> {
        use crate::repositories::tokens::token_repository::BlacklistReason;
        
        self.add_to_blacklist_detailed(
            token,
            BlacklistReason::Other("legacy_logout".to_string()),
            None,
            None,
        ).await
    }

    /// 로그아웃 처리 (세션 삭제 + 액세스 토큰 블랙리스트 추가, 상세 정보 포함)
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// * `access_token` - 현재 사용중인 액세스 토큰 (블랙리스트 추가용)
    /// * `ip_address` - 요청자 IP 주소 (선택사항)
    /// * `user_agent` - 사용자 에이전트 (선택사항)
    /// 
    /// # Note
    /// 1. Refresh Token과 모든 관련 세션 정보 삭제
    /// 2. 현재 Access Token을 상세 정보와 함께 블랙리스트에 추가
    pub async fn logout_with_blacklist_detailed(
        &self,
        user_id: &str,
        access_token: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::repositories::tokens::token_repository::BlacklistReason;
        
        // 1. 현재 액세스 토큰을 상세 정보와 함께 블랙리스트에 추가
        if let Err(e) = self.add_to_blacklist_detailed(
            access_token, 
            BlacklistReason::Logout,
            ip_address.clone(),
            user_agent.clone()
        ).await {
            log::warn!("액세스 토큰 블랙리스트 추가 실패: {}", e);
            // 블랙리스트 추가 실패해도 로그아웃은 계속 진행
        }
        
        // 2. 모든 사용자 세션 정보 삭제
        self.token_repo.delete_all_user_tokens(user_id).await?;
        
        log::info!("사용자 로그아웃 완료 - user_id: {}, 세션 삭제 및 토큰 블랙리스트 추가됨 (IP: {:?})", 
                   user_id, ip_address);
        Ok(())
    }

    /// 로그아웃 처리 (세션 삭제 + 액세스 토큰 블랙리스트 추가, 기본 버전)
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// * `access_token` - 현재 사용중인 액세스 토큰 (블랙리스트 추가용)
    /// 
    /// # Note
    /// 1. Refresh Token과 모든 관련 세션 정보 삭제
    /// 2. 현재 Access Token을 블랙리스트에 추가
    /// 
    /// 새로운 코드에서는 `logout_with_blacklist_detailed`를 사용하세요.
    pub async fn logout_with_blacklist(
        &self,
        user_id: &str,
        access_token: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.logout_with_blacklist_detailed(user_id, access_token, None, None).await
    }

    /// 기존 로그아웃 처리 (세션 정보만 삭제)
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// 
    /// # Note
    /// Refresh Token과 모든 관련 세션 정보를 삭제합니다.
    /// Access Token은 여전히 유효하지만 Refresh가 불가능해집니다.
    /// 
    /// 새로운 코드에서는 `logout_with_blacklist`를 사용하세요.
    pub async fn logout(
        &self,
        user_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 모든 사용자 토큰 및 세션 정보 삭제
        self.token_repo.delete_all_user_tokens(user_id).await?;
        
        log::info!("사용자 로그아웃 완료 - user_id: {}, 모든 세션 정보 삭제됨", user_id);
        Ok(())
    }

    /// 토큰 검증 및 상세 결과 반환 (블랙리스트 확인 포함)
    /// 
    /// # Arguments
    /// * `token` - 검증할 JWT 토큰
    /// 
    /// # Returns
    /// TokenValidation 구조체 (is_valid, claims, error_message)
    pub async fn validate_access_token(&self, token: &str) -> TokenValidation {
        match self.verify_token(token).await {
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

    /// 사용자의 모든 블랙리스트된 토큰 조회 (관리자용)
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// 
    /// # Returns
    /// 해당 사용자의 모든 블랙리스트된 토큰 정보
    pub async fn get_user_blacklisted_tokens(
        &self,
        user_id: &str,
    ) -> Result<Vec<crate::repositories::tokens::token_repository::BlacklistedTokenInfo>, Box<dyn std::error::Error>> {
        self.token_repo.get_user_blacklisted_tokens(user_id).await
    }

    /// 특정 토큰의 블랙리스트 정보 조회
    /// 
    /// # Arguments
    /// * `token` - 조회할 액세스 토큰
    /// 
    /// # Returns
    /// 블랙리스트 정보 (있는 경우)
    pub async fn get_blacklisted_token_info(
        &self,
        token: &str,
    ) -> Result<Option<crate::repositories::tokens::token_repository::BlacklistedTokenInfo>, Box<dyn std::error::Error>> {
        self.token_repo.get_blacklisted_token_info(token).await
    }
}