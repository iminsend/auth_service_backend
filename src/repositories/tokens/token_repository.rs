use std::sync::Arc;
use serde::{Deserialize, Serialize};
use chrono::{Utc};
use singleton_macro::repository;
use crate::caching::redis::RedisClient;
use crate::core::registry::Repository;

/// JWT 토큰 관리를 위한 Repository
/// 
/// Redis를 사용하여 다음 기능을 제공합니다:
/// - Refresh Token 저장 및 검증
/// - Access Token Blacklist 관리
/// - 토큰 만료 시간 자동 관리 (TTL)
#[repository(name = "token", collection = "tokens")]
pub struct TokenRepository {
    redis: Arc<RedisClient>,
}

/// Refresh Token 정보 (최적화된 최소 정보)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenInfo {
    /// 사용자 등록 ID
    pub user_id: String,
    /// 사용자명 (세션 식별용)
    pub username: String,
    /// 인증 방식 (Local, Google 등)
    pub auth_provider: String,
    /// 로그인 일시 (Unix timestamp)
    pub login_at: i64,
    /// Refresh Token 문자열 (JWT)
    pub refresh_token: String,
    /// 만료 시간 (TTL 계산용)
    pub expires_at: i64,
    /// 로그인 IP (보안용, 선택사항)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_ip: Option<String>,
    /// 사용자 에이전트 (보안용, 선택사항)  
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

impl TokenRepository {
    /// Refresh Token 저장 (최소한의 필수 정보만)
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// * `username` - 사용자명
    /// * `auth_provider` - 인증 방식 (Local, Google 등)
    /// * `refresh_token` - 저장할 refresh token
    /// * `ttl_seconds` - TTL (초 단위)
    /// 
    /// # Example
    /// ```rust,ignore
    /// repo.store_refresh_token("user123", "jang_hoon", "Google", "refresh_token_value", 86400).await?;
    /// ```
    pub async fn store_refresh_token(
        &self,
        user_id: &str,
        username: &str,
        auth_provider: &str,
        refresh_token: &str,
        ttl_seconds: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = format!("refresh_token:{}", user_id);
        
        // TTL 값 검증 및 디버깅
        log::info!("store_refresh_token 호출됨 - user_id: {}, ttl_seconds: {}", user_id, ttl_seconds);
        
        if ttl_seconds == 0 {
            log::error!("TTL이 0입니다! user_id: {}, auth_provider: {}", user_id, auth_provider);
            return Err("TTL cannot be zero".into());
        }
        
        // 최소 TTL 값 보장 (1분)
        let safe_ttl = if ttl_seconds < 60 {
            log::warn!("TTL이 너무 작습니다 ({}초). 최소값 60초로 설정합니다.", ttl_seconds);
            60
        } else {
            ttl_seconds
        };
        
        let now = Utc::now().timestamp();
        let token_info = RefreshTokenInfo {
            user_id: user_id.to_string(),
            username: username.to_string(),
            auth_provider: auth_provider.to_string(),
            login_at: now,
            refresh_token: refresh_token.to_string(),
            expires_at: now + safe_ttl as i64,
            login_ip: None, // TODO: HTTP 요청에서 IP 추출하여 저장
            user_agent: None, // TODO: HTTP 요청에서 User-Agent 추출하여 저장
        };

        let token_json = serde_json::to_string(&token_info)?;
        self.redis.setex(&key, safe_ttl, &token_json).await?;
        
        log::info!("Refresh token 저장 완료 - user_id: {}, ttl: {}초", user_id, safe_ttl);
        Ok(())
    }

    /// Refresh Token 조회 및 검증
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// * `refresh_token` - 검증할 refresh token
    /// 
    /// # Returns
    /// * `Some(RefreshTokenInfo)` - 유효한 토큰인 경우
    /// * `None` - 토큰이 없거나 일치하지 않는 경우
    pub async fn get_refresh_token(
        &self,
        user_id: &str,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenInfo>, Box<dyn std::error::Error>> {
        let key = format!("refresh_token:{}", user_id);
        
        match self.redis.get_string(&key).await? {
            Some(token_json) => {
                let token_info: RefreshTokenInfo = serde_json::from_str(&token_json)?;
                
                // 토큰 값 검증
                if token_info.refresh_token == refresh_token {
                    // 만료 시간 검증
                    if token_info.expires_at > Utc::now().timestamp() {
                        Ok(Some(token_info))
                    } else {
                        // 만료된 토큰 삭제
                        self.redis.del(&key).await?;
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Refresh Token 삭제 (로그아웃시 사용)
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    pub async fn delete_refresh_token(
        &self,
        user_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = format!("refresh_token:{}", user_id);
        self.redis.del(&key).await?;
        Ok(())
    }

    /// Access Token을 Blacklist에 추가
    /// 
    /// # Arguments
    /// * `jti` - JWT ID (토큰의 고유 식별자)
    /// * `ttl_seconds` - TTL (남은 토큰 만료 시간과 동일하게 설정)
    /// 
    /// # Example
    /// ```rust,ignore
    /// // 로그아웃시 현재 토큰을 블랙리스트에 추가
    /// repo.blacklist_token("jwt_unique_id", 3600).await?;
    /// ```
    pub async fn blacklist_token(
        &self,
        jti: &str,
        ttl_seconds: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = format!("blacklist_token:{}", jti);
        
        // 단순히 존재 여부만 확인하므로 값은 "1"로 설정
        self.redis.setex(&key, ttl_seconds, "1").await?;
        Ok(())
    }

    /// Token이 Blacklist에 있는지 확인
    /// 
    /// # Arguments
    /// * `jti` - JWT ID
    /// 
    /// # Returns
    /// * `true` - 블랙리스트에 있음 (사용 불가)
    /// * `false` - 블랙리스트에 없음 (사용 가능)
    pub async fn is_token_blacklisted(
        &self,
        jti: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let key = format!("blacklist_token:{}", jti);
        Ok(self.redis.exists(&key).await?)
    }

    /// 사용자의 모든 세션 정보 삭제 (완전한 로그아웃)
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// 
    /// # Note
    /// 다음 정보들을 모두 삭제합니다:
    /// - Refresh Token
    /// - 사용자 캐시 정보 (user_id + email 기반)
    /// - 기타 세션 관련 데이터
    pub async fn delete_all_user_tokens(
        &self,
        user_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("사용자 모든 세션 정보 삭제 시작 - user_id: {}", user_id);
        
        // 1. Refresh Token 삭제
        let refresh_key = format!("refresh_token:{}", user_id);
        self.redis.del(&refresh_key).await?;
        log::info!("Refresh token 삭제 완료: {}", refresh_key);
        
        // 2. user:email:* 패턴에서 해당 user_id 찾아서 삭제
        let email_pattern = "user:email:*";
        let email_keys: Vec<String> = self.redis.keys(email_pattern).await?;
        let mut email_deleted = 0;
        
        for key in email_keys {
            if let Some(user_json) = self.redis.get_string(&key).await? {
                // JSON에서 user_id 확인
                if user_json.contains(&format!("\"{}\"", user_id)) || 
                   user_json.contains(&format!("\"_id\":{{\"$oid\":\"{}\"}}", user_id)) {
                    self.redis.del(&key).await?;
                    log::info!("사용자 이메일 캐시 삭제: {}", key);
                    email_deleted += 1;
                }
            }
        }
        
        // 3. 기타 user_id 기반 패턴들
        let patterns = vec![
            format!("user:{}", user_id),           // user:user_id
            format!("user:{}:*", user_id),         // user:user_id:*
            format!("user:*:{}", user_id),         // user:*:user_id
            format!("profile:{}", user_id),        // profile:user_id
            format!("session:{}", user_id),        // session:user_id
            format!("session:{}:*", user_id),      // session:user_id:*
            format!("cache:user:{}", user_id),     // cache:user:user_id
        ];
        
        let mut pattern_deleted = 0;
        for pattern in patterns {
            let keys: Vec<String> = self.redis.keys(&pattern).await?;
            if !keys.is_empty() {
                log::info!("패턴 '{}' 매칭 키들: {:?}", pattern, keys);
                self.redis.del_multiple(&keys).await?;
                pattern_deleted += keys.len();
            }
        }
        
        // 4. 안전을 위해 user_id가 포함된 모든 키 검색 및 삭제
        let user_related_keys: Vec<String> = self.redis.keys(&format!("*{}*", user_id)).await?;
        let mut additional_deleted = 0;
        
        if !user_related_keys.is_empty() {
            log::info!("사용자 ID 포함 추가 키들: {:?}", user_related_keys);
            
            // 이미 삭제한 키들 제외
            let additional_keys: Vec<String> = user_related_keys.into_iter()
                .filter(|key| !key.starts_with("refresh_token:") && !key.starts_with("user:email:"))
                .collect();
                
            if !additional_keys.is_empty() {
                self.redis.del_multiple(&additional_keys).await?;
                additional_deleted += additional_keys.len();
            }
        }
        
        let total_deleted = 1 + email_deleted + pattern_deleted + additional_deleted; // 1 = refresh_token
        log::info!("사용자 모든 세션 정보 삭제 완료 - user_id: {}, 총 {}개 키 삭제됨 (refresh: 1, email: {}, pattern: {}, additional: {})", 
                   user_id, total_deleted, email_deleted, pattern_deleted, additional_deleted);
        Ok(())
    }

    /// 메모리 사용량 통계 조회 (관리자용)
    /// 
    /// Redis에 저장된 토큰 관련 데이터의 메모리 사용량을 분석합니다.
    /// 
    /// # Returns
    /// 
    /// * `Ok((user_cache_count, session_count, estimated_memory_mb))` - 통계 정보
    pub async fn get_memory_stats(&self) -> Result<(u64, u64, f64), Box<dyn std::error::Error>> {
        // 사용자 캐시 수 조회
        let user_cache_keys: Vec<String> = self.redis.keys("user:email:*").await?;
        let user_cache_count = user_cache_keys.len() as u64;
        
        // 세션 수 조회  
        let session_keys: Vec<String> = self.redis.keys("refresh_token:*").await?;
        let session_count = session_keys.len() as u64;
        
        // 추정 메모리 사용량 (MB)
        let estimated_memory_mb = (user_cache_count as f64 * 1.0) + (session_count as f64 * 0.6);
        
        Ok((user_cache_count, session_count, estimated_memory_mb))
    }

    /// 만료된 토큰들 정리 (선택적 - Redis TTL이 자동 처리하지만 수동 정리시 사용)
    /// 
    /// # Note
    /// 일반적으로 Redis TTL이 자동으로 처리하므로 필요시에만 사용
    pub async fn cleanup_expired_tokens(&self) -> Result<u32, Box<dyn std::error::Error>> {
        let mut cleaned_count = 0u32;
        
        // Refresh token 패턴으로 검색
        let refresh_keys: Vec<String> = self.redis.keys("refresh_token:*").await?;
        
        for key in refresh_keys {
            if let Some(token_json) = self.redis.get_string(&key).await? {
                if let Ok(token_info) = serde_json::from_str::<RefreshTokenInfo>(&token_json) {
                    if token_info.expires_at <= Utc::now().timestamp() {
                        self.redis.del(&key).await?;
                        cleaned_count += 1;
                    }
                }
            }
        }
        
        Ok(cleaned_count)
    }
}
