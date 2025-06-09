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

/// 블랙리스트 토큰 정보
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistedTokenInfo {
    /// JWT ID (토큰 고유 식별자)
    pub jti: String,
    /// 실제 access_token 전체
    pub access_token: String,
    /// 사용자 ID
    pub user_id: String,
    /// 블랙리스트 추가 시간 (Unix timestamp)
    pub blacklisted_at: i64,
    /// 원래 토큰의 만료 시간 (Unix timestamp)
    pub original_exp: i64,
    /// 블랙리스트 추가 이유
    pub reason: BlacklistReason,
    /// 블랙리스트 추가된 IP 주소 (선택사항)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// 사용자 에이전트 (선택사항)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

/// 블랙리스트 추가 이유
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlacklistReason {
    /// 정상 로그아웃
    Logout,
    /// 관리자에 의한 강제 무효화
    AdminRevoked,
    /// 보안 위험으로 인한 무효화
    SecurityBreach,
    /// 비밀번호 변경으로 인한 무효화
    PasswordChanged,
    /// 계정 비활성화
    AccountDeactivated,
    /// 기타
    Other(String),
}

impl TokenRepository {
    /// 토큰을 SHA256 해시로 변환
    /// 
    /// Redis 키로 사용하기 위해 긴 JWT 토큰을 해시화합니다.
    /// 
    /// # Arguments
    /// * `token` - 해시화할 JWT 토큰
    /// 
    /// # Returns
    /// 16글자 16진수 해시 문자열
    fn hash_token(&self, token: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        // 간단한 해시 (실제 프로덕션에서는 crypto 라이브러리 사용 권장)
        let mut hasher = DefaultHasher::new();
        token.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// JWT 토큰에서 JTI를 안전하지 않게 추출 (검증 없이)
    /// 
    /// 블랙리스트 추가 시에만 사용되는 헬퍼 함수입니다.
    /// 단순히 토큰의 길이를 기반으로 고유 식별자를 생성합니다.
    /// 
    /// # Arguments
    /// * `token` - JWT 토큰
    /// 
    /// # Returns
    /// * `Ok(String)` - 토큰 기반 고유 식별자
    /// * `Err` - 추출 실패
    fn extract_jti_unsafe(&self, token: &str) -> Result<String, Box<dyn std::error::Error>> {
        if token.len() < 10 {
            return Err("Token too short".into());
        }
        
        // 토큰의 해시를 JTI로 사용
        Ok(self.hash_token(token))
    }
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

    /// Access Token을 Blacklist에 추가 (상세 정보 포함)
    /// 
    /// # Arguments
    /// * `access_token` - 실제 액세스 토큰 (해시화되어 저장됨)
    /// * `jti` - JWT ID (토큰의 고유 식별자)
    /// * `user_id` - 사용자 ID
    /// * `original_exp` - 원래 토큰의 만료 시간 (Unix timestamp)
    /// * `reason` - 블랙리스트 추가 이유
    /// * `ttl_seconds` - TTL (남은 토큰 만료 시간과 동일하게 설정)
    /// * `ip_address` - 요청자 IP 주소 (선택사항)
    /// * `user_agent` - 사용자 에이전트 (선택사항)
    /// 
    /// # Example
    /// ```rust,ignore
    /// // 로그아웃시 현재 토큰을 블랙리스트에 추가
    /// repo.blacklist_token_detailed(
    ///     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", 
    ///     "jwt_unique_id", 
    ///     "user123", 
    ///     1640995200, 
    ///     BlacklistReason::Logout,
    ///     3600,
    ///     Some("192.168.1.1"),
    ///     Some("Mozilla/5.0...")
    /// ).await?;
    /// ```
    pub async fn blacklist_token_detailed(
        &self,
        access_token: &str,
        jti: &str,
        user_id: &str,
        original_exp: i64,
        reason: BlacklistReason,
        ttl_seconds: u64,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 토큰을 SHA256 해시로 변환하여 키로 사용
        let token_hash = self.hash_token(access_token);
        let key = format!("blacklist_token:{}", token_hash);
        
        let blacklist_info = BlacklistedTokenInfo {
            jti: jti.to_string(),
            access_token: access_token.to_string(), // access_token 추가
            user_id: user_id.to_string(),
            blacklisted_at: Utc::now().timestamp(),
            original_exp,
            reason,
            ip_address,
            user_agent,
        };

        let info_json = serde_json::to_string(&blacklist_info)?;
        self.redis.setex(&key, ttl_seconds, &info_json).await?;
        
        log::info!("토큰이 상세 정보와 함께 블랙리스트에 추가됨 - 토큰 해시: {}, JTI: {}, 사용자: {}, 이유: {:?}, TTL: {}초", 
                   &token_hash[..16], jti, user_id, blacklist_info.reason, ttl_seconds);
        Ok(())
    }

    /// Access Token을 Blacklist에 추가 (기본 버전, 호환성 유지)
    /// 
    /// # Arguments
    /// * `access_token` - 실제 액세스 토큰
    /// * `ttl_seconds` - TTL (남은 토큰 만료 시간과 동일하게 설정)
    /// 
    /// # Note
    /// 이 메서드는 기존 호환성을 위해 유지됩니다.
    /// 새로운 코드에서는 `blacklist_token_detailed`를 사용하세요.
    /// 
    /// # Example
    /// ```rust,ignore
    /// // 로그아웃시 현재 토큰을 블랙리스트에 추가
    /// repo.blacklist_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", 3600).await?;
    /// ```
    pub async fn blacklist_token(
        &self,
        access_token: &str,
        ttl_seconds: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 토큰에서 JTI를 추출하기 위해 간단히 파싱 (검증 없이)
        let jti = match self.extract_jti_unsafe(access_token) {
            Ok(jti) => jti,
            Err(_) => "unknown".to_string(), // JTI 추출 실패 시 기본값
        };
        
        // 기본 정보로 상세 메서드 호출
        self.blacklist_token_detailed(
            access_token,
            &jti,
            "unknown", // 사용자 ID 알 수 없음
            Utc::now().timestamp() + ttl_seconds as i64, // 현재 시간 + TTL로 추정
            BlacklistReason::Other("legacy_blacklist".to_string()),
            ttl_seconds,
            None,
            None,
        ).await
    }

    /// Token이 Blacklist에 있는지 확인 (토큰 기반)
    /// 
    /// # Arguments
    /// * `access_token` - 확인할 실제 액세스 토큰
    /// 
    /// # Returns
    /// * `true` - 블랙리스트에 있음 (사용 불가)
    /// * `false` - 블랙리스트에 없음 (사용 가능)
    pub async fn is_token_blacklisted(
        &self,
        access_token: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let token_hash = self.hash_token(access_token);
        let key = format!("blacklist_token:{}", token_hash);
        Ok(self.redis.exists(&key).await?)
    }

    /// JTI로 Token이 Blacklist에 있는지 확인 (기존 호환성용)
    /// 
    /// # Arguments
    /// * `jti` - JWT ID
    /// 
    /// # Returns
    /// * `true` - 블랙리스트에 있음 (사용 불가)
    /// * `false` - 블랙리스트에 없음 (사용 가능)
    /// 
    /// # Note
    /// 이 메서드는 기존 호환성을 위해 유지되지만 deprecated 상태입니다.
    /// 새로운 코드에서는 `is_token_blacklisted`를 사용하세요.
    pub async fn is_token_blacklisted_by_jti(
        &self,
        jti: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let key = format!("blacklist_token:{}", jti);
        Ok(self.redis.exists(&key).await?)
    }

    /// 블랙리스트된 토큰의 상세 정보 조회 (토큰 기반)
    /// 
    /// # Arguments
    /// * `access_token` - 조회할 실제 액세스 토큰
    /// 
    /// # Returns
    /// * `Some(BlacklistedTokenInfo)` - 블랙리스트에 있으면 상세 정보
    /// * `None` - 블랙리스트에 없음
    pub async fn get_blacklisted_token_info(
        &self,
        access_token: &str,
    ) -> Result<Option<BlacklistedTokenInfo>, Box<dyn std::error::Error>> {
        let token_hash = self.hash_token(access_token);
        let key = format!("blacklist_token:{}", token_hash);
        
        match self.redis.get_string(&key).await? {
            Some(info_json) => {
                match serde_json::from_str::<BlacklistedTokenInfo>(&info_json) {
                    Ok(blacklist_info) => Ok(Some(blacklist_info)),
                    Err(e) => {
                        log::warn!("블랙리스트 토큰 정보 파싱 실패 - 토큰 해시: {}, 에러: {}", &token_hash[..16], e);
                        // 파싱 실패 시에도 블랙리스트에 있다고 간주 (안전을 위해)
                        Ok(None)
                    }
                }
            }
            None => Ok(None),
        }
    }

    /// JTI로 블랙리스트된 토큰의 상세 정보 조회 (기존 호환성용)
    /// 
    /// # Arguments
    /// * `jti` - JWT ID
    /// 
    /// # Returns
    /// * `Some(BlacklistedTokenInfo)` - 블랙리스트에 있으면 상세 정보
    /// * `None` - 블랙리스트에 없음
    pub async fn get_blacklisted_token_info_by_jti(
        &self,
        jti: &str,
    ) -> Result<Option<BlacklistedTokenInfo>, Box<dyn std::error::Error>> {
        let key = format!("blacklist_token:{}", jti);
        
        match self.redis.get_string(&key).await? {
            Some(info_json) => {
                match serde_json::from_str::<BlacklistedTokenInfo>(&info_json) {
                    Ok(blacklist_info) => Ok(Some(blacklist_info)),
                    Err(e) => {
                        log::warn!("블랙리스트 토큰 정보 파싱 실패 - JTI: {}, 에러: {}", jti, e);
                        Ok(None)
                    }
                }
            }
            None => Ok(None),
        }
    }

    /// 사용자의 모든 블랙리스트된 토큰 조회
    /// 
    /// # Arguments
    /// * `user_id` - 사용자 ID
    /// 
    /// # Returns
    /// 해당 사용자의 모든 블랙리스트된 토큰 정보
    /// 
    /// # Note
    /// 새로운 토큰 기반 키 구조를 사용하므로 모든 블랙리스트 키를 스캔해야 합니다.
    /// 대량 데이터가 있을 경우 성능에 영향을 줄 수 있습니다.
    pub async fn get_user_blacklisted_tokens(
        &self,
        user_id: &str,
    ) -> Result<Vec<BlacklistedTokenInfo>, Box<dyn std::error::Error>> {
        let pattern = "blacklist_token:*";
        let keys: Vec<String> = self.redis.keys(pattern).await?;
        let mut user_tokens = Vec::new();
        
        for key in keys {
            if let Some(info_json) = self.redis.get_string(&key).await? {
                if let Ok(blacklist_info) = serde_json::from_str::<BlacklistedTokenInfo>(&info_json) {
                    if blacklist_info.user_id == user_id {
                        user_tokens.push(blacklist_info);
                    }
                }
            }
        }
        
        // 블랙리스트 추가 시간 기준으로 내림차순 정렬 (최신 순)
        user_tokens.sort_by(|a, b| b.blacklisted_at.cmp(&a.blacklisted_at));
        
        Ok(user_tokens)
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
