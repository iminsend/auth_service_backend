//! RSA 키 관리 서비스
//!
//! 마이크로서비스 간 RSA 인증을 위한 공개키 관리 서비스입니다.
//! MongoDB에 등록된 서비스들의 공개키를 관리하고 검증합니다.
//!
//! # 특징
//!
//! - 동적 공개키 등록 및 관리
//! - 서비스별 키 상태 관리 (활성/비활성)
//! - 만료된 키 자동 정리
//! - 싱글톤 패턴으로 성능 최적화
//!
//! # 보안
//!
//! - RSA 공개키 형식 검증
//! - 서비스 이름 중복 방지
//! - 키 만료 시간 관리
//! - 신뢰할 수 있는 키만 허용

use mongodb::{Collection, bson::doc};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use once_cell::sync::OnceCell;
use crate::core::registry::ServiceLocator;
use crate::db::Database;
use rsa::pkcs8::DecodePublicKey;

/// 등록된 RSA 공개키 정보
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredRsaKey {
    /// 고유 식별자
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<mongodb::bson::oid::ObjectId>,
    
    /// 서비스 이름 (고유)
    pub service_name: String,
    
    /// RSA 공개키 (PEM 형식)
    pub public_key: String,
    
    /// 서비스 추가 정보
    pub service_info: Option<serde_json::Value>,
    
    /// 등록 시간
    pub created_at: DateTime<Utc>,
    
    /// 마지막 수정 시간
    pub updated_at: DateTime<Utc>,
    
    /// 키 활성 상태
    pub is_active: bool,
    
    /// 키 만료 시간 (옵션)
    pub expires_at: Option<DateTime<Utc>>,
    
    /// 등록한 관리자 정보
    pub registered_by: Option<String>,
}

/// RSA 서비스
///
/// 마이크로서비스 간 인증을 위한 RSA 공개키 관리를 담당하는 싱글톤 서비스입니다.
/// MongoDB를 사용하여 등록된 서비스들의 공개키를 저장하고 관리합니다.
pub struct RsaService {
    /// RSA 키 컬렉션
    collection: Collection<RegisteredRsaKey>,
}

/// 싱글톤 인스턴스 저장소
static RSA_SERVICE_INSTANCE: OnceCell<Arc<RsaService>> = OnceCell::new();

impl RsaService {
    /// 공개키 데이터를 정리합니다 (NUL byte 및 잘못된 문자 제거)
    ///
    /// # Arguments
    ///
    /// * `public_key` - 원본 공개키 문자열
    ///
    /// # Returns
    ///
    /// 정리된 공개키 문자열
    fn sanitize_public_key(public_key: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // 1. NUL byte 제거
        let cleaned = public_key.replace('\0', "");
        
        // 2. 다른 제어 문자 제거 (CR, LF 제외)
        let cleaned: String = cleaned
            .chars()
            .filter(|&c| c == '\r' || c == '\n' || c >= ' ')
            .collect();
        
        // 3. 공백 문자 정리 (앞뒤 공백 제거, 내부 줄바꿈 정리)
        let cleaned = cleaned.trim();
        
        // 4. PEM 형식 검증 및 정리
        if !cleaned.contains("-----BEGIN") || !cleaned.contains("-----END") {
            return Err("Invalid PEM format: Missing BEGIN/END markers".into());
        }
        
        // 5. 줄바꿈 정규화 (Windows CRLF -> Unix LF)
        let cleaned = cleaned.replace("\r\n", "\n");
        
        // 6. 빈 줄 제거 (PEM 헤더와 푸터 사이의 불필요한 공백)
        let lines: Vec<&str> = cleaned.lines().collect();
        let mut result_lines = Vec::new();
        
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            result_lines.push(trimmed);
        }
        
        // 7. 최종 PEM 형식으로 재조립
        let result = result_lines.join("\n");
        
        log::debug!("🔧 Sanitized public key: {} chars -> {} chars", public_key.len(), result.len());
        
        Ok(result)
    }

    /// 싱글톤 인스턴스를 가져옵니다.
    ///
    /// 첫 호출 시 MongoDB 연결을 설정하여 인스턴스를 생성하고,
    /// 이후 호출에서는 캐시된 인스턴스를 반환합니다.
    pub fn instance() -> Arc<Self> {
        RSA_SERVICE_INSTANCE
            .get_or_init(|| {
                Arc::new(Self::new())
            })
            .clone()
    }

    /// 새로운 RSA 서비스 인스턴스를 생성합니다.
    fn new() -> Self {
        let database = ServiceLocator::get::<Database>();
        let collection = database.get_database()
            .collection::<RegisteredRsaKey>("rsa_keys");

        Self {
            collection,
        }
    }

    /// 새로운 공개키를 등록합니다.
    ///
    /// # Arguments
    ///
    /// * `service_name` - 서비스 이름 (고유해야 함)
    /// * `public_key` - RSA 공개키 (PEM 형식)
    /// * `service_info` - 추가 서비스 정보 (옵션)
    ///
    /// # Errors
    ///
    /// - 공개키 형식이 올바르지 않은 경우
    /// - 데이터베이스 오류
    pub async fn register_public_key(
        &self,
        service_name: String,
        public_key: String,
        service_info: Option<serde_json::Value>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 1. 공개키 전처리 - NUL byte 및 잘못된 문자 제거
        let cleaned_public_key = Self::sanitize_public_key(&public_key)?;
        
        // 2. 공개키 형식 검증
        if let Err(e) = rsa::RsaPublicKey::from_public_key_pem(&cleaned_public_key) {
            return Err(format!("Invalid RSA public key format: {}", e).into());
        }

        // 3. 기존 서비스 확인 및 업데이트 또는 새로 등록
        let existing = self.collection
            .find_one(doc! { "service_name": &service_name })
            .await?;

        let now = Utc::now();

        if let Some(mut existing_key) = existing {
            // 기존 서비스가 있으면 업데이트
            existing_key.public_key = cleaned_public_key;
            existing_key.service_info = service_info;
            existing_key.updated_at = now;
            existing_key.is_active = true; // 재등록 시 활성화

            self.collection
                .replace_one(
                    doc! { "service_name": &service_name },
                    &existing_key
                )
                .await?;

            log::info!("✅ Updated existing public key for service: {}", service_name);
        } else {
            // 새 서비스 등록
            let new_key = RegisteredRsaKey {
                id: None,
                service_name: service_name.clone(),
                public_key: cleaned_public_key,
                service_info,
                created_at: now,
                updated_at: now,
                is_active: true,
                expires_at: None,
                registered_by: Some("system".to_string()),
            };

            self.collection.insert_one(new_key).await?;
            log::info!("✅ Successfully registered new public key for service: {}", service_name);
        }

        Ok(())
    }

    /// 등록된 서비스 목록을 조회합니다.
    ///
    /// # Returns
    ///
    /// 등록된 서비스 이름 목록
    pub async fn get_registered_services(&self) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let mut cursor = self.collection
            .find(doc! { "is_active": true })
            .await?;

        let mut services = Vec::new();
        use futures_util::StreamExt;
        
        while let Some(key) = cursor.next().await {
            match key {
                Ok(key) => services.push(key.service_name),
                Err(e) => return Err(e.into()),
            }
        }

        Ok(services)
    }

    /// 모든 키 정보를 조회합니다 (관리용).
    ///
    /// # Returns
    ///
    /// 모든 등록된 키 정보 목록
    pub async fn get_all_keys(&self) -> Result<Vec<RegisteredRsaKey>, Box<dyn std::error::Error + Send + Sync>> {
        let mut cursor = self.collection.find(doc! {}).await?;
        
        use futures_util::StreamExt;
        let mut keys = Vec::new();
        
        while let Some(key) = cursor.next().await {
            match key {
                Ok(key) => keys.push(key),
                Err(e) => return Err(e.into()),
            }
        }
        
        Ok(keys)
    }

    /// 특정 서비스의 키를 비활성화합니다.
    ///
    /// # Arguments
    ///
    /// * `service_name` - 비활성화할 서비스 이름
    pub async fn deactivate_key(&self, service_name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let result = self.collection
            .update_one(
                doc! { "service_name": service_name },
                doc! { 
                    "$set": { 
                        "is_active": false, 
                        "updated_at": mongodb::bson::DateTime::now()
                    } 
                }
            )
            .await?;

        if result.matched_count == 0 {
            return Err(format!("Service '{}' not found", service_name).into());
        }

        log::info!("🔒 Deactivated RSA key for service: {}", service_name);
        Ok(())
    }

    /// 특정 서비스의 키를 활성화합니다.
    ///
    /// # Arguments
    ///
    /// * `service_name` - 활성화할 서비스 이름
    pub async fn activate_key(&self, service_name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let result = self.collection
            .update_one(
                doc! { "service_name": service_name },
                doc! { 
                    "$set": { 
                        "is_active": true, 
                        "updated_at": mongodb::bson::DateTime::now()
                    } 
                }
            )
            .await?;

        if result.matched_count == 0 {
            return Err(format!("Service '{}' not found", service_name).into());
        }

        log::info!("🔓 Activated RSA key for service: {}", service_name);
        Ok(())
    }

    /// 만료된 키들을 정리합니다.
    ///
    /// # Returns
    ///
    /// 삭제된 키의 개수
    pub async fn cleanup_expired_keys(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let now = mongodb::bson::DateTime::now();
        
        let result = self.collection
            .delete_many(doc! {
                "expires_at": { "$lt": now },
                "is_active": false
            })
            .await?;

        log::info!("🧹 Cleaned up {} expired RSA keys", result.deleted_count);
        Ok(result.deleted_count)
    }

    /// 신뢰할 수 있는 공개키를 조회합니다.
    ///
    /// # Arguments
    ///
    /// * `service_name` - 조회할 서비스 이름
    ///
    /// # Returns
    ///
    /// 공개키 바이트 배열 (PEM 형식)
    pub async fn get_trusted_public_key(&self, service_name: &str) -> Option<Vec<u8>> {
        match self.collection
            .find_one(doc! { 
                "service_name": service_name,
                "is_active": true 
            })
            .await
        {
            Ok(Some(key)) => {
                log::info!("📋 Found trusted public key for service: {}", service_name);
                Some(key.public_key.into_bytes())
            },
            Ok(None) => {
                log::warn!("⚠️ No trusted public key found for service: {}", service_name);
                None
            },
            Err(e) => {
                log::error!("❌ Failed to query trusted public key for {}: {}", service_name, e);
                None
            }
        }
    }

    /// 특정 서비스의 키 정보를 업데이트합니다.
    ///
    /// # Arguments
    ///
    /// * `service_name` - 업데이트할 서비스 이름
    /// * `new_public_key` - 새로운 공개키 (옵션)
    /// * `new_service_info` - 새로운 서비스 정보 (옵션)
    /// * `expires_at` - 만료 시간 설정 (옵션)
    pub async fn update_key(
        &self,
        service_name: &str,
        new_public_key: Option<String>,
        new_service_info: Option<serde_json::Value>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut update_doc = doc! {
            "updated_at": mongodb::bson::DateTime::now()
        };

        // 새로운 공개키가 제공되면 형식 검증 후 업데이트
        if let Some(public_key) = new_public_key {
            let cleaned_public_key = Self::sanitize_public_key(&public_key)?;
            if let Err(e) = rsa::RsaPublicKey::from_public_key_pem(&cleaned_public_key) {
                return Err(format!("Invalid RSA public key format: {}", e).into());
            }
            update_doc.insert("public_key", cleaned_public_key);
        }

        if let Some(service_info) = new_service_info {
            update_doc.insert("service_info", mongodb::bson::to_bson(&service_info)?);
        }

        if let Some(expires_at) = expires_at {
            update_doc.insert("expires_at", mongodb::bson::DateTime::now());
        }

        let result = self.collection
            .update_one(
                doc! { "service_name": service_name },
                doc! { "$set": update_doc }
            )
            .await?;

        if result.matched_count == 0 {
            return Err(format!("Service '{}' not found", service_name).into());
        }

        log::info!("✅ Updated RSA key for service: {}", service_name);
        Ok(())
    }

    /// 서비스별 키 사용 통계를 조회합니다.
    ///
    /// # Returns
    ///
    /// 서비스별 통계 정보
    pub async fn get_key_statistics(&self) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let total_keys = self.collection.count_documents(doc! {}).await?;
        let active_keys = self.collection.count_documents(doc! { "is_active": true }).await?;
        let inactive_keys = total_keys - active_keys;

        let now = mongodb::bson::DateTime::now();
        let expired_keys = self.collection.count_documents(doc! {
            "expires_at": { "$lt": now }
        }).await?;

        Ok(serde_json::json!({
            "total_keys": total_keys,
            "active_keys": active_keys,
            "inactive_keys": inactive_keys,
            "expired_keys": expired_keys,
            "generated_at": Utc::now()
        }))
    }
}

/// 서비스 레지스트리 생성자 함수
fn rsa_service_constructor() -> Box<dyn std::any::Any + Send + Sync> {
    Box::new(RsaService::instance() as Arc<dyn std::any::Any + Send + Sync>)
}

/// 전역 서비스 레지스트리에 RSA 서비스를 등록합니다.
inventory::submit! {
    crate::core::registry::ServiceRegistration {
        name: "rsa_service", 
        constructor: rsa_service_constructor,
    }
}
