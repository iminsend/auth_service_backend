//! 싱글톤 의존성 주입 시스템
//!
//! 싱글톤 기반 의존성 주입 컨테이너와 자동 서비스 레지스트리를 제공합니다.
//!
//! # 주요 구성 요소
//!
//! - **ServiceLocator**: 전역 싱글톤 컨테이너로 모든 서비스/리포지토리 인스턴스 관리
//! - **자동 레지스트리**: `inventory` 기반 컴파일 타임 서비스 자동 수집
//! - **지연 초기화**: 첫 사용 시점에 인스턴스 생성
//!
//! # 사용 예제
//!
//! ```rust,ignore
//! #[service]
//! struct UserService {
//!     user_repository: Arc<UserRepository>,
//!     email_service: Arc<EmailService>,
//! }
//!
//! #[repository(collection = "users")]
//! struct UserRepository {
//!     db: Arc<Database>,
//! }
//!
//! // 사용
//! let user_service = ServiceLocator::get::<UserService>();
//! ```

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use crate::utils::display_terminal::{print_boxed_title, print_cache_initialized, print_final_summary, print_step_complete, print_step_start, print_sub_task};

/// 비즈니스 로직 서비스를 위한 공통 인터페이스
///
/// `#[service]` 매크로가 적용된 구조체가 자동으로 구현합니다.
#[async_trait]
pub trait Service: Send + Sync {
    /// 서비스의 고유 이름을 반환합니다.
    fn name(&self) -> &str;

    /// 서비스 초기화 로직을 수행합니다.
    ///
    /// # Errors
    ///
    /// 초기화 중 오류가 발생하면 에러를 반환합니다.
    async fn init(&self) -> Result<(), Box<dyn std::error::Error>>;
}

/// 데이터 액세스 리포지토리를 위한 공통 인터페이스
///
/// `#[repository]` 매크로가 적용된 구조체가 자동으로 구현합니다.
#[async_trait]
pub trait Repository: Send + Sync {
    /// 리포지토리의 고유 이름을 반환합니다.
    fn name(&self) -> &str;

    /// 연결된 MongoDB 컬렉션의 이름을 반환합니다.
    fn collection_name(&self) -> &str;

    /// 리포지토리 초기화 로직을 수행합니다.
    ///
    /// # Errors
    ///
    /// 초기화 중 오류가 발생하면 에러를 반환합니다.
    async fn init(&self) -> Result<(), Box<dyn std::error::Error>>;
}

/// 서비스 등록 정보
///
/// `#[service]` 매크로에 의해 자동 생성됩니다.
pub struct ServiceRegistration {
    /// 서비스의 고유 이름
    pub name: &'static str,
    /// 인스턴스 생성 함수
    pub constructor: fn() -> Box<dyn Any + Send + Sync>,
}

/// 리포지토리 등록 정보
///
/// `#[repository]` 매크로에 의해 자동 생성됩니다.
pub struct RepositoryRegistration {
    /// 리포지토리의 고유 이름
    pub name: &'static str,
    /// 인스턴스 생성 함수
    pub constructor: fn() -> Box<dyn Any + Send + Sync>,
}

// inventory를 통한 자동 수집
inventory::collect!(ServiceRegistration);
inventory::collect!(RepositoryRegistration);

/// 서비스 이름 매핑 캐시
static SERVICE_NAME_CACHE: Lazy<HashMap<String, &'static ServiceRegistration>> = Lazy::new(|| {
    let mut cache = HashMap::new();
    
    for registration in inventory::iter::<ServiceRegistration>() {
        let clean_name = extract_clean_name_static(registration.name);
        cache.insert(clean_name, registration);
    }
    
    print_cache_initialized("Service", cache.len());
    cache
});

/// 리포지토리 이름 매핑 캐시
static REPOSITORY_NAME_CACHE: Lazy<HashMap<String, &'static RepositoryRegistration>> = Lazy::new(|| {
    let mut cache = HashMap::new();
    
    for registration in inventory::iter::<RepositoryRegistration>() {
        let clean_name = extract_clean_name_static(registration.name);
        cache.insert(clean_name, registration);
    }
    
    print_cache_initialized("Repository", cache.len());
    cache
});

/// 등록된 이름에서 접미사를 제거하여 정규화합니다.
fn extract_clean_name_static(name: &str) -> String {
    if name.ends_with("_service") {
        name[..name.len() - 8].to_string()
    } else if name.ends_with("_repository") {
        name[..name.len() - 11].to_string()
    } else {
        name.to_string()
    }
}

/// 싱글톤 의존성 주입 컨테이너
///
/// 전체 DI 시스템의 핵심으로 다음 기능을 제공합니다:
/// - 싱글톤 인스턴스 관리
/// - 지연 초기화
/// - 순환 참조 방지
/// - Thread-safe 동시성 보장
pub struct ServiceLocator {
    /// 생성된 인스턴스들의 캐시
    instances: RwLock<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>,
    /// 현재 초기화 중인 타입들 (순환 참조 방지용)
    initializing: RwLock<HashSet<TypeId>>,
}

impl ServiceLocator {
    /// 새로운 ServiceLocator 인스턴스를 생성합니다.
    fn new() -> Self {
        Self {
            instances: RwLock::new(HashMap::new()),
            initializing: RwLock::new(HashSet::new()),
        }
    }
    
    /// 지정된 타입의 싱글톤 인스턴스를 가져옵니다.
    ///
    /// # Returns
    ///
    /// 요청된 타입의 Arc 래핑된 인스턴스
    ///
    /// # Panics
    ///
    /// - 순환 참조가 감지된 경우
    /// - 등록되지 않은 타입을 요청한 경우
    /// - 타입 불일치가 발생한 경우
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let user_service = ServiceLocator::get::<UserService>();
    /// let user_repo = ServiceLocator::get::<UserRepository>();
    /// ```
    pub fn get<T: 'static + Send + Sync>() -> Arc<T> {
        let type_id = TypeId::of::<T>();
        let type_name = std::any::type_name::<T>();
        
        // 이미 생성된 인스턴스 확인
        {
            let instances = LOCATOR.instances.read().unwrap();
            if let Some(instance) = instances.get(&type_id) {
                return instance.clone()
                    .downcast::<T>()
                    .expect("Type mismatch in ServiceLocator");
            }
        }
        
        // 순환 참조 검사
        {
            let initializing = LOCATOR.initializing.read().unwrap();
            if initializing.contains(&type_id) {
                eprintln!("❌ Circular dependency detected for type: {}", type_name);
                panic!("Circular dependency detected: {} is already being initialized", type_name);
            }
        }
        // 초기화 중임을 표시
        {
            let mut initializing = LOCATOR.initializing.write().unwrap();
            initializing.insert(type_id);
        }
        
        // 인스턴스 생성 시도
        let result = std::panic::catch_unwind(|| {
            let mut instances = LOCATOR.instances.write().unwrap();
            
            // 더블 체크
            if let Some(instance) = instances.get(&type_id) {
                return instance.clone()
                    .downcast::<T>()
                    .expect("Type mismatch in ServiceLocator");
            }
            
            // 타입 이름에서 실제 타입 이름 추출
            let clean_type_name = Self::extract_clean_type_name(type_name);
            
            // 리포지토리 찾기
            if clean_type_name.contains("Repository") {
                let entity_name = clean_type_name
                    .strip_suffix("Repository")
                    .unwrap_or(&clean_type_name)
                    .to_lowercase();
                
                if let Some(registration) = REPOSITORY_NAME_CACHE.get(&entity_name) {
                    let boxed_instance = (registration.constructor)();
                    
                    if let Ok(arc_instance) = boxed_instance.downcast::<Arc<T>>() {
                        let instance = (*arc_instance).clone();
                        instances.insert(type_id, instance.clone() as Arc<dyn Any + Send + Sync>);
                        return instance;
                    } else {
                        panic!("Type mismatch for repository: {}", registration.name);
                    }
                } else {
                    panic!("No repository found for entity: {}", entity_name);
                }
            }
            
            // 서비스 찾기
            if clean_type_name.contains("Service") {
                let entity_name = clean_type_name
                    .strip_suffix("Service")
                    .unwrap_or(&clean_type_name)
                    .to_lowercase();
                
                if let Some(registration) = SERVICE_NAME_CACHE.get(&entity_name) {
                    let boxed_instance = (registration.constructor)();
                    
                    if let Ok(arc_instance) = boxed_instance.downcast::<Arc<T>>() {
                        let instance = (*arc_instance).clone();
                        instances.insert(type_id, instance.clone() as Arc<dyn Any + Send + Sync>);
                        return instance;
                    } else {
                        panic!("Type mismatch for service: {}", registration.name);
                    }
                } else {
                    panic!("No service found for entity: {}", entity_name);
                }
            }
            
            panic!("Service not found: {}. Make sure it's registered with #[service] or #[repository] macro, or manually registered with ServiceLocator::set()", type_name);
        });
        
        // 초기화 완료 표시
        {
            let mut initializing = LOCATOR.initializing.write().unwrap();
            initializing.remove(&type_id);
        }
        
        match result {
            Ok(instance) => instance,
            Err(e) => {
                let mut initializing = LOCATOR.initializing.write().unwrap();
                initializing.remove(&type_id);
                
                eprintln!("ERROR: Failed to create instance for {}: {:?}", type_name, e);
                panic!("Failed to create instance for {}", type_name);
            }
        }
    }
    
    /// 타입 이름에서 실제 타입 이름을 추출합니다.
    fn extract_clean_type_name(type_name: &str) -> String {
        if let Some(pos) = type_name.rfind("::") {
            type_name[pos + 2..].to_string()
        } else {
            type_name.to_string()
        }
    }
    
    /// 외부에서 생성된 인스턴스를 직접 등록합니다.
    ///
    /// 매크로로 관리되지 않는 외부 컴포넌트들(Database, RedisClient 등)을
    /// 수동으로 등록할 때 사용됩니다.
    ///
    /// # Arguments
    ///
    /// * `instance` - 등록할 인스턴스 (Arc로 래핑됨)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let database = Database::connect("mongodb://localhost").await?;
    /// ServiceLocator::set(database);
    /// ```
    pub fn set<T: 'static + Send + Sync>(instance: Arc<T>) {
        let type_id = TypeId::of::<T>();
        let type_name = std::any::type_name::<T>();
        let clean_name = Self::extract_clean_type_name(type_name);
        
        println!("📦 Registering: {}", clean_name);
        
        let mut instances = LOCATOR.instances.write().unwrap();
        instances.insert(type_id, instance as Arc<dyn Any + Send + Sync>);
    }
    
    /// 모든 서비스와 리포지토리를 초기화합니다.
    ///
    /// 애플리케이션 시작 시 모든 컴포넌트를 미리 생성하여
    /// 런타임 성능을 향상시킵니다.
    ///
    /// # Errors
    ///
    /// 초기화 중 오류가 발생하면 에러를 반환합니다.
    pub async fn initialize_all() -> Result<(), Box<dyn std::error::Error>> {
        print_boxed_title("🔄 INITIALIZING SERVICE REGISTRY");
        
        // 리포지토리 초기화
        let repo_registrations: Vec<_> = inventory::iter::<RepositoryRegistration>().collect();
        let repo_count = repo_registrations.len();
        
        if repo_count > 0 {
            print_step_start(1, "Creating Repository instances");
            
            for registration in repo_registrations {
                print_sub_task(registration.name, "Creating...");
                let _boxed_instance = (registration.constructor)();
                print_sub_task(registration.name, "✓ Created");
            }
            
            print_step_complete(1, "Repository instances created", repo_count);
        }
        
        // 서비스 초기화
        let service_registrations: Vec<_> = inventory::iter::<ServiceRegistration>().collect();
        let service_count = service_registrations.len();
        
        if service_count > 0 {
            print_step_start(2, "Creating Service instances");
            
            for registration in service_registrations {
                print_sub_task(registration.name, "Creating...");
                let _boxed_instance = (registration.constructor)();
                print_sub_task(registration.name, "✓ Created");
            }
            
            print_step_complete(2, "Service instances created", service_count);
        }
        
        print_final_summary(repo_count, service_count);
        
        Ok(())
    }
}

/// 전역 서비스 로케이터 인스턴스
static LOCATOR: Lazy<ServiceLocator> = Lazy::new(ServiceLocator::new);
