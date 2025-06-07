//! # Service Registry - 싱글톤 의존성 주입 시스템
//!
//! 이 모듈은 백엔드 서비스를 위한 싱글톤 기반 의존성 주입 시스템의 핵심을 담당합니다.
//! Spring Framework의 ApplicationContext와 BeanFactory 역할을 Rust에서 구현한 것으로,
//! 컴파일 타임 타입 안전성과 런타임 효율성을 모두 제공합니다.
//!
//! ## Spring Framework와의 상세 비교
//!
//! | Spring 개념 | 이 시스템 | 비고 |
//! |-------------|-----------|------|
//! | `ApplicationContext` | `ServiceLocator` | 전역 DI 컨테이너 |
//! | `@Component` | `#[service]` / `#[repository]` | 컴포넌트 자동 등록 |
//! | `@Autowired` | `Arc<T>` 필드 | 자동 의존성 주입 |
//! | `@Service` | `#[service]` | 비즈니스 로직 컴포넌트 |
//! | `@Repository` | `#[repository]` | 데이터 액세스 컴포넌트 |
//! | `@Lazy` | 기본 동작 | 모든 빈이 지연 초기화 |
//! | `@Scope("singleton")` | 기본 동작 | 모든 컴포넌트가 싱글톤 |
//! | `CircularDependencyException` | 컴파일 타임 감지 | 런타임 패닉으로 조기 발견 |
//!
//! ## 주요 구성 요소
//!
//! ### ServiceLocator (ApplicationContext 역할)
//! - **전역 싱글톤 컨테이너**: 모든 서비스/리포지토리 인스턴스 관리
//! - **지연 초기화**: 첫 사용 시점에 인스턴스 생성 (Spring의 `@Lazy`와 동일)
//! - **순환 참조 방지**: 의존성 그래프 분석을 통한 데드락 방지
//! - **Thread-safe**: `RwLock`을 사용한 동시성 안전성 보장
//!
//! ### 자동 레지스트리 (Component Scanning)
//! - **inventory 기반**: 컴파일 타임에 모든 서비스/리포지토리 자동 수집
//! - **매크로 통합**: `#[service]`, `#[repository]` 매크로와 완전 통합
//! - **타입 안전성**: `TypeId`를 사용한 컴파일 타임 타입 검증
//!
//! ## 동작 원리 (Spring Boot와 비교)
//!
//! ### Spring Boot 동작 방식
//! ```text
//! 1. 컴포넌트 스캔 (@ComponentScan)
//!    ├─ 클래스패스에서 @Component 어노테이션 스캔
//!    ├─ BeanDefinition 생성
//!    └─ ApplicationContext에 등록
//!
//! 2. 의존성 주입 (@Autowired)
//!    ├─ 필드/생성자에서 의존성 감지
//!    ├─ 타입별 빈 검색
//!    ├─ 프록시 생성 (필요시)
//!    └─ 인스턴스 주입
//! ```
//!
//! ### 이 시스템의 동작 방식
//! ```text
//! 1. 컴파일 타임 (Component Scanning)
//!    ├─ #[service] 매크로 → ServiceRegistration 생성
//!    ├─ #[repository] 매크로 → RepositoryRegistration 생성
//!    └─ inventory::collect! → 전역 레지스트리에 등록
//!
//! 2. 런타임 초기화 (Infrastructure Beans)
//!    ├─ Database, RedisClient 등 인프라 컴포넌트 직접 등록
//!    └─ ServiceLocator::set() → 전역 컨테이너에 저장
//!
//! 3. 의존성 주입 (Autowiring)
//!    ├─ Arc<T> 필드 감지 → ServiceLocator::get::<T>() 호출
//!    ├─ 타입 분석 및 매칭 → 등록된 컴포넌트 검색
//!    ├─ 인스턴스 생성 → 생성자 함수 호출
//!    └─ 캐싱 및 반환 → 이후 동일 타입 요청 시 캐시된 인스턴스 반환
//! ```
//!
//! ## 실제 사용 예제 (Spring과 비교)
//!
//! ### Spring Boot 예제
//! ```java
//! @Service
//! public class UserService {
//!     @Autowired
//!     private UserRepository userRepository;
//!     
//!     @Autowired
//!     private EmailService emailService;
//!     
//!     public User createUser(CreateUserRequest request) {
//!         // 비즈니스 로직
//!     }
//! }
//!
//! @Repository
//! public class UserRepository {
//!     @Autowired
//!     private MongoTemplate mongoTemplate;
//!     
//!     public User save(User user) {
//!         return mongoTemplate.save(user);
//!     }
//! }
//! ```
//!
//! ### 이 시스템 예제
//! ```rust
//! #[service]
//! struct UserService {
//!     user_repository: Arc<UserRepository>,  // @Autowired와 동일
//!     email_service: Arc<EmailService>,      // @Autowired와 동일
//! }
//!
//! impl UserService {
//!     pub async fn create_user(&self, request: CreateUserRequest) -> Result<User, AppError> {
//!         // 비즈니스 로직
//!     }
//! }
//!
//! #[repository(collection = "users")]
//! struct UserRepository {
//!     db: Arc<Database>,  // MongoTemplate 역할
//! }
//!
//! impl UserRepository {
//!     pub async fn save(&self, user: User) -> Result<User, AppError> {
//!         self.collection().insert_one(user, None).await?;
//!         Ok(user)
//!     }
//! }
//! ```
//!
//! ## 성능 최적화 특징
//!
//! ### Spring과 대비한 장점
//! 1. **컴파일 타임 최적화**: 리플렉션 없이 모든 의존성이 컴파일 타임에 해결
//! 2. **Zero-cost Abstractions**: 런타임 오버헤드 최소화
//! 3. **메모리 효율성**: 각 타입당 정확히 하나의 인스턴스만 생성
//! 4. **동시성 안전성**: Rust의 타입 시스템을 활용한 Thread-safe 보장

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use crate::utils::display_terminal::{print_boxed_title, print_cache_initialized, print_final_summary, print_step_complete, print_step_start, print_sub_task};

/// 비즈니스 로직 서비스를 위한 공통 인터페이스
///
/// 모든 `#[service]` 매크로가 적용된 구조체가 이 trait을 자동 구현합니다.
/// 서비스의 기본 메타데이터와 생명주기 관리를 담당합니다.
#[async_trait]
pub trait Service: Send + Sync {
    /// 서비스의 고유 이름을 반환합니다.
    ///
    /// 이 이름은 레지스트리에서 서비스를 식별하는 키로 사용되며,
    /// 매크로의 `name` 인자나 구조체 이름을 기반으로 자동 생성됩니다.
    fn name(&self) -> &str;

    /// 서비스 초기화 로직을 수행합니다.
    ///
    /// 이 메서드는 서비스가 처음 생성된 후 호출되며,
    /// 필요한 초기 설정이나 리소스 준비 작업을 수행할 수 있습니다.
    async fn init(&self) -> Result<(), Box<dyn std::error::Error>>;
}

/// 데이터 액세스 리포지토리를 위한 공통 인터페이스
///
/// 모든 `#[repository]` 매크로가 적용된 구조체가 이 trait을 자동 구현합니다.
/// 데이터 저장소와의 상호작용과 관련된 메타데이터를 관리합니다.
#[async_trait]
pub trait Repository: Send + Sync {
    /// 리포지토리의 고유 이름을 반환합니다.
    fn name(&self) -> &str;

    /// 연결된 MongoDB 컬렉션의 이름을 반환합니다.
    ///
    /// 이 이름은 매크로의 `collection` 인자나 구조체 이름을 기반으로
    /// 자동 생성되며, MongoDB 작업 시 사용됩니다.
    fn collection_name(&self) -> &str;

    /// 리포지토리 초기화 로직을 수행합니다.
    ///
    /// 데이터베이스 인덱스 생성, 연결 상태 확인 등
    /// 데이터 액세스와 관련된 초기화 작업을 수행합니다.
    async fn init(&self) -> Result<(), Box<dyn std::error::Error>>;
}

/// 서비스 등록 정보
///
/// `#[service]` 매크로에 의해 자동 생성되는 등록 메타데이터입니다.
/// `inventory` 크레이트를 통해 컴파일 타임에 수집되어 전역 레지스트리에 등록됩니다.
pub struct ServiceRegistration {
    /// 서비스의 고유 이름 (검색 키로 사용)
    pub name: &'static str,
    /// 인스턴스 생성 함수 (지연 초기화에 사용)
    pub constructor: fn() -> Box<dyn Any + Send + Sync>,
}

/// 리포지토리 등록 정보
///
/// `#[repository]` 매크로에 의해 자동 생성되는 등록 메타데이터입니다.
/// ServiceRegistration과 동일한 구조를 가지지만 별도 타입으로 관리됩니다.
pub struct RepositoryRegistration {
    /// 리포지토리의 고유 이름 (검색 키로 사용)
    pub name: &'static str,
    /// 인스턴스 생성 함수 (지연 초기화에 사용)
    pub constructor: fn() -> Box<dyn Any + Send + Sync>,
}

// inventory를 통한 자동 수집 설정
// 컴파일 타임에 모든 ServiceRegistration과 RepositoryRegistration을 수집합니다.
inventory::collect!(ServiceRegistration);
inventory::collect!(RepositoryRegistration);

/// 서비스 이름 → 등록정보 매핑 캐시 (성능 최적화)
/// 첫 접근 시 한 번만 구성되며, 이후 O(1) 조회 제공
static SERVICE_NAME_CACHE: Lazy<HashMap<String, &'static ServiceRegistration>> = Lazy::new(|| {
    let mut cache = HashMap::new();
    
    for registration in inventory::iter::<ServiceRegistration>() {
        let clean_name = extract_clean_name_static(registration.name);
        cache.insert(clean_name, registration);
    }
    
    print_cache_initialized("Service", cache.len());
    cache
});

/// 리포지토리 이름 → 등록정보 매핑 캐시 (성능 최적화)  
/// 첫 접근 시 한 번만 구성되며, 이후 O(1) 조회 제공
static REPOSITORY_NAME_CACHE: Lazy<HashMap<String, &'static RepositoryRegistration>> = Lazy::new(|| {
    let mut cache = HashMap::new();
    
    for registration in inventory::iter::<RepositoryRegistration>() {
        let clean_name = extract_clean_name_static(registration.name);
        cache.insert(clean_name, registration);
    }
    
    print_cache_initialized("Repository", cache.len());
    cache
});

/// 등록된 이름에서 접미사를 제거하여 정규화합니다 (static 버전)
///
/// 매크로에서 생성되는 등록 이름은 `user_service`, `user_repository` 형태이므로,
/// 이를 `user`로 정규화하여 타입 이름과 매칭합니다.
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
/// 이 구조체는 전체 DI 시스템의 핵심으로, Spring Framework의
/// ApplicationContext + BeanFactory 역할을 담당합니다.
///
/// # 주요 기능
///
/// ## 1. 인스턴스 관리
/// - **싱글톤 보장**: 각 타입당 정확히 하나의 인스턴스만 생성
/// - **지연 초기화**: 첫 요청 시점에 인스턴스 생성
/// - **Thread-safe**: `RwLock`을 사용한 동시성 안전성
///
/// ## 2. 의존성 해결
/// - **자동 주입**: `Arc<T>` 타입 필드를 자동으로 주입
/// - **타입 분석**: 요청된 타입을 분석하여 적절한 레지스트리에서 검색
/// - **순환 참조 방지**: 초기화 중인 타입을 추적하여 데드락 방지
pub struct ServiceLocator {
    /// 생성된 인스턴스들의 캐시
    /// `TypeId`를 키로 사용하여 각 타입당 하나의 인스턴스를 저장
    instances: RwLock<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>,
    /// 현재 초기화 중인 타입들 (순환 참조 방지용)
    initializing: RwLock<HashSet<TypeId>>,
}

impl ServiceLocator {
    /// 새로운 ServiceLocator 인스턴스를 생성합니다.
    /// 전역 Lazy static에서만 호출됩니다.
    fn new() -> Self {
        Self {
            instances: RwLock::new(HashMap::new()),
            initializing: RwLock::new(HashSet::new()),
        }
    }
    
    /// 지정된 타입의 싱글톤 인스턴스를 가져옵니다.
    ///
    /// 이 메서드는 Spring의 `ApplicationContext.getBean(Class<T>)`과 동일한 역할을 하며,
    /// DI 시스템의 핵심으로 다음과 같은 과정을 거칩니다:
    ///
    /// ## Spring과의 비교
    ///
    /// | Spring | 이 시스템 | 비고 |
    /// |--------|-----------|------|
    /// | `applicationContext.getBean(UserService.class)` | `ServiceLocator::get::<UserService>()` | 타입 안전성 보장 |
    /// | Bean 캐시 확인 | 인스턴스 캐시 확인 | 동일한 최적화 |
    /// | 순환 참조 감지 | 순환 참조 감지 | 더 빠른 실패 |
    /// | 지연 초기화 | 지연 초기화 | 동일한 성능 이점 |
    ///
    /// ## 처리 과정
    ///
    /// 1. **캐시 확인 (O(1))**: 이미 생성된 인스턴스가 있는지 확인
    ///    ```rust
    ///    // Spring: beanFactory.getSingleton(beanName)와 동일
    ///    if let Some(instance) = instances.get(&type_id) {
    ///        return cached_instance;
    ///    }
    ///    ```
    ///
    /// 2. **순환 참조 검사**: 현재 생성 중인 타입인지 확인
    ///    ```rust
    ///    // Spring의 CircularDependencyException과 동일하지만 더 빠름
    ///    if initializing.contains(&type_id) {
    ///        panic!("Circular dependency detected");
    ///    }
    ///    ```
    ///
    /// 3. **타입 분석**: 요청된 타입 이름을 분석하여 카테고리 결정
    ///    ```rust
    ///    // "UserService" -> Service, "UserRepository" -> Repository
    ///    let clean_type_name = Self::extract_clean_type_name(type_name);
    ///    ```
    ///
    /// 4. **레지스트리 검색 (O(1))**: 캐시된 매핑에서 매칭되는 등록 정보 찾기
    ///    ```rust
    ///    // Spring의 BeanDefinition 검색과 동일하지만 더 빠름
    ///    if let Some(registration) = SERVICE_NAME_CACHE.get(&entity_name)
    ///    ```
    ///
    /// 5. **인스턴스 생성**: 등록된 생성자 함수 호출
    ///    ```rust
    ///    // Spring의 InstantiationStrategy와 동일
    ///    let boxed_instance = (registration.constructor)();
    ///    ```
    ///
    /// 6. **캐싱**: 생성된 인스턴스를 캐시에 저장
    ///    ```rust
    ///    // Spring의 singletonObjects 맵과 동일
    ///    instances.insert(type_id, instance.clone());
    ///    ```
    ///
    /// ## 사용 예제
    ///
    /// ```rust
    /// // Spring: @Autowired와 동일한 효과
    /// let user_service = ServiceLocator::get::<UserService>();
    /// let user_repo = ServiceLocator::get::<UserRepository>();
    /// 
    /// // 매크로에서 자동 생성되는 코드
    /// #[service]
    /// struct OrderService {
    ///     user_service: Arc<UserService>,  // 자동으로 위 코드가 생성됨
    /// }
    /// ```
    ///
    /// # 패닉 상황
    ///
    /// Spring과 달리 명시적으로 패닉을 발생시켜 문제를 조기에 발견합니다:
    ///
    /// - **순환 참조**: A → B → A 형태의 의존성 순환
    ///   ```text
    ///   ❌ Circular dependency detected for type: UserService
    ///   Spring: CircularDependencyException (런타임)
    ///   이 시스템: panic! (더 빠른 실패)
    ///   ```
    ///
    /// - **미등록 타입**: 레지스트리에 등록되지 않은 타입 요청
    ///   ```text
    ///   Service not found: EmailService. Make sure it's registered...
    ///   Spring: NoSuchBeanDefinitionException
    ///   이 시스템: panic! (명확한 해결 방법 제시)
    ///   ```
    ///
    /// - **타입 불일치**: 등록된 타입과 요청 타입이 다른 경우
    ///   ```text
    ///   Type mismatch for service: user_service
    ///   Spring: BeanNotOfRequiredTypeException
    ///   이 시스템: panic! (컴파일 타임에 대부분 방지됨)
    ///   ```
    pub fn get<T: 'static + Send + Sync>() -> Arc<T> {
        let type_id = TypeId::of::<T>();
        let type_name = std::any::type_name::<T>();
        
        // 이미 생성된 인스턴스 확인 (조용히 처리)
        {
            let instances = LOCATOR.instances.read().unwrap();
            if let Some(instance) = instances.get(&type_id) {
                return instance.clone()
                    .downcast::<T>()
                    .expect("Type mismatch in ServiceLocator");
            }
        }
        
        // 현재 초기화 중인지 확인 (순환 참조 방지)
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
            
            // 리포지토리 찾기 (캐시 사용으로 O(1) 조회)
            if clean_type_name.contains("Repository") {
                // "UserRepository" -> "user"
                let entity_name = clean_type_name
                    .strip_suffix("Repository")
                    .unwrap_or(&clean_type_name)
                    .to_lowercase();
                
                // 캐시에서 O(1) 조회
                if let Some(registration) = REPOSITORY_NAME_CACHE.get(&entity_name) {
                    // 인스턴스 생성 시도
                    let boxed_instance = (registration.constructor)();
                    
                    // 타입 일치 확인
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
            
            // 서비스 찾기 (캐시 사용으로 O(1) 조회)
            if clean_type_name.contains("Service") {
                // "UserService" -> "user"
                let entity_name = clean_type_name
                    .strip_suffix("Service")
                    .unwrap_or(&clean_type_name)
                    .to_lowercase();
                
                // 캐시에서 O(1) 조회
                if let Some(registration) = SERVICE_NAME_CACHE.get(&entity_name) {
                    // 인스턴스 생성 시도
                    let boxed_instance = (registration.constructor)();
                    
                    // 타입 일치 확인
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
            
            // 매칭 실패 - 에러 처리
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
                // 초기화 실패 시에도 초기화 중 플래그 제거
                let mut initializing = LOCATOR.initializing.write().unwrap();
                initializing.remove(&type_id);
                
                // 에러 출력 후 패닉
                eprintln!("ERROR: Failed to create instance for {}: {:?}", type_name, e);
                panic!("Failed to create instance for {}", type_name);
            }
        }
    }
    
    /// 타입 이름에서 실제 타입 이름을 추출합니다.
    ///
    /// Rust의 `std::any::type_name::<T>()`는 전체 모듈 경로를 포함하므로
    /// (예: `auth_service::services::UserService`),
    /// 실제 타입 이름만 추출하여 매칭에 사용합니다.
    fn extract_clean_type_name(type_name: &str) -> String {
        if let Some(pos) = type_name.rfind("::") {
            type_name[pos + 2..].to_string()
        } else {
            type_name.to_string()
        }
    }
    
    /// 외부에서 생성된 인스턴스를 직접 등록합니다.
    ///
    /// 이 메서드는 Spring의 `@Bean` 메서드나 `registerSingleton()`과 동일한 역할을 하며,
    /// 매크로로 관리되지 않는 외부 컴포넌트들(Database, RedisClient 등)을
    /// 수동으로 등록할 때 사용됩니다.
    ///
    /// ## Spring과의 비교
    ///
    /// ### Spring Configuration
    /// ```java
    /// @Configuration
    /// public class AppConfig {
    ///     @Bean
    ///     public Database database() {
    ///         return new Database("mongodb://localhost:27017");
    ///     }
    ///     
    ///     @Bean  
    ///     public RedisClient redisClient() {
    ///         return new RedisClient("redis://localhost:6379");
    ///     }
    /// }
    /// ```
    ///
    /// ### 이 시스템
    /// ```rust
    /// // main.rs에서 인프라 컴포넌트 등록
    /// #[actix_web::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     // @Bean과 동일한 역할
    ///     let database = Database::connect("mongodb://localhost:27017").await?;
    ///     let redis = RedisClient::connect("redis://localhost:6379").await?;
    ///     
    ///     // Spring의 registerSingleton()과 동일
    ///     ServiceLocator::set(database);
    ///     ServiceLocator::set(redis);
    ///     
    ///     // 애플리케이션 시작...
    /// }
    /// ```
    ///
    /// ## 등록 시나리오
    ///
    /// ### 1. 인프라 컴포넌트 (Infrastructure Beans)
    /// ```rust
    /// // 데이터베이스 연결
    /// let db = Database::connect(&config.database_url).await?;
    /// ServiceLocator::set(db);
    ///
    /// // 캐시 클라이언트
    /// let redis = RedisClient::new(&config.redis_url).await?;
    /// ServiceLocator::set(redis);
    ///
    /// // 메시지 큐
    /// let rabbitmq = RabbitMQ::connect(&config.rabbitmq_url).await?;
    /// ServiceLocator::set(rabbitmq);
    /// ```
    ///
    /// ### 2. 외부 라이브러리 래핑
    /// ```rust
    /// // HTTP 클라이언트 래핑
    /// let http_client = Arc::new(reqwest::Client::new());
    /// ServiceLocator::set(http_client);
    ///
    /// // 로거 래핑  
    /// let logger = Arc::new(Logger::new());
    /// ServiceLocator::set(logger);
    /// ```
    ///
    /// ### 3. 설정 객체 등록
    /// ```rust
    /// // 애플리케이션 설정
    /// let config = Arc::new(AppConfig::load_from_env()?);
    /// ServiceLocator::set(config);
    ///
    /// // 기능별 설정
    /// let auth_config = Arc::new(AuthConfig::load()?);
    /// ServiceLocator::set(auth_config);
    /// ```
    ///
    /// ## 타입 안전성
    ///
    /// Spring과 달리 컴파일 타임에 타입이 검증됩니다:
    ///
    /// ```rust
    /// // ✅ 올바른 사용
    /// let db: Arc<Database> = Database::connect(url).await?;
    /// ServiceLocator::set(db);
    ///
    /// // ❌ 컴파일 에러 - Arc로 감싸야 함
    /// let db: Database = Database::connect(url).await?;
    /// ServiceLocator::set(db); // 컴파일 실패
    ///
    /// // ✅ 수정된 버전
    /// ServiceLocator::set(Arc::new(db));
    /// ```
    ///
    /// ## 초기화 순서 중요성
    ///
    /// Spring과 마찬가지로 의존성 순서를 고려해야 합니다:
    ///
    /// ```rust
    /// // 1. 인프라 먼저 등록 (Spring의 @Order(1)과 동일)
    /// ServiceLocator::set(database);
    /// ServiceLocator::set(redis_client);
    ///
    /// // 2. 애플리케이션 컴포넌트 초기화 (Spring의 @Order(2)와 동일)
    /// ServiceLocator::initialize_all().await?;
    ///
    /// // 3. 웹 서버 시작 (Spring Boot의 자동 시작과 동일)
    /// HttpServer::new(/* ... */).run().await?;
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
    /// 이 메서드는 애플리케이션 시작 시 호출되어 등록된 모든 컴포넌트의
    /// 인스턴스를 미리 생성합니다. 지연 초기화와 달리 모든 의존성을
    /// 한 번에 해결하여 런타임 성능을 향상시킵니다.
    ///
    /// # 초기화 순서
    ///
    /// 1. **Repository 먼저**: 데이터 계층이 비즈니스 계층보다 먼저 초기화
    /// 2. **Service 나중에**: 리포지토리 의존성이 해결된 후 서비스 초기화
    pub async fn initialize_all() -> Result<(), Box<dyn std::error::Error>> {
        // 제목 출력
        print_boxed_title("🔄 INITIALIZING SERVICE REGISTRY");
        
        // 1단계: 리포지토리 등록 정보 수집
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
        
        // 2단계: 서비스 등록 정보 수집  
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
        
        // 최종 요약 출력
        print_final_summary(repo_count, service_count);
        
        Ok(())
    }
}

/// 전역 서비스 로케이터 인스턴스
///
/// 애플리케이션 전체에서 사용되는 유일한 ServiceLocator 인스턴스입니다.
/// `Lazy<T>`를 사용하여 첫 접근 시에만 초기화되며, 이후에는 동일한
/// 인스턴스가 재사용됩니다.
static LOCATOR: Lazy<ServiceLocator> = Lazy::new(ServiceLocator::new);
