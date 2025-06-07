//! # Data Configuration Module
//! 
//! 데이터베이스, 서버, 환경 및 보안 관련 설정을 관리하는 모듈입니다.
//! Spring Boot의 `application.yml`과 유사한 역할을 수행하며,
//! 환경 변수 기반의 설정 관리를 제공합니다.
//!
//! ## 주요 기능
//!
//! - **환경별 설정 분리**: 개발/테스트/스테이징/프로덕션 환경별 최적화된 설정
//! - **보안 설정 관리**: 패스워드 해싱, 암호화 강도 설정
//! - **서버 설정**: 호스트, 포트 등 서버 바인딩 설정
//! - **타입 안전성**: 컴파일 타임 설정 검증 및 런타임 타입 변환
//!
//! ## Spring Boot 와의 비교
//!
//! | Spring Boot | 이 모듈 |
//! |-------------|---------|
//! | `@Profile("dev")` | `Environment::Development` |
//! | `server.port` | `ServerConfig::port()` |
//! | `server.address` | `ServerConfig::host()` |
//! | `spring.security.bcrypt.strength` | `PasswordConfig::bcrypt_cost()` |
//!
//! ## 환경 변수 설정 예제
//!
//! ### 개발 환경 (.env.dev)
//! ```bash
//! ENVIRONMENT=development
//! HOST=127.0.0.1
//! PORT=8080
//! BCRYPT_COST=4
//! ```
//!
//! ### 프로덕션 환경 (.env.prod)
//! ```bash
//! ENVIRONMENT=production
//! HOST=0.0.0.0
//! PORT=8080
//! BCRYPT_COST=12
//! ```

use std::env;

/// 애플리케이션 실행 환경을 나타내는 열거형
/// 
/// Spring의 Profile 개념과 유사하게 동작하며, 각 환경별로
/// 최적화된 설정값을 제공합니다.
///
/// ## 환경별 특성
///
/// - **Development**: 빠른 개발을 위한 설정 (낮은 보안 강도)
/// - **Test**: 자동화된 테스트를 위한 설정 (일관된 성능)
/// - **Staging**: 프로덕션과 유사한 환경 (중간 강도 보안)
/// - **Production**: 최고 보안 및 성능 설정
///
/// ## 환경 감지 우선순위
///
/// 1. `ENVIRONMENT` 환경 변수
/// 2. `NODE_ENV` 환경 변수 (Node.js 호환성)
/// 3. 기본값: `Production` (안전 우선)
#[derive(Debug, Clone, PartialEq)]
pub enum Environment {
    /// 개발 환경
    /// - 빠른 재시작과 디버깅에 최적화
    /// - 낮은 bcrypt cost (4)
    /// - 개발자 친화적 로깅
    Development,
    
    /// 테스트 환경  
    /// - 자동화된 테스트 실행에 최적화
    /// - 일관된 성능을 위한 낮은 bcrypt cost (4)
    /// - 테스트 격리를 위한 설정
    Test,
    
    /// 스테이징 환경
    /// - 프로덕션 환경의 시뮬레이션
    /// - 중간 강도의 보안 설정 (bcrypt cost: 10)
    /// - 성능 테스트 및 부하 테스트용
    Staging,
    
    /// 프로덕션 환경
    /// - 최고 수준의 보안 및 성능
    /// - 높은 bcrypt cost (12)
    /// - 상용 서비스 제공을 위한 설정
    Production,
}

impl Environment {
    /// 현재 실행 환경을 감지합니다.
    /// 
    /// 환경 변수 우선순위:
    /// 1. `ENVIRONMENT`
    /// 2. `NODE_ENV` (Node.js 생태계 호환)
    /// 3. 기본값: `Production` (보안 우선)
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::Environment;
    ///
    /// let env = Environment::current();
    /// match env {
    ///     Environment::Development => println!("개발 환경에서 실행 중"),
    ///     Environment::Production => println!("프로덕션 환경에서 실행 중"),
    ///     _ => {}
    /// }
    /// ```
    ///
    /// # 환경 변수 설정
    ///
    /// ```bash
    /// # 개발 환경
    /// export ENVIRONMENT=development
    ///
    /// # 프로덕션 환경  
    /// export ENVIRONMENT=production
    /// ```
    pub fn current() -> Self {
        match env::var("ENVIRONMENT")
            .unwrap_or_else(|_| env::var("NODE_ENV").unwrap_or_else(|_| "production".to_string()))
            .to_lowercase()
            .as_str()
        {
            "development" | "dev" => Environment::Development,
            "test" | "testing" => Environment::Test,
            "staging" | "stage" => Environment::Staging,
            _ => Environment::Production,
        }
    }

    /// 문자열에서 Environment를 생성합니다.
    /// 
    /// 주로 테스트나 특정 상황에서 환경을 강제로 설정할 때 사용됩니다.
    ///
    /// # 인자
    ///
    /// * `s` - 환경 이름 문자열 (대소문자 무관)
    ///
    /// # 지원되는 값
    ///
    /// - `"development"`, `"dev"` → `Environment::Development`
    /// - `"test"`, `"testing"` → `Environment::Test`  
    /// - `"staging"`, `"stage"` → `Environment::Staging`
    /// - 기타 모든 값 → `Environment::Production`
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::Environment;
    ///
    /// let dev_env = Environment::from_str("development");
    /// let prod_env = Environment::from_str("unknown"); // Production 으로 fallback
    /// ```
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Environment::Development,
            "test" | "testing" => Environment::Test,
            "staging" | "stage" => Environment::Staging,
            _ => Environment::Production,
        }
    }
}

/// 패스워드 해싱 관련 설정을 관리하는 구조체
/// 
/// Spring Security의 BCryptPasswordEncoder 설정과 유사한 역할을 합니다.
/// 환경별로 최적화된 bcrypt cost를 제공하여 보안과 성능의 균형을 맞춥니다.
///
/// ## bcrypt cost 값별 특성
///
/// | Cost | 시간 (대략) | 용도 |
/// |------|-------------|------|
/// | 4    | ~1ms       | 개발/테스트 |
/// | 10   | ~10ms      | 스테이징 |
/// | 12   | ~250ms     | 프로덕션 |
/// | 15   | ~2s        | 고보안 요구사항 |
///
/// ## 환경 변수
///
/// - `BCRYPT_COST`: 사용자 정의 cost (4-15 범위)
pub struct PasswordConfig;

impl PasswordConfig {
    /// 현재 환경에 맞는 bcrypt cost를 반환합니다.
    ///
    /// 환경 변수 `BCRYPT_COST`가 설정되어 있으면 해당 값을 사용하고,
    /// 그렇지 않으면 현재 환경에 맞는 기본값을 사용합니다.
    ///
    /// # 반환값
    ///
    /// - 4-15 범위의 유효한 bcrypt cost 값
    /// - 잘못된 값이 설정된 경우 환경별 기본값 사용
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::PasswordConfig;
    ///
    /// let cost = PasswordConfig::bcrypt_cost();
    /// println!("bcrypt cost: {}", cost);
    /// ```
    ///
    /// # 환경 변수 설정
    ///
    /// ```bash
    /// # 커스텀 cost 설정 (4-15 범위)
    /// export BCRYPT_COST=10
    /// ```
    pub fn bcrypt_cost() -> u32 {
        if let Ok(cost_str) = env::var("BCRYPT_COST") {
            if let Ok(cost) = cost_str.parse::<u32>() {
                if cost >= 4 && cost <= 15 {
                    return cost;
                }
            }
        }

        Self::bcrypt_cost_for_env(&Environment::current())
    }

    /// 특정 환경에 대한 bcrypt cost를 반환합니다.
    ///
    /// 각 환경별로 최적화된 기본값을 제공합니다:
    /// - Development/Test: 4 (빠른 개발/테스트)
    /// - Staging: 10 (중간 보안)
    /// - Production: 12 (고보안)
    ///
    /// # 인자
    ///
    /// * `env` - 대상 환경
    ///
    /// # 반환값
    ///
    /// 해당 환경에 최적화된 bcrypt cost 값
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::{Environment, PasswordConfig};
    ///
    /// let prod_cost = PasswordConfig::bcrypt_cost_for_env(&Environment::Production);
    /// assert_eq!(prod_cost, 12);
    /// ```
    pub fn bcrypt_cost_for_env(env: &Environment) -> u32 {
        match env {
            Environment::Development => 4,  // 빠른 개발 반복
            Environment::Test => 4,         // 일관된 테스트 성능
            Environment::Staging => 10,     // 프로덕션 유사 환경
            Environment::Production => 12,  // 최고 보안
        }
    }
}

/// 서버 바인딩 및 네트워크 설정을 관리하는 구조체
///
/// Spring Boot의 `server.*` 설정과 유사한 역할을 합니다.
/// 개발 환경과 프로덕션 환경에 따라 적절한 기본값을 제공합니다.
///
/// ## 환경 변수
///
/// - `PORT`: 서버 포트 (기본값: 8080)
/// - `HOST`: 서버 호스트 (기본값: 0.0.0.0)
pub struct ServerConfig;

impl ServerConfig {
    /// 서버가 바인딩할 포트를 반환합니다.
    ///
    /// 환경 변수 `PORT`에서 값을 읽으며, 설정되지 않았거나
    /// 잘못된 값인 경우 8080을 기본값으로 사용합니다.
    ///
    /// # 반환값
    ///
    /// 1-65535 범위의 유효한 포트 번호
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::ServerConfig;
    ///
    /// let port = ServerConfig::port();
    /// println!("서버 포트: {}", port);
    /// ```
    ///
    /// # 환경 변수 설정
    ///
    /// ```bash
    /// # 커스텀 포트 설정
    /// export PORT=3000
    /// ```
    pub fn port() -> u16 {
        env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .unwrap_or(8080)
    }

    /// 서버가 바인딩할 호스트 주소를 반환합니다.
    ///
    /// 환경 변수 `HOST`에서 값을 읽으며, 설정되지 않은 경우
    /// 모든 인터페이스에서 접근 가능한 "0.0.0.0"을 기본값으로 사용합니다.
    ///
    /// # 반환값
    ///
    /// 유효한 IP 주소 문자열
    ///
    /// # 일반적인 설정값
    ///
    /// - `"0.0.0.0"`: 모든 네트워크 인터페이스 (프로덕션)
    /// - `"127.0.0.1"`: 로컬호스트만 (개발)
    /// - `"::1"`: IPv6 로컬호스트
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// use crate::config::ServerConfig;
    ///
    /// let host = ServerConfig::host();
    /// println!("서버 호스트: {}", host);
    /// ```
    ///
    /// # 환경 변수 설정
    ///
    /// ```bash
    /// # 로컬호스트만 허용 (개발 환경)
    /// export HOST=127.0.0.1
    ///
    /// # 모든 인터페이스 허용 (프로덕션)
    /// export HOST=0.0.0.0
    /// ```
    pub fn host() -> String {
        env::var("HOST")
            .unwrap_or_else(|_| "0.0.0.0".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_from_string() {
        assert_eq!(Environment::from_str("development"), Environment::Development);
        assert_eq!(Environment::from_str("test"), Environment::Test);
        assert_eq!(Environment::from_str("production"), Environment::Production);
        assert_eq!(Environment::from_str("unknown"), Environment::Production);
    }

    #[test]
    fn test_bcrypt_cost_for_each_environment() {
        assert_eq!(PasswordConfig::bcrypt_cost_for_env(&Environment::Development), 4);
        assert_eq!(PasswordConfig::bcrypt_cost_for_env(&Environment::Test), 4);
        assert_eq!(PasswordConfig::bcrypt_cost_for_env(&Environment::Staging), 10);
        assert_eq!(PasswordConfig::bcrypt_cost_for_env(&Environment::Production), 12);
    }
    
    #[test]
    fn test_server_config_defaults() {
        // PORT 환경 변수가 없는 경우 기본값 테스트
        if env::var("PORT").is_err() {
            assert_eq!(ServerConfig::port(), 8080);
        }
        
        // HOST 환경 변수가 없는 경우 기본값 테스트
        if env::var("HOST").is_err() {
            assert_eq!(ServerConfig::host(), "0.0.0.0");
        }
    }
}
