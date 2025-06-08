//! 데이터 및 서버 설정 관리 모듈
//!
//! 데이터베이스, 서버, 환경 및 보안 관련 설정을 관리합니다.

use std::env;

/// 애플리케이션 실행 환경
#[derive(Debug, Clone, PartialEq)]
pub enum Environment {
    /// 개발 환경 - 빠른 개발을 위한 설정
    Development,
    /// 테스트 환경 - 자동화된 테스트용 설정
    Test,
    /// 스테이징 환경 - 프로덕션 유사 환경
    Staging,
    /// 프로덕션 환경 - 최고 수준의 보안 및 성능
    Production,
}

impl Environment {
    /// 현재 실행 환경을 감지합니다.
    ///
    /// `ENVIRONMENT` 또는 `NODE_ENV` 환경 변수를 확인하며,
    /// 설정되지 않은 경우 `Production`을 기본값으로 사용합니다.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let env = Environment::current();
    /// match env {
    ///     Environment::Development => println!("개발 환경"),
    ///     Environment::Production => println!("프로덕션 환경"),
    ///     _ => {}
    /// }
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
    /// # Arguments
    ///
    /// * `s` - 환경 이름 문자열 (대소문자 무관)
    ///
    /// # Returns
    ///
    /// 해당하는 Environment 값. 알 수 없는 값인 경우 `Production`을 반환합니다.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Environment::Development,
            "test" | "testing" => Environment::Test,
            "staging" | "stage" => Environment::Staging,
            _ => Environment::Production,
        }
    }
}

/// 패스워드 해싱 설정
pub struct PasswordConfig;

impl PasswordConfig {
    /// 현재 환경에 맞는 bcrypt cost를 반환합니다.
    ///
    /// # Returns
    ///
    /// 4-15 범위의 bcrypt cost 값
    ///
    /// # Environment Defaults
    ///
    /// - Development/Test: 4 (빠른 처리)
    /// - Staging: 10 (중간 보안)
    /// - Production: 12 (고보안)
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
    /// # Arguments
    ///
    /// * `env` - 대상 환경
    ///
    /// # Returns
    ///
    /// 해당 환경에 최적화된 bcrypt cost 값
    pub fn bcrypt_cost_for_env(env: &Environment) -> u32 {
        match env {
            Environment::Development => 4,
            Environment::Test => 4,
            Environment::Staging => 10,
            Environment::Production => 12,
        }
    }
}

/// 서버 바인딩 설정
pub struct ServerConfig;

impl ServerConfig {
    /// 서버가 바인딩할 포트를 반환합니다.
    ///
    /// # Returns
    ///
    /// 포트 번호. 기본값: 8080
    ///
    /// # Environment Variables
    ///
    /// - `PORT`: 커스텀 포트 설정
    pub fn port() -> u16 {
        env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .unwrap_or(8080)
    }

    /// 서버가 바인딩할 호스트 주소를 반환합니다.
    ///
    /// # Returns
    ///
    /// 호스트 주소. 기본값: "0.0.0.0" (모든 인터페이스)
    ///
    /// # Environment Variables
    ///
    /// - `HOST`: 커스텀 호스트 설정
    pub fn host() -> String {
        env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_from_string() {
        assert_eq!(
            Environment::from_str("development"),
            Environment::Development
        );
        assert_eq!(Environment::from_str("test"), Environment::Test);
        assert_eq!(Environment::from_str("production"), Environment::Production);
        assert_eq!(Environment::from_str("unknown"), Environment::Production);
    }

    #[test]
    fn test_bcrypt_cost_for_each_environment() {
        assert_eq!(
            PasswordConfig::bcrypt_cost_for_env(&Environment::Development),
            4
        );
        assert_eq!(PasswordConfig::bcrypt_cost_for_env(&Environment::Test), 4);
        assert_eq!(
            PasswordConfig::bcrypt_cost_for_env(&Environment::Staging),
            10
        );
        assert_eq!(
            PasswordConfig::bcrypt_cost_for_env(&Environment::Production),
            12
        );
    }

    #[test]
    fn test_server_config_defaults() {
        if env::var("PORT").is_err() {
            assert_eq!(ServerConfig::port(), 8080);
        }

        if env::var("HOST").is_err() {
            assert_eq!(ServerConfig::host(), "0.0.0.0");
        }
    }
}
