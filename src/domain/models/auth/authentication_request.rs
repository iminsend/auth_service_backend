/// 인증 모드를 정의하는 열거형
#[derive(Debug, Clone, PartialEq)]
pub enum AuthMode {
    /// 인증이 반드시 필요함
    Required,
    /// 인증이 선택사항임 (있으면 검증, 없어도 허용)
    Optional,
}

/// 요구되는 역할 정보
#[derive(Debug, Clone)]
pub enum RequiredRole {
    /// 특정 단일 역할이 필요
    Single(String),
    /// 여러 역할 중 하나라도 있으면 허용 (OR 조건)
    Any(Vec<String>),
}

impl RequiredRole {
    /// 사용자 역할이 요구사항을 만족하는지 확인
    pub fn is_satisfied(&self, user_roles: &[String]) -> bool {
        match self {
            RequiredRole::Single(required_role) => user_roles.contains(required_role),
            RequiredRole::Any(required_roles) => {
                required_roles.iter().any(|role| user_roles.contains(role))
            }
        }
    }
}