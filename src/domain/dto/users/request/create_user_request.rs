//! 사용자 생성 요청 DTO
//!
//! 새로운 사용자 계정 생성을 위한 HTTP 요청 데이터 구조를 정의합니다.
//! 클라이언트 입력 데이터의 검증과 타입 안전성을 보장합니다.
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

/// 새로운 사용자 계정 생성을 위한 요청 DTO
///
/// JSON 역직렬화와 입력 검증을 자동으로 수행합니다.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validate_passwords_match"))]
pub struct CreateUserRequest {
    /// 사용자 이메일 주소 (RFC 5322 표준)
    #[validate(email(message = "유효한 이메일 주소를 입력해주세요"))]
    pub email: String,
    
    /// 사용자명 (3-30자, 영문/숫자/언더스코어만 허용)
    #[validate(length(
        min = 3,
        max = 30,
        message = "사용자명은 3-30자 사이여야 합니다"
    ))]
    #[validate(custom(function = "validate_username"))]
    pub username: String,
    
    /// 표시 이름 (1-50자, 유니코드 지원)
    #[validate(length(
        min = 1,
        max = 50,
        message = "표시 이름은 1-50자 사이여야 합니다"
    ))]
    pub display_name: String,
    
    /// 계정 비밀번호 (최소 8자, 대소문자+숫자 포함)
    #[validate(length(
        min = 8,
        message = "비밀번호는 최소 8자 이상이어야 합니다"
    ))]
    #[validate(custom(function = "validate_password_strength"))]
    pub password: String,
    
    /// 비밀번호 확인 (password와 일치해야 함)
    pub password_confirm: String,
}

/// 비밀번호 일치 여부를 검증
fn validate_passwords_match(req: &CreateUserRequest) -> Result<(), ValidationError> {
    if req.password != req.password_confirm {
        return Err(ValidationError::new("passwords_mismatch")
            .with_message("비밀번호가 일치하지 않습니다".into()));
    }
    Ok(())
}

/// 사용자명 형식 검증 (영문, 숫자, 언더스코어만 허용)
fn validate_username(username: &str) -> Result<(), ValidationError> {
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(ValidationError::new("invalid_username")
            .with_message("사용자명은 알파벳, 숫자, 언더스코어만 사용 가능합니다".into()));
    }
    Ok(())
}

/// 비밀번호 보안 강도 검증 (대문자, 소문자, 숫자 필수 포함)
fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));
    
    if !(has_uppercase && has_lowercase && has_digit) {
        return Err(ValidationError::new("weak_password")
            .with_message("비밀번호는 대문자, 소문자, 숫자를 포함해야 합니다".into()));
    }
    
    Ok(())
}
