//! # 사용자 생성 요청 DTO
//!
//! 이 모듈은 새로운 사용자 계정 생성을 위한 HTTP 요청 데이터 구조를 정의합니다.
//! Spring Boot의 `@Valid @RequestBody` 패턴을 Rust로 구현한 것으로,
//! 클라이언트 입력 데이터의 검증과 타입 안전성을 보장합니다.
//!
//! ## 검증 규칙
//!
//! ### 이메일 (`email`)
//! - RFC 5322 표준 이메일 형식 준수
//! - 중복 여부는 서비스 계층에서 별도 검증
//!
//! ### 사용자명 (`username`)
//! - 길이: 3-30자
//! - 허용 문자: 영문, 숫자, 언더스코어(_)
//! - 대소문자 구분 없이 유일성 보장 (서비스 계층에서 처리)
//!
//! ### 표시 이름 (`display_name`)
//! - 길이: 1-50자
//! - 유니코드 문자 지원 (한글, 이모지 포함)
//!
//! ### 비밀번호 (`password`)
//! - 최소 길이: 8자
//! - 필수 포함: 대문자, 소문자, 숫자
//! - 특수문자 포함 권장 (현재는 선택사항)
//!
//! ## 사용 예제
//!
//! ```rust,ignore
//! use actix_web::{web, HttpResponse, Result};
//! use validator::Validate;
//! use crate::domain::dto::users::request::CreateUserRequest;
//!
//! #[actix_web::post("/api/v1/users")]
//! async fn create_user_endpoint(
//!     req: web::Json<CreateUserRequest>
//! ) -> Result<HttpResponse> {
//!     // 1. 입력 검증
//!     req.validate().map_err(|e| {
//!         HttpResponse::BadRequest().json(format!("입력 오류: {:?}", e))
//!     })?;
//!
//!     // 2. 서비스 계층 호출
//!     let user_service = UserService::instance();
//!     let created_user = user_service.create_user(req.into_inner()).await?;
//!
//!     Ok(HttpResponse::Created().json(created_user))
//! }
//! ```

use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

/// 새로운 사용자 계정 생성을 위한 요청 DTO
///
/// 이 구조체는 클라이언트로부터 받은 사용자 생성 데이터를 표현하며,
/// 자동으로 JSON 역직렬화와 입력 검증을 수행합니다.
///
/// # 검증 단계
///
/// 1. **필드별 검증**: 각 필드의 형식과 길이 제약 검사
/// 2. **구조체 수준 검증**: 비밀번호 일치 확인
/// 3. **비즈니스 로직 검증**: 서비스 계층에서 중복 확인 등 수행
///
/// # JSON 예제
///
/// ```json
/// {
///   "email": "user@example.com",
///   "username": "john_doe",
///   "display_name": "John Doe",
///   "password": "SecurePass123",
///   "password_confirm": "SecurePass123"
/// }
/// ```
///
/// # 에러 응답 예제
///
/// 검증 실패 시:
/// ```json
/// {
///   "error": "ValidationError",
///   "details": {
///     "email": ["유효한 이메일 주소를 입력해주세요"],
///     "password": ["비밀번호는 대문자, 소문자, 숫자를 포함해야 합니다"]
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validate_passwords_match"))]
pub struct CreateUserRequest {
    /// 사용자 이메일 주소
    ///
    /// - 로그인 인증과 알림 발송에 사용
    /// - RFC 5322 표준 이메일 형식 필수
    /// - 시스템 내 유일성 보장 (서비스 계층에서 검증)
    #[validate(email(message = "유효한 이메일 주소를 입력해주세요"))]
    pub email: String,
    
    /// 사용자명 (로그인 ID)
    ///
    /// - URL 친화적 식별자로 사용
    /// - 영문, 숫자, 언더스코어만 허용
    /// - 3-30자 제한으로 가독성과 저장 효율성 균형
    #[validate(length(
        min = 3,
        max = 30,
        message = "사용자명은 3-30자 사이여야 합니다"
    ))]
    #[validate(custom(function = "validate_username"))]
    pub username: String,
    
    /// 표시 이름 (화면에 보여지는 이름)
    ///
    /// - 프로필과 UI에서 사용자에게 표시
    /// - 유니코드 문자 지원 (한글, 이모지 등)
    /// - 사용자명과 달리 중복 허용
    #[validate(length(
        min = 1,
        max = 50,
        message = "표시 이름은 1-50자 사이여야 합니다"
    ))]
    pub display_name: String,
    
    /// 계정 비밀번호
    ///
    /// - 보안을 위해 최소 8자 이상 요구
    /// - 대문자, 소문자, 숫자 조합 필수
    /// - 해싱 후 저장되므로 평문으로 유지하지 않음
    #[validate(length(
        min = 8,
        message = "비밀번호는 최소 8자 이상이어야 합니다"
    ))]
    #[validate(custom(function = "validate_password_strength"))]
    pub password: String,
    
    /// 비밀번호 확인
    ///
    /// - 사용자 입력 오류 방지를 위한 재입력 필드
    /// - `password` 필드와 정확히 일치해야 함
    /// - UI에서 실시간 일치 검사도 권장
    pub password_confirm: String,
}

/// 비밀번호 일치 여부를 검증하는 구조체 수준 검증 함수
///
/// 이 함수는 `password`와 `password_confirm` 필드가 정확히 일치하는지 확인합니다.
/// 사용자의 타이핑 실수를 방지하고 의도한 비밀번호가 정확히 입력되었는지 보장합니다.
///
/// # 인자
///
/// * `req` - 검증할 `CreateUserRequest` 인스턴스
///
/// # 반환값
///
/// * `Ok(())` - 비밀번호가 일치하는 경우
/// * `Err(ValidationError)` - 비밀번호가 일치하지 않는 경우
///
/// # 에러 코드
///
/// - `passwords_mismatch`: 두 비밀번호 필드가 일치하지 않을 때
fn validate_passwords_match(req: &CreateUserRequest) -> Result<(), ValidationError> {
    if req.password != req.password_confirm {
        return Err(ValidationError::new("passwords_mismatch")
            .with_message("비밀번호가 일치하지 않습니다".into()));
    }
    Ok(())
}

/// 사용자명의 형식과 문자 제약을 검증하는 함수
///
/// 사용자명은 시스템의 URL과 식별자로 사용되므로 안전한 문자만 허용합니다.
/// 알파벳(대소문자), 숫자, 언더스코어만 사용 가능하며,
/// 이는 URL 인코딩 없이도 안전하게 사용할 수 있는 문자들입니다.
///
/// # 허용 문자
///
/// - 알파벳: a-z, A-Z
/// - 숫자: 0-9  
/// - 특수문자: 언더스코어(_)만 허용
///
/// # 인자
///
/// * `username` - 검증할 사용자명 문자열
///
/// # 반환값
///
/// * `Ok(())` - 모든 문자가 허용된 문자인 경우
/// * `Err(ValidationError)` - 허용되지 않은 문자가 포함된 경우
///
/// # 예제
///
/// ```rust,ignore
/// // 유효한 사용자명
/// assert!(validate_username("john_doe123").is_ok());
/// assert!(validate_username("user_2024").is_ok());
///
/// // 무효한 사용자명  
/// assert!(validate_username("user-name").is_err());  // 하이픈 불허
/// assert!(validate_username("user@domain").is_err()); // @ 불허
/// assert!(validate_username("user name").is_err());   // 공백 불허
/// ```
fn validate_username(username: &str) -> Result<(), ValidationError> {
    // 알파벳, 숫자, 언더스코어만 허용
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(ValidationError::new("invalid_username")
            .with_message("사용자명은 알파벳, 숫자, 언더스코어만 사용 가능합니다".into()));
    }
    Ok(())
}

/// 비밀번호 보안 강도를 검증하는 함수
///
/// 계정 보안을 위해 비밀번호가 최소한의 복잡성 요구사항을 만족하는지 확인합니다.
/// 현재는 대문자, 소문자, 숫자의 조합을 필수로 하며,
/// 특수문자는 권장사항으로 처리합니다.
///
/// # 필수 요구사항
///
/// - **대문자**: 최소 1개 이상 (A-Z)
/// - **소문자**: 최소 1개 이상 (a-z)  
/// - **숫자**: 최소 1개 이상 (0-9)
///
/// # 권장사항 (현재 미적용)
///
/// - **특수문자**: 보안 강화를 위해 권장하지만 필수는 아님
/// - **길이**: 8자 이상 (이미 별도 검증에서 처리)
///
/// # 인자
///
/// * `password` - 검증할 비밀번호 문자열
///
/// # 반환값
///
/// * `Ok(())` - 모든 필수 요구사항을 만족하는 경우
/// * `Err(ValidationError)` - 요구사항을 만족하지 않는 경우
///
/// # 에러 코드
///
/// - `weak_password`: 대문자, 소문자, 숫자 중 하나 이상이 누락된 경우
///
/// # 예제
///
/// ```rust,ignore
/// // 강한 비밀번호
/// assert!(validate_password_strength("MyPassword123").is_ok());
/// assert!(validate_password_strength("SecurePass1").is_ok());
///
/// // 약한 비밀번호
/// assert!(validate_password_strength("password123").is_err());   // 대문자 없음
/// assert!(validate_password_strength("PASSWORD123").is_err());   // 소문자 없음  
/// assert!(validate_password_strength("MyPassword").is_err());    // 숫자 없음
/// ```
///
/// # 향후 개선사항
///
/// - 특수문자 필수 요구사항 추가 고려
/// - 일반적인 비밀번호 패턴 차단 (예: "password123")
/// - 사용자 정보 기반 비밀번호 검증 (이름, 이메일 포함 금지)
fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));
    let _has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    if !(has_uppercase && has_lowercase && has_digit) {
        return Err(ValidationError::new("weak_password")
            .with_message("비밀번호는 대문자, 소문자, 숫자를 포함해야 합니다".into()));
    }
    
    Ok(())
}
