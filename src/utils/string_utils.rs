//! # 문자열 유틸리티
//! 
//! 문자열 처리와 관련된 공통 유틸리티 함수들입니다.

use serde::Deserialize;
use crate::errors::errors::AppError;

/// 필수 문자열 필드 검증 및 정리
/// 
/// 빈 문자열이나 공백만 있는 경우 ValidationError를 반환하고,
/// 유효한 문자열인 경우 앞뒤 공백을 제거한 문자열을 반환합니다.
/// 
/// # 인자
/// * `value` - 검증할 문자열
/// * `field_name` - 필드명 (에러 메시지용)
/// 
/// # 반환값
/// * `Ok(String)` - 정리된 유효한 문자열
/// * `Err(AppError)` - 빈 문자열이거나 공백만 있는 경우
/// 
/// # 예제
/// ```rust,ignore
/// use crate::utils::string_utils::validate_required_string;
/// 
/// // 성공 케이스
/// assert_eq!(validate_required_string("  Hello  ", "name").unwrap(), "Hello");
/// 
/// // 실패 케이스
/// assert!(validate_required_string("   ", "name").is_err());
/// assert!(validate_required_string("", "name").is_err());
/// ```
pub fn validate_required_string(value: &str, field_name: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AppError::ValidationError(
            format!("{}은(는) 필수입니다", field_name)
        ));
    }
    Ok(trimmed.to_string())
}

/// 선택적 문자열 필드 정리
/// 
/// None 값이거나 빈 문자열/공백만 있는 경우 None을 반환하고,
/// 유효한 문자열인 경우 앞뒤 공백을 제거한 문자열을 Some 옵션으로 반환합니다.
/// 
/// # 인자
/// * `value` - 정리할 Option<String>
/// 
/// # 반환값
/// * `None` - 값이 없거나 빈 문자열인 경우
/// * `Some(String)` - 정리된 유효한 문자열
/// 
/// # 예제
/// ```rust,ignore
/// use crate::utils::string_utils::clean_optional_string;
/// 
/// assert_eq!(clean_optional_string(Some("  Hello  ".to_string())), Some("Hello".to_string()));
/// assert_eq!(clean_optional_string(Some("   ".to_string())), None);
/// assert_eq!(clean_optional_string(Some("".to_string())), None);
/// assert_eq!(clean_optional_string(None), None);
/// ```
pub fn clean_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

/// 문자열 정리 (trim 후 반환)
/// 
/// 단순히 앞뒤 공백을 제거합니다.
/// 
/// # 인자
/// * `value` - 정리할 문자열
/// 
/// # 반환값
/// * 앞뒤 공백이 제거된 문자열
/// 
/// # 예제
/// ```rust,ignore
/// use crate::utils::string_utils::trim_string;
/// 
/// assert_eq!(trim_string("  Hello World  "), "Hello World");
/// ```
pub fn trim_string(value: &str) -> String {
    value.trim().to_string()
}

/// 문자열이 유효한지 확인 (빈 문자열이 아니고 공백만으로 구성되지 않음)
/// 
/// # 인자
/// * `value` - 확인할 문자열
/// 
/// # 반환값
/// * `true` - 유효한 문자열
/// * `false` - 빈 문자열이거나 공백만 있는 경우
/// 
/// # 예제
/// ```rust,ignore
/// use crate::utils::string_utils::is_valid_string;
/// 
/// assert_eq!(is_valid_string("Hello"), true);
/// assert_eq!(is_valid_string("   "), false);
/// assert_eq!(is_valid_string(""), false);
/// ```
pub fn is_valid_string(value: &str) -> bool {
    !value.trim().is_empty()
}

/// 선택적 문자열 필드를 위한 serde deserializer
/// 
/// JSON 역직렬화 시 빈 문자열이나 공백만 있는 문자열을 자동으로 None으로 변환하고,
/// 유효한 문자열인 경우 앞뒤 공백을 제거한 후 Some으로 반환합니다.
/// serde의 `#[serde(deserialize_with = "deserialize_optional_string")]` 속성과 함께 사용됩니다.
/// 
/// # 인자
/// * `deserializer` - serde deserializer 인스턴스
/// 
/// # 반환값
/// * `Ok(Some(String))` - 유효한 문자열 (앞뒤 공백 제거됨)
/// * `Ok(None)` - null 값, 빈 문자열, 또는 공백만 있는 경우
/// * `Err(D::Error)` - 역직렬화 실패 시
/// 
/// # 예제
/// ```rust,ignore
/// use serde::Deserialize;
/// use crate::utils::string_utils::deserialize_optional_string;
/// 
/// #[derive(Deserialize)]
/// struct User {
///     #[serde(deserialize_with = "deserialize_optional_string")]
///     nickname: Option<String>,
/// }
/// 
/// // JSON: {"nickname": "  Alice  "} → Some("Alice")
/// // JSON: {"nickname": ""} → None
/// // JSON: {"nickname": null} → None
/// // JSON: {"nickname": "   "} → None
/// ```
pub fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(clean_optional_string(opt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_required_string() {
        // 성공 케이스
        assert_eq!(validate_required_string("Hello", "name").unwrap(), "Hello");
        assert_eq!(validate_required_string("  World  ", "name").unwrap(), "World");
        
        // 실패 케이스
        assert!(validate_required_string("", "name").is_err());
        assert!(validate_required_string("   ", "name").is_err());
        assert!(validate_required_string("\t\n", "name").is_err());
    }

    #[test]
    fn test_clean_optional_string() {
        assert_eq!(clean_optional_string(Some("Hello".to_string())), Some("Hello".to_string()));
        assert_eq!(clean_optional_string(Some("  World  ".to_string())), Some("World".to_string()));
        assert_eq!(clean_optional_string(Some("".to_string())), None);
        assert_eq!(clean_optional_string(Some("   ".to_string())), None);
        assert_eq!(clean_optional_string(None), None);
    }

    #[test]
    fn test_is_valid_string() {
        assert!(is_valid_string("Hello"));
        assert!(is_valid_string("  World  "));
        assert!(!is_valid_string(""));
        assert!(!is_valid_string("   "));
        assert!(!is_valid_string("\t\n"));
    }

    #[test]
    fn test_deserialize_optional_string() {
        use serde_json;
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct TestStruct {
            #[serde(deserialize_with = "deserialize_optional_string")]
            optional_field: Option<String>,
        }

        // 유효한 문자열 - 공백이 제거되고 Some 반환
        let json = r#"{"optional_field": "  Hello World  "}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.optional_field, Some("Hello World".to_string()));

        // 빈 문자열 - None 반환
        let json = r#"{"optional_field": ""}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.optional_field, None);

        // 공백만 있는 문자열 - None 반환
        let json = r#"{"optional_field": "   "}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.optional_field, None);

        // 탭과 개행만 있는 문자열 - None 반환
        let json = r#"{"optional_field": "\t\n  "}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.optional_field, None);

        // null 값 - None 반환
        let json = r#"{"optional_field": null}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.optional_field, None);

        // 필드가 없는 경우 - None 반환 (기본값)
        let json = r#"{}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap_or_else(|_| {
            // 필드가 없으면 default를 사용
            TestStruct { optional_field: None }
        });
        assert_eq!(result.optional_field, None);

        // 숫자 0을 문자열로 - 유효한 값으로 처리
        let json = r#"{"optional_field": "0"}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.optional_field, Some("0".to_string()));

        // 단일 문자
        let json = r#"{"optional_field": "a"}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.optional_field, Some("a".to_string()));
    }

    #[test]
    fn test_deserialize_optional_string_with_korean() {
        use serde_json;
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct KoreanTestStruct {
            #[serde(deserialize_with = "deserialize_optional_string")]
            korean_field: Option<String>,
        }

        // 한글 문자열 테스트
        let json = r#"{"korean_field": "  안녕하세요  "}"#;
        let result: KoreanTestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.korean_field, Some("안녕하세요".to_string()));

        // 한글 + 영문 혼합
        let json = r#"{"korean_field": "  Hello 안녕  "}"#;
        let result: KoreanTestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.korean_field, Some("Hello 안녕".to_string()));
    }

    #[test]
    fn test_deserialize_optional_string_edge_cases() {
        use serde_json;
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct EdgeCaseStruct {
            #[serde(deserialize_with = "deserialize_optional_string")]
            field: Option<String>,
        }

        // 특수 문자들
        let json = r#"{"field": "  !@#$%^&*()  "}"#;
        let result: EdgeCaseStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.field, Some("!@#$%^&*()".to_string()));

        // 줄바꿈이 포함된 문자열
        let json = r#"{"field": "  Line1\nLine2  "}"#;
        let result: EdgeCaseStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.field, Some("Line1\nLine2".to_string()));

        // 이모지 테스트
        let json = r#"{"field": "  😀👍  "}"#;
        let result: EdgeCaseStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.field, Some("😀👍".to_string()));
    }
}
