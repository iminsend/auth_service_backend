//! 공통 유틸리티 함수 모듈
//! 
//! 애플리케이션 전체에서 사용되는 공통 유틸리티 함수들을 제공합니다.
//! 문자열 처리, 터미널 출력 등의 기능을 포함합니다.
//!
//! # Modules
//!
//! - [`string_utils`] - 문자열 검증, 정리, 변환 유틸리티
//! - [`display_terminal`] - 터미널 출력 포맷팅 함수들
//!
//! # Examples
//!
//! ```rust,ignore
//! use crate::utils::string_utils::validate_required_string;
//! use crate::utils::display_terminal::print_boxed_title;
//!
//! // 문자열 검증
//! let clean_name = validate_required_string("  John  ", "name")?;
//!
//! // 터미널 출력
//! print_boxed_title("System Initialized");
//! ```

pub mod string_utils;
pub mod display_terminal;
