//! 터미널 출력 포맷팅 유틸리티
//! 
//! 애플리케이션 초기화 과정에서 사용되는 터미널 출력 함수들을 제공합니다.
//! 박스 형태의 제목, 진행 단계 표시, 완료 상태 등을 시각적으로 표현합니다.

/// 박스 형태로 둘러싸인 제목을 출력합니다
/// 
/// Unicode 박스 문자를 사용하여 시각적으로 눈에 띄는 제목을 출력합니다.
/// 텍스트는 자동으로 중앙 정렬됩니다.
/// 
/// # Arguments
/// 
/// * `title` - 출력할 제목 문자열
/// 
/// # Examples
/// 
/// ```rust,ignore
/// use crate::utils::display_terminal::print_boxed_title;
/// 
/// print_boxed_title("System Started");
/// ```
/// 
/// Output:
/// ```text
/// ╔══════════════════════════════════════════════════╗
/// ║                  System Started                  ║
/// ╚══════════════════════════════════════════════════╝
/// ```
pub fn print_boxed_title(title: &str) {
    // 고정 너비 50칸 사용 (박스 내부 콘텐츠)
    let content_width = 50;
    let border = "═".repeat(content_width);

    println!("╔{}╗", border);
    println!("║{:^49}║", title);  // ^49로 49칸 중앙 정렬
    println!("╚{}╝", border);
}

/// 진행 단계 시작을 표시합니다
/// 
/// 특정 단계가 시작되었음을 화살표 기호와 함께 출력합니다.
/// 
/// # Arguments
/// 
/// * `step` - 단계 번호 (1부터 시작)
/// * `description` - 단계 설명
/// 
/// # Examples
/// 
/// ```rust,ignore
/// use crate::utils::display_terminal::print_step_start;
/// 
/// print_step_start(1, "Initializing database connection");
/// ```
/// 
/// Output:
/// ```text
/// → Step 1: Initializing database connection
/// ```
pub fn print_step_start(step: u8, description: &str) {
    println!("→ Step {}: {}", step, description);
}

/// 진행 단계 완료를 표시합니다
/// 
/// 특정 단계가 완료되었음을 체크 표시와 함께 출력하고,
/// 처리된 항목 수를 함께 표시합니다.
/// 
/// # Arguments
/// 
/// * `step` - 완료된 단계 번호
/// * `description` - 단계 설명
/// * `count` - 처리된 항목 수
/// 
/// # Examples
/// 
/// ```rust,ignore
/// use crate::utils::display_terminal::print_step_complete;
/// 
/// print_step_complete(1, "Services registered", 5);
/// ```
/// 
/// Output:
/// ```text
/// ✓ Step 1: Services registered (5 items)
/// ```
pub fn print_step_complete(step: u8, description: &str, count: usize) {
    println!("✓ Step {}: {} ({} items)", step, description, count);
}

/// 서브 작업의 상태를 표시합니다
/// 
/// 들여쓰기된 트리 구조로 하위 작업의 진행 상황을 출력합니다.
/// 
/// # Arguments
/// 
/// * `name` - 서브 작업의 이름
/// * `status` - 현재 상태 또는 결과
/// 
/// # Examples
/// 
/// ```rust,ignore
/// use crate::utils::display_terminal::print_sub_task;
/// 
/// print_sub_task("UserRepository", "OK");
/// print_sub_task("Database", "Connected");
/// ```
/// 
/// Output:
/// ```text
///    ├─ UserRepository: OK
///    ├─ Database: Connected
/// ```
pub fn print_sub_task(name: &str, status: &str) {
    println!("   ├─ {}: {}", name, status);
}

/// 최종 완료 요약을 출력합니다
/// 
/// 서비스 초기화 완료 후 전체 등록된 컴포넌트의 요약 정보를 
/// 시각적으로 강조된 형태로 출력합니다.
/// 
/// # Arguments
/// 
/// * `repos` - 등록된 리포지토리 수
/// * `services` - 등록된 서비스 수
/// 
/// # Examples
/// 
/// ```rust,ignore
/// use crate::utils::display_terminal::print_final_summary;
/// 
/// print_final_summary(3, 5);
/// ```
/// 
/// Output:
/// ```text
/// ╔══════════════════════════════════════════════════╗
/// ║           🎉 SERVICE REGISTRY INITIALIZED        ║
/// ╚══════════════════════════════════════════════════╝
///    📦 Repositories: 3
///    🔧 Services: 5
///    🚀 Total Components: 8
/// ```
pub fn print_final_summary(repos: usize, services: usize) {
    let total = repos + services;
    println!();
    print_boxed_title("🎉 SERVICE REGISTRY INITIALIZED");
    println!("   📦 Repositories: {}", repos);
    println!("   🔧 Services: {}", services);
    println!("   🚀 Total Components: {}", total);
    println!();
}

/// 캐시 초기화 완료 상태를 출력합니다
/// 
/// 특정 유형의 캐시가 초기화되었음을 서브 작업 형태로 표시합니다.
/// 
/// # Arguments
/// 
/// * `cache_type` - 캐시 유형 (예: "Redis", "Memory")
/// * `count` - 로드된 항목 수
/// 
/// # Examples
/// 
/// ```rust,ignore
/// use crate::utils::display_terminal::print_cache_initialized;
/// 
/// print_cache_initialized("Redis", 150);
/// print_cache_initialized("Memory", 25);
/// ```
/// 
/// Output:
/// ```text
///    ├─ Redis Cache: 150 entries loaded
///    ├─ Memory Cache: 25 entries loaded
/// ```
pub fn print_cache_initialized(cache_type: &str, count: usize) {
    println!("   ├─ {} Cache: {} entries loaded", cache_type, count);
}
