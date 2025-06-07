pub fn print_boxed_title(title: &str) {
    let width = title.len() + 16;
    let border = "═".repeat(width);

    println!("╔{}╗", border);
    println!("║         {}         ║", title);
    println!("╚{}╝", border);
}

/// 진행 단계 시작 표시
pub fn print_step_start(step: u8, description: &str) {
    println!("→ Step {}: {}", step, description);
}

/// 진행 단계 완료 표시
pub fn print_step_complete(step: u8, description: &str, count: usize) {
    println!("✓ Step {}: {} ({} items)", step, description, count);
}

/// 서브 작업 표시
pub fn print_sub_task(name: &str, status: &str) {
    println!("   ├─ {}: {}", name, status);
}

/// 최종 완료 표시
pub fn print_final_summary(repos: usize, services: usize) {
    let total = repos + services;
    println!();
    print_boxed_title("🎉 SERVICE REGISTRY INITIALIZED");
    println!("   📦 Repositories: {}", repos);
    println!("   🔧 Services: {}", services);
    println!("   🚀 Total Components: {}", total);
    println!();
}

/// 캐시 초기화 완료 표시
pub fn print_cache_initialized(cache_type: &str, count: usize) {
    println!("   ├─ {} Cache: {} entries loaded", cache_type, count);
}