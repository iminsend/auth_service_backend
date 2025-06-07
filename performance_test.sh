#!/bin/bash

# 성능 테스트 스크립트
# 다양한 bcrypt cost 설정에서 사용자 생성 성능을 측정합니다.

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 서버 URL
BASE_URL="http://localhost:8080"
API_URL="${BASE_URL}/api/v1/users"

echo -e "${BLUE}🚀 인증 서비스 성능 테스트 시작${NC}"
echo "=================================="

# 서버 상태 확인
check_server() {
    echo -e "${YELLOW}📡 서버 상태 확인 중...${NC}"
    
    if curl -s "${BASE_URL}/health" > /dev/null; then
        echo -e "${GREEN}✅ 서버가 실행 중입니다${NC}"
    else
        echo -e "${RED}❌ 서버가 실행되지 않았습니다. 서버를 먼저 시작해주세요.${NC}"
        echo "cargo run --bin auth_service_backend"
        exit 1
    fi
}

# 사용자 생성 성능 테스트
test_user_creation() {
    local cost=$1
    local description=$2
    
    echo -e "\n${YELLOW}📊 테스트: ${description} (Cost: ${cost})${NC}"
    echo "----------------------------------------"
    
    # 환경변수 설정
    export BCRYPT_COST=${cost}
    
    # 랜덤 사용자 데이터 생성
    local timestamp=$(date +%s)
    local random_id=$((RANDOM % 1000))
    local test_email="test_${timestamp}_${random_id}@example.com"
    local test_username="test_${timestamp}_${random_id}"
    
    # JSON 페이로드 생성
    local json_payload=$(cat <<EOF
{
  "email": "${test_email}",
  "username": "${test_username}",
  "display_name": "Test User ${timestamp}",
  "password": "TestPassword123!",
  "password_confirm": "TestPassword123!"
}
EOF
)
    
    echo "사용자 데이터: ${test_email}"
    
    # 성능 측정
    local start_time=$(date +%s.%3N)
    
    local response=$(curl -s -w "HTTPSTATUS:%{http_code};TIME:%{time_total}" \
        -X POST "${API_URL}" \
        -H "Content-Type: application/json" \
        -d "${json_payload}")
    
    local end_time=$(date +%s.%3N)
    
    # 응답 파싱
    local http_code=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://' | cut -d';' -f1)
    local time_total=$(echo "${response}" | tr -d '\n' | sed -e 's/.*TIME://' | cut -d';' -f1)
    local response_body=$(echo "${response}" | sed -E 's/HTTPSTATUS:[0-9]+;TIME:[0-9.]+$//')
    
    # 결과 출력
    if [ "${http_code}" = "201" ]; then
        echo -e "${GREEN}✅ 성공${NC}"
        echo "HTTP 상태: ${http_code}"
        echo "응답 시간: ${time_total}초 ($(echo "${time_total} * 1000" | bc -l | cut -d. -f1)ms)"
        
        # 사용자 ID 추출 및 조회 테스트
        local user_id=$(echo "${response_body}" | jq -r '.user.id' 2>/dev/null)
        if [ "${user_id}" != "null" ] && [ -n "${user_id}" ]; then
            test_user_retrieval "${user_id}"
        fi
    else
        echo -e "${RED}❌ 실패${NC}"
        echo "HTTP 상태: ${http_code}"
        echo "응답 시간: ${time_total}초"
        echo "에러 응답: ${response_body}"
    fi
}

# 사용자 조회 성능 테스트
test_user_retrieval() {
    local user_id=$1
    
    echo -e "\n${YELLOW}🔍 사용자 조회 테스트 (ID: ${user_id})${NC}"
    
    local start_time=$(date +%s.%3N)
    
    local response=$(curl -s -w "HTTPSTATUS:%{http_code};TIME:%{time_total}" \
        -X GET "${API_URL}/${user_id}")
    
    local end_time=$(date +%s.%3N)
    
    # 응답 파싱
    local http_code=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://' | cut -d';' -f1)
    local time_total=$(echo "${response}" | tr -d '\n' | sed -e 's/.*TIME://' | cut -d';' -f1)
    
    if [ "${http_code}" = "200" ]; then
        echo -e "${GREEN}✅ 조회 성공${NC}"
        echo "응답 시간: ${time_total}초 ($(echo "${time_total} * 1000" | bc -l | cut -d. -f1)ms)"
    else
        echo -e "${RED}❌ 조회 실패 (HTTP: ${http_code})${NC}"
    fi
}

# 성능 비교 테스트 실행
run_performance_comparison() {
    echo -e "\n${BLUE}📈 bcrypt cost별 성능 비교${NC}"
    echo "=================================="
    
    # Cost 4 (개발용)
    test_user_creation 4 "개발 환경 (빠른 해싱)"
    
    # Cost 8 (중간)
    test_user_creation 8 "중간 보안"
    
    # Cost 10 (스테이징)
    test_user_creation 10 "스테이징 환경"
    
    # Cost 12 (프로덕션)
    test_user_creation 12 "프로덕션 환경 (높은 보안)"
}

# 배치 테스트 (동시 요청)
run_batch_test() {
    echo -e "\n${BLUE}⚡ 배치 테스트 (동시 요청 5개)${NC}"
    echo "=================================="
    
    local cost=4
    export BCRYPT_COST=${cost}
    
    echo "Cost ${cost}로 5개 사용자 동시 생성..."
    
    local pids=()
    local start_time=$(date +%s.%3N)
    
    for i in {1..5}; do
        (
            local timestamp=$(date +%s)
            local random_id=$((RANDOM % 10000))
            local test_email="batch_${timestamp}_${random_id}@example.com"
            local test_username="batch_${timestamp}_${random_id}"
            
            local json_payload=$(cat <<EOF
{
  "email": "${test_email}",
  "username": "${test_username}",
  "display_name": "Batch User ${i}",
  "password": "BatchPassword123!",
  "password_confirm": "BatchPassword123!"
}
EOF
)
            
            curl -s -o /dev/null -w "Request ${i}: %{time_total}s\n" \
                -X POST "${API_URL}" \
                -H "Content-Type: application/json" \
                -d "${json_payload}"
        ) &
        pids+=($!)
    done
    
    # 모든 요청 완료 대기
    for pid in "${pids[@]}"; do
        wait $pid
    done
    
    local end_time=$(date +%s.%3N)
    local total_time=$(echo "${end_time} - ${start_time}" | bc -l)
    
    echo -e "${GREEN}✅ 배치 테스트 완료${NC}"
    echo "총 소요 시간: ${total_time}초"
}

# 메인 실행
main() {
    # 필수 도구 확인
    if ! command -v jq &> /dev/null; then
        echo -e "${YELLOW}⚠️  jq가 설치되지 않았습니다. JSON 파싱이 제한됩니다.${NC}"
    fi
    
    if ! command -v bc &> /dev/null; then
        echo -e "${YELLOW}⚠️  bc가 설치되지 않았습니다. 계산이 제한됩니다.${NC}"
    fi
    
    # 테스트 실행
    check_server
    run_performance_comparison
    run_batch_test
    
    echo -e "\n${GREEN}🎉 모든 성능 테스트가 완료되었습니다!${NC}"
    echo -e "${BLUE}💡 개발 중에는 ENVIRONMENT=development로 설정하여 빠른 테스트를 진행하세요.${NC}"
}

# 도움말
show_help() {
    echo "사용법: $0 [옵션]"
    echo ""
    echo "옵션:"
    echo "  -h, --help     이 도움말을 표시"
    echo "  -s, --server   서버 상태만 확인"
    echo "  -c, --compare  성능 비교 테스트만 실행"
    echo "  -b, --batch    배치 테스트만 실행"
    echo ""
    echo "예제:"
    echo "  $0              # 전체 테스트 실행"
    echo "  $0 -c           # 성능 비교만 실행"
    echo "  $0 -s           # 서버 상태 확인"
}

# 명령행 인자 처리
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    -s|--server)
        check_server
        exit 0
        ;;
    -c|--compare)
        check_server
        run_performance_comparison
        exit 0
        ;;
    -b|--batch)
        check_server
        run_batch_test
        exit 0
        ;;
    "")
        main
        ;;
    *)
        echo -e "${RED}❌ 알 수 없는 옵션: $1${NC}"
        show_help
        exit 1
        ;;
esac
