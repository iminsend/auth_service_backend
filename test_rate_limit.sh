#!/bin/bash

echo "🚦 Rate Limiting 테스트 시작..."
echo "📊 초당 20 요청 제한, 버스트 40개 제한 테스트"
echo ""

# 서버 URL
SERVER_URL="http://127.0.0.1:8080"

echo "1️⃣  정상 요청 테스트 (5개 요청)"
for i in {1..5}; do
    echo -n "요청 $i: "
    curl -s -o /dev/null -w "HTTP %{http_code} - 응답시간: %{time_total}s\n" \
        "$SERVER_URL/health"
    sleep 0.1
done

echo ""
echo "2️⃣  Rate Limit 테스트 (50개 빠른 요청)"
echo "처음 40개는 성공, 나머지는 429 (Too Many Requests) 응답 예상"

success_count=0
rate_limited_count=0

for i in {1..50}; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL/health")
    
    if [ "$response" = "200" ]; then
        success_count=$((success_count + 1))
        echo -n "✅"
    elif [ "$response" = "429" ]; then
        rate_limited_count=$((rate_limited_count + 1))
        echo -n "🚫"
    else
        echo -n "❓"
    fi
    
    # 10개마다 줄바꿈
    if [ $((i % 10)) -eq 0 ]; then
        echo " ($i/50)"
    fi
done

echo ""
echo "📊 결과:"
echo "   ✅ 성공: $success_count 개"
echo "   🚫 Rate Limited: $rate_limited_count 개"
echo "   📈 차단률: $(( rate_limited_count * 100 / 50 ))%"

echo ""
echo "3️⃣  복구 테스트 (1초 대기 후 재시도)"
sleep 1
echo -n "1초 후 재시도: "
curl -s -o /dev/null -w "HTTP %{http_code}\n" "$SERVER_URL/health"

echo ""
echo "4️⃣  인증 API 테스트"
echo -n "로그인 엔드포인트: "
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
    -X POST "$SERVER_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"test123"}'

echo ""
echo "🎉 Rate Limiting 테스트 완료!"
echo "💡 팁: 응답 헤더에서 남은 요청 수를 확인할 수 있습니다:"
echo "   curl -I $SERVER_URL/health | grep -i ratelimit"
