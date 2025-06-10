#!/bin/bash
# scripts/generate_jwt_keys.sh

echo "🔑 Generating RSA key pair for JWT..."

# 키 저장 디렉토리 생성
mkdir -p secrets

# RSA 개인키 생성 (2048비트)
openssl genrsa -out secrets/jwt_private_key.pem 2048

# 공개키 추출
openssl rsa -in secrets/jwt_private_key.pem -pubout -out secrets/jwt_public_key.pem

# 권한 설정 (보안)
chmod 600 secrets/jwt_private_key.pem
chmod 644 secrets/jwt_public_key.pem

echo "✅ JWT RSA keys generated:"
echo "   Private key: secrets/jwt_private_key.pem"
echo "   Public key:  secrets/jwt_public_key.pem"
echo ""
echo "🔒 Set environment variables:"
echo "   JWT_PRIVATE_KEY_PATH=./secrets/jwt_private_key.pem"
echo "   JWT_PUBLIC_KEY_PATH=./secrets/jwt_public_key.pem"