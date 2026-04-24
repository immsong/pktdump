#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="pktdump-builder"
APP_NAME="pktdump"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
DIST_DIR="dist"

# 1. 빌드용 이미지 생성
docker build -t "$IMAGE_NAME" .

# 2. x86_64 빌드 (컨테이너 내에서 실행 후 호스트 target 폴더에 저장)
docker run --rm \
  --mount type=bind,src="$(pwd)",dst=/work \
  -w /work \
  "$IMAGE_NAME" \
  cargo build --target x86_64-unknown-linux-gnu --release

# 3. aarch64(ARM64) 빌드
docker run --rm \
  --mount type=bind,src="$(pwd)",dst=/work \
  -w /work \
  "$IMAGE_NAME" \
  cargo build --target aarch64-unknown-linux-gnu --release

# 4. 결과물 추출
mkdir -p "$DIST_DIR"

cp "target/x86_64-unknown-linux-gnu/release/$APP_NAME" \
   "$DIST_DIR/${APP_NAME}-v${VERSION}-x86_64"

cp "target/aarch64-unknown-linux-gnu/release/$APP_NAME" \
   "$DIST_DIR/${APP_NAME}-v${VERSION}-aarch64"

echo "[INFO] 빌드 완료:"
echo "  - $DIST_DIR/${APP_NAME}-v${VERSION}-x86_64"
echo "  - $DIST_DIR/${APP_NAME}-v${VERSION}-aarch64"