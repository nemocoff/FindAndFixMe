# Base 이미지: 기존에 사용하던 AFL++ 최신 버전
FROM aflplusplus/aflplusplus:latest

# root 권한으로 패키지 설치
USER root

# 패키지 목록 업데이트 및 필수 C++ 라이브러리 설치
# - libboost-all-dev: QuantLib 빌드를 위한 Boost 라이브러리
# - libssl-dev: OpenSSL 등 암호화 관련 빌드용
# - libquantlib0-dev: QuantLib 헤더 및 라이브러리 (추가됨)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libboost-all-dev \
    libssl-dev \
    libquantlib0-dev \
    libclang-16-dev \
    libclang-cpp16t64 \
    libz3-dev \
    && rm -rf /var/lib/apt/lists/*

# 컨테이너 실행 시 기본 사용자 설정 (AFL++ 기본 권한 유지)
USER root
