/**
 * test_target.cpp — FindAndFixMe 파이프라인 통합 테스트 타겟
 *
 * 설계 원칙: 입력값에 따라 **서로 다른 함수**를 호출하여
 * 함수 수준 계측(instrumentation)에서 경로 차이가 명확하게 드러나도록 구성.
 *
 * 경로 분포 (buf[0] 기준):
 *   [78%]  0~199   → common_processing()   → 정상 경로
 *   [16%]  200~240 → uncommon_processing() → 정상 경로
 *   [5%]   241~253 → rare_processing()     → 코너 케이스 ❗
 *   [0.4%] 254     → critical_edge_case()  → 코너 케이스 ❗
 *   [0.4%] 255     → abort() 크래시        → CRASH(SIGABRT) ❗
 *
 * 추가 크래시 경로 (buf[1] == 0):
 *   → division by zero                    → CRASH(SIGFPE) ❗
 *
 * MutationEngine 주입 대상:
 *   - CWE-190: 정수 덧셈 오버플로우 (a + b)
 *   - CWE-193: for 루프 경계 조건 오류 (i < size → i <= size)
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdint>

// ═════════════════════════════════════════════════════════════════════════════
// [CWE-190 주입 대상] 정수 덧셈 — binaryOperator(hasOperatorName("+"))
// ═════════════════════════════════════════════════════════════════════════════

// 자주 실행: 기본 합산
int compute_sum(int a, int b) {
    int result = a + b;   // ← CWE-190 주입 포인트 #1
    return result;
}

// 드물게 실행: 복합 연산
int compute_complex(int x, int y, int z) {
    int partial = x + y;  // ← CWE-190 주입 포인트 #2
    int total = partial + z;  // ← CWE-190 주입 포인트 #3
    return total;
}

// 매우 드물게 실행: 임계값 연산
int compute_critical(int base, int offset) {
    int adjusted = base + offset;  // ← CWE-190 주입 포인트 #4
    return adjusted * 2;
}

// ═════════════════════════════════════════════════════════════════════════════
// [CWE-193 주입 대상] 루프 경계 조건 — for문 내 < 또는 <= 연산자
// ═════════════════════════════════════════════════════════════════════════════

// 자주 실행: 배열 초기화 루프
void fill_array(int* arr, int size) {
    for (int i = 0; i < size; i++) {   // ← CWE-193 주입 포인트 #1
        arr[i] = i * 2;
    }
}

// 드물게 실행: 배열 누적 합산 루프
int accumulate_array(int* arr, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {  // ← CWE-193 주입 포인트 #2
        total = total + arr[i];        // ← CWE-190 추가 포인트
    }
    return total;
}

// 매우 드물게 실행: 버퍼 복사 루프
void copy_buffer(char* dst, const char* src, int len) {
    for (int i = 0; i < len; i++) {    // ← CWE-193 주입 포인트 #3
        dst[i] = src[i];
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 실행 경로 — 입력에 따라 서로 다른 함수 조합을 호출
// ═════════════════════════════════════════════════════════════════════════════

// [78%] 가장 자주 실행되는 경로
void common_processing(uint8_t val) {
    int data[8] = {};
    int size = (val % 7) + 1;
    fill_array(data, size);
    int sum = compute_sum(val, 50);
    std::cout << "common: sum=" << sum << std::endl;
}

// [16%] 가끔 실행되는 경로 — 다른 함수 조합
void uncommon_processing(uint8_t val) {
    int data[8] = {};
    int size = (val % 5) + 1;
    fill_array(data, size);
    int acc = accumulate_array(data, size);
    int result = compute_sum(acc, val);
    std::cout << "uncommon: acc=" << acc << " result=" << result << std::endl;
}

// [5%] 희귀 경로 — 완전히 다른 함수 호출 체인
void rare_processing(uint8_t val) {
    int x = compute_complex(val, val * 2, 100);
    char dst[32] = {};
    char src[] = "RARE_PATH_HIT";
    copy_buffer(dst, src, 13);
    std::cout << "rare: complex=" << x << " buf=" << dst << std::endl;
}

// [0.4%] 극희귀 경로 — 유일한 함수 호출 체인
void critical_edge_case(uint8_t val) {
    int base = compute_critical(val, 255);
    int data[4] = {base, base * 2, base + 1, base - 1};
    int acc = accumulate_array(data, 4);
    char dst[64] = {};
    char msg[] = "CRITICAL_EDGE";
    copy_buffer(dst, msg, 13);
    std::cout << "CRITICAL: acc=" << acc << " msg=" << dst << std::endl;
}

// ═════════════════════════════════════════════════════════════════════════════
// main: AFL++는 stdin으로 입력을 공급합니다 (최대 8바이트 읽기)
// ═════════════════════════════════════════════════════════════════════════════
int main() {
    uint8_t buf[8] = {100, 1, 0, 0, 0, 0, 0, 0};  // 기본값: common_processing

    fread(buf, 1, sizeof(buf), stdin);

    // ── 크래시 경로: buf[1] == 0 → division by zero → CRASH(SIGFPE) ──
    if (buf[1] == 0) {
        int crash = buf[2] / buf[1];  // SIGFPE
        std::cout << crash << std::endl;
        return 1;
    }

    // ── buf[0] 값에 따른 실행 경로 분기 ──
    uint8_t selector = buf[0];

    if (selector <= 199) {
        // 78%: 가장 흔한 경로
        common_processing(selector);
    } else if (selector <= 240) {
        // 16%: 가끔 실행
        uncommon_processing(selector);
    } else if (selector <= 253) {
        // 5%: 희귀 경로 → 코너 케이스
        rare_processing(selector);
    } else if (selector == 254) {
        // 0.4%: 극희귀 경로 → 코너 케이스
        critical_edge_case(selector);
    } else {
        // 0.4%: buf[0] == 255 → abort 크래시
        std::cerr << "[CRITICAL] Fatal input detected!" << std::endl;
        abort();  // CRASH(SIGABRT)
    }

    return 0;
}
