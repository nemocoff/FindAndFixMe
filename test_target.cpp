/**
 * test_target.cpp — FindAndFixMe 파이프라인 통합 테스트 타겟
 *
 * 설계 원칙: 입력값에 따라 **서로 다른 함수**를 호출하여
 * 함수 수준 계측(instrumentation)에서 경로 차이가 명확하게 드러나도록 구성.
 *
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

int compute_sum(int a, int b) {
    int result = a + b;   // ← CWE-190 주입 포인트 #1
    return result;
}

int compute_complex(int x, int y, int z) {
    int partial = x + y;  // ← CWE-190 주입 포인트 #2
    int total = partial + z;  // ← CWE-190 주입 포인트 #3
    return total;
}

int compute_critical(int base, int offset) {
    int adjusted = base + offset;  // ← CWE-190 주입 포인트 #4
    return adjusted * 2;
}

void fill_array(int* arr, int size) {
    for (int i = 0; i < size; i++) {   // ← CWE-193 주입 포인트 #1
        arr[i] = i * 2;
    }
}

int accumulate_array(int* arr, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {  // ← CWE-193 주입 포인트 #2
        total = total + arr[i];        // ← CWE-190 추가 포인트
    }
    return total;
}

void copy_buffer(char* dst, const char* src, int len) {
    for (int i = 0; i < len; i++) {    // ← CWE-193 주입 포인트 #3
        dst[i] = src[i];
    }
}

void common_processing(uint8_t val) {
    int data[8] = {};
    int size = (val % 7) + 1;
    fill_array(data, size);
    int sum = compute_sum(val, 50);
    std::cout << "common: sum=" << sum << std::endl;
}

void uncommon_processing(uint8_t val) {
    int data[8] = {};
    int size = (val % 5) + 1;
    fill_array(data, size);
    int acc = accumulate_array(data, size);
    int result = compute_sum(acc, val);
    std::cout << "uncommon: acc=" << acc << " result=" << result << std::endl;
}

void rare_processing(uint8_t val) {
    int x = compute_complex(val, val * 2, 100);
    char dst[32] = {};
    char src[] = "RARE_PATH_HIT";
    copy_buffer(dst, src, 13);
    std::cout << "rare: complex=" << x << " buf=" << dst << std::endl;
}

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
        common_processing(selector);
    } else if (selector <= 240) {
        uncommon_processing(selector);
    } else if (selector <= 253) {
        rare_processing(selector);
    } else if (selector == 254) {
        critical_edge_case(selector);
    } else {
        std::cerr << "[CRITICAL] Fatal input detected!" << std::endl;
        abort();  // CRASH(SIGABRT)
    }

    return 0;
}
