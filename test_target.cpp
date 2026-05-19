/**
 * test_target.cpp — FindAndFixMe 파이프라인 통합 테스트 타겟
 *
 * 이 파일은 MutationEngine의 CWE-190, CWE-193 결함 주입 대상입니다.
 * 파일 업로드 파이프라인을 통해 업로드하면 전체 분석 파이프라인이 작동합니다.
 *
 * AFL++가 stdin으로 최대 16바이트 입력을 공급합니다.
 * 아래 경로들이 다양한 실행 빈도를 갖도록 설계되었습니다.
 *
 *   [자주 실행]   기본 경로 (정상 입력)
 *   [드물게 실행] buf[3] == 0         → division by zero → CRASH
 *   [매우 드물게] magic bytes 0xDEAD  → abort() → CRASH
 *   [행(hang)]   buf[4] == 0xFF      → 무한루프 → HANG
 *
 * MutationEngine 주입 대상:
 *   - CWE-190: compute_sum() 내 정수 덧셈 (a + b)
 *   - CWE-193: process_array() 내 for 루프 경계 조건 (i < size)
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdint>

// ─────────────────────────────────────────────────────────────────────────────
// [CWE-190] 정수 덧셈 오버플로우 타겟
//   AST 매처: binaryOperator(hasOperatorName("+"))
//   주입 결과: a + b → 2147483647 + 1 (INT_MAX overflow)
// ─────────────────────────────────────────────────────────────────────────────
int compute_sum(int a, int b) {
    int result = a + b;   // ← CWE-190 주입 포인트
    return result;
}

int accumulate(int* arr, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {  // ← CWE-193 주입 포인트 (루프 내 <)
        total = total + arr[i];        // ← CWE-190 추가 주입 포인트
    }
    return total;
}

// ─────────────────────────────────────────────────────────────────────────────
// [CWE-193] 루프 경계 조건 오류 타겟
//   AST 매처: binaryOperator(hasOperatorName("<"), hasAncestor(forStmt()))
//   주입 결과: i < size → i <= size (Off-by-one, 배열 범위 초과)
// ─────────────────────────────────────────────────────────────────────────────
void process_array(int* arr, int size) {
    for (int i = 0; i < size; i++) {  // ← CWE-193 주입 포인트
        arr[i] = i * 2;
    }
}

void copy_buffer(char* dst, const char* src, int len) {
    for (int i = 0; i < len; i++) {   // ← CWE-193 추가 주입 포인트
        dst[i] = src[i];
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// [코너 케이스 1] Division by Zero — 빈도 약 1/256 (~0.4%)
// ─────────────────────────────────────────────────────────────────────────────
int safe_divide(int a, int b) {
    return a / b;   // b == 0 이면 SIGFPE → crash
}

// ─────────────────────────────────────────────────────────────────────────────
// [코너 케이스 2] Magic Bytes 경로 — 빈도 약 1/65536 (~0.0015%)
// ─────────────────────────────────────────────────────────────────────────────
void check_magic(uint8_t a, uint8_t b) {
    if (a == 0xDE) {
        if (b == 0xAD) {
            std::cerr << "[MAGIC] Dead path triggered!" << std::endl;
            abort();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// [코너 케이스 3] 잠재적 무한 루프 — AFL++ hangs/ 저장
// ─────────────────────────────────────────────────────────────────────────────
void potential_hang(uint8_t control) {
    if (control == 0xFF) {
        volatile int x = 0;
        while (x == 0) {
            x = x;  // 탈출 불가 → HANG
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// [일반 경로] 다양한 값 계산 — 자주 실행되는 정상 경로
// ─────────────────────────────────────────────────────────────────────────────
void normal_path(uint8_t val) {
    int data[8] = {};
    int size = (val % 7) + 1;      // 1 ~ 7
    process_array(data, size);

    int sum = compute_sum((int)val * 10, 50);

    char dst[16] = {};
    char src[] = "HELLO";
    copy_buffer(dst, src, 5);

    int acc = accumulate(data, size);
    std::cout << "sum=" << sum << " acc=" << acc << " size=" << size << std::endl;
}

// ─────────────────────────────────────────────────────────────────────────────
// main: AFL++는 stdin으로 입력을 공급합니다 (최대 16바이트 읽기)
// ─────────────────────────────────────────────────────────────────────────────
int main() {
    uint8_t buf[16] = {1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    // AFL++가 stdin으로 변이된 입력을 공급
    fread(buf, 1, sizeof(buf), stdin);

    // ── 기본 정상 실행 경로 (항상 실행) ──
    normal_path(buf[0]);

    // ── [코너 케이스 3] 무한루프 검사 ──
    potential_hang(buf[4]);

    // ── [코너 케이스 2] Magic bytes 검사 ──
    check_magic(buf[0], buf[1]);

    // ── [코너 케이스 1] Division by zero ──
    if (buf[3] != 0) {
        int result = safe_divide((int)buf[2] + 1, (int)buf[3]);
        std::cout << "div=" << result << std::endl;
    } else {
        safe_divide(1, 0);
    }

    return 0;
}
