/**
 * test_target.cpp — FindAndFixMe 파이프라인 통합 테스트 타겟
 *
 * 설계 원칙: 입력값에 따라 **서로 다른 함수**를 호출하여
 * 함수 수준 계측(instrumentation)에서 경로 차이가 명확하게 드러나도록 구성.
 *
 * 추가 크래시 경로 (buf[1] == 0):
 *   → division by zero                    → CRASH(SIGFPE) ❗
 *
 * [신규 패턴]
 *   buf[2] == 1 → CWE-416 (Use After Free)  경로
 *   buf[2] == 2 → CWE-125/787 (OOB Read/Write) 경로
 *   buf[2] == 3 → CWE-362 (Race Condition)  경로
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <stdexcept>
#include <thread>
#include <mutex>
#include <atomic>

// ── CWE-190: 정수 덧셈 오버플로우 주입 대상 함수 ──
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

// ── CWE-193: 루프 경계 조건 오류 주입 대상 함수 ──
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

// ── CWE-390: 예외 처리 누락 주입 대상 함수 ──
void handle_error_logic(int val) {
    if (val < 0) {
        abort(); // ← CWE-390 주입 포인트 #1
    }
    try {
        if (val == 42) {
            throw std::runtime_error("CWE-390 test");
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl; // ← CWE-390 주입 포인트 #2
    }
}

// ── CWE-401: 메모리 누수 주입 대상 함수 ──
void resource_management() {
    int* ptr1 = new int[10];
    char* ptr2 = (char*)malloc(20);
    delete[] ptr1; // ← CWE-401 주입 포인트 #1
    free(ptr2);   // ← CWE-401 주입 포인트 #2
}

// ── CWE-476: NULL 포인터 역참조 주입 대상 함수 ──
void pointer_operations() {
    int x = 10;
    int* ptr = &x; // ← CWE-476 주입 포인트 #1
    int* wild_ptr; // ← CWE-476 주입 포인트 #2
    (void)ptr;
    (void)wild_ptr;
}

// ── CWE-682: 산술/논리/비트 연산 오류 주입 대상 함수 ──
int logic_and_math(int a, int b) {
    int rem = a % b; // ← CWE-682 주입 포인트 #1
    int mul = a;
    mul *= b; // ← 복합대입이라 CWE-190 매처 미대상 (동작 동일, 핫 경로 매칭 제거)
    bool cond = (a > 0) && (b > 0); // ← CWE-682 주입 포인트 #3
    return rem + mul + cond;
}

// ── CWE-416: Use After Free 주입 대상 함수 ──
// 해제된 메모리를 다시 참조하는 패턴 (실제 UAF 버그의 가장 흔한 형태)
void* uaf_alloc_and_free(size_t size) {
    void* buf = malloc(size);      // ← CWE-416 주입 포인트 #1 (할당)
    if (!buf) return nullptr;
    memset(buf, 0xAA, size);
    free(buf);                     // ← CWE-416 주입 포인트 #2 (해제)
    return buf;                    // ← CWE-416 주입 포인트 #3 (해제된 포인터 반환 → UAF 트리거)
}

int uaf_compute(int val) {
    // 정상 참조 경로
    int* data = new int[4];        // ← CWE-416 주입 포인트 #4 (할당)
    data[0] = val;
    data[1] = val * 2;
    data[2] = val + 10;
    data[3] = val - 5;
    int sum = data[0] + data[1];   // ← CWE-416 주입 포인트 #5 (정상 접근)
    delete[] data;                 // ← CWE-416 주입 포인트 #6 (해제)
    // sum은 해제 이전에 계산 완료 — 정상 흐름
    return sum;
}

void uaf_string_operation(const char* input, int len) {
    char* buf = (char*)malloc(len + 1);  // ← CWE-416 주입 포인트 #7 (할당)
    if (!buf) return;
    strncpy(buf, input, len);
    buf[len] = '\0';
    std::cout << "uaf_str: " << buf << std::endl;
    free(buf);                           // ← CWE-416 주입 포인트 #8 (해제)
    // 이후 buf에 접근하지 않는 정상 흐름
}

// ── CWE-125 / CWE-787: Out-of-Bounds Read/Write 주입 대상 함수 ──
// 배열 경계 밖 메모리 읽기/쓰기 패턴
int oob_read_element(const int* arr, int size, int index) {
    if (index < 0) index = 0;           // ← CWE-125 주입 포인트 #1 (경계 검사)
    if (index >= size) index = size - 1; // ← CWE-125 주입 포인트 #2 (경계 검사)
    return arr[index];                   // ← CWE-125 주입 포인트 #3 (읽기)
}

void oob_write_element(int* arr, int size, int index, int value) {
    if (index < 0) index = 0;           // ← CWE-787 주입 포인트 #1 (경계 검사)
    if (index >= size) index = size - 1; // ← CWE-787 주입 포인트 #2 (경계 검사)
    arr[index] = value;                  // ← CWE-787 주입 포인트 #3 (쓰기)
}

int oob_safe_sum(const int* arr, int size, int from, int to) {
    int total = 0;
    for (int i = from; i < to; i++) {   // ← CWE-125 주입 포인트 #4 (루프 경계)
        total += arr[i];                 // ← CWE-125 주입 포인트 #5 (접근)
    }
    return total;
}

void oob_buffer_copy(char* dst, int dst_size, const char* src, int copy_len) {
    int actual_len = copy_len;           // ← CWE-787 주입 포인트 #4 (길이 결정)
    if (actual_len > dst_size - 1)      // ← CWE-787 주입 포인트 #5 (경계 검사)
        actual_len = dst_size - 1;
    memcpy(dst, src, actual_len);        // ← CWE-787 주입 포인트 #6 (복사)
    dst[actual_len] = '\0';             // ← CWE-787 주입 포인트 #7 (널 종료)
}

// ── CWE-362: Race Condition 주입 대상 함수 ──
// 멀티스레딩 환경의 공유 자원 경쟁 조건 패턴
static int g_shared_counter = 0;        // ← CWE-362 주입 포인트 #1 (공유 변수)
static std::mutex g_counter_mutex;      // ← CWE-362 주입 포인트 #2 (보호 뮤텍스)
static std::atomic<int> g_atomic_flag{0};

void race_increment_safe(int iterations) {
    for (int i = 0; i < iterations; i++) {
        std::lock_guard<std::mutex> lock(g_counter_mutex); // ← CWE-362 주입 포인트 #3 (락 획득)
        g_shared_counter++;              // ← CWE-362 주입 포인트 #4 (공유 변수 수정)
    }
}

void race_check_and_set(int expected, int new_val) {
    // compare-and-swap 패턴 — 원자적 연산
    int current = g_atomic_flag.load();  // ← CWE-362 주입 포인트 #5 (읽기)
    if (current == expected) {           // ← CWE-362 주입 포인트 #6 (비교, TOCTOU 지점)
        g_atomic_flag.store(new_val);   // ← CWE-362 주입 포인트 #7 (쓰기)
    }
}

int race_produce_result(int base) {
    // 여러 연산을 거쳐 결과 생성 — 뮤텍스 보호 구간
    std::lock_guard<std::mutex> lock(g_counter_mutex);  // ← CWE-362 주입 포인트 #8 (락)
    int snapshot = g_shared_counter;    // ← CWE-362 주입 포인트 #9 (스냅샷)
    int result = snapshot + base;       // ← CWE-362 주입 포인트 #10 (계산)
    return result;
}

// ── 신규 패턴 디스패처 함수 ──
void uaf_processing(uint8_t val) {
    // Use After Free 패턴 테스트 경로
    char input[16] = {};
    snprintf(input, sizeof(input), "val_%d", val);

    // 할당-해제-반환 시나리오
    void* dangling = uaf_alloc_and_free(val % 64 + 8);
    (void)dangling;  // 반환된 dangling pointer는 사용하지 않음 (정상 흐름)

    // 할당-사용-해제 정상 시나리오
    int computed = uaf_compute(val);

    // 문자열 할당-사용-해제 정상 시나리오
    uaf_string_operation(input, strlen(input));

    std::cout << "uaf_path: computed=" << computed << std::endl;
}

void oob_processing(uint8_t val) {
    // Out-of-Bounds Read/Write 패턴 테스트 경로
    int arr[8] = {10, 20, 30, 40, 50, 60, 70, 80};
    char buf[32] = {};
    char src[] = "OOB_TEST_STRING_DATA";

    // 안전한 인덱스 클램핑 후 읽기
    int idx = val % 16;  // 0~15 범위 (배열 크기 8보다 클 수 있음)
    int read_val = oob_read_element(arr, 8, idx);    // 경계 내로 클램핑

    // 안전한 인덱스로 쓰기
    oob_write_element(arr, 8, idx, read_val * 2);

    // 범위 합산
    int from = 0, to = val % 8 + 1;
    int sum = oob_safe_sum(arr, 8, from, to);

    // 버퍼 복사 (길이 클램핑)
    int copy_len = val % 40;  // 최대 39 (buf 크기 32보다 클 수 있음)
    oob_buffer_copy(buf, sizeof(buf), src, copy_len);

    std::cout << "oob_path: read=" << read_val << " sum=" << sum
              << " buf=" << buf << std::endl;
}

void race_processing(uint8_t val) {
    // Race Condition 패턴 테스트 경로 (단일 스레드 환경에서 검증)
    int iterations = (val % 8) + 1;

    // 카운터 증가 (뮤텍스 보호)
    race_increment_safe(iterations);

    // CAS 패턴 테스트
    race_check_and_set(0, val);
    race_check_and_set(val, 0);  // 복원

    // 결과 생성
    int result = race_produce_result(val);

    std::cout << "race_path: counter=" << g_shared_counter
              << " result=" << result << std::endl;
}

// ── CWE-457: 초기화되지 않은 변수 사용 주입 대상 함수 ──
// 정수형 변수의 초기값이 제거되는 패턴
int cwe457_compute(int base) {
    int result = 0;             // ← CWE-457 주입 포인트 #1 (0으로 정품 초기화)
    int multiplier = 1;         // ← CWE-457 주입 포인트 #2 (기본값 1)
    int offset = 0;             // ← CWE-457 주입 포인트 #3 (오프셋 초기화)
    result = base * multiplier + offset;
    return result;
}

void cwe457_string_process(const char* input) {
    int length = 0;             // ← CWE-457 주입 포인트 #4 (길이 정품 초기화)
    int count = 0;              // ← CWE-457 주입 포인트 #5 (카운터 정품 초기화)
    if (input != nullptr) {
        length = (int)strlen(input);
        for (int i = 0; i < length; i++) { // ← CWE-457 주입 포인트 #6 (루프의 count 사용)
            count++;
        }
    }
    std::cout << "cwe457: len=" << length << " count=" << count << std::endl;
}

// ── CWE-369: 0으로 나누기 주입 대상 함수 ──
// 제수가 0인지 확인하는 방어 로직이 있는 패턴
int cwe369_safe_divide(int numerator, int divisor) {
    if (divisor == 0) {         // ← CWE-369 주입 포인트 #1 (방어 조건 == 0)
        return -1;              // ← CWE-369 주입 포인트 #2 (오류 반환)
    }
    return numerator / divisor; // ← CWE-369 주입 포인트 #3 (나눗셈)
}

int cwe369_compute_ratio(int a, int b, int scale) {
    int denominator = b;        // ← CWE-369 주입 포인트 #4 (분모에 b 할당)
    if (denominator == 0) {     // ← CWE-369 주입 포인트 #5 (방어 조건 == 0)
        denominator = 1;        // ← CWE-369 주입 포인트 #6 (기본값 대체)
    }
    return (a * scale) / denominator; // ← CWE-369 주입 포인트 #7 (나눗셈)
}

// ── CWE-835: 이상적 루프 (Hang) 주입 대상 함수 ──
// for문의 증감식이 주입 타겟이 되는 패턴
void cwe835_process_array(const int* arr, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {        // ← CWE-835 주입 포인트 #1 (i++ 증감식)
        sum += arr[i];
    }
    std::cout << "cwe835: sum=" << sum << std::endl;
}

int cwe835_count_valid(const char* str, int len) {
    int count = 0;
    for (int i = 0; i < len; i++) {      // ← CWE-835 주입 포인트 #2 (i++ 증감식)
        if (str[i] != '\0') count++;
    }
    return count;
}

void cwe835_fill_result(int* out, int n, int val) {
    for (int i = 0; i < n; i++) {        // ← CWE-835 주입 포인트 #3 (i++ 증감식)
        out[i] = val;
    }
}

// ── CWE-131: 메모리 복사 크기 계산 오류 주입 대상 함수 ──
// memcpy/memset 제3 인자에 'count * sizeof(type)' 패턴
void cwe131_copy_structs(int* dst, const int* src, int count) {
    memcpy(dst, src, count * sizeof(int));  // ← CWE-131 주입 포인트 #1 (count * sizeof)
}

void cwe131_zero_buffer(short* buf, int n) {
    memset(buf, 0, n * sizeof(short));      // ← CWE-131 주입 포인트 #2 (n * sizeof)
}

void cwe131_move_data(double* dst, double* src, int n) {
    memmove(dst, src, n * sizeof(double));  // ← CWE-131 주입 포인트 #3 (n * sizeof)
}

// ── CWE-134: 통제되지 않은 포맷 스트링 주입 대상 함수 ──
// printf/sprintf에 "%s", 형식으로 포맷 스트링이 삽입되는 패턴
void cwe134_log_message(const char* msg) {
    printf("%s", msg);           // ← CWE-134 주입 포인트 #1 ("%s", msg 패턴)
    printf("\n");
}

void cwe134_report(const char* label, int val) {
    char buf[64] = {};
    snprintf(buf, sizeof(buf), "%s", label);  // ← CWE-134 주입 포인트 #2
    printf("%s", buf);           // ← CWE-134 주입 포인트 #3 ("%s", 패턴)
    printf(": %d\n", val);
}

// ── CWE-415: 이중 해제 (Copy-Paste) 주입 대상 함수 ──
// delete 후 ptr=nullptr를 잘맞게 수행하는 정상 패턴 (주입 후 nullptr 누락)
void cwe415_process_data(int* data, int n) {
    if (data == nullptr) return; // ← CWE-476 코리로 가듥, CWE-415 주입 포인트 #1
    for (int i = 0; i < n; i++) {
        data[i] = data[i] * 2;
    }
    delete[] data;               // ← CWE-415 주입 포인트 #2 (해제)
    data = nullptr;              // ← CWE-415 주입 포인트 #3 (nullptr 췴초화 — 주입 시 주석)
}

void cwe415_double_buffer(int n) {
    int* buf1 = new int[n];      // ← CWE-415 주입 포인트 #4 (할당)
    for (int i = 0; i < n; i++) buf1[i] = i;
    delete[] buf1;               // ← CWE-415 주입 포인트 #5 (정상 해제)
    buf1 = nullptr;              // ← CWE-415 주입 포인트 #6 (nullptr 췴초화 — 주입 시 주석)
}

// ── 신규 6패턴 디스패쳄 함수 ──
void cwe457_processing(uint8_t val) {
    int result = cwe457_compute(val);
    char msg[32] = {};
    snprintf(msg, sizeof(msg), "input_%d", val);
    cwe457_string_process(msg);
    std::cout << "cwe457_path: result=" << result << std::endl;
}

void cwe369_processing(uint8_t val) {
    // val이 0이면 safe_divide에서 -1 반환 (정상)
    // CWE-369 주입 후 '== 0' → '!= 0'를 바꾸면: val==0일 때 방어 따돌림
    int a = cwe369_safe_divide(100, val % 8);       // val%8 범위: 0~7
    int b = cwe369_compute_ratio(val, val % 4, 10); // val%4 범위: 0~3
    std::cout << "cwe369_path: a=" << a << " b=" << b << std::endl;
}

void cwe835_processing(uint8_t val) {
    int arr[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    int out[8] = {};
    char msg[] = "LOOP_TEST";

    cwe835_process_array(arr, (val % 7) + 1);
    int cnt = cwe835_count_valid(msg, 9);
    cwe835_fill_result(out, (val % 6) + 1, val);
    std::cout << "cwe835_path: cnt=" << cnt << " out[0]=" << out[0] << std::endl;
}

void cwe131_processing(uint8_t val) {
    int ibuf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    int idst[8] = {};
    short sbuf[4] = {};
    double dbuf[4] = {1.1, 2.2, 3.3, 4.4};
    double ddst[4] = {};

    cwe131_copy_structs(idst, ibuf, (val % 7) + 1);
    cwe131_zero_buffer(sbuf, 4);
    cwe131_move_data(ddst, dbuf, (val % 3) + 1);
    std::cout << "cwe131_path: dst[0]=" << idst[0] << " ddst[0]=" << ddst[0] << std::endl;
}

void cwe134_processing(uint8_t val) {
    char label[32] = {};
    snprintf(label, sizeof(label), "VAL_%d", val);
    cwe134_log_message(label);
    cwe134_report(label, val);
}

void cwe415_processing(uint8_t val) {
    int n = (val % 7) + 1;
    int* data = new int[n];
    for (int i = 0; i < n; i++) data[i] = i + val;
    cwe415_process_data(data, n);
    // data는 cwe415_process_data 내에서 해제되었지만 nullptr 췴초화 누락 시 dangling
    cwe415_double_buffer((val % 4) + 1);
    std::cout << "cwe415_path: n=" << n << std::endl;
}

// ── 콜드패스 전용 주입 표면 (buf[2]==10에서만 도달, 핫 경로에서 호출 없음) ──
// --target-func=cold_surface_processing 지정 시 결함이 이 함수에만 주입된다.
void cold_surface_processing(uint8_t val) {
    int mul = (int)val * 3;              // CWE-190 (* in decl)
    int arr[8] = {};
    for (int i = 0; i < 8; i++) {        // CWE-193 (<), CWE-835 (i++)
        arr[i] = i * 2;
    }
    if (mul == 0) {                      // CWE-369 (== 0)
        return;
    }
    int div = 100 / (mul != 0 ? mul : 1);
    int* p = new int[8];                 // CWE-125/787 (new[]), CWE-415 (delete)
    for (int j = 0; j < 8; j++) {
        p[j] = arr[j];
    }
    if (p == nullptr) {                  // CWE-476 (nullptr 검사)
        return;
    }
    if (val > 0 && mul > 0) {            // CWE-682 (&& in if)
        p[0] += 1;
    }
    int zero = 0;                        // CWE-457 (= 0)
    char msg[32] = {};
    snprintf(msg, sizeof(msg), "input_%d", val);
    printf("%s", msg);                   // CWE-134 ("%s")
    printf("\n");
    memcpy(msg, msg, 8 * sizeof(char));  // CWE-131 (3번째 인자에 *)
    char* tmp = (char*)malloc(16);       // CWE-401 (free 대상)
    if (tmp != nullptr) {
        tmp[0] = (char)val;
    }
    free(tmp);                           // CWE-401
    (void)zero;
    (void)div;
    delete[] p;                          // CWE-401 (delete)
    p = nullptr;                         // CWE-416 (= nullptr)
    if (val == 42) {
        throw std::runtime_error("cold_surface");  // CWE-390 (throw)
    }
    std::cout << "cold_surface: mul=" << mul << std::endl;
}

// ── 퍼저 호출 경로 분기용 헬퍼 함수 ──
void common_processing(uint8_t val) {
    int data[8] = {};
    int size = (val % 7) + 1;
    fill_array(data, size);
    int sum = compute_sum(val, 50);
    int extra = logic_and_math(val, 5);
    pointer_operations();
    std::cout << "common: sum=" << sum << " extra=" << extra << std::endl;
}

void uncommon_processing(uint8_t val) {
    int data[8] = {};
    int size = (val % 5) + 1;
    fill_array(data, size);
    int acc = accumulate_array(data, size);
    int result = compute_sum(acc, val);
    handle_error_logic(val - 220); // trigger logic check
    std::cout << "uncommon: acc=" << acc << " result=" << result << std::endl;
}

void rare_processing(uint8_t val) {
    int x = compute_complex(val, val * 2, 100);
    char dst[32] = {};
    char src[] = "RARE_PATH_HIT";
    copy_buffer(dst, src, 13);
    resource_management();
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
//
// 입력 레이아웃:
//   buf[0] : 기존 6패턴 경로 선택 (0x00~0xFF)
//   buf[1] : 0이면 SIGFPE 크래시 (division by zero)
//   buf[2] : 신규 패턴 선택
//             1=CWE-416  2=CWE-125/787  3=CWE-362
//             4=CWE-457  5=CWE-369      6=CWE-835
//             7=CWE-131  8=CWE-134      9=CWE-415
//             10=COLD surface (cold_surface_processing, 14패턴 집약)
//   buf[3] : 신규 패턴의 서브 입력값
// ═════════════════════════════════════════════════════════════════════════════
int main() {
    uint8_t buf[8] = {100, 1, 0, 0, 0, 0, 0, 0};  // 기본값: common_processing

    fread(buf, 1, sizeof(buf), stdin);

    // Edge case check: SIGFPE 크래시 경로
    if (buf[1] == 0) {
        int crash = buf[2] / buf[1];
        std::cout << crash << std::endl;
        return 1;
    }

    // ── buf[2] 신규 패턴 분기 ──
    uint8_t new_pattern = buf[2];
    uint8_t sub_val     = buf[3] ? buf[3] : (buf[0] ? buf[0] : 42);

    if (new_pattern == 1) {
        uaf_processing(sub_val);     // CWE-416: Use After Free
        return 0;
    } else if (new_pattern == 2) {
        oob_processing(sub_val);     // CWE-125/787: Out-of-Bounds
        return 0;
    } else if (new_pattern == 3) {
        race_processing(sub_val);    // CWE-362: Race Condition
        return 0;
    } else if (new_pattern == 4) {
        cwe457_processing(sub_val);  // CWE-457: Uninitialized Variable
        return 0;
    } else if (new_pattern == 5) {
        cwe369_processing(sub_val);  // CWE-369: Divide By Zero
        return 0;
    } else if (new_pattern == 6) {
        cwe835_processing(sub_val);  // CWE-835: Loop Defect
        return 0;
    } else if (new_pattern == 7) {
        cwe131_processing(sub_val);  // CWE-131: Missing sizeof in memcpy
        return 0;
    } else if (new_pattern == 8) {
        cwe134_processing(sub_val);  // CWE-134: Uncontrolled Format String
        return 0;
    } else if (new_pattern == 9) {
        cwe415_processing(sub_val);  // CWE-415: Double Free
        return 0;
    } else if (new_pattern == 10) {
        cold_surface_processing(sub_val);  // COLD surface: 14-pattern injection target
        return 0;
    }

    // ── buf[0] 기존 6패턴 분기 ──
    uint8_t selector = buf[0];

    if (selector <= 199) {
        common_processing(selector);       // CWE-190, CWE-193, CWE-682, CWE-476
    } else if (selector <= 240) {
        uncommon_processing(selector);     // CWE-193, CWE-390
    } else if (selector <= 253) {
        rare_processing(selector);         // CWE-190, CWE-193, CWE-401
    } else if (selector == 254) {
        critical_edge_case(selector);      // CWE-190, CWE-193, CWE-401
    } else {
        std::cerr << "[CRITICAL] Fatal input detected!" << std::endl;
        abort();  // CRASH(SIGABRT)
    }

    return 0;
}
