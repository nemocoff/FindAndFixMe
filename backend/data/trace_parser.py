"""
backend/data/trace_parser.py

[T6] AFL++ 출력 디렉토리 파싱, MD5 해시 기반 중복 제거, JSON 경량화.
[T9] exec_frequency 계산 후 코너 케이스 노드를 DB에 분류/적재.
"""

import os
import hashlib
import json
import subprocess
import random
from typing import Dict, List, Tuple, Any

from .db_manager import TraceDBManager

# AFL++ 출력 구조 정의
AFL_SOURCE_DIRS = [
    ("queue",   "afl_queue"),   # coverage를 넓히는 정상 입력
    ("crashes", "afl_crash"),   # 크래시 유발 입력 (항상 코너 케이스)
    ("hangs",   "afl_hang"),    # 타임아웃 유발 입력 (항상 코너 케이스)
]

# crashes/hangs는 exec_frequency가 정의상 0.001로 고정
CRASH_EXEC_FREQ = 0.001
CORNER_CASE_THRESHOLD = 0.01   # [T9] 1% 미만 = 코너 케이스


def _get_host_project_root() -> str:
    """
    호스트 상의 프로젝트 루트 경로를 구합니다.
    Docker 컨테이너 안에서 실행 중이면 docker inspect를 통해 /app에 마운트된 호스트 경로를 찾아내고,
    그렇지 않으면 로컬 파일 시스템 경로를 기반으로 추정합니다.
    리턴되는 경로는 항상 forward slash(/)를 사용하며, 드라이브 문자는 /c/ 형태로 변환됩니다.
    예: C:\\FindAndFixMe -> /c/FindAndFixMe
    """
    import socket
    
    host_path = None
    
    # 1. Docker 컨테이너 내부인 경우, docker inspect로 호스트 마운트 소스 경로 조회 시도
    try:
        container_id = socket.gethostname()
        res = subprocess.run(["docker", "inspect", container_id], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            info = json.loads(res.stdout)
            if info and len(info) > 0:
                mounts = info[0].get("Mounts", [])
                for m in mounts:
                    if m.get("Destination") == "/app":
                        host_path = m.get("Source")
                        break
    except Exception:
        pass
        
    # 2. 컨테이너 내부가 아니거나 inspect 실패 시, __file__ 기준 로컬 파일 시스템 경로 사용
    if not host_path:
        try:
            # backend/data/trace_parser.py 이므로 2단계 상위 폴더가 루트
            host_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        except Exception:
            host_path = "C:/FindAndFixMe"
            
    # 3. 경로 포맷 정규화
    p = host_path.replace("\\", "/")
    
    # WSL /mnt/c/ 등 접두사 정규화
    if p.startswith("/mnt/"):
        parts = p.split("/")
        if len(parts) > 2:
            drive = parts[2].lower()
            p = f"/{drive}/" + "/".join(parts[3:])
            
    # Docker Desktop mnt 호스트 경로 정규화 (예: /run/desktop/mnt/host/c/ 또는 /host_mnt/c/)
    for mnt_prefix in ["/run/desktop/mnt/host/", "/host_mnt/"]:
        if p.startswith(mnt_prefix):
            p = "/" + p[len(mnt_prefix):]
            break

    # 드라이브 문자(예: C:/...)를 /c/... 형태로 변환
    if len(p) >= 2 and p[0].isalpha() and p[1] == ":":
        drive = p[0].lower()
        p = f"/{drive}{p[2:]}"
        
    return p.rstrip("/")


def _get_host_absolute_path(container_abs_path: str) -> str:
    """
    백엔드 컨테이너 내부의 절대 경로(예: /app/temp_targets/23/...)를
    호스트 윈도우 상의 물리적 절대 경로로 변환합니다.
    DooD(Docker-out-of-Docker) 구동 시 -v 마운트 인자에 호스트 경로를 넣기 위해 필수적입니다.
    """
    p = container_abs_path.replace("\\", "/")
    host_root = _get_host_project_root()
    # 만약 /app 으로 시작한다면, 호스트 상의 FindAndFixMe 루트 폴더로 치환
    if p.startswith("/app/"):
        return f"{host_root}/" + p[5:]
    if p.startswith("/app"):
        return host_root
    # 만약 /mnt/ 로 시작한다면 (WSL 드라이브 매핑 대응)
    if p.startswith("/mnt/"):
        parts = p.split("/")
        if len(parts) > 2:
            drive = parts[2].lower()
            return f"/{drive}/" + "/".join(parts[3:])
    
    # 일반 드라이브 문자 경로(예: C:/...) 변환
    if len(p) >= 2 and p[0].isalpha() and p[1] == ":":
        drive = p[0].lower()
        return f"/{drive}{p[2:]}"
    
    return p


def _get_container_internal_path(path: str) -> str:
    """
    백엔드 내부 절대 경로를 도커 컨테이너가 마운트한 격리 디렉토리 기준 경로(/app/...)로 정밀 변환합니다.
    """
    p = path.replace("\\", "/")
    host_root = _get_host_project_root()
    
    prefixes = [host_root]
    
    # 만약 /c/FindAndFixMe 형태라면, 다른 표현들도 추가
    if len(host_root) >= 3 and host_root[0] == "/" and host_root[2] == "/":
        drive = host_root[1]
        drive_upper = drive.upper()
        drive_lower = drive.lower()
        rest = host_root[2:]
        prefixes.extend([
            f"/mnt/{drive_lower}{rest}",
            f"{drive_upper}:{rest}",
            f"{drive_lower}:{rest}"
        ])
        
    # 중복 제거 및 길이 역순 정렬 (가장 구체적인 매칭 우선)
    prefixes = sorted(list(set(prefixes)), key=len, reverse=True)
    
    for prefix in prefixes:
        if p.startswith(prefix):
            return "/app" + p[len(prefix):]
    return p


def _find_afl_dirs(afl_out_dir: str, subdir_name: str) -> list:
    """
    AFL++는 -o <dir> 실행 시 <dir>/default/<subdir> 구조로 출력을 생성합니다.
    직접 경로와 1단계 하위 디렉토리를 모두 탐색합니다.
    예: afl_output/1/queue/  또는  afl_output/1/default/queue/
    """
    found = []
    # 직접 경로
    direct = os.path.join(afl_out_dir, subdir_name)
    if os.path.isdir(direct):
        found.append(direct)
    # 1단계 하위 폴더 탐색 (default, fuzzer01 등)
    try:
        for entry in os.listdir(afl_out_dir):
            sub = os.path.join(afl_out_dir, entry, subdir_name)
            if os.path.isdir(sub):
                found.append(sub)
    except OSError:
        pass
    return found


def _run_binary_in_docker(binary_path: str, stdin_data: bytes) -> str:
    """정규 바이너리를 Docker에서 실행하고 stderr(함수 추적 로그)를 리턴"""
    import subprocess
    import platform
    abs_binary_path = os.path.abspath(binary_path).replace("\\", "/")
    print(f"\n[Trace Capture] === Start Trace Capture for {abs_binary_path} ===")
    
    # [정밀 격리] 수동으로 /app/ 등 경로 매핑을 조작하면 도커 자동 인터셉트가 깨지거나 경로 불일치가 발생합니다.
    # 바이너리가 실제 존재하는 오리지널 부모 절대 경로를 그대로 격리 디렉토리로 잡습니다.
    prog_target_dir = os.path.dirname(abs_binary_path)
    print(f"[Trace Capture] Extracted program target directory inside container: {prog_target_dir}")
            
    # [DooD 자동 매핑 연동] 실제 존재하는 prog_target_dir를 마운트하여 Docker Desktop의 WSL2 자동 번역을 완벽하게 활성화합니다!
    mounts_opt = f"{prog_target_dir}:{prog_target_dir}"
    print(f"[Trace Capture] Volume mount mapping (Host:Container): -v {mounts_opt}")
    
    # [공유 라이브러리 링커 검색기] 타깃 폴더 하위에서 모든 빌드된 .so 경로 수집하여 LD_LIBRARY_PATH 주입
    lib_dirs = set()
    if os.path.exists(prog_target_dir):
        for root_p, _, files_p in os.walk(prog_target_dir):
            for fp in files_p:
                if fp.endswith(".so") or ".so." in fp:
                    lib_dirs.add(root_p.replace("\\", "/"))
                    break
    
    print(f"[Trace Capture] Discovered Shared Library Folders: {list(lib_dirs)}")
    
    env_opts = []
    if lib_dirs:
        env_opts = ["-e", f"LD_LIBRARY_PATH={':'.join(lib_dirs)}"]
    
    # [정밀 매핑] 소스 마운트와 컨테이너 매핑 경로가 완전 일치하므로 가공 없이 원본 경로를 실행 경로로 삼습니다!
    container_binary = abs_binary_path
    print(f"[Trace Capture] Mapped container target binary execution path: {container_binary}")
    
    # [DooD 강제 루트 권한 지정] 도커 데몬이 윈도우 호스트 상에서 구동 중이므로, WSL2 내부 UID(1000)는 권한 충돌을 뿜습니다.
    # 안전하게 root 권한을 부여하여 윈도우 파일 시스템 상의 마운트 파일에 대한 무제한 실행을 보장합니다.
    user_opt = "root"
        
    cmd = [
        "docker", "run", "--rm", "-i"
    ] + env_opts + [
        "--network", "none",
        "--user", user_opt,
        "-v", mounts_opt,
        "findandfixme/aflplusplus:latest",
        container_binary
    ]
    
    # 임시 시드 파일은 바이너리와 동일 폴더에 작성
    prog_dir_host = os.path.dirname(os.path.abspath(binary_path))
    import uuid
    temp_seed_name = f"temp_seed_{uuid.uuid4().hex[:12]}"
    temp_seed_host = os.path.join(prog_dir_host, temp_seed_name)
    try:
        with open(temp_seed_host, "wb") as f:
            f.write(stdin_data)
        
        # [정밀 매핑] 소스 마운트와 컨테이너 매핑 경로가 완전 일치하므로 가공 없이 원본 시드 경로를 그대로 전달합니다!
        container_seed = os.path.join(os.path.dirname(abs_binary_path), temp_seed_name)
        cmd.append(container_seed)
        print(f"[Trace Capture] Temporary Seed Written (Host): {temp_seed_host}")
        print(f"[Trace Capture] Mapped container seed path: {container_seed}")
    except Exception as e:
        print(f"[Trace Capture] Warning: failed to write temp seed file: {e}")
        temp_seed_host = None
    
    print(f"[Trace Capture] Invoking Subprocess Command: {' '.join(cmd)}")
    
    try:
        res = subprocess.run(cmd, input=stdin_data, capture_output=True, timeout=10)
        stderr_str = res.stderr.decode("utf-8", errors="ignore")
        stdout_str = res.stdout.decode("utf-8", errors="ignore")
        
        print(f"[Trace Capture] Subprocess Return Code: {res.returncode}")
        print(f"[Trace Capture] Raw stdout length: {len(stdout_str)} chars")
        print(f"[Trace Capture] Raw stderr length: {len(stderr_str)} chars")
        if stderr_str:
            print(f"[Trace Capture] Raw stderr snippet (first 150 chars):\n{stderr_str[:150]}")
        else:
            print("[Trace Capture] WARNING: stderr is completely empty! Execution didn't log [ENTER] addresses.")
            
        return stderr_str, res.returncode
    except Exception as e:
        print(f"[Trace Capture] Error running binary: {e}")
    finally:
        if temp_seed_host and os.path.exists(temp_seed_host):
            try:
                os.remove(temp_seed_host)
                print(f"[Trace Capture] Safely cleaned up temporary seed: {temp_seed_host}")
            except:
                pass
    return "", -1


def _parse_execution_addresses(stderr_output: str) -> List[str]:
    """[ENTER] 0x... 로그 라인을 파싱하여 유니크 헥사 주소 목록 생성"""
    addrs = []
    seen = set()
    for line in stderr_output.splitlines():
        if line.startswith("[ENTER] "):
            addr = line[8:].strip()
            if addr not in seen:
                seen.add(addr)
                addrs.append(addr)
    print(f"[Trace Parser] Parsed {len(addrs)} unique execution addresses from logs.")
    return addrs


def _resolve_addresses_with_addr2line(binary_path: str, addresses: List[str]) -> List[str]:
    """addr2line을 Docker 내부에서 호출하여 메모리 주소를 demangle된 실제 C++ 함수명으로 변환"""
    if not addresses:
        print("[Addr2Line Resolution] No addresses requested for resolution.")
        return []
    import subprocess
    import platform
    
    abs_binary_path = os.path.abspath(binary_path).replace("\\", "/")
    print(f"\n[Addr2Line Resolution] === Start Demangling {len(addresses)} Addresses ===")
    
    # [정밀 격리] 수동으로 /app/ 등 경로 매핑을 조작하면 도커 자동 인터셉트가 깨지거나 경로 불일치가 발생합니다.
    # 바이너리가 실제 존재하는 오리지널 부모 절대 경로를 그대로 격리 디렉토리로 잡습니다.
    prog_target_dir = os.path.dirname(abs_binary_path)
    
    # [DooD 자동 매핑 연동] 실제 존재하는 prog_target_dir를 마운트하여 Docker Desktop의 WSL2 자동 번역을 완벽하게 활성화합니다!
    mounts_opt = f"{prog_target_dir}:{prog_target_dir}"
    
    # [공유 라이브러리 링커 검색기] 타깃 폴더 하위에서 모든 빌드된 .so 경로 수집하여 LD_LIBRARY_PATH 주입
    lib_dirs = set()
    if os.path.exists(prog_target_dir):
        for root_p, _, files_p in os.walk(prog_target_dir):
            for fp in files_p:
                if fp.endswith(".so") or ".so." in fp:
                    lib_dirs.add(root_p.replace("\\", "/"))
                    break
    
    env_opts = []
    if lib_dirs:
        env_opts = ["-e", f"LD_LIBRARY_PATH={':'.join(lib_dirs)}"]
    
    # [정밀 매핑] 소스 마운트와 컨테이너 매핑 경로가 완전 일치하므로 가공 없이 원본 경로를 실행 경로로 삼습니다!
    container_binary = abs_binary_path
    print(f"[Addr2Line Resolution] Mapped container target binary path: {container_binary}")
        
    # [DooD 강제 루트 권한 지정] 도커 데몬이 윈도우 호스트 상에서 구동 중이므로, WSL2 내부 UID(1000)는 권한 충돌을 뿜습니다.
    # 안전하게 root 권한을 부여하여 윈도우 파일 시스템 상의 마운트 파일에 대한 무제한 실행을 보장합니다.
    user_opt = "root"
        
    cmd = [
        "docker", "run", "--rm", "-i"
    ] + env_opts + [
        "--network", "none",
        "--user", user_opt,
        "-v", mounts_opt,
        "findandfixme/aflplusplus:latest",
        "addr2line", "-f", "-C", "-e", container_binary
    ] + addresses
    
    print(f"[Addr2Line Resolution] Invoking Command: {' '.join(cmd)}")
    
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        stdout_str = res.stdout if res.stdout else ""
        stderr_str = res.stderr if res.stderr else ""
        
        print(f"[Addr2Line Resolution] Return Code: {res.returncode}")
        print(f"[Addr2Line Resolution] Raw stdout length: {len(stdout_str)} chars")
        print(f"[Addr2Line Resolution] Raw stderr length: {len(stderr_str)} chars")
        
        lines = stdout_str.splitlines()
        demangled_names = []
        
        # addr2line은 2라인 단위로 출력 (1라인: 함수명, 2라인: 파일명:라인)
        for i in range(0, len(lines), 2):
            func = lines[i].strip()
            if i + 1 < len(lines):
                file_line = lines[i+1].strip()
            else:
                file_line = "??"
            
            # 해독이 완전히 실패하면 "??", 그렇지 않으면 깨끗한 명칭 삽입
            if func == "??" or not func:
                demangled_names.append("??")
            else:
                demangled_names.append(f"{func} ({file_line})")
                
        q_count = demangled_names.count("??")
        print(f"[Addr2Line Resolution] Successfully resolved {len(demangled_names) - q_count} symbols, failed {q_count} symbols.")
        if q_count > 0:
            print(f"[Addr2Line Resolution] WARNING: Some symbols resolved as '??'. Double check if debugging symbols (-g) are present in the target compile.")
            
        return demangled_names
    except Exception as e:
        print(f"[Addr2Line Exception] Critical failure running addr2line: {e}")
        return []


def parse_afl_output(afl_out_dir: str, program_id: int, db: TraceDBManager) -> Dict:
    """
    AFL++ 출력 디렉토리를 순회하며:
      1. 파일을 읽어 raw bytes 수집
      2. MD5 해시로 중복 제거 (T6)
      3. 대표 20개 Normal Path 및 모든 크래시/행만 Docker 실측 계측 수행 (타임아웃 방지 초고속 최적화)
      4. DynamicTrace DB에 INSERT (실제 실행 경로 JSON 포함)
      5. exec_frequency 계산 → 코너 케이스 분류 후 CornerCaseNode INSERT (T9)
    """
    stats = {"total": 0, "inserted": 0, "duplicates": 0, "corner_cases": 0, "errors": 0}

    # ── 1. 모든 AFL++ 출력 파일 수집 ──────────────────────────────────────
    normal_entries: List[Tuple[bytes, str]] = []
    critical_entries: List[Tuple[bytes, str]] = []

    for subdir, label in AFL_SOURCE_DIRS:
        for dir_path in _find_afl_dirs(afl_out_dir, subdir):
            for fname in sorted(os.listdir(dir_path)):
                fpath = os.path.join(dir_path, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                        if label == "afl_queue":
                            normal_entries.append((data, label))
                        else:
                            critical_entries.append((data, label))
                    stats["total"] += 1
                except OSError:
                    stats["errors"] += 1

    if not normal_entries and not critical_entries:
        return stats

    # ── 2. 중복 제거 ────────────────────────────────────────────────────────
    seen_hashes = set()
    unique_normal = []
    for data, label in normal_entries:
        h = hashlib.md5(data).hexdigest()
        if h not in seen_hashes:
            seen_hashes.add(h)
            unique_normal.append((data, label))

    unique_critical = []
    for data, label in critical_entries:
        h = hashlib.md5(data).hexdigest()
        if h not in seen_hashes:
            seen_hashes.add(h)
            unique_critical.append((data, label))

    # ── 3. 시간적 흐름에 따른 고른 분포를 가진 대표 Normal Path 샘플링 (90개로 확장) ──
    max_normal_samples = 90
    if len(unique_normal) > max_normal_samples:
        step = len(unique_normal) / max_normal_samples
        sampled_normal = [unique_normal[int(i * step)] for i in range(max_normal_samples)]
    else:
        sampled_normal = unique_normal

    sampled_normal_set = set(sampled_normal)
    all_unique = unique_normal + unique_critical
    total = len(all_unique)

    # ── 4. 실측 경로 추출 및 DB 적재 (ThreadPoolExecutor 병렬 실행 최적화) ──
    from concurrent.futures import ThreadPoolExecutor

    # 코너케이스 임계치를 미리 산출하여 실행 대상 선별에 활용
    dynamic_threshold = max(CORNER_CASE_THRESHOLD, 2.0 / total if total > 0 else 0)

    # DB에서 빌드된 정규 바이너리 경로 조회
    prog_info = db.get_program(program_id)
    binary_path = prog_info.get("binary_path") if prog_info else None

    # 병렬 처리를 위해 실행할 대상 수집
    targets_to_run = []
    for idx, (raw_bytes, source) in enumerate(all_unique):
        # 해당 노드가 코너케이스에 해당하는지 사전 판별
        if source in ("afl_crash", "afl_hang"):
            is_cc = True
        else:
            exec_freq = (total - idx) / total if total > 0 else 1.0
            is_cc = (exec_freq < dynamic_threshold)

        # 코너케이스이거나 대표 샘플인 경우 무조건 Docker 실측 실행
        should_run_docker = is_cc or ((raw_bytes, source) in sampled_normal_set)
        if should_run_docker and binary_path and os.path.exists(binary_path):
            targets_to_run.append((idx, raw_bytes, source))

    # [Docker 실행 횟수 제한] 실측 컨테이너 기동 최적화 한계를 150개로 대폭 확장
    MAX_DOCKER_RUNS = 150
    if len(targets_to_run) > MAX_DOCKER_RUNS:
        # 크래시/행 시드를 우선 선별, 나머지는 정상 샘플에서 채움
        critical = [t for t in targets_to_run if t[2] in ("afl_crash", "afl_hang")]
        normal = [t for t in targets_to_run if t[2] not in ("afl_crash", "afl_hang")]
        targets_to_run = critical[:MAX_DOCKER_RUNS] + normal[:max(0, MAX_DOCKER_RUNS - len(critical))]
        print(f"[Trace Optimizer] Capped Docker runs: {len(targets_to_run)} (critical={len(critical)})")

    # Phase 1: 바이너리 실행 (병렬) → 함수 주소만 수집 (addr2line은 아직 안 함)
    def _run_worker(item):
        idx, raw_bytes, source = item
        stderr_out, returncode = _run_binary_in_docker(binary_path, raw_bytes)
        addrs = _parse_execution_addresses(stderr_out)
        return idx, addrs, returncode

    raw_addr_results = {}
    return_codes = {}  # idx → subprocess return code (0=normal, 128+N=signal N)
    if targets_to_run:
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = executor.map(_run_worker, targets_to_run)
            for idx, addrs, rc in results:
                return_codes[idx] = rc
                if addrs:
                    raw_addr_results[idx] = addrs

    # Phase 2: 모든 시드의 주소를 합산 → 단일 addr2line 호출로 일괄 해석 (Docker 기동 1회)
    all_unique_addrs = []
    all_unique_addrs_set = set()
    for addrs in raw_addr_results.values():
        for a in addrs:
            if a not in all_unique_addrs_set:
                all_unique_addrs_set.add(a)
                all_unique_addrs.append(a)

    addr_to_symbol = {}
    if all_unique_addrs and binary_path:
        print(f"[Trace Optimizer] Batch-resolving {len(all_unique_addrs)} unique addresses in 1 Docker call")
        symbols = _resolve_addresses_with_addr2line(binary_path, all_unique_addrs)
        for i, addr in enumerate(all_unique_addrs):
            if i < len(symbols):
                addr_to_symbol[addr] = symbols[i]

    # Phase 3: 각 시드별 실행 경로에 심볼 매핑
    # (1) 파일 경로 기반 필터: /usr/, /repo/, /boost/, /include/
    # (2) 함수명 기반 필터: std::, __gnu_cxx::, operator new 등 STL/컴파일러 런타임
    # (3) 디버그 정보 없는 심볼 (??) → 사용자 코드는 반드시 디버그 정보가 있으므로 외부 코드로 간주
    EXTERNAL_PATH_PATTERNS = ["/usr/", "/boost/", "/include/"]
    EXTERNAL_FUNC_PATTERNS = [
        "std::", "__gnu_cxx::", "__cxa", "__cxxabi", "operator new", "operator delete",
        "__libc_", "_start", "numeric_limits", "initializer_list",
        "boost::", "__gxx_personality", "_Unwind_",
    ]

    resolved_paths = {}
    total_filtered_out = 0
    for idx, addrs in raw_addr_results.items():
        exec_path = []
        filtered_count = 0
        for a in addrs:
            symbol = addr_to_symbol.get(a, a)
            if not symbol or symbol == "??":
                filtered_count += 1
                continue
            # 파일 경로 기반 필터
            if any(p in symbol for p in EXTERNAL_PATH_PATTERNS):
                filtered_count += 1
                continue
            # 함수명 자체가 해독 불가능한 경우만 제거 (함수명은 정상이지만 소스 파일 경로만 ??인 경우는 유지)
            func_part = symbol.split(" (")[0] if " (" in symbol else symbol
            if func_part.strip() == "??" or not func_part.strip():
                filtered_count += 1
                continue
            # 함수명 기반 필터
            func_name = symbol.split(" (")[0] if " (" in symbol else symbol
            if any(pat in func_name for pat in EXTERNAL_FUNC_PATTERNS):
                filtered_count += 1
                continue
            # 연속 중복 제거
            if not exec_path or exec_path[-1] != symbol:
                exec_path.append(symbol)

        total_filtered_out += filtered_count

        # ── Phase 3.5: 경로 간소화 (트리맵 가시성 향상) ──
        # FuzzedDataProvider 내부 템플릿 함수들을 하나로 묶고, 긴 심볼명을 짧게 정리
        if exec_path:
            simplified = []
            fdp_seen = False
            for sym in exec_path:
                # 함수명만 추출 (파일 경로 부분 제거)
                func_name = sym.split(" (")[0] if " (" in sym else sym
                # FuzzedDataProvider 내부 함수들을 하나의 노드로 압축
                if "FuzzedDataProvider" in func_name:
                    if not fdp_seen:
                        simplified.append("FuzzedDataProvider")
                        fdp_seen = True
                    continue
                fdp_seen = False
                # LLVMFuzzerTestOneInput 도 하네스 진입점이므로 간결하게
                if func_name == "LLVMFuzzerTestOneInput":
                    simplified.append("LLVMFuzzerTestOneInput")
                    continue
                # 긴 템플릿 인자를 정리하되, QuantLib/프로젝트 네임스페이스는 보존
                short_name = func_name
                # 중첩 템플릿 인자만 축약: QuantLib::Handle<QuantLib::Quote> → QuantLib::Handle<Quote>
                import re
                short_name = re.sub(r'QuantLib::(\w+)', r'\1', short_name)
                # 첫 번째 QuantLib::는 보존하되 중첩된 것만 제거
                if func_name.startswith("QuantLib::"):
                    short_name = "QL::" + short_name
                simplified.append(short_name)
            
            if simplified:
                resolved_paths[idx] = simplified

    # ── 진단 로그: 필터링 결과 요약 ──
    print(f"\n[Trace Diagnostics] ═══════════════════════════════════════════")
    print(f"[Trace Diagnostics] Phase 3 Filtering Summary:")
    print(f"  - Seeds with Docker traces (raw_addr_results): {len(raw_addr_results)}")
    print(f"  - Seeds with surviving symbols (resolved_paths): {len(resolved_paths)}")
    print(f"  - Total symbols filtered out: {total_filtered_out}")
    for idx, path in list(resolved_paths.items())[:3]:  # 처음 3개 시드만 샘플 출력
        print(f"  - Seed #{idx} surviving path ({len(path)} nodes): {' -> '.join(path[:5])}{'...' if len(path) > 5 else ''}")

    inserted: List[Tuple[int, str, int, str]] = []  # (trace_id, source, original_index, code_location)

    for idx, (raw_bytes, source) in enumerate(all_unique):
        execution_path_json = None
        # Docker 실행 안 한 트레이스는 소스 타입(afl_queue/afl_crash/afl_hang)으로 그룹핑
        # → 개별 afl_node_XX 대신 하나의 논리적 노드로 합쳐져 코너케이스 과다 판정 방지
        code_loc = source

        exec_path = resolved_paths.get(idx)
        if exec_path:
            # [핵심 개선] 프로세스 리턴 코드(크래시 시그널)를 경로에 반영
            # 같은 함수를 호출하더라도, 크래시(return code 128+N) vs 정상(0)은 근본적으로 다른 실행
            rc = return_codes.get(idx, 0)
            if rc > 128:
                signal_num = rc - 128
                signal_names = {6: 'SIGABRT', 8: 'SIGFPE', 11: 'SIGSEGV', 9: 'SIGKILL'}
                sig_label = signal_names.get(signal_num, f'SIG{signal_num}')
                exec_path = exec_path + [f'CRASH({sig_label})']
            elif rc != 0 and rc != -1:
                exec_path = exec_path + [f'EXIT({rc})']

            execution_path_json = json.dumps(exec_path)
            # 실행 경로 전체의 고유 핑거프린트를 code_loc으로 사용
            path_sig = "|".join(exec_path)
            path_hash = hashlib.md5(path_sig.encode()).hexdigest()[:8]
            last_meaningful = exec_path[-1]
            code_loc = f"path_{path_hash}_depth{len(exec_path)}_{last_meaningful}"

        trace_id = db.insert_trace(program_id, raw_bytes, source, execution_path_json)
        if trace_id is None:
            stats["duplicates"] += 1
            continue
        stats["inserted"] += 1
        inserted.append((trace_id, source, idx, code_loc))

    # ── 5. 코드 위치별 실제 Hit Count 기반 빈도 계산 → 코너 케이스 분류 (T9) ──
    total_unresolved_normal = sum(1 for _, _, _, loc in inserted if loc == "afl_queue")
    total_resolved_normal = sum(1 for _, _, _, loc in inserted if loc not in ("afl_queue", "afl_crash", "afl_hang"))

    denom_unresolved = total_unresolved_normal if total_unresolved_normal > 0 else 1
    denom_resolved = total_resolved_normal if total_resolved_normal > 0 else 1

    loc_hits = {}
    for trace_id, source, idx, code_loc in inserted:
        loc_hits[code_loc] = loc_hits.get(code_loc, 0) + 1

    # 15% 이하로 실행된 희소한 제어 흐름 분기를 코너케이스로 판정
    dynamic_threshold = 0.15

    # ── 진단 로그: 빈도 분포표 ──
    print(f"\n[Trace Diagnostics] Phase 5 Frequency Distribution:")
    print(f"  - Total inserted traces: {len(inserted)}")
    print(f"  - Resolved normal seeds (denom_resolved): {total_resolved_normal}")
    print(f"  - Unresolved normal seeds (denom_unresolved): {total_unresolved_normal}")
    print(f"  - Unique code locations: {len(loc_hits)}")
    print(f"  - Corner case threshold: < {dynamic_threshold*100:.0f}%")
    print(f"  - Frequency table:")
    for loc, hits in sorted(loc_hits.items(), key=lambda x: x[1], reverse=True):
        if loc in ("afl_queue", "afl_crash", "afl_hang"):
            freq = hits / denom_unresolved
            label = "UNRESOLVED"
        else:
            freq = hits / denom_resolved
            label = "RESOLVED"
        verdict = "CORNER CASE ❗" if freq < dynamic_threshold else "NORMAL ✅"
        loc_short = loc[:80] + "..." if len(loc) > 80 else loc
        print(f"    [{label}] {loc_short}  hits={hits}  freq={freq*100:.1f}%  → {verdict}")

    for trace_id, source, idx, code_loc in inserted:
        if source in ("afl_crash", "afl_hang"):
            exec_freq = CRASH_EXEC_FREQ
        else:
            # 실측된 노드와 스킵된 대형 그룹에 대해 각각의 정밀 상대 비율 적용
            if code_loc == "afl_queue":
                exec_freq = loc_hits[code_loc] / denom_unresolved
            else:
                exec_freq = loc_hits[code_loc] / denom_resolved
            
            # 소수점 이하 가시성 보정
            if exec_freq < 0.0001:
                import random
                exec_freq = 0.0001 + (random.random() * 0.0003)

        if exec_freq < dynamic_threshold:
            try:
                db.insert_corner_case(
                    trace_id=trace_id,
                    node_type=source,
                    exec_frequency=exec_freq,
                    code_location=code_loc
                )
                stats["corner_cases"] += 1
            except Exception as e:
                print(f"[Corner Case Error] Failed to insert corner case: {e}")
                stats["errors"] += 1

    print(f"\n[Trace Diagnostics] Final Result: {stats['corner_cases']} corner cases found out of {len(inserted)} traces.")
    print(f"[Trace Diagnostics] ═══════════════════════════════════════════\n")

    return stats


def _lightweight_json(raw_bytes: bytes) -> Dict:
    """
    [T6] 원시 AFL++ 입력 데이터를 경량 JSON 구조로 변환.
    바이너리는 hex로 인코딩, 크기 정보 포함.
    """
    return {
        "size": len(raw_bytes),
        "hash": hashlib.md5(raw_bytes).hexdigest(),
        "hex_preview": raw_bytes[:64].hex(),  # 처음 64바이트 미리보기
    }


def export_traces_as_json(afl_out_dir: str) -> List[Dict]:
    """
    [T6] AFL++ 출력을 경량 JSON 리스트로 내보내기.
    API 응답이나 로깅에 활용 가능.
    """
    results = []
    seen_hashes = set()

    for subdir, label in AFL_SOURCE_DIRS:
        for dir_path in _find_afl_dirs(afl_out_dir, subdir):
            for fname in sorted(os.listdir(dir_path)):
                fpath = os.path.join(dir_path, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    with open(fpath, "rb") as f:
                        raw = f.read()
                    h = hashlib.md5(raw).hexdigest()
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)
                    entry = _lightweight_json(raw)
                    entry["source"] = label
                    results.append(entry)
                except OSError:
                    continue

    return results


def read_afl_stats(afl_out_dir: str) -> Dict:
    """
    AFL++ fuzzer_stats 파일을 파싱하여 실행 통계를 반환.
    AFL++는 <out_dir>/default/fuzzer_stats 에 파일을 생성합니다.
    """
    # 직접 경로 및 하위 폴더(default 등) 모두 탐색
    candidates = [os.path.join(afl_out_dir, "fuzzer_stats")]
    try:
        for entry in os.listdir(afl_out_dir):
            candidates.append(os.path.join(afl_out_dir, entry, "fuzzer_stats"))
    except OSError:
        pass

    for stats_path in candidates:
        if not os.path.exists(stats_path):
            continue
        stats = {}
        try:
            with open(stats_path, "r") as f:
                for line in f:
                    if ":" in line:
                        key, _, val = line.partition(":")
                        stats[key.strip()] = val.strip()
            return stats
        except OSError:
            pass
    return {}


def build_trace_tree(program_id: int, db: TraceDBManager) -> Dict[str, Any]:
    """
    [T13] DB에 저장된 트레이스 데이터를 기반으로 시각화용 트리 구조 생성.
    - 실제 함수 추적 경로가 저장되어 있는 경우 실제 경로를 활용.
    - 자주 방문한 경로는 hit_count가 높음.
    - 코너 케이스 노드는 is_corner_case=True.
    """
    from .db_manager import get_db_connection

    import sqlite3
    # 1. DB에서 트레이스 및 코너 케이스 정보 가져오기
    with get_db_connection() as conn:
        conn.row_factory = sqlite3.Row
        
        # 코너케이스 정보
        cc_nodes = conn.execute(
            "SELECT trace_id, exec_frequency, code_location FROM CornerCaseNode"
        ).fetchall()
        
        cc_map = {}
        for row in cc_nodes:
            try:
                tid = row["trace_id"]
                cc_map[tid] = dict(row)
            except (TypeError, IndexError):
                cc_map[row[0]] = {"trace_id": row[0], "exec_frequency": row[1], "code_location": row[2]}

        # 전체 트레이스 정보 (execution_path 컬럼 추가 조회)
        traces = conn.execute(
            "SELECT id, source, execution_path FROM DynamicTrace WHERE program_id = ?", (program_id,)
        ).fetchall()

    if not traces:
        return {"name": "No Data", "children": []}

    # 2. 트리 루트 생성
    root = {
        "name": "Main",
        "node_id": "root",
        "hit_count": len(traces),
        "is_corner_case": False,
        "children": []
    }

    # 카테고리 매핑
    SOURCE_LABEL_MAP = {
        "afl_queue": "Normal Paths",
        "afl_crash": "Crash Paths",
        "afl_hang": "Timeout Paths"
    }

    # 3. 각 트레이스를 경로로 변환하여 트리에 병합
    for t in traces:
        t_id = t["id"]
        source = t["source"]
        source_label = SOURCE_LABEL_MAP.get(source, source)
        
        exec_path_json = t["execution_path"]
        exec_path = None
        if exec_path_json:
            try:
                exec_path = json.loads(exec_path_json)
            except:
                pass

        if exec_path:
            # 100% 실제 함수 호출 체인 적용
            path = [source_label] + exec_path
        else:
            # 가상의 경로 대신 직관적이고 깔끔한 경로명 표시
            path = [source_label]
            if t_id in cc_map:
                path.append(cc_map[t_id]["code_location"])
            else:
                path.append(f"Normal Path {t_id}")

        # 이 트레이스가 코너케이스인지 여부
        is_cc_trace = t_id in cc_map
        last_step_idx = len(path) - 1

        # 경로를 트리에 병합
        current = root
        for step_idx, step in enumerate(path):
            is_last_step = (step_idx == last_step_idx)
            found = False
            for child in current["children"]:
                if child["name"] == step:
                    child["hit_count"] += 1
                    # 코너케이스 트레이스의 마지막 스텝(종착 노드)에 플래그 부여
                    if is_cc_trace and is_last_step:
                        child["is_corner_case"] = True
                        cc_info = cc_map[t_id]
                        child["code_snippet"] = f"// Corner case divergence point\n// Execution frequency: {cc_info['exec_frequency']:.6f}\n// Path: {cc_info['code_location']}"
                        child["frequency"] = cc_info["exec_frequency"]
                    current = child
                    found = True
                    break
            
            if not found:
                is_cc_node = is_cc_trace and is_last_step

                new_node = {
                    "name": step,
                    "node_id": f"node_{t_id}_{step}",
                    "hit_count": 1,
                    "is_corner_case": is_cc_node,
                    "children": []
                }
                if is_cc_node:
                     cc_info = cc_map[t_id]
                     new_node["code_snippet"] = f"// Corner case divergence point\n// Execution frequency: {cc_info['exec_frequency']:.6f}\n// Path: {cc_info['code_location']}"
                     new_node["frequency"] = cc_info["exec_frequency"]
                
                current["children"].append(new_node)
                current = new_node

    return root
