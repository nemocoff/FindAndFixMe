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
    prog_dir_host = os.path.dirname(os.path.abspath(binary_path))
    binary_name = os.path.basename(binary_path)
    
    # 임시 시드 파일 작성 (LibFuzzer 바이너리가 인자로 읽을 수 있게 함)
    import uuid
    temp_seed_name = f"temp_seed_{uuid.uuid4().hex[:12]}"
    temp_seed_host = os.path.join(prog_dir_host, temp_seed_name)
    try:
        with open(temp_seed_host, "wb") as f:
            f.write(stdin_data)
    except Exception as e:
        print(f"[Trace Capture] Warning: failed to write temp seed file: {e}")
        temp_seed_name = None

    # 윈도우 환경 대응 및 Docker 마운트 설정
    mounts_opt = f"{os.path.abspath(prog_dir_host)}:/target"
    
    try:
        user_opt = "root" if platform.system() == "Windows" else f"{os.getuid()}:{os.getgid()}"
    except AttributeError:
        user_opt = "root"
        
    cmd = [
        "docker", "run", "--rm", "-i",
        "--network", "none",
        "--user", user_opt,
        "-v", mounts_opt,
        "findandfixme/aflplusplus:latest",
        f"/target/{binary_name}"
    ]
    if temp_seed_name:
        cmd.append(f"/target/{temp_seed_name}")
    
    try:
        res = subprocess.run(cmd, input=stdin_data, capture_output=True, timeout=10)
        return res.stderr.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[Trace Capture Error] {e}")
        return ""
    finally:
        if temp_seed_name and os.path.exists(temp_seed_host):
            try:
                os.remove(temp_seed_host)
            except:
                pass


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
    return addrs


def _resolve_addresses_with_addr2line(binary_path: str, addresses: List[str]) -> List[str]:
    """addr2line을 Docker 내부에서 호출하여 메모리 주소를 demangle된 실제 C++ 함수명으로 변환"""
    if not addresses:
        return []
    import subprocess
    import platform
    prog_dir_host = os.path.dirname(os.path.abspath(binary_path))
    binary_name = os.path.basename(binary_path)
    mounts_opt = f"{os.path.abspath(prog_dir_host)}:/target"
    
    try:
        user_opt = "root" if platform.system() == "Windows" else f"{os.getuid()}:{os.getgid()}"
    except AttributeError:
        user_opt = "root"
        
    # addr2line -f -C -e <binary> <addr1> <addr2> ...
    cmd = [
        "docker", "run", "--rm", "-i",
        "--network", "none",
        "--user", user_opt,
        "-v", mounts_opt,
        "findandfixme/aflplusplus:latest",
        "addr2line", "-f", "-C", "-e", f"/target/{binary_name}"
    ] + addresses
    
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        lines = res.stdout.splitlines()
        # addr2line -f 출력은 2줄당 1개 심볼 (첫줄: 함수명, 둘째줄: 파일명:라인)
        resolved = []
        for i in range(0, len(lines), 2):
            if i < len(lines):
                func_name = lines[i].strip()
                # 만약 ?? 이거나 알 수 없는 함수명이면 주소 그대로 노출
                if func_name == "??" or not func_name:
                    resolved.append(addresses[i // 2])
                else:
                    resolved.append(func_name)
        return resolved
    except Exception as e:
        print(f"[Symbol Resolution Error] {e}")
        return addresses


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

    # ── 3. 시간적 흐름에 따른 고른 분포를 가진 대표 Normal Path 20개 샘플링 ──
    max_normal_samples = 20
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

    # 스레드 작업 정의
    def _worker(item):
        idx, raw_bytes, source = item
        stderr_out = _run_binary_in_docker(binary_path, raw_bytes)
        addrs = _parse_execution_addresses(stderr_out)
        exec_path = None
        if addrs:
            exec_path = _resolve_addresses_with_addr2line(binary_path, addrs)
        return idx, exec_path

    # 최대 8개 병렬 스레드로 Docker 실행 가속 (WSL2 Docker 기동 지연 극복)
    resolved_paths = {}
    if targets_to_run:
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = executor.map(_worker, targets_to_run)
            for idx, exec_path in results:
                if exec_path:
                    resolved_paths[idx] = exec_path

    inserted: List[Tuple[int, str, int, str]] = []  # (trace_id, source, original_index, code_location)

    for idx, (raw_bytes, source) in enumerate(all_unique):
        execution_path_json = None
        code_loc = f"afl_node_{idx}"

        exec_path = resolved_paths.get(idx)
        if exec_path:
            execution_path_json = json.dumps(exec_path)
            code_loc = exec_path[-1]  # 마지막 실행 지점을 함수명으로 마킹

        trace_id = db.insert_trace(program_id, raw_bytes, source, execution_path_json)
        if trace_id is None:
            stats["duplicates"] += 1
            continue
        stats["inserted"] += 1
        inserted.append((trace_id, source, idx, code_loc))

    # ── 5. exec_frequency 계산 → 코너 케이스 분류 (T9) ────────────────────
    dynamic_threshold = max(CORNER_CASE_THRESHOLD, 2.0 / total if total > 0 else 0)

    for trace_id, source, idx, code_loc in inserted:
        if source in ("afl_crash", "afl_hang"):
            exec_freq = CRASH_EXEC_FREQ
        else:
            exec_freq = (total - idx) / total if total > 0 else 1.0

        if exec_freq < dynamic_threshold:
            try:
                db.insert_corner_case(
                    trace_id=trace_id,
                    node_type=source,
                    exec_frequency=exec_freq,
                    code_location=code_loc
                )
                stats["corner_cases"] += 1
            except Exception:
                stats["errors"] += 1

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

        # 경로를 트리에 병합
        current = root
        for step in path:
            found = False
            for child in current["children"]:
                if child["name"] == step:
                    child["hit_count"] += 1
                    # 만약 이 기존 노드가 이번 트레이스에서 코너케이스 지점이라면 코너케이스 플래그 및 메타데이터 업데이트!
                    if t_id in cc_map and step == cc_map[t_id]["code_location"]:
                        child["is_corner_case"] = True
                        child["code_snippet"] = f"// Vulnerability candidate at {step}\n// Execution frequency: {cc_map[t_id]['exec_frequency']:.6f}"
                        child["frequency"] = cc_map[t_id]["exec_frequency"]
                    current = child
                    found = True
                    break
            
            if not found:
                is_cc = False
                if t_id in cc_map:
                    # 코너케이스 여부 확인: 현재 노드가 해당 트레이스 코너케이스의 code_location이거나 마지막 스텝인 경우
                    is_cc = (step == cc_map[t_id]["code_location"])

                new_node = {
                    "name": step,
                    "node_id": f"node_{t_id}_{step}",
                    "hit_count": 1,
                    "is_corner_case": is_cc,
                    "children": []
                }
                if is_cc:
                    new_node["code_snippet"] = f"// Vulnerability candidate at {step}\n// Execution frequency: {cc_map[t_id]['exec_frequency']:.6f}"
                    new_node["frequency"] = cc_map[t_id]["exec_frequency"]
                
                current["children"].append(new_node)
                current = new_node

    return root
