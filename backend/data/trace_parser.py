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


def parse_afl_output(afl_out_dir: str, program_id: int, db: TraceDBManager) -> Dict:
    """
    AFL++ 출력 디렉토리를 순회하며:
      1. 파일을 읽어 raw bytes 수집
      2. MD5 해시로 중복 제거 (T6)
      3. DynamicTrace DB에 INSERT
      4. exec_frequency 계산 → 코너 케이스 분류 후 CornerCaseNode INSERT (T9)

    Returns:
        stats dict: {"total", "inserted", "duplicates", "corner_cases", "errors"}
    """
    stats = {"total": 0, "inserted": 0, "duplicates": 0, "corner_cases": 0, "errors": 0}

    # ── 1. 모든 AFL++ 출력 파일 수집 ──────────────────────────────────────
    raw_entries: List[Tuple[bytes, str]] = []  # (raw_bytes, source_label)

    for subdir, label in AFL_SOURCE_DIRS:
        for dir_path in _find_afl_dirs(afl_out_dir, subdir):
            for fname in sorted(os.listdir(dir_path)):
                fpath = os.path.join(dir_path, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    with open(fpath, "rb") as f:
                        raw_entries.append((f.read(), label))
                    stats["total"] += 1
                except OSError:
                    stats["errors"] += 1

    if not raw_entries:
        return stats

    total = len(raw_entries)

    # ── 2. 중복 제거 + DB 적재 ────────────────────────────────────────────
    inserted: List[Tuple[int, str, int]] = []  # (trace_id, source, original_index)

    for idx, (raw_bytes, source) in enumerate(raw_entries):
        trace_id = db.insert_trace(program_id, raw_bytes, source)
        if trace_id is None:
            # MD5 충돌 → 중복, 건너뜀
            stats["duplicates"] += 1
            continue
        stats["inserted"] += 1
        inserted.append((trace_id, source, idx))

    # ── 3. exec_frequency 계산 → 코너 케이스 분류 (T9) ───────────────────
    # queue 항목: AFL++가 나중에 발견한 경로일수록 희귀 (index / total)
    # crash/hang: 정의상 항상 코너 케이스 (freq = 0.001)

    # 전체 개수가 적을 때는 1% 고정값이 너무 엄격하므로 최소 1개는 포함하도록 유동적 기준 적용
    dynamic_threshold = max(CORNER_CASE_THRESHOLD, 2.0 / total if total > 0 else 0)

    for trace_id, source, idx in inserted:
        if source in ("afl_crash", "afl_hang"):
            exec_freq = CRASH_EXEC_FREQ
        else:
            # 나중에 발견된 경로(큰 idx)일수록 더 희귀함 -> (total - idx) / total 로 계산
            exec_freq = (total - idx) / total if total > 0 else 1.0

        if exec_freq < dynamic_threshold:
            try:
                db.insert_corner_case(
                    trace_id=trace_id,
                    node_type=source,
                    exec_frequency=exec_freq,
                    code_location=f"afl_node_{idx}"
                )
                stats["corner_cases"] += 1
            except Exception:
                # DB 제약 위반 등 예외 처리
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
    - 자주 방문한 경로는 hit_count가 높음 (Frontend에서 파란색 처리 가능)
    - 코너 케이스 노드는 is_corner_case=True (Frontend에서 빨간색 처리 가능)
    """
    from .db_manager import get_db_connection

    # 1. DB에서 트레이스 및 코너 케이스 정보 가져오기
    with get_db_connection() as conn:
        # conn.row_factory = None # 명시적으로 튜플/리스트 반환하게 설정 가능하나 Row 그대로 사용
        
        # 코너케이스 정보
        cc_nodes = conn.execute(
            "SELECT trace_id, exec_frequency, code_location FROM CornerCaseNode"
        ).fetchall()
        cc_map = {row["trace_id"]: row for row in cc_nodes}

        # 전체 트레이스 정보
        traces = conn.execute(
            "SELECT id, source FROM DynamicTrace WHERE program_id = ?", (program_id,)
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

    # 3. 각 트레이스를 경로로 변환하여 트리에 병합
    for t in traces:
        t_id = t["id"]
        source = t["source"]
        
        # 가상의 경로 생성 (AFL++ 소스 -> 노드 구조)
        # 실제로는 계측 데이터를 통해 얻은 기본 블록 시퀀스를 사용해야 함
        path = [source]
        if t_id in cc_map:
            # 코너케이스는 해당 위치를 경로의 끝으로 설정
            path.append(cc_map[t_id]["code_location"])
        else:
            # 일반 경로는 소스 기반의 가상 지점 생성
            path.append(f"block_{hash(str(t_id)) % 8}")

        # 경로를 트리에 병합
        current = root
        for step in path:
            found = False
            for child in current["children"]:
                if child["name"] == step:
                    child["hit_count"] += 1
                    current = child
                    found = True
                    break
            
            if not found:
                is_cc = (t_id in cc_map and step == cc_map[t_id]["code_location"])
                new_node = {
                    "name": step,
                    "node_id": f"node_{t_id}_{step}",
                    "hit_count": 1,
                    "is_corner_case": is_cc,
                    "children": []
                }
                if is_cc:
                    # 코너케이스일 때만 코드 스니펫 및 빈도 정보 추가
                    new_node["code_snippet"] = f"// Vulnerability candidate at {step}\n// Execution frequency: {cc_map[t_id]['exec_frequency']:.6f}"
                    new_node["frequency"] = cc_map[t_id]["exec_frequency"]
                
                current["children"].append(new_node)
                current = new_node

    return root