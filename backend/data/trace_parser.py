"""
backend/data/trace_parser.py

[T6] AFL++ 출력 디렉토리 파싱, MD5 해시 기반 중복 제거, JSON 경량화.
[T9] exec_frequency 계산 후 코너 케이스 노드를 DB에 분류/적재.
"""

import os
import hashlib
import json
import subprocess
from typing import Dict, List, Tuple

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

    for trace_id, source, idx in inserted:
        if source in ("afl_crash", "afl_hang"):
            exec_freq = CRASH_EXEC_FREQ
        else:
            exec_freq = (idx + 1) / total if total > 0 else 1.0

        if exec_freq < CORNER_CASE_THRESHOLD:
            try:
                db.insert_corner_case(
                    trace_id=trace_id,
                    node_type=source,
                    exec_frequency=exec_freq,
                    code_location=f"afl_node_{idx}"
                )
                stats["corner_cases"] += 1
            except Exception:
                # DB CHECK 제약 위반 등 예외 무시 (이미 0.01 미만만 넘어옴)
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
