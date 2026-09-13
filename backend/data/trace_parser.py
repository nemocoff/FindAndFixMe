"""
backend/data/trace_parser.py

[T6] AFL++ 출력 디렉토리 파싱, MD5 해시 기반 중복 제거, JSON 경량화.
[T9] exec_frequency 계산 후 코너 케이스 노드를 DB에 분류/적재.

[최적화] afl-showmap 기반 경량화
  - 기존: 시드 N개 × Docker 컨테이너 기동 (최대 150회) + addr2line 1회
  - 신규: afl-showmap 전체 시드 일괄처리 (3~4회 Docker 고정, N에 무관)
  - exec_frequency: 순서 기반 추정값 → afl-showmap 실측 hit rate로 교체
"""

import os
import hashlib
import json
import subprocess
import tempfile
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
CORNER_CASE_THRESHOLD = 0.15   # 15% 미만 = 코너 케이스

# Docker 이미지는 환경변수로 오버라이드 가능 (기본값: 로컬 빌드 이미지)
DOCKER_IMAGE = os.environ.get("DOCKER_IMAGE", "findandfixme/aflplusplus:latest")


# ─────────────────────────────────────────────────────────────────────────────
# 경로 헬퍼
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# [신규] afl-showmap 기반 커버리지 수집 헬퍼
# ─────────────────────────────────────────────────────────────────────────────

def _run_afl_showmap_bulk(afl_binary_path: str, seed_dir: str) -> Dict[str, int]:
    """
    afl-showmap -C 로 seed_dir 내 모든 시드를 한 번에 실행하여
    누적 커버리지 맵 {edge_id: total_hit_count} 를 반환합니다.
    Docker 컨테이너를 1회만 기동합니다.
    """
    abs_binary = os.path.abspath(afl_binary_path).replace("\\", "/")
    abs_seed_dir = os.path.abspath(seed_dir).replace("\\", "/")
    prog_dir = os.path.dirname(abs_binary)

    print(f"\n[afl-showmap Bulk] Binary: {abs_binary}")
    print(f"[afl-showmap Bulk] Seed dir: {abs_seed_dir}")

    # 임시 출력 파일 경로 (컨테이너 내부)
    container_out = f"{prog_dir}/.showmap_bulk_out"

    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--user", "root",
        "-e", "AFL_NO_UI=1",
        "-e", "AFL_SKIP_CPUFREQ=1",
        "-e", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1",
        "-e", "AFL_FORKSRV_INIT_TMOUT=5000",
        "-v", f"{prog_dir}:{prog_dir}",
        "-v", f"{abs_seed_dir}:{abs_seed_dir}",
        DOCKER_IMAGE,
        "afl-showmap",
        "-C",                    # 모든 입력의 커버리지 누적
        "-i", abs_seed_dir,      # 입력 디렉토리
        "-o", container_out,     # 출력 파일
        "--",
        abs_binary, "@@"         # @@는 afl-showmap이 각 시드 경로로 대체
    ]

    print(f"[afl-showmap Bulk] Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        stderr_str = result.stderr.decode("utf-8", errors="ignore")
        stdout_str = result.stdout.decode("utf-8", errors="ignore")
        print(f"[afl-showmap Bulk] Return code: {result.returncode}")
        if stderr_str:
            print(f"[afl-showmap Bulk] stderr: {stderr_str[:300]}")
    except subprocess.TimeoutExpired:
        print("[afl-showmap Bulk] Timeout!")
        return {}
    except Exception as e:
        print(f"[afl-showmap Bulk] Exception: {e}")
        return {}

    # 출력 파일 파싱: "edge_id:hit_count" 형식
    coverage_map = {}
    out_host = container_out  # 동일 경로로 마운트됨
    if os.path.exists(out_host):
        try:
            with open(out_host, "r") as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) == 2:
                            try:
                                edge_id = parts[0].strip()
                                hit_count = int(parts[1].strip())
                                coverage_map[edge_id] = hit_count
                            except ValueError:
                                pass
            os.remove(out_host)
        except Exception as e:
            print(f"[afl-showmap Bulk] Failed to parse output: {e}")
    else:
        print(f"[afl-showmap Bulk] Output file not found: {out_host}")
        # stdin 모드로 재시도 (@@를 지원하지 않는 바이너리)
        coverage_map = _run_afl_showmap_bulk_stdin(afl_binary_path, seed_dir)

    print(f"[afl-showmap Bulk] Total edges covered: {len(coverage_map)}")
    return coverage_map


def _run_afl_showmap_bulk_stdin(afl_binary_path: str, seed_dir: str) -> Dict[str, int]:
    """
    바이너리가 stdin에서 입력을 받는 경우의 afl-showmap 실행.
    각 시드를 순차적으로 처리하되, Docker는 1회만 기동.
    (afl-showmap -i stdin 모드)
    """
    abs_binary = os.path.abspath(afl_binary_path).replace("\\", "/")
    abs_seed_dir = os.path.abspath(seed_dir).replace("\\", "/")
    prog_dir = os.path.dirname(abs_binary)
    container_out = f"{prog_dir}/.showmap_stdin_out"

    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--user", "root",
        "-e", "AFL_NO_UI=1",
        "-e", "AFL_SKIP_CPUFREQ=1",
        "-e", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1",
        "-v", f"{prog_dir}:{prog_dir}",
        "-v", f"{abs_seed_dir}:{abs_seed_dir}",
        DOCKER_IMAGE,
        "afl-showmap",
        "-C",
        "-i", abs_seed_dir,
        "-o", container_out,
        "--",
        abs_binary
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        print(f"[afl-showmap stdin] Return code: {result.returncode}")
    except Exception as e:
        print(f"[afl-showmap stdin] Exception: {e}")
        return {}

    coverage_map = {}
    if os.path.exists(container_out):
        try:
            with open(container_out, "r") as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) == 2:
                            try:
                                coverage_map[parts[0].strip()] = int(parts[1].strip())
                            except ValueError:
                                pass
            os.remove(container_out)
        except Exception as e:
            print(f"[afl-showmap stdin] Parse failed: {e}")

    return coverage_map


def _run_afl_showmap_per_seed(
    afl_binary_path: str,
    seed_files: List[str],
    max_seeds: int = 200
) -> Dict[str, Dict[str, int]]:
    """
    각 시드 파일에 대해 afl-showmap을 개별 실행하여
    {seed_filename: {edge_id: hit_count}} 맵을 반환합니다.

    [최적화] 시드 파일들을 임시 디렉토리에 모아놓고 Docker 1회 실행으로 배치 처리합니다.
    개별 Docker 기동 없이 컨테이너 내부 스크립트로 반복 실행합니다.
    """
    if not seed_files:
        return {}

    abs_binary = os.path.abspath(afl_binary_path).replace("\\", "/")
    prog_dir = os.path.dirname(abs_binary)

    # 시드 수 제한
    sampled = seed_files[:max_seeds]
    print(f"\n[afl-showmap PerSeed] Processing {len(sampled)} seeds (limit={max_seeds})")

    # 임시 디렉토리에 시드 수집 (여러 AFL 디렉토리에서 모인 파일들을 한 곳에)
    import shutil
    tmp_seed_dir = os.path.join(prog_dir, ".showmap_seeds_tmp")
    tmp_maps_dir = os.path.join(prog_dir, ".showmap_maps_tmp")
    os.makedirs(tmp_seed_dir, exist_ok=True)
    os.makedirs(tmp_maps_dir, exist_ok=True)

    # 심볼릭 링크 없이 복사 (Windows 호환)
    seed_index = {}  # 임시이름 → 원본경로
    for i, sf in enumerate(sampled):
        dst_name = f"seed_{i:06d}"
        dst = os.path.join(tmp_seed_dir, dst_name)
        try:
            shutil.copy2(sf, dst)
            seed_index[dst_name] = sf
        except Exception as e:
            print(f"[afl-showmap PerSeed] Copy failed {sf}: {e}")

    if not seed_index:
        # 복사 실패 시 생성된 빈 임시 디렉토리도 정리
        for _tmp in (tmp_seed_dir, tmp_maps_dir):
            try:
                shutil.rmtree(_tmp)
            except Exception:
                pass
        return {}

    # 컨테이너 내부 배치 스크립트: 각 시드마다 afl-showmap 실행
    # Docker 1회 기동으로 컨테이너 내부에서 루프 실행
    script = "#!/bin/sh\nset -e\n"
    for seed_name in seed_index.keys():
        seed_path = f"{tmp_seed_dir}/{seed_name}"
        map_path = f"{tmp_maps_dir}/{seed_name}.map"
        # stdin 모드: cat seed | afl-showmap
        script += (
            f"AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "
            f"afl-showmap -o {map_path} -- {abs_binary} < {seed_path} 2>/dev/null || true\n"
        )

    script_path = os.path.join(prog_dir, ".showmap_batch.sh")
    with open(script_path, "w", newline="\n") as f:
        f.write(script)

    # 실행 권한 부여 (Linux 컨테이너에서)
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--user", "root",
        "-e", "AFL_NO_UI=1",
        "-e", "AFL_SKIP_CPUFREQ=1",
        "-e", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1",
        "-v", f"{prog_dir}:{prog_dir}",
        "-v", f"{tmp_seed_dir}:{tmp_seed_dir}",
        "-v", f"{tmp_maps_dir}:{tmp_maps_dir}",
        DOCKER_IMAGE,
        "sh", script_path
    ]

    print(f"[afl-showmap PerSeed] Running batch script in 1 Docker call...")
    per_seed_maps = {}
    try:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=300)
            stderr_str = result.stderr.decode("utf-8", errors="ignore")
            print(f"[afl-showmap PerSeed] Return code: {result.returncode}")
            if stderr_str and len(stderr_str) < 500:
                print(f"[afl-showmap PerSeed] stderr: {stderr_str}")
        except subprocess.TimeoutExpired:
            print("[afl-showmap PerSeed] Batch timeout!")
        except Exception as e:
            print(f"[afl-showmap PerSeed] Exception: {e}")

        # 결과 파싱
        for seed_name, orig_path in seed_index.items():
            map_file = os.path.join(tmp_maps_dir, f"{seed_name}.map")
            edge_map = {}
            if os.path.exists(map_file):
                try:
                    with open(map_file, "r") as f:
                        for line in f:
                            line = line.strip()
                            if ":" in line:
                                parts = line.split(":")
                                if len(parts) == 2:
                                    try:
                                        edge_map[parts[0].strip()] = int(parts[1].strip())
                                    except ValueError:
                                        pass
                except Exception:
                    pass
            per_seed_maps[orig_path] = edge_map
    finally:
        # 임시 파일 정리 (예외/타임아웃 시에도 항상 수행)
        try:
            shutil.rmtree(tmp_seed_dir)
        except Exception:
            pass
        try:
            shutil.rmtree(tmp_maps_dir)
        except Exception:
            pass
        try:
            os.remove(script_path)
        except Exception:
            pass

    covered = sum(1 for m in per_seed_maps.values() if m)
    print(f"[afl-showmap PerSeed] {covered}/{len(sampled)} seeds produced coverage maps")
    return per_seed_maps


def _extract_function_names_via_nm(binary_path: str) -> Dict[str, str]:
    """
    nm --demangle으로 바이너리의 심볼 테이블을 추출하여
    {주소: 함수명} 딕셔너리를 반환합니다.
    Docker 1회 실행.
    """
    abs_binary = os.path.abspath(binary_path).replace("\\", "/")
    prog_dir = os.path.dirname(abs_binary)

    print(f"\n[nm Symbol Table] Extracting symbols from: {abs_binary}")

    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--user", "root",
        "-v", f"{prog_dir}:{prog_dir}",
        DOCKER_IMAGE,
        "nm", "--demangle", "--defined-only", "-n",
        abs_binary
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        stdout_str = result.stdout.decode("utf-8", errors="ignore")
        stderr_str = result.stderr.decode("utf-8", errors="ignore")
        print(f"[nm Symbol Table] Return code: {result.returncode}, output lines: {len(stdout_str.splitlines())}")
    except Exception as e:
        print(f"[nm Symbol Table] Exception: {e}")
        return {}

    # nm 출력 형식: "address type name"
    # 예: 0000000000401234 T compute_sum(int, int)
    EXTERNAL_FUNC_PATTERNS = [
        "std::", "__gnu_cxx::", "__cxa", "__cxxabi", "operator new", "operator delete",
        "__libc_", "_start", "numeric_limits", "initializer_list",
        "boost::", "__gxx_personality", "_Unwind_", "_ZN9__gnu_",
    ]

    addr_to_name = {}
    for line in stdout_str.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        addr, sym_type, name = parts[0], parts[1], parts[2]
        # T/t = 텍스트(코드) 섹션 심볼만 추출 (함수)
        if sym_type.lower() != "t":
            continue
        # 외부 라이브러리 함수 필터링
        if any(p in name for p in EXTERNAL_FUNC_PATTERNS):
            continue
        # C++ 템플릿 등 과도하게 긴 심볼 축약
        display_name = name[:100] if len(name) > 100 else name
        addr_to_name[addr] = display_name

    print(f"[nm Symbol Table] Extracted {len(addr_to_name)} user-defined function symbols")
    return addr_to_name


def _compute_exec_frequency_from_showmap(
    per_seed_maps: Dict[str, Dict[str, int]],
    bulk_coverage: Dict[str, int]
) -> Dict[str, float]:
    """
    각 시드별 커버리지 맵에서 edge별 hit seed count를 계산하여
    {seed_path: exec_frequency} 를 반환합니다.

    exec_frequency = 해당 시드만 커버하는 희소 edge의 비율
    (전체 시드 중 이 시드만 hit하는 edge가 많을수록 코너케이스)
    """
    total_seeds = len(per_seed_maps)
    if total_seeds == 0:
        return {}

    # 각 edge가 몇 개의 시드에서 hit되었는지 카운트
    edge_seed_count: Dict[str, int] = {}
    for seed_path, edge_map in per_seed_maps.items():
        for edge_id in edge_map:
            edge_seed_count[edge_id] = edge_seed_count.get(edge_id, 0) + 1

    # 각 시드의 exec_frequency = 커버한 edge 중 가장 희귀한 edge의 점유율.
    # 희귀 코드를 한 번이라도 밟은 시드는 코너케이스다 (기존 1-희귀비율은
    # 공통 prologue/main edge에 희석되어 단일 함수 novelty를 놓쳤다).
    seed_freq = {}
    for seed_path, edge_map in per_seed_maps.items():
        if not edge_map:
            # 커버리지 맵이 없는 시드는 중간값 부여
            seed_freq[seed_path] = 0.5
            continue

        min_share = min(
            edge_seed_count.get(eid, total_seeds) / total_seeds for eid in edge_map)
        seed_freq[seed_path] = max(min_share, 0.0001)

    return seed_freq


def _infer_function_from_edges(
    edge_map: Dict[str, int],
    bulk_coverage: Dict[str, int],
    seed_label: str
) -> List[str]:
    """
    커버리지 edge 맵에서 의미 있는 실행 경로 레이블을 생성합니다.
    (nm 심볼 테이블 없이도 동작하는 폴백 방법)

    edge_id를 기반으로 상대적 희소성을 나타내는 경로명을 만들어 반환합니다.
    """
    if not edge_map:
        return []

    # 전체 커버리지 대비 이 시드에서만 나온 edge 찾기
    unique_edges = [eid for eid in edge_map if eid not in bulk_coverage or bulk_coverage[eid] <= 1]
    common_edges = [eid for eid in edge_map if eid in bulk_coverage and bulk_coverage[eid] > 10]

    path_parts = []
    if common_edges:
        path_parts.append(f"common_path_edges={len(common_edges)}")
    if unique_edges:
        path_parts.append(f"rare_edges={len(unique_edges)}")

    total_edges = len(edge_map)
    path_parts.append(f"total_cov={total_edges}")

    return path_parts if path_parts else [f"{seed_label}_cov{total_edges}"]


# ─────────────────────────────────────────────────────────────────────────────
# 기존 호환성 유지용 (regular binary 트레이스 - 트리 시각화 전용)
# ─────────────────────────────────────────────────────────────────────────────

def _run_binary_in_docker(binary_path: str, stdin_data: bytes) -> Tuple[str, int]:
    """
    [트리 시각화 전용] 정규 바이너리(-finstrument-functions 빌드)를 Docker에서 실행하고
    stderr([ENTER] 0x...) 함수 추적 로그를 반환합니다.

    exec_frequency 계산에는 사용하지 않습니다 (afl-showmap으로 대체됨).
    """
    import subprocess
    abs_binary_path = os.path.abspath(binary_path).replace("\\", "/")
    prog_target_dir = os.path.dirname(abs_binary_path)
    mounts_opt = f"{prog_target_dir}:{prog_target_dir}"

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

    container_binary = abs_binary_path

    import uuid
    prog_dir_host = os.path.dirname(os.path.abspath(binary_path))
    temp_seed_name = f"temp_seed_{uuid.uuid4().hex[:12]}"
    temp_seed_host = os.path.join(prog_dir_host, temp_seed_name)

    cmd = [
        "docker", "run", "--rm", "-i"
    ] + env_opts + [
        "--network", "none",
        "--user", "root",
        "-v", mounts_opt,
        DOCKER_IMAGE,
        container_binary
    ]

    try:
        with open(temp_seed_host, "wb") as f:
            f.write(stdin_data)
        container_seed = os.path.join(os.path.dirname(abs_binary_path), temp_seed_name)
        cmd.append(container_seed)
    except Exception as e:
        print(f"[Trace Capture] Warning: failed to write temp seed file: {e}")
        temp_seed_host = None

    try:
        res = subprocess.run(cmd, input=stdin_data, capture_output=True, timeout=10)
        stderr_str = res.stderr.decode("utf-8", errors="ignore")
        return stderr_str, res.returncode
    except Exception as e:
        print(f"[Trace Capture] Error running binary: {e}")
    finally:
        if temp_seed_host and os.path.exists(temp_seed_host):
            try:
                os.remove(temp_seed_host)
            except Exception:
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
    return addrs


def _resolve_addresses_with_addr2line(binary_path: str, addresses: List[str]) -> List[str]:
    """addr2line을 Docker 내부에서 호출하여 메모리 주소를 demangle된 실제 C++ 함수명으로 변환"""
    if not addresses:
        return []

    abs_binary_path = os.path.abspath(binary_path).replace("\\", "/")
    prog_target_dir = os.path.dirname(abs_binary_path)
    mounts_opt = f"{prog_target_dir}:{prog_target_dir}"

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

    container_binary = abs_binary_path

    cmd = [
        "docker", "run", "--rm", "-i"
    ] + env_opts + [
        "--network", "none",
        "--user", "root",
        "-v", mounts_opt,
        DOCKER_IMAGE,
        "addr2line", "-f", "-C", "-e", container_binary
    ] + addresses

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        stdout_str = res.stdout if res.stdout else ""
        lines = stdout_str.splitlines()
        demangled_names = []
        for i in range(0, len(lines), 2):
            func = lines[i].strip()
            file_line = lines[i+1].strip() if i + 1 < len(lines) else "??"
            if func == "??" or not func:
                demangled_names.append("??")
            else:
                demangled_names.append(f"{func} ({file_line})")
        return demangled_names
    except Exception as e:
        print(f"[Addr2Line Exception] {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# 메인 파싱 함수
# ─────────────────────────────────────────────────────────────────────────────

def parse_afl_output(afl_out_dir: str, program_id: int, db: TraceDBManager) -> Dict:
    """
    AFL++ 출력 디렉토리를 순회하며:
      1. 파일을 읽어 raw bytes 수집 + MD5 중복 제거 (T6)
      2. [신규] afl-showmap -C 로 전체 누적 커버리지 수집 (Docker 1회)
      3. [신규] afl-showmap 배치로 시드별 커버리지 수집 (Docker 1회)
      4. [신규] exec_frequency = 실측 edge hit rate 기반 계산
      5. DynamicTrace DB에 INSERT (실제 실행 경로 JSON 포함)
      6. exec_frequency → 코너 케이스 분류 후 CornerCaseNode INSERT (T9)

    [최적화] 기존 N+1회 Docker → 3~4회 Docker 고정
    """
    stats = {"total": 0, "inserted": 0, "duplicates": 0, "corner_cases": 0, "errors": 0}

    # ── 1. 모든 AFL++ 출력 파일 수집 ──────────────────────────────────────
    normal_entries: List[Tuple[bytes, str, str]] = []   # (data, label, filepath)
    critical_entries: List[Tuple[bytes, str, str]] = []

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
                        normal_entries.append((data, label, fpath))
                    else:
                        critical_entries.append((data, label, fpath))
                    stats["total"] += 1
                except OSError:
                    stats["errors"] += 1

    if not normal_entries and not critical_entries:
        return stats

    # ── 2. 중복 제거 ────────────────────────────────────────────────────────
    seen_hashes = set()
    unique_normal: List[Tuple[bytes, str, str]] = []
    for data, label, fpath in normal_entries:
        h = hashlib.md5(data).hexdigest()
        if h not in seen_hashes:
            seen_hashes.add(h)
            unique_normal.append((data, label, fpath))

    unique_critical: List[Tuple[bytes, str, str]] = []
    for data, label, fpath in critical_entries:
        h = hashlib.md5(data).hexdigest()
        if h not in seen_hashes:
            seen_hashes.add(h)
            unique_critical.append((data, label, fpath))

    all_unique = unique_normal + unique_critical
    total = len(all_unique)
    print(f"\n[Parse AFL Output] {total} unique entries ({len(unique_normal)} normal, {len(unique_critical)} critical)")

    # ── 3. [신규] afl-showmap 기반 커버리지 수집 ────────────────────────────
    prog_info = db.get_program(program_id)
    afl_binary_path = prog_info.get("afl_binary_path") if prog_info else None

    bulk_coverage: Dict[str, int] = {}
    per_seed_maps: Dict[str, Dict[str, int]] = {}
    seed_exec_freq: Dict[str, float] = {}

    if afl_binary_path and os.path.exists(afl_binary_path):
        # queue 디렉토리 목록 수집
        queue_dirs = _find_afl_dirs(afl_out_dir, "queue")
        queue_files = []
        for qd in queue_dirs:
            for fname in sorted(os.listdir(qd)):
                fp = os.path.join(qd, fname)
                if os.path.isfile(fp):
                    queue_files.append(fp)

        if queue_dirs:
            print(f"\n[afl-showmap] Step 1/2: Bulk coverage map (Docker 1 call)...")
            # queue 디렉토리가 여러 개면 첫 번째만 사용 (afl-showmap -i는 단일 디렉토리)
            bulk_coverage = _run_afl_showmap_bulk(afl_binary_path, queue_dirs[0])

        if queue_files:
            print(f"\n[afl-showmap] Step 2/2: Per-seed coverage (Docker 1 call, batch script)...")
            per_seed_maps = _run_afl_showmap_per_seed(
                afl_binary_path, queue_files, max_seeds=200
            )
            seed_exec_freq = _compute_exec_frequency_from_showmap(per_seed_maps, bulk_coverage)

        print(f"\n[afl-showmap] Bulk edges: {len(bulk_coverage)}, Per-seed maps: {len(per_seed_maps)}")
        print(f"[afl-showmap] exec_frequency computed for {len(seed_exec_freq)} seeds")
    else:
        print(f"[afl-showmap] AFL binary not available ({afl_binary_path}), using order-based fallback")

    # ── 4. [폴백] regular binary 트레이스로 함수명 추출 (트리 시각화용) ──────
    # afl-showmap에서 함수명을 직접 얻기 어려우므로,
    # 대표 샘플만 regular binary로 실행하여 트리 구조에 사용할 execution_path 수집
    binary_path = prog_info.get("binary_path") if prog_info else None

    # 대표 샘플: 코너케이스 후보 (exec_freq 낮은 것) + 전체에서 균등 샘플
    MAX_TREE_SAMPLES = 30  # 트리 시각화용 샘플 수 (대폭 축소)

    sampled_for_tree: List[Tuple[bytes, str, str]] = []
    if binary_path and os.path.exists(binary_path):
        # exec_freq 낮은 시드 우선 선택
        if seed_exec_freq:
            sorted_by_rarity = sorted(
                [(data, label, fpath) for data, label, fpath in unique_normal
                 if fpath in seed_exec_freq],
                key=lambda x: seed_exec_freq.get(x[2], 1.0)
            )
            # 희귀한 것 절반 + 균등 샘플 절반
            rare_count = MAX_TREE_SAMPLES // 2
            sampled_for_tree = sorted_by_rarity[:rare_count]
            # 나머지는 균등 샘플
            remaining = MAX_TREE_SAMPLES - len(sampled_for_tree)
            step = max(1, len(unique_normal) // remaining) if remaining > 0 else 1
            for i in range(0, len(unique_normal), step):
                if len(sampled_for_tree) >= MAX_TREE_SAMPLES:
                    break
                entry = unique_normal[i]
                if entry not in sampled_for_tree:
                    sampled_for_tree.append(entry)
        else:
            # exec_freq 정보 없으면 균등 샘플
            step = max(1, len(unique_normal) // MAX_TREE_SAMPLES)
            sampled_for_tree = [unique_normal[i] for i in range(0, len(unique_normal), step)][:MAX_TREE_SAMPLES]

        # 크래시/행은 모두 포함
        sampled_for_tree += unique_critical

        print(f"\n[Tree Trace] Sampling {len(sampled_for_tree)} seeds for function tree (Docker batch)...")

    # Phase 1: 선택된 샘플만 binary 실행 → 함수 주소 수집
    from concurrent.futures import ThreadPoolExecutor

    raw_addr_results = {}
    return_codes = {}

    if sampled_for_tree and binary_path and os.path.exists(binary_path):
        def _run_worker(item):
            idx, (data, label, fpath) = item
            stderr_out, returncode = _run_binary_in_docker(binary_path, data)
            addrs = _parse_execution_addresses(stderr_out)
            return idx, addrs, returncode

        indexed = list(enumerate(sampled_for_tree))
        with ThreadPoolExecutor(max_workers=6) as executor:
            for idx, addrs, rc in executor.map(_run_worker, indexed):
                return_codes[idx] = rc
                if addrs:
                    raw_addr_results[idx] = addrs

    # Phase 2: 일괄 addr2line (Docker 1회)
    all_unique_addrs = []
    all_unique_addrs_set = set()
    for addrs in raw_addr_results.values():
        for a in addrs:
            if a not in all_unique_addrs_set:
                all_unique_addrs_set.add(a)
                all_unique_addrs.append(a)

    addr_to_symbol = {}
    if all_unique_addrs and binary_path:
        print(f"[Tree Trace] Batch addr2line: {len(all_unique_addrs)} addresses (Docker 1 call)")
        symbols = _resolve_addresses_with_addr2line(binary_path, all_unique_addrs)
        for i, addr in enumerate(all_unique_addrs):
            if i < len(symbols):
                addr_to_symbol[addr] = symbols[i]

    # Phase 3: 심볼 매핑 + 필터링
    EXTERNAL_PATH_PATTERNS = ["/usr/", "/boost/", "/include/"]
    EXTERNAL_FUNC_PATTERNS = [
        "std::", "__gnu_cxx::", "__cxa", "__cxxabi", "operator new", "operator delete",
        "__libc_", "_start", "numeric_limits", "initializer_list",
        "boost::", "__gxx_personality", "_Unwind_",
    ]

    resolved_paths = {}
    for idx, addrs in raw_addr_results.items():
        exec_path = []
        for a in addrs:
            symbol = addr_to_symbol.get(a, a)
            if not symbol or symbol == "??":
                continue
            if any(p in symbol for p in EXTERNAL_PATH_PATTERNS):
                continue
            func_part = symbol.split(" (")[0] if " (" in symbol else symbol
            if func_part.strip() == "??" or not func_part.strip():
                continue
            func_name = symbol.split(" (")[0] if " (" in symbol else symbol
            if any(pat in func_name for pat in EXTERNAL_FUNC_PATTERNS):
                continue
            if not exec_path or exec_path[-1] != symbol:
                exec_path.append(symbol)

        # 경로 간소화
        if exec_path:
            import re
            simplified = []
            fdp_seen = False
            for sym in exec_path:
                func_name = sym.split(" (")[0] if " (" in sym else sym
                if "FuzzedDataProvider" in func_name:
                    if not fdp_seen:
                        simplified.append("FuzzedDataProvider")
                        fdp_seen = True
                    continue
                fdp_seen = False
                if func_name == "LLVMFuzzerTestOneInput":
                    simplified.append("LLVMFuzzerTestOneInput")
                    continue
                short_name = func_name
                short_name = re.sub(r'QuantLib::(\w+)', r'\1', short_name)
                if func_name.startswith("QuantLib::"):
                    short_name = "QL::" + short_name
                simplified.append(short_name)
            if simplified:
                resolved_paths[idx] = simplified

    print(f"\n[Tree Trace] {len(resolved_paths)} seeds with resolved function paths")

    # ── 5. DB INSERT ────────────────────────────────────────────────────────
    # sampled_for_tree 인덱스 → 원본 all_unique 인덱스 매핑
    sampled_set_fpaths = {fpath for _, _, fpath in sampled_for_tree}

    inserted: List[Tuple[int, str, int, str, str]] = []  # (trace_id, source, idx, code_loc, fpath)

    for idx, (raw_bytes, source, fpath) in enumerate(all_unique):
        execution_path_json = None
        code_loc = source

        # sampled_for_tree 인덱스 찾기
        tree_idx = None
        for ti, (td, tl, tf) in enumerate(sampled_for_tree):
            if tf == fpath:
                tree_idx = ti
                break

        exec_path = resolved_paths.get(tree_idx) if tree_idx is not None else None
        if exec_path:
            rc = return_codes.get(tree_idx, 0)
            if rc > 128:
                signal_num = rc - 128
                signal_names = {6: 'SIGABRT', 8: 'SIGFPE', 11: 'SIGSEGV', 9: 'SIGKILL'}
                sig_label = signal_names.get(signal_num, f'SIG{signal_num}')
                exec_path = exec_path + [f'CRASH({sig_label})']
            elif rc != 0 and rc != -1:
                exec_path = exec_path + [f'EXIT({rc})']

            execution_path_json = json.dumps(exec_path)
            path_sig = "|".join(exec_path)
            path_hash = hashlib.md5(path_sig.encode()).hexdigest()[:8]
            last_meaningful = exec_path[-1]
            code_loc = f"path_{path_hash}_depth{len(exec_path)}_{last_meaningful}"

        trace_id = db.insert_trace(program_id, raw_bytes, source, execution_path_json)
        if trace_id is None:
            stats["duplicates"] += 1
            continue
        stats["inserted"] += 1
        inserted.append((trace_id, source, idx, code_loc, fpath))

    # ── 6. exec_frequency 계산 → 코너 케이스 분류 (T9) ──────────────────────
    # [신규] afl-showmap 실측값 우선 사용, 없으면 loc_hits 기반 폴백
    loc_hits = {}
    for trace_id, source, idx, code_loc, fpath in inserted:
        loc_hits[code_loc] = loc_hits.get(code_loc, 0) + 1

    total_resolved_normal = sum(1 for _, s, _, loc, _ in inserted if s == "afl_queue" and loc != "afl_queue")
    total_unresolved_normal = sum(1 for _, s, _, loc, _ in inserted if s == "afl_queue" and loc == "afl_queue")
    denom_resolved = total_resolved_normal if total_resolved_normal > 0 else 1
    denom_unresolved = total_unresolved_normal if total_unresolved_normal > 0 else 1

    print(f"\n[Trace Diagnostics] Phase 6 Frequency Distribution:")
    print(f"  - Total inserted: {len(inserted)}")
    print(f"  - afl-showmap exec_freq available: {len(seed_exec_freq)} seeds")
    print(f"  - Resolved tree paths: {len(resolved_paths)}")
    print(f"  - Corner case threshold: < {CORNER_CASE_THRESHOLD*100:.0f}%")

    for trace_id, source, idx, code_loc, fpath in inserted:
        if source in ("afl_crash", "afl_hang"):
            exec_freq = CRASH_EXEC_FREQ
        else:
            # [신규] afl-showmap 실측값 우선
            if fpath in seed_exec_freq:
                exec_freq = seed_exec_freq[fpath]
            elif code_loc == "afl_queue":
                exec_freq = loc_hits[code_loc] / denom_unresolved
            else:
                exec_freq = loc_hits[code_loc] / denom_resolved

            if exec_freq < 0.0001:
                exec_freq = 0.0001

        if exec_freq < CORNER_CASE_THRESHOLD:
            try:
                db.insert_corner_case(
                    trace_id=trace_id,
                    node_type=source,
                    exec_frequency=exec_freq,
                    code_location=code_loc
                )
                stats["corner_cases"] += 1
            except Exception as e:
                print(f"[Corner Case Error] {e}")
                stats["errors"] += 1

    print(f"[Trace Diagnostics] Final: {stats['corner_cases']} corner cases / {len(inserted)} traces")
    return stats


# ─────────────────────────────────────────────────────────────────────────────
# 유틸리티 함수 (변경 없음)
# ─────────────────────────────────────────────────────────────────────────────

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
    with get_db_connection() as conn:
        conn.row_factory = sqlite3.Row

        cc_nodes = conn.execute(
            "SELECT c.trace_id, c.exec_frequency, c.code_location FROM CornerCaseNode c JOIN DynamicTrace t ON c.trace_id=t.id WHERE t.program_id=?",
            (program_id,),
        ).fetchall()

        cc_map = {}
        for row in cc_nodes:
            try:
                tid = row["trace_id"]
                cc_map[tid] = dict(row)
            except (TypeError, IndexError):
                cc_map[row[0]] = {"trace_id": row[0], "exec_frequency": row[1], "code_location": row[2]}

        traces = conn.execute(
            "SELECT id, source, execution_path FROM DynamicTrace WHERE program_id = ?", (program_id,)
        ).fetchall()

    if not traces:
        return {"name": "No Data", "children": []}

    root = {
        "name": "Main",
        "node_id": "root",
        "hit_count": len(traces),
        "is_corner_case": False,
        "children": []
    }

    SOURCE_LABEL_MAP = {
        "afl_queue": "Normal Paths",
        "afl_crash": "Crash Paths",
        "afl_hang": "Timeout Paths"
    }

    for t in traces:
        t_id = t["id"]
        source = t["source"]
        source_label = SOURCE_LABEL_MAP.get(source, source)

        exec_path_json = t["execution_path"]
        exec_path = None
        if exec_path_json:
            try:
                exec_path = json.loads(exec_path_json)
            except Exception:
                pass

        if exec_path:
            path = [source_label] + exec_path
        else:
            path = [source_label]
            if t_id in cc_map:
                path.append(cc_map[t_id]["code_location"])
            else:
                path.append(f"Normal Path {t_id}")

        is_cc_trace = t_id in cc_map
        last_step_idx = len(path) - 1

        current = root
        for step_idx, step in enumerate(path):
            is_last_step = (step_idx == last_step_idx)
            found = False
            for child in current["children"]:
                if child["name"] == step:
                    child["hit_count"] += 1
                    if is_cc_trace and is_last_step:
                        child["is_corner_case"] = True
                        cc_info = cc_map[t_id]
                        child["code_snippet"] = (
                            f"// Corner case divergence point\n"
                            f"// Execution frequency: {cc_info['exec_frequency']:.6f}\n"
                            f"// Path: {cc_info['code_location']}"
                        )
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
                    new_node["code_snippet"] = (
                        f"// Corner case divergence point\n"
                        f"// Execution frequency: {cc_info['exec_frequency']:.6f}\n"
                        f"// Path: {cc_info['code_location']}"
                    )
                    new_node["frequency"] = cc_info["exec_frequency"]

                current["children"].append(new_node)
                current = new_node

    return root
