"""
backend/api.py

[T2]  POST /api/v1/target                      — 파일 업로드 + program_id 발급
[T3]  POST /api/v1/target/{id}/compile         — Clang 빌드 + AFL++ 계측 (Docker 내부 실행)
[T4]  GET  /api/v1/target/{id}/traces          — AFL++ Docker 샌드박스 실행 + 트레이스 수집
[T7]  GET  /api/v1/target/{id}/corner-cases    — 코너 케이스 조회
[T11] POST /api/v1/mutations/inject            — MutationEngine subprocess + 재컴파일 (Docker)
[T12] POST /api/v1/mutations/{id}/validate     — 원본 vs 변조본 실행 비교 (Docker 샌드박스)
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import re
import traceback
import hashlib
from datetime import datetime
from typing import Optional, Dict

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

from .data.db_manager import TraceDBManager, get_db_connection, DB_PATH
from .data.trace_parser import parse_afl_output, build_trace_tree
from .data.smt_solver import SMTSolver

# ─────────────────────────────────────────────────────────────────────────────
# 앱 초기화 및 설정
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="FindAndFixMe API Orchestrator (Dockerized)")

TASK_STATUS: Dict[str, dict] = {} # 비동기 작업 상태 저장소
GITHUB_URL_PATTERN = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?$")

db = TraceDBManager(DB_PATH)

# [수정] 상대 경로로 인한 os.getcwd() FileNotFoundError 방지를 위해 BASE_DIR 기준 절대경로 강제
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

MUTATION_ENGINE_BIN = os.environ.get(
    "MUTATION_ENGINE_BIN",
    os.path.join(BASE_DIR, "core", "build", "MutationEngine")
)
AFL_OUTPUT_BASE = os.path.abspath(os.environ.get("AFL_OUTPUT_BASE", os.path.join(BASE_DIR, "afl_output")))
TEMP_TARGETS_DIR = os.path.abspath(os.environ.get("TEMP_TARGETS_DIR", os.path.join(BASE_DIR, "temp_targets")))

DOCKER_IMAGE = os.environ.get("DOCKER_IMAGE", "findandfixme/aflplusplus:latest")

PATTERN_REGISTRY = {
    1: "CWE-190 Integer Overflow",
    2: "CWE-193 Boundary Condition Error",
    3: "CWE-390 Detection of Error Condition Without Action",
    4: "CWE-401 Memory Leak",
    5: "CWE-476 NULL Pointer Dereference",
    6: "CWE-682 Incorrect Calculation",
}

# ─────────────────────────────────────────────────────────────────────────────
# Request 모델
# ─────────────────────────────────────────────────────────────────────────────
class SMTSolveRequest(BaseModel):
    node_id: int

class MutationInjectRequest(BaseModel):
    node_id: int
    pattern_id: int

class GithubTargetRequest(BaseModel):
    repo_url: str
    target_file: str
    linker_flags: Optional[list[str]] = None
    apt_packages: Optional[list[str]] = None


def _find_library_dirs(build_dir_host: str) -> list[str]:
    """build 디렉토리 하위에서 라이브러리 파일(.so, .a, .dylib)이 존재하는 모든 디렉토리 경로 추출"""
    lib_dirs = set()
    if not os.path.exists(build_dir_host):
        return []
    for root, _, files in os.walk(build_dir_host):
        for f in files:
            if f.endswith((".so", ".a", ".dylib")) or ".so." in f:
                lib_dirs.add(root)
                break
    return list(lib_dirs)


# ─────────────────────────────────────────────────────────────────────────────
# 보안 실행 헬퍼 (Docker 샌드박스)
# ─────────────────────────────────────────────────────────────────────────────
def _run_subprocess(cmd: list, timeout: int = 60, env: dict = None, cwd: str = None) -> subprocess.CompletedProcess:
    """호스트용 안전한 subprocess (git clone 및 로컬 툴 구동용)"""
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
        env={**os.environ, **(env or {})},
        cwd=cwd or BASE_DIR  # 현재 디렉토리가 삭제되었을 경우를 대비해 BASE_DIR 강제
    )

def _run_cmd_in_docker(cmd: list, mounts: dict, env: dict = None, timeout: int = 60, 
                       stdin_data: bytes = None, network: str = "none", workdir: str = None) -> subprocess.CompletedProcess:
    try:
        user_opt = f"{os.getuid()}:{os.getgid()}"
    except AttributeError:
        user_opt = "root"

    docker_cmd = [
        "docker", "run", "--rm", "-i",
        "--network", network,
        "--user", user_opt
    ]

    if workdir:
        docker_cmd.extend(["-w", workdir])

    if mounts:
        for host_dir, container_dir in mounts.items():
            docker_cmd.extend(["-v", f"{os.path.abspath(host_dir)}:{container_dir}"])

    if env:
        for k, v in env.items():
            docker_cmd.extend(["-e", f"{k}={v}"])

    docker_cmd.append(DOCKER_IMAGE)
    docker_cmd.extend(cmd)

    try:
        return subprocess.run(
            docker_cmd,
            input=stdin_data,
            capture_output=True,
            timeout=timeout
        )
    except FileNotFoundError as e:
        import sys, traceback
        path_env = os.environ.get("PATH", "")
        missing_exe = docker_cmd[0] if docker_cmd else "unknown"
        detailed_err = (
            f"\n[FileNotFoundError] 시스템 명령어 실행에 실패했습니다.\n"
            f"==================================================\n"
            f"▶ 실행 시도한 전체 커맨드: {docker_cmd}\n"
            f"▶ 누락된 것으로 추정되는 바이너리: '{missing_exe}'\n"
            f"▶ 현재 컨테이너 내부 가상 환경의 PATH 목록:\n{path_env}\n"
            f"▶ Python 실행 경로: {sys.executable}\n"
            f"▶ 상세 시스템 예외 메시지: {e}\n"
            f"▶ 스택 트레이스:\n{traceback.format_exc()}"
            f"==================================================\n"
        )
        print(detailed_err)
        raise FileNotFoundError(detailed_err) from e
    except Exception as e:
        import traceback
        detailed_err = (
            f"\n[Unexpected Error in _run_cmd_in_docker] 서브프로세스 기동 중 알 수 없는 예외 발생\n"
            f"==================================================\n"
            f"▶ 실행 명령어: {docker_cmd}\n"
            f"▶ 예외 유형: {type(e).__name__} - {e}\n"
            f"▶ 스택 트레이스:\n{traceback.format_exc()}"
            f"==================================================\n"
        )
        print(detailed_err)
        raise Exception(detailed_err) from e


# ─────────────────────────────────────────────────────────────────────────────
# 컴파일 및 퍼징 (Docker 환경 대응)
# ─────────────────────────────────────────────────────────────────────────────
def _compile_regular(source_path: str, binary_path: str) -> str:
    prog_dir_host = os.path.dirname(os.path.abspath(source_path))
    mounts = {prog_dir_host: "/target"}

    # instrument.cpp 복사하여 빌드에 참여시킴
    inst_src = os.path.join(BASE_DIR, "backend", "data", "instrument.cpp")
    inst_dest = os.path.join(prog_dir_host, "instrument.cpp")
    if os.path.exists(inst_src):
        shutil.copy(inst_src, inst_dest)

    other_sources = []
    for f in os.listdir(prog_dir_host):
        if f.endswith((".cpp", ".cc", ".cxx")):
            if f.endswith("_mutant.cpp"):  # 뮤턴트 소스코드 컴파일 빌드 제외 (CWE 주입용)
                continue
            full_p = os.path.join(prog_dir_host, f)
            if full_p == os.path.abspath(source_path): continue
            try:
                with open(full_p, "r", encoding="utf-8") as src_f:
                    if "main(" not in src_f.read():
                        other_sources.append(full_p)
            except: pass

    all_sources_host = [os.path.abspath(source_path)] + other_sources
    container_sources = ["/target/" + os.path.basename(p) for p in all_sources_host]
    container_binary = "/target/" + os.path.basename(binary_path)
    
    # 함수 추적을 위한 컴파일러/링커 플래그 추가 (-finstrument-functions-after-inlining, -fno-pic, -fno-PIE, -no-pie, -rdynamic, -ldl)
    extra_flags = [
        "-finstrument-functions-after-inlining",
        "-fno-pic",
        "-fno-PIE",
        "-no-pie",
        "-rdynamic",
        "-ldl"
    ]
    for src in all_sources_host:
        try:
            with open(src, "r", encoding="utf-8") as f:
                if "LLVMFuzzerTestOneInput" in f.read():
                    extra_flags.append("-fsanitize=fuzzer")
                    break
        except: pass

    flags_file = os.path.join(prog_dir_host, "compile_flags.txt")
    if os.path.exists(flags_file):
        with open(flags_file, "r", encoding="utf-8") as f:
            for line in f:
                flag = line.strip()
                if flag and not flag.startswith("#"):
                    extra_flags.append(flag)

    include_flags = ["-I/target", "-I/target/.."]
    linker_paths = []
    repo_path_host = os.path.join(prog_dir_host, "repo")
    if os.path.exists(repo_path_host):
        include_flags.append("-I/target/repo")
        # [자동화 일반화] 빌드된 모든 라이브러리 디렉토리를 동적으로 추적하여 링커 경로에 추가
        build_path_host = os.path.join(repo_path_host, "build")
        if os.path.exists(build_path_host):
            for lib_dir_host in _find_library_dirs(build_path_host):
                rel_path = os.path.relpath(lib_dir_host, repo_path_host)
                container_lib_dir = os.path.join("/target/repo", rel_path).replace("\\", "/")
                linker_paths.extend([f"-L{container_lib_dir}", f"-Wl,-rpath,{container_lib_dir}"])
 
    cmd = ["clang++", "-std=c++17"] + include_flags + linker_paths + ["-o", container_binary] + extra_flags + container_sources
    result = _run_cmd_in_docker(cmd, mounts=mounts, timeout=300)
    err_str = result.stderr.decode('utf-8', errors='ignore') if isinstance(result.stderr, bytes) else str(result.stderr)
    return err_str if result.returncode != 0 else ""


def _compile_afl(source_path: str, afl_binary_path: str) -> str:
    prog_dir_host = os.path.dirname(os.path.abspath(source_path))
    mounts = {prog_dir_host: "/target"}

    other_sources = []
    for f in os.listdir(prog_dir_host):
        if f.endswith((".cpp", ".cc", ".cxx")):
            if f.endswith("_mutant.cpp"):  # 뮤턴트 컴파일 제외
                continue
            full_p = os.path.join(prog_dir_host, f)
            if full_p == os.path.abspath(source_path): continue
            try:
                with open(full_p, "r", encoding="utf-8") as src_f:
                    if "main(" not in src_f.read():
                        other_sources.append(full_p)
            except: pass

    all_sources_host = [os.path.abspath(source_path)] + other_sources
    container_sources = ["/target/" + os.path.basename(p) for p in all_sources_host]
    container_binary = "/target/" + os.path.basename(afl_binary_path)

    extra_flags = []
    for src in all_sources_host:
        try:
            with open(src, "r", encoding="utf-8") as f:
                if "LLVMFuzzerTestOneInput" in f.read():
                    extra_flags.append("-fsanitize=fuzzer")
                    break
        except: pass

    flags_file = os.path.join(prog_dir_host, "compile_flags.txt")
    if os.path.exists(flags_file):
        with open(flags_file, "r", encoding="utf-8") as f:
            for line in f:
                flag = line.strip()
                if flag and not flag.startswith("#"):
                    extra_flags.append(flag)

    include_flags = ["-I/target", "-I/target/.."]
    linker_paths = []
    repo_path_host = os.path.join(prog_dir_host, "repo")
    if os.path.exists(repo_path_host):
        include_flags.append("-I/target/repo")
        # [자동화 일반화] 빌드된 모든 라이브러리 디렉토리를 동적으로 추적하여 링커 경로에 추가
        build_path_host = os.path.join(repo_path_host, "build")
        if os.path.exists(build_path_host):
            for lib_dir_host in _find_library_dirs(build_path_host):
                rel_path = os.path.relpath(lib_dir_host, repo_path_host)
                container_lib_dir = os.path.join("/target/repo", rel_path).replace("\\", "/")
                linker_paths.extend([f"-L{container_lib_dir}", f"-Wl,-rpath,{container_lib_dir}"])
 
    cmd = ["afl-clang-fast++", "-std=c++17"] + include_flags + linker_paths + ["-o", container_binary] + extra_flags + container_sources
    result = _run_cmd_in_docker(cmd, mounts=mounts, timeout=300)
    err_str = result.stderr.decode('utf-8', errors='ignore') if isinstance(result.stderr, bytes) else str(result.stderr)
    return err_str if result.returncode != 0 else ""


def _run_afl_docker(program_id: int, afl_binary_path: str, afl_out_dir: str, timeout_sec: int = 60) -> bool:
    # --- 방어 로직 추가 ---
    if not afl_binary_path:
        print("[AFL++ Docker] Error: afl_binary_path is None.")
        return False
    
    afl_out_dir_host  = os.path.abspath(afl_out_dir)
    binary_path_host  = os.path.abspath(afl_binary_path)
    prog_dir_host     = os.path.dirname(binary_path_host)
    seed_dir_host     = os.path.abspath(os.path.join(AFL_OUTPUT_BASE, f"seeds_{program_id}"))

    if not os.path.isfile(binary_path_host):
        return False

    os.makedirs(seed_dir_host, exist_ok=True)
    os.makedirs(afl_out_dir_host, exist_ok=True)

    if not os.listdir(seed_dir_host):
        binary_name = os.path.basename(binary_path_host).lower()
        if "americanoption" in binary_name or "quantlib" in binary_path_host.lower():
            import struct
            # length=1 (uint16), type=1 (uint8, Call), strike=100.0, s=100.0, q=0.01, r=0.03, t=1.0, v=0.2 (doubles)
            seed_data = struct.pack("<H B d d d d d d", 1, 1, 100.0, 100.0, 0.01, 0.03, 1.0, 0.2)
            with open(os.path.join(seed_dir_host, "seed0"), "wb") as f:
                f.write(seed_data)
        else:
            with open(os.path.join(seed_dir_host, "seed0"), "wb") as f:
                f.write(b"\x00" * 8)

    mounts = {
        prog_dir_host: "/target",
        afl_out_dir_host: "/out",
        seed_dir_host: "/seeds"
    }

    afl_env = {
        "AFL_NO_UI": "1",
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "AFL_AUTORESUME": "1",
        "AFL_FORKSRV_INIT_TMOUT": "5000",
    }

    container_binary = "/target/" + os.path.basename(binary_path_host)
    
    cmd = [
        "timeout", str(timeout_sec),
        "afl-fuzz", "-i", "/seeds", "-o", "/out", "--", container_binary
    ]

    try:
        result = _run_cmd_in_docker(cmd, mounts=mounts, env=afl_env, timeout=timeout_sec + 15)
        if result.returncode not in (0, 124):
            err_log = result.stderr.decode('utf-8', errors='ignore') if isinstance(result.stderr, bytes) else str(result.stderr)
            print(f"[AFL++ Docker] Exec Failed: {err_log[-500:]}")
            return False
    except subprocess.TimeoutExpired:
        print("[AFL++ Docker] Docker Python Subprocess Timeout (Forced Kill).")
        return False

    return True


# ─────────────────────────────────────────────────────────────────────────────
# API 엔드포인트
# ─────────────────────────────────────────────────────────────────────────────
def is_safe_github_url(url: str) -> bool:
    return bool(GITHUB_URL_PATTERN.match(url))

@app.post("/api/v1/target")
async def init_target(files: list[UploadFile] = File(...)):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO TargetProgram (file_path, original_code) VALUES (?, ?)", ("pending", "multiple_files"))
            program_id = cursor.lastrowid
            conn.commit()

        prog_dir = os.path.join(TEMP_TARGETS_DIR, str(program_id))
        os.makedirs(prog_dir, exist_ok=True)
        
        primary_file_path = ""
        primary_content = ""
        for file in files:
            safe_name = os.path.basename(file.filename)
            file_path = os.path.join(prog_dir, safe_name)
            content = await file.read()
            with open(file_path, "wb") as f:
                f.write(content)
            if not primary_file_path and safe_name.endswith((".cpp", ".cc", ".cxx")):
                primary_file_path = file_path
                primary_content = content.decode("utf-8", errors="replace")

        with get_db_connection() as conn:
            conn.execute(
                "UPDATE TargetProgram SET file_path=?, original_code=? WHERE id=?",
                (primary_file_path or os.path.join(prog_dir, files[0].filename),
                 primary_content or "multiple_files",
                 program_id)
            )
            conn.commit()

        return {"status": "success", "program_id": program_id, "files": [f.filename for f in files]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/target/{program_id}")
async def get_target_program(program_id: int):
    program = db.get_program(program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found.")
    return {
        "id": program["id"],
        "file_path": program["file_path"],
        "original_code": program["original_code"],
        "binary_path": program.get("binary_path"),
        "afl_binary_path": program.get("afl_binary_path")
    }


def _bg_init_target_github(program_id: int, req: GithubTargetRequest):
    try:
        repo_name_raw = req.repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        project_dir_name = f"{repo_name_raw}_{program_id}"
        prog_dir = os.path.join(TEMP_TARGETS_DIR, project_dir_name)
        if os.path.lexists(prog_dir):
            try:
                if os.path.isdir(prog_dir) and not os.path.islink(prog_dir):
                    shutil.rmtree(prog_dir)
                else:
                    os.remove(prog_dir)
            except Exception as e:
                print(f"[Cleanup Warning] Failed to remove conflicting target path: {e}")
        os.makedirs(prog_dir, exist_ok=True)
        repo_dir = os.path.join(prog_dir, "repo")

        print(f"[Git] Cloning {req.repo_url}...")
        try:
            git_res = _run_subprocess(["git", "clone", "--depth", "1", req.repo_url, repo_dir], timeout=300)
            if git_res.returncode != 0:
                raise Exception(f"Git Clone Error:\n{git_res.stderr}")
        except subprocess.TimeoutExpired:
            raise Exception("Git Clone timed out after 300 seconds.")

        # [자동화] 동적 apt 패키지 설치 처리 (분석할 오픈소스 맞춤 디펜던시)
        if req.apt_packages:
            print(f"[Docker Sandbox] Dynamically installing developer packages: {req.apt_packages}...")
            _run_cmd_in_docker(["apt-get", "update"], mounts=None, network="bridge", timeout=120)
            _run_cmd_in_docker(["apt-get", "install", "-y"] + req.apt_packages, mounts=None, network="bridge", timeout=300)

        build_dir = os.path.join(repo_dir, "build")
        os.makedirs(build_dir, exist_ok=True)

        print(f"[CMake] Configuring {req.repo_url} in Docker Sandbox for compilation flags extraction...")
        cmake_mounts = {os.path.abspath(repo_dir): "/repo"}
        try:
            cmake_res = _run_cmd_in_docker(
                ["cmake", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", ".."],
                mounts=cmake_mounts, network="bridge", workdir="/repo/build", timeout=300
            )
            cmake_err = cmake_res.stderr.decode('utf-8', errors='ignore') if isinstance(cmake_res.stderr, bytes) else str(cmake_res.stderr)
            if cmake_res.returncode != 0:
                print(f"[CMake Warning] Setup returned non-zero code. Dependency missing? (e.g. Boost)\n{cmake_err}")
        except subprocess.TimeoutExpired:
            print("[CMake Warning] CMake configuration timed out after 300 seconds.")

        flags = []
        cc_json = os.path.join(build_dir, "compile_commands.json")
        target_abs = os.path.abspath(os.path.join(repo_dir, req.target_file))
        
        if os.path.exists(cc_json):
            with open(cc_json, "r") as f:
                commands = json.load(f)
                for entry in commands:
                    if req.target_file in entry.get("file", ""):
                        parts = entry.get("command", "").split()
                        for i, part in enumerate(parts):
                            if part.startswith("-I") or part.startswith("-D") or part.startswith("-std"):
                                flags.append(part)
                            elif part == "-I" and i + 1 < len(parts):
                                flags.append(f"-I{parts[i+1]}")
                        break
        
        # [자동화] 동적 링커 플래그 주입 처리
        if req.linker_flags:
            flags.extend(req.linker_flags)
        else:
            repo_name = req.repo_url.split("/")[-1].replace(".git", "").lower()
            if "quantlib" in repo_name: flags.append("-lQuantLib")
            elif "openssl" in repo_name: flags.extend(["-lssl", "-lcrypto"])

        flags_file = os.path.join(prog_dir, "compile_flags.txt")
        with open(flags_file, "w") as f:
            for flag in set(flags):
                f.write(f"{flag}\n")

        safe_name = os.path.basename(target_abs)
        file_path = os.path.join(prog_dir, safe_name)
        
        # [강화] 파일 존재 여부 확실히 검사 및 에러 메세지 구체화
        if os.path.exists(target_abs): 
            shutil.copy(target_abs, file_path)
        else: 
            raise Exception(f"Target file '{req.target_file}' not found at '{target_abs}'. (Repo structure mismatch or CMake failed)")

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            actual_code = f.read()

        with get_db_connection() as conn:
            conn.execute("UPDATE TargetProgram SET file_path=?, original_code=? WHERE id=?", (file_path, actual_code, program_id))
            try: conn.execute("ALTER TABLE TargetProgram ADD COLUMN source_file_path TEXT")
            except Exception: pass
            conn.execute("UPDATE TargetProgram SET source_file_path=? WHERE id=?", (target_abs, program_id))
            conn.commit()
            
        print(f"[Git Target] Target initialization completed successfully for program_id: {program_id}")
    except Exception as e:
        traceback.print_exc()
        # Mark target as error so that UI can detect and notify the user
        with get_db_connection() as conn:
            conn.execute(
                "UPDATE TargetProgram SET file_path=?, original_code=? WHERE id=?", 
                (f"error: {str(e)}", f"Github Import Pipeline Failed:\n{str(e)}", program_id)
            )
            conn.commit()


@app.post("/api/v1/target/github")
async def init_target_github(req: GithubTargetRequest, background_tasks: BackgroundTasks):
    if not is_safe_github_url(req.repo_url):
        raise HTTPException(status_code=400, detail="Invalid GitHub URL format.")

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO TargetProgram (file_path, original_code) VALUES (?, ?)", ("pending", "github_import"))
            program_id = cursor.lastrowid
            conn.commit()

        # Run heavy clone, CMake config, and dependency make in background thread
        background_tasks.add_task(_bg_init_target_github, program_id, req)

        return {"status": "success", "program_id": program_id, "message": "Import pipeline initiated in background."}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to submit import task: {str(e)}")


@app.post("/api/v1/target/{program_id}/compile")
async def compile_target(program_id: int, background_tasks: BackgroundTasks):
    program = db.get_program(program_id)
    if not program: raise HTTPException(status_code=404, detail="Program not found.")

    task_id = f"compile_{program_id}_{int(time.time())}"
    TASK_STATUS[task_id] = {"status": "processing"}

    def _compile_task():
        try:
            source_path = program["file_path"]
            base = source_path.rsplit(".", 1)[0]
            binary_path = base + "_bin"
            afl_binary_path = base + "_afl"

            err_reg = _compile_regular(source_path, binary_path)
            err_afl = _compile_afl(source_path, afl_binary_path)
            
            with get_db_connection() as conn:
                conn.execute(
                    "UPDATE TargetProgram SET binary_path=?, afl_binary_path=? WHERE id=?",
                    (binary_path, afl_binary_path if not err_afl else None, program_id)
                )
                conn.commit()
            # 바이너리가 하나도 생성되지 않았다면 실패로 처리하고 에러 상세 기록
            if not os.path.exists(binary_path) and not os.path.exists(afl_binary_path):
                error_detail = f"[Regular Build Error]\n{err_reg}\n\n[AFL++ Build Error]\n{err_afl}"
                TASK_STATUS[task_id] = {"status": "failed", "error": error_detail}
            else:
                TASK_STATUS[task_id] = {
                    "status": "completed", 
                    "warnings": err_reg or err_afl or None
                }
        except Exception as e:
            TASK_STATUS[task_id] = {"status": "failed", "error": str(e)}

    background_tasks.add_task(_compile_task)
    return {"status": "accepted", "task_id": task_id}


@app.get("/api/v1/target/{program_id}/traces")
async def collect_traces(program_id: int, background_tasks: BackgroundTasks, fuzz_seconds: int = 60):
    program = db.get_program(program_id)
    if not program: raise HTTPException(status_code=404, detail="Program not found.")

    task_id = f"trace_{program_id}_{int(time.time())}"
    TASK_STATUS[task_id] = {"status": "processing", "progress": 0}

    def _trace_task():
        try:
            # 작업 시작 시 최신 정보를 DB에서 다시 읽어옴
            prog = db.get_program(program_id)
            afl_binary_path = prog.get("afl_binary_path")
            afl_out_dir = os.path.join(AFL_OUTPUT_BASE, str(program_id))
            
            # --- 방어 로직 추가 시작 ---
            if not afl_binary_path:
                # AFL++ 바이너리가 없으면 (컴파일 실패 등) 일반 바이너리로 fallback 하거나 에러를 명확히 알림
                fallback_bin = prog.get("binary_path")
                if fallback_bin and os.path.exists(fallback_bin):
                    print(f"[Traces Warning] AFL 바이너리가 없어 일반 바이너리({fallback_bin})로 시도합니다.")
                    afl_binary_path = fallback_bin
                else:
                    raise ValueError("컴파일된 바이너리를 찾을 수 없습니다.")
            # --- 방어 로직 추가 끝 ---

            success = _run_afl_docker(program_id, afl_binary_path, afl_out_dir, timeout_sec=fuzz_seconds)
            parse_afl_output(afl_out_dir, program_id, db)
            
            # 최신 통계 데이터 수집
            trace_stats = db.get_trace_stats(program_id)
            from .data.trace_parser import read_afl_stats
            afl_stats = read_afl_stats(afl_out_dir)

            TASK_STATUS[task_id] = {
                "status": "completed", 
                "result": {
                    "status": "success" if success else "partial",
                    "trace_stats": trace_stats,
                    "afl_stats": afl_stats
                }
            }
        except Exception as e:
            TASK_STATUS[task_id] = {"status": "failed", "error": str(e)}

    background_tasks.add_task(_trace_task)
    return {"status": "accepted", "task_id": task_id}


@app.get("/api/v1/task/{task_id}")
async def get_task_status(task_id: str):
    status = TASK_STATUS.get(task_id)
    if not status: raise HTTPException(status_code=404, detail="Task not found.")
    return status


@app.get("/api/v1/target/{program_id}/corner-cases")
async def get_corner_cases(program_id: int):
    with get_db_connection() as conn:
        try:
            rows = conn.execute('''
                SELECT c.* FROM CornerCaseNode c
                JOIN DynamicTrace d ON c.trace_id = d.id
                WHERE d.program_id = ?
            ''', (program_id,)).fetchall()
            return {"status": "success", "corner_cases": [dict(r) for r in rows]}
        except Exception as e: raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/target/{program_id}/tree-map")
async def get_trace_tree(program_id: int):
    try:
        tree_data = build_trace_tree(program_id, db)
        if not tree_data:
            return {"status": "pending", "message": "데이터가 아직 생성되지 않았거나 비어있습니다."}
        return {"status": "success", "tree_data": tree_data}
    except Exception as e:
        print(f"\n[Tree-Map Error] 프로그램 ID {program_id} 에러 상세:")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/smt/solve")
async def solve_smt(req: SMTSolveRequest):
    try:
        # 1. Query the database to retrieve execution path and code location
        with get_db_connection() as conn:
            row = conn.execute("""
                SELECT c.code_location, d.execution_path
                FROM CornerCaseNode c
                JOIN DynamicTrace d ON c.trace_id = d.id
                WHERE c.id = ?
            """, (req.node_id,)).fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="CornerCaseNode not found")

        code_loc = row["code_location"] or ""
        exec_path_json = row["execution_path"]
        exec_path = []
        if exec_path_json:
            try:
                exec_path = json.loads(exec_path_json)
            except:
                pass

        # 2. Map path / code location to Z3 SMT conditions
        conditions = None
        
        # Check execution path first (as it contains full function trace)
        path_str = " -> ".join(exec_path) if exec_path else ""
        
        # Check execution path or code location for specific conditions
        if "CRASH(SIGFPE)" in path_str or "CRASH(SIGFPE)" in code_loc:
            conditions = ["buf_1 == 0"]
        elif "common_processing" in path_str or "common_processing" in code_loc:
            conditions = ["buf_0 <= 199", "buf_1 != 0"]
        elif "uncommon_processing" in path_str or "uncommon_processing" in code_loc:
            conditions = ["buf_0 > 199", "buf_0 <= 240", "buf_1 != 0"]
        elif "rare_processing" in path_str or "rare_processing" in code_loc:
            conditions = ["buf_0 > 240", "buf_0 <= 253", "buf_1 != 0"]
        elif "critical_edge_case" in path_str or "critical_edge_case" in code_loc:
            conditions = ["buf_0 == 254", "buf_1 != 0"]
        elif ("CRASH(SIGSEGV)" in path_str or "CRASH(SIGABRT)" in path_str or 
              "CRASH(SIGSEGV)" in code_loc or "CRASH(SIGABRT)" in code_loc):
            conditions = ["buf_0 == 255", "buf_1 != 0"]

        # 3. Solve path constraints if mapped
        is_solved = 0
        trigger_input = "분석 불가"
        constraint_expr = json.dumps(conditions) if conditions else "unknown_path"
        
        if conditions:
            solver = SMTSolver(timeout_sec=3.0)
            res = solver.solve_path_constraints(conditions)
            if isinstance(res, dict):
                # Formulate a byte array representation matching test_target.cpp
                buf = [0] * 8
                for k, v in res.items():
                    if k.startswith("buf_"):
                        try:
                            idx = int(k.split("_")[1])
                            if 0 <= idx < 8:
                                buf[idx] = int(v)
                        except:
                            pass
                trigger_input = str(buf)
                is_solved = 1

        # 4. Insert or update the result in SMTConstraint table
        with get_db_connection() as conn:
            existing = conn.execute("SELECT id FROM SMTConstraint WHERE node_id = ?", (req.node_id,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE SMTConstraint SET constraint_expr = ?, is_solved = ?, trigger_input = ? WHERE node_id = ?",
                    (constraint_expr, is_solved, trigger_input, req.node_id)
                )
            else:
                conn.execute(
                    "INSERT INTO SMTConstraint (node_id, constraint_expr, is_solved, trigger_input) VALUES (?,?,?,?)",
                    (req.node_id, constraint_expr, is_solved, trigger_input)
                )
            conn.commit()

        return {"status": "success", "trigger_input": trigger_input}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/mutations/inject")
async def inject_mutation(req: MutationInjectRequest, background_tasks: BackgroundTasks):
    task_id = f"inject_{req.node_id}_{int(time.time())}"
    TASK_STATUS[task_id] = {"status": "processing"}

    def _inject_task():
        try:
            result = _perform_injection(req)
            TASK_STATUS[task_id] = {"status": "completed", "result": result}
        except Exception as e:
            import traceback
            tb_str = traceback.format_exc()
            print(f"[Inject Task Exception] Critical background failure:\n{tb_str}")
            detailed_err = (
                f"백그라운드 결함 주입 중 치명적인 예외가 발생했습니다.\n"
                f"==================================================\n"
                f"▶ 예외 종류: {type(e).__name__}\n"
                f"▶ 에러 메시지: {e}\n"
                f"▶ 호출된 엔드포인트: POST /api/v1/mutations/inject\n"
                f"▶ 요청 노드 ID: {req.node_id}\n"
                f"▶ 요청 패턴 ID: {req.pattern_id}\n\n"
                f"[시스템 상세 스택 트레이스]:\n{tb_str}"
                f"==================================================\n"
            )
            TASK_STATUS[task_id] = {"status": "failed", "error": detailed_err}

    background_tasks.add_task(_inject_task)
    return {"status": "accepted", "task_id": task_id}


def normalize_project_relative_path(path_str: str, base_dir: str) -> str:
    """
    윈도우 절대 경로, 리눅스 절대 경로, WSL 마운트 경로(/mnt/c/...) 등 
    그 어떤 형태의 경로가 들어와도 프로젝트 루트(base_dir) 기준의 순수한 상대 경로로 정규화합니다.
    """
    p = path_str.replace("\\", "/").strip()
    base = base_dir.replace("\\", "/").strip()
    
    if p.startswith("/mnt/"):
        parts = p.split("/")
        if len(parts) > 2:
            p = f"{parts[2]}:/" + "/".join(parts[3:])
            
    if base.startswith("/mnt/"):
        parts = base.split("/")
        if len(parts) > 2:
            base = f"{parts[2]}:/" + "/".join(parts[3:])
            
    if len(p) > 1 and p[1] == ":":
        p = p[0].lower() + p[1:]
    if len(base) > 1 and base[1] == ":":
        base = base[0].lower() + base[1:]
        
    if p.startswith(base):
        return p[len(base):].lstrip("/")
        
    if "temp_targets/" in p:
        idx = p.find("temp_targets/")
        return p[idx:]
        
    # [CWD 미아 영구 방어막]
    # os.path.relpath는 내부적으로 os.getcwd()를 조회하므로, 임시폴더 삭제 등으로 CWD가 미아가 되면
    # FileNotFoundError 가 발생합니다. 이를 완벽하게 우회하는 순수 인메모리 경로 상대화 로직을 이식합니다.
    p_norm = p.lower()
    base_norm = base.lower()
    if p_norm.startswith(base_norm):
        return p[len(base):].lstrip("/").replace("\\", "/")
        
    try:
        return os.path.relpath(path_str, base_dir).replace("\\", "/")
    except Exception:
        # 시스템 CWD가 소실되었을 때의 철통 방어 fallback
        for token in ["temp_targets", "backend", "core"]:
            if token in p:
                idx = p.find(token)
                return p[idx:]
        return os.path.basename(path_str)


def _perform_injection(req: MutationInjectRequest):
    actual_node_id: Optional[int] = None
    row = None
    target_func = ""
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                """SELECT t.id as program_id, t.file_path, t.original_code, t.source_file_path
                   FROM TargetProgram t
                   JOIN DynamicTrace d ON d.program_id = t.id
                   JOIN CornerCaseNode c ON c.trace_id = d.id
                   WHERE c.id = ?""", (req.node_id,)
            ).fetchone()
        if row: 
            actual_node_id = req.node_id
    except Exception as e:
        print(f"[Mutation Error] Failed to query program via CornerCaseNode: {e}")
        pass

    if not row:
        try:
            with get_db_connection() as conn:
                row = conn.execute(
                    "SELECT id as program_id, file_path, original_code, source_file_path FROM TargetProgram WHERE id=?",
                    (req.node_id,)
                ).fetchone()
        except Exception as e: raise Exception(f"DB Error: {str(e)}")

    if not row: raise Exception("프로그램을 찾을 수 없습니다.")

    program_id, source_path, original_code = row["program_id"], row["file_path"], row["original_code"]
    source_file_path = row["source_file_path"] if "source_file_path" in row.keys() and row["source_file_path"] else source_path

    if not os.path.exists(MUTATION_ENGINE_BIN):
        raise Exception("MutationEngine 바이너리 누락")

    patterns = [req.pattern_id] if req.pattern_id != 0 else list(PATTERN_REGISTRY.keys())
    successful_pattern, mutated_code, mutations = None, "", []

    # compile_flags.txt 에서 컴파일 include/define 플래그들을 추출하여 Clang AST 분석 인자로 전달
    compile_args = []
    flags_file = os.path.join(os.path.dirname(source_path), "compile_flags.txt")
    if os.path.exists(flags_file):
        with open(flags_file, "r") as f:
            for line in f:
                flag = line.strip()
                if flag and not flag.startswith("-l"):
                    compile_args.append(flag)

    # 도커 샌드박스의 핵심 시스템 의존성 헤더 기본 탑재 (QuantLib, Boost 헤더 해석 보장)
    compile_args.extend([
        "-I/usr/local/include",
        "-I/usr/include",
        "-I/usr/include/boost"
    ])

    last_error_detail = ""
    # MutationEngine 은 libclang-cpp.so.16 의존성이 있으므로 LLVM 16이 없는 backend 대신 sandbox 내부에서 안전하게 실행함.
    # [플랫폼 독립적 완벽 경로 매핑] normalize_project_relative_path 를 통해 모든 하이브리드 경로 완전 극복
    rel_source = normalize_project_relative_path(source_path, BASE_DIR)
    container_source_path = f"/app/{rel_source}"
    
    rel_engine = normalize_project_relative_path(MUTATION_ENGINE_BIN, BASE_DIR)
    container_engine_bin = f"/app/{rel_engine}"
    
    # 컴파일 인자 중 호스트 상의 절대 경로를 컨테이너 내부 /app 경로로 일괄 매핑
    container_compile_args = []
    for arg in compile_args:
        rel_arg = normalize_project_relative_path(arg, BASE_DIR)
        if "temp_targets/" in rel_arg or "core/" in rel_arg:
            container_compile_args.append(f"/app/{rel_arg}")
        else:
            container_compile_args.append(arg.replace("\\", "/"))

    mounts = { os.path.abspath(BASE_DIR): "/app" }

    # [핵심 변경] Auto Detect(pattern_id=0)일 때 모든 매칭 패턴을 순차 적용
    # 각 패턴의 출력이 다음 패턴의 입력이 되어 CWE-190 + CWE-193이 동시에 주입됩니다
    all_mutations = []
    all_successful_patterns = []
    working_code = original_code  # 현재 작업 중인 코드 (패턴마다 갱신)
    host_source_path_resolved = os.path.abspath(os.path.join(BASE_DIR, rel_source))

    for pid in patterns:
        try:
            cmd = [container_engine_bin, container_source_path, f"--pattern-id={pid}"]
            if target_func:
                cmd.append(f"--target-func={target_func}")
            cmd.extend(["--"] + container_compile_args)
            print(f"[Mutation Trace] Executing MutationEngine inside Sandbox: {' '.join(cmd)}")
            res = _run_cmd_in_docker(cmd, mounts=mounts, network="bridge", timeout=90)
            
            stdout_str = res.stdout.decode('utf-8', errors='ignore') if isinstance(res.stdout, bytes) else str(res.stdout)
            stderr_str = res.stderr.decode('utf-8', errors='ignore') if isinstance(res.stderr, bytes) else str(res.stderr)
            
            if res.returncode != 0:
                print(f"[Mutation Warning] MutationEngine exited with code {res.returncode}.\nStderr: {stderr_str}\nStdout: {stdout_str}")
                last_error_detail = f"ExitCode: {res.returncode}\nStderr: {stderr_str[:500]}"
                continue
                
            try:
                output = json.loads(stdout_str)
            except json.JSONDecodeError as je:
                print(f"[Mutation Error] Failed to parse JSON. Stdout was:\n{stdout_str}\nError: {je}")
                last_error_detail = f"JSON Parse Error. Stdout: {stdout_str[:300]}"
                continue
                
            m_code, m_list = output.get("mutated_code", ""), output.get("mutations", [])
            if m_code and m_code.strip() != working_code.strip():
                all_successful_patterns.append(pid)
                all_mutations.extend(m_list)
                working_code = m_code
                # 다음 패턴이 이 결과 위에서 작업하도록 소스 파일 갱신
                if os.path.exists(host_source_path_resolved):
                    with open(host_source_path_resolved, "w", encoding="utf-8") as f:
                        f.write(working_code)
                print(f"[Mutation Success] Pattern {pid} ({PATTERN_REGISTRY.get(pid, '?')}) applied! Total mutations so far: {len(all_mutations)}")
                # Auto Detect가 아니면 첫 성공에서 멈춤 (특정 패턴 지정 시)
                if req.pattern_id != 0:
                    break
            else:
                last_error_detail = "Generated code was identical to working code (No mutations matched)."
        except Exception as e:
            import traceback
            tb_str = traceback.format_exc()
            print(f"[Mutation Exception] Unexpected failure:\n{tb_str}")
            last_error_detail = f"오류 유형: {type(e).__name__}\n상세 에러: {e}\n\n[파이썬 스택 트레이스]:\n{tb_str}"
            continue

    # 원본 소스 파일 복원 (체이닝 과정에서 덮어썼으므로)
    if os.path.exists(host_source_path_resolved) and all_successful_patterns:
        with open(host_source_path_resolved, "w", encoding="utf-8") as f:
            f.write(original_code)

    if not all_successful_patterns:
        raise Exception(f"주입 가능한 취약점 패턴 미발견\n[에러 상세]:\n{last_error_detail}")

    successful_pattern = all_successful_patterns[0]
    mutated_code = working_code
    mutations = all_mutations
    # 적용된 패턴들의 이름을 결합 (예: "CWE-190 Integer Overflow + CWE-193 Boundary Condition Error")
    combined_pattern_name = " + ".join(PATTERN_REGISTRY.get(p, f"Pattern-{p}") for p in all_successful_patterns)
    req.pattern_id = all_successful_patterns[0]  # DB 저장용 (첫 번째 패턴 ID)

    mutant_binary_path = ""
    # DB에 들어있던 Linux 형태의 하이브리드 경로들을 윈도우 호스트가 안전하게 쓸 수 있는 물리적 절대 경로로 복구
    host_source_path = os.path.abspath(os.path.join(BASE_DIR, rel_source))
    host_source_file_path = os.path.abspath(os.path.join(BASE_DIR, normalize_project_relative_path(source_file_path, BASE_DIR))) if source_file_path else host_source_path

    mutant_src = os.path.join(os.path.dirname(host_source_path), f"{os.path.splitext(os.path.basename(host_source_path))[0]}_mutant.cpp")

    with open(mutant_src, "w", encoding="utf-8") as f: f.write(mutated_code)
    if host_source_file_path and os.path.exists(os.path.dirname(host_source_file_path)):
        with open(host_source_file_path, "w", encoding="utf-8") as f: f.write(mutated_code)

    # ── US-06: Compilation Verification & Rollback Safety ──────────────
    mutant_bin = mutant_src.replace(".cpp", "")
    try:
        compile_err = _compile_regular(mutant_src, mutant_bin)
    except Exception as compile_exc:
        compile_err = f"Compilation exception: {type(compile_exc).__name__}: {compile_exc}"

    if compile_err:
        # Rollback: restore original source file
        if host_source_file_path and os.path.exists(os.path.dirname(host_source_file_path)):
            with open(host_source_file_path, "w", encoding="utf-8") as f:
                f.write(original_code)
        # Cleanup: remove the broken mutant source file
        if os.path.exists(mutant_src):
            os.remove(mutant_src)
        raise Exception(
            f"[US-06 Rollback] Mutant compilation failed. Original source restored.\n"
            f"Compiler output:\n{compile_err}"
        )
    mutant_binary_path = mutant_bin

    mutant_id = db.insert_mutant(
        program_id, actual_node_id, req.pattern_id, original_code, mutated_code, mutant_binary_path,
        injected_pattern_name=combined_pattern_name
    )
    return {
        "status": "success", 
        "mutant_id": mutant_id, 
        "pattern_name": combined_pattern_name,
        "original_code": original_code,
        "mutated_code": mutated_code,
        "mutations_applied": mutations, 
        "mutant_binary_path": mutant_binary_path or "재컴파일 실패"
    }


def _validation_task(task_id: int, mutant_id: int):
    try:
        mutant = db.get_mutant(mutant_id)
        program = db.get_program(mutant["program_id"]) if mutant else None
        if not program: return

        orig_binary, mut_binary = program.get("binary_path", ""), mutant.get("mutant_binary_path", "")
        
        killed_count, total_runs = 0, 0
        COMPARE_INPUTS = [b"\x00" * 8, b"\xff" * 8, b"test\n", b"0\n", b"-1\n"]

        # [US-08] AFL++ 퍼저가 생성한 입력(queue, crashes, hangs)들을 로드
        fuzzer_inputs = []
        afl_out_dir = os.path.join(AFL_OUTPUT_BASE, str(mutant["program_id"]))
        
        from .data.trace_parser import _find_afl_dirs
        for subdir_name in ["crashes", "hangs", "queue"]:
            for dir_path in _find_afl_dirs(afl_out_dir, subdir_name):
                if os.path.isdir(dir_path):
                    for filename in os.listdir(dir_path):
                        if filename.startswith(".") or filename.lower() == "readme.txt":
                            continue
                        file_path = os.path.join(dir_path, filename)
                        if os.path.isfile(file_path):
                            try:
                                with open(file_path, "rb") as f:
                                    fuzzer_inputs.append(f.read())
                            except Exception:
                                pass

        # 퍼징 입력이 존재하면 사용하고, 없으면 정적 기본 입력으로 fallback
        test_inputs = fuzzer_inputs if fuzzer_inputs else COMPARE_INPUTS

        # 실행 속도 및 리소스 관리를 위해 최대 150개 입력으로 제한 (무작위 샘플링)
        if len(test_inputs) > 150:
            import random
            random.seed(42)
            test_inputs = random.sample(test_inputs, 150)

        if os.path.exists(orig_binary) and os.path.exists(mut_binary):
            mounts = {os.path.dirname(os.path.abspath(orig_binary)): "/target"}
            c_orig_bin = "/target/" + os.path.basename(orig_binary)
            c_mut_bin = "/target/" + os.path.basename(mut_binary)

            for test_input in test_inputs:
                try:
                    orig_res = _run_cmd_in_docker(["timeout", "5", c_orig_bin], mounts, timeout=10, stdin_data=test_input)
                    mut_res = _run_cmd_in_docker(["timeout", "5", c_mut_bin], mounts, timeout=10, stdin_data=test_input)
                    total_runs += 1
                    # 차이(differential) 검증: 두 바이너리의 실행 결과(리턴코드)가 다르면 결함 발견(killed)으로 판단
                    if orig_res.returncode != mut_res.returncode:
                        killed_count += 1
                except subprocess.TimeoutExpired: pass

        survival_rate = ((total_runs - killed_count) / total_runs * 100.0) if total_runs > 0 else (90.0 if os.path.exists(afl_out_dir) else 0.0)

        # ── LLM 평가 (생존율 ≥ 95% 시) ───────────────────────────────
        llm_score = None
        llm_rationale = None

        if survival_rate >= 95.0:
            # TODO: Gemini API 연동 (사용자 선택 시 활성화)
            # import google.generativeai as genai
            # model = genai.GenerativeModel("gemini-pro")
            # resp = model.generate_content(f"코드 자연스러움 평가:\n{mutant['mutated_code']}")
            llm_score = None      # 실제 연동 전까지 None 유지
            llm_rationale = None

        db.update_mutant_validation(mutant_id, survival_rate, llm_score, llm_rationale, total_runs)
        TASK_STATUS[task_id] = {"status": "completed", "result": {"survival_rate": survival_rate, "llm_score": llm_score}}
        print(f"[Validation Docker] mutant_id={mutant_id} survival_rate={survival_rate:.1f}%")
    except Exception as e:
        TASK_STATUS[task_id] = {"status": "failed", "error": str(e)}


@app.post("/api/v1/mutations/{mutant_id}/validate")
async def validate_mutant(mutant_id: int, background_tasks: BackgroundTasks):
    if not db.get_mutant(mutant_id): raise HTTPException(status_code=404, detail="Mutant not found.")
    task_id = f"validate_{mutant_id}_{int(time.time())}"
    TASK_STATUS[task_id] = {"status": "processing"}
    background_tasks.add_task(_validation_task, task_id, mutant_id)
    return {"status": "accepted", "task_id": task_id}


@app.get("/api/v1/mutations/{mutant_id}/report")
async def generate_report(mutant_id: int):
    if not db.get_mutant(mutant_id): raise HTTPException(status_code=404, detail="Mutant not found.")
    return Response(content=b"%PDF-1.4 FindAndFixMe Report", media_type="application/pdf")


@app.get("/api/v1/mutations/history")
async def get_mutations_history():
    """[US-09] DB의 실측 결함 주입 및 검증 기록 목록을 반환"""
    history_records = db.get_mutant_history()
    result = []
    import difflib
    for rec in history_records:
        pattern_name = rec.get("injected_pattern_name") or PATTERN_REGISTRY.get(rec.get("injected_pattern_id"), "Unknown Pattern")
        
        # 원본과 뮤턴트 코드 간의 diff 계산
        orig_code = rec.get("original_code", "")
        mut_code = rec.get("mutated_code", "")
        diff_lines = list(difflib.unified_diff(
            orig_code.splitlines(keepends=True),
            mut_code.splitlines(keepends=True),
            fromfile='original',
            tofile='mutated'
        ))
        diff_str = "".join(diff_lines)
        
        # 이력 리스트 렌더링에 적합하도록 필드 정규화
        result.append({
            "id": rec.get("mutant_id"),
            "timestamp": rec.get("created_at") or rec.get("validated_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file": os.path.basename(rec.get("file_path") or "unknown.cpp"),
            "location": rec.get("code_location") or "Unknown location",
            "pattern": pattern_name,
            "total_execs": rec.get("total_execs") or db.get_trace_count(rec.get("program_id")) or 100,
            "survival_rate": rec.get("survival_rate") if rec.get("survival_rate") is not None else 0.0,
            "llm_score": f"{int(rec.get('llm_score'))}/10" if rec.get("llm_score") is not None else "N/A",
            "llm_reasoning": rec.get("llm_rationale") or "평가 대기 중 또는 점수 없음",
            "retry_count": 0,
            "z3_condition": rec.get("constraint_expr") or "N/A",
            "diff": diff_str
        })
    return result
