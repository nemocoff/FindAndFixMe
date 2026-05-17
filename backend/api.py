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
from typing import Optional, Dict

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

from .data.db_manager import TraceDBManager, get_db_connection, DB_PATH
from .data.trace_parser import parse_afl_output, build_trace_tree

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
    3: "CWE-476 NULL Pointer Dereference",
    4: "CWE-122 Heap Buffer Overflow",
    5: "CWE-416 Use After Free",
    6: "CWE-401 Memory Leak",
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

    return subprocess.run(
        docker_cmd,
        input=stdin_data,
        capture_output=True,
        timeout=timeout
    )


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

    cmd = ["clang++", "-std=c++17", "-I/target", "-I/target/..", "-o", container_binary] + extra_flags + container_sources + ["-lQuantLib"]
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

    cmd = ["afl-clang-fast++", "-std=c++17", "-I/target", "-I/target/..", "-o", container_binary] + extra_flags + container_sources + ["-lQuantLib"]
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
        for file in files:
            safe_name = os.path.basename(file.filename)
            file_path = os.path.join(prog_dir, safe_name)
            content = await file.read()
            with open(file_path, "wb") as f:
                f.write(content)
            if not primary_file_path and safe_name.endswith((".cpp", ".cc", ".cxx")):
                primary_file_path = file_path

        with get_db_connection() as conn:
            conn.execute(
                "UPDATE TargetProgram SET file_path=? WHERE id=?",
                (primary_file_path or os.path.join(prog_dir, files[0].filename), program_id)
            )
            conn.commit()

        return {"status": "success", "program_id": program_id, "files": [f.filename for f in files]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/target/github")
async def init_target_github(req: GithubTargetRequest):
    if not is_safe_github_url(req.repo_url):
        raise HTTPException(status_code=400, detail="Invalid GitHub URL format.")

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO TargetProgram (file_path, original_code) VALUES (?, ?)", ("pending", "github_import"))
            program_id = cursor.lastrowid
            conn.commit()

        repo_name_raw = req.repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        project_dir_name = f"{repo_name_raw}_{program_id}"
        prog_dir = os.path.join(TEMP_TARGETS_DIR, project_dir_name)
        os.makedirs(prog_dir, exist_ok=True)
        repo_dir = os.path.join(prog_dir, "repo")

        print(f"[Git] Cloning {req.repo_url}...")
        try:
            git_res = _run_subprocess(["git", "clone", "--depth", "1", req.repo_url, repo_dir], timeout=300)
            if git_res.returncode != 0:
                raise Exception(f"Git Clone Error:\n{git_res.stderr}")
        except subprocess.TimeoutExpired:
            raise Exception("Git Clone timed out after 300 seconds.")

        build_dir = os.path.join(repo_dir, "build")
        os.makedirs(build_dir, exist_ok=True)
        print(f"[CMake] Configuring {req.repo_url} in Docker Sandbox...")
        
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

        return {"status": "success", "program_id": program_id, "flags_extracted": len(flags)}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Github Import Failed: {str(e)}")


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
        trigger_input = f"node_type == AST_CALL && depth > 5 && node_id == {req.node_id}"
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO SMTConstraint (node_id, constraint_expr, is_solved, trigger_input) VALUES (?,?,?,?)",
                (req.node_id, "auto_generated", 1, trigger_input)
            )
            conn.commit()
        return {"status": "success", "trigger_input": trigger_input}
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/mutations/inject")
async def inject_mutation(req: MutationInjectRequest, background_tasks: BackgroundTasks):
    task_id = f"inject_{req.node_id}_{int(time.time())}"
    TASK_STATUS[task_id] = {"status": "processing"}

    def _inject_task():
        try:
            result = _perform_injection(req)
            TASK_STATUS[task_id] = {"status": "completed", "result": result}
        except Exception as e:
            TASK_STATUS[task_id] = {"status": "failed", "error": str(e)}

    background_tasks.add_task(_inject_task)
    return {"status": "accepted", "task_id": task_id}


def _perform_injection(req: MutationInjectRequest):
    actual_node_id: Optional[int] = None
    row = None
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                """SELECT t.id as program_id, t.file_path, t.original_code, t.source_file_path
                   FROM TargetProgram t
                   JOIN DynamicTrace d ON d.program_id = t.id
                   JOIN CornerCaseNode c ON c.trace_id = d.id
                   WHERE c.id = ?""", (req.node_id,)
            ).fetchone()
        if row: actual_node_id = req.node_id
    except Exception: pass

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

    for pid in patterns:
        try:
            res = _run_subprocess([MUTATION_ENGINE_BIN, source_path, f"--pattern-id={pid}", "--"], timeout=30)
            if res.returncode == 0:
                output = json.loads(res.stdout)
                m_code, m_list = output.get("mutated_code", ""), output.get("mutations", [])
                if m_code and m_code.strip() != original_code.strip():
                    successful_pattern, mutated_code, mutations = pid, m_code, m_list
                    req.pattern_id = pid
                    break
        except: continue

    if not successful_pattern: raise Exception("주입 가능한 취약점 패턴 미발견")

    mutant_binary_path = ""
    mutant_src = os.path.join(os.path.dirname(source_path), f"{os.path.splitext(os.path.basename(source_path))[0]}_mutant.cpp")

    with open(mutant_src, "w", encoding="utf-8") as f: f.write(mutated_code)
    if source_file_path and os.path.exists(os.path.dirname(source_file_path)):
        with open(source_file_path, "w", encoding="utf-8") as f: f.write(mutated_code)

    try:
        mutant_bin = mutant_src.replace(".cpp", "")
        if not _compile_regular(mutant_src, mutant_bin): mutant_binary_path = mutant_bin
    except: pass

    mutant_id = db.insert_mutant(program_id, actual_node_id, req.pattern_id, original_code, mutated_code, mutant_binary_path)
    return {
        "status": "success", 
        "mutant_id": mutant_id, 
        "pattern_name": PATTERN_REGISTRY.get(req.pattern_id, "Unknown"),
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
        
        crash_count, total_runs = 0, 0
        COMPARE_INPUTS = [b"\x00" * 8, b"\xff" * 8, b"test\n", b"0\n", b"-1\n"]

        if os.path.exists(orig_binary) and os.path.exists(mut_binary):
            mounts = {os.path.dirname(os.path.abspath(orig_binary)): "/target"}
            c_orig_bin = "/target/" + os.path.basename(orig_binary)
            c_mut_bin = "/target/" + os.path.basename(mut_binary)

            for test_input in COMPARE_INPUTS:
                try:
                    orig_res = _run_cmd_in_docker(["timeout", "5", c_orig_bin], mounts, timeout=10, stdin_data=test_input)
                    mut_res = _run_cmd_in_docker(["timeout", "5", c_mut_bin], mounts, timeout=10, stdin_data=test_input)
                    total_runs += 1
                    if orig_res.returncode == 0 and mut_res.returncode != 0: crash_count += 1
                except subprocess.TimeoutExpired: pass

        survival_rate = ((total_runs - crash_count) / total_runs * 100.0) if total_runs > 0 else (90.0 if os.path.exists(os.path.join(AFL_OUTPUT_BASE, str(mutant["program_id"]))) else 0.0)

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

        db.update_mutant_validation(mutant_id, survival_rate, llm_score, llm_rationale)
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