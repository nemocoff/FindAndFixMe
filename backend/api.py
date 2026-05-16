"""
backend/api.py

[T2]  POST /api/v1/target                      — 파일 업로드 + program_id 발급
[T3]  POST /api/v1/target/{id}/compile         — Clang 빌드 + AFL++ 계측 빌드
[T4]  GET  /api/v1/target/{id}/traces          — AFL++ Docker 실행 + 트레이스 수집
[T7]  GET  /api/v1/target/{id}/corner-cases    — 코너 케이스 조회
[T11] POST /api/v1/mutations/inject            — MutationEngine subprocess + 재컴파일
[T12] POST /api/v1/mutations/{id}/validate     — 원본 vs 변조본 실행 비교 (비동기)
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

from .data.db_manager import TraceDBManager, get_db_connection, DB_PATH
from .data.trace_parser import parse_afl_output, export_traces_as_json, read_afl_stats, build_trace_tree

# ─────────────────────────────────────────────────────────────────────────────
# 앱 초기화
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="FindAndFixMe API Orchestrator")
db = TraceDBManager(DB_PATH)

# 경로 설정 (환경변수 우선, 기본값 폴백)
MUTATION_ENGINE_BIN = os.environ.get(
    "MUTATION_ENGINE_BIN",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "core", "build", "MutationEngine"))
)
AFL_OUTPUT_BASE = os.environ.get("AFL_OUTPUT_BASE", "afl_output")
TEMP_TARGETS_DIR = os.environ.get("TEMP_TARGETS_DIR", "temp_targets")

# [T10] 패턴 레지스트리: pattern_id → CWE 이름
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
    target_file: str # 저장소 내 상대 경로 (예: fuzz-test-suite/date.cpp)


# ─────────────────────────────────────────────────────────────────────────────
# 내부 헬퍼
# ─────────────────────────────────────────────────────────────────────────────
def _run_subprocess(cmd: list, timeout: int = 60, env: dict = None) -> subprocess.CompletedProcess:
    """subprocess.run 래퍼 — timeout + 에러 로깅."""
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
        env={**os.environ, **(env or {})}
    )


def _compile_regular(source_path: str, binary_path: str) -> str:
    """[T3-a] clang++-16으로 일반 바이너리 컴파일. source_path가 공백 포함 시 리스트로 처리."""
    prog_dir = os.path.dirname(source_path)
    all_sources = [os.path.join(prog_dir, f) for f in os.listdir(prog_dir) if f.endswith((".cpp", ".cc", ".cxx"))]
    
    extra_flags = []
    # LibFuzzer 하네스 자동 감지
    for src in all_sources:
        try:
            with open(src, "r", encoding="utf-8") as f:
                if "LLVMFuzzerTestOneInput" in f.read():
                    extra_flags.append("-fsanitize=fuzzer")
                    break
        except Exception:
            pass

    # 커스텀 컴파일 플래그 파일 읽기
    flags_file = os.path.join(prog_dir, "compile_flags.txt")
    if os.path.exists(flags_file):
        with open(flags_file, "r", encoding="utf-8") as f:
            for line in f:
                flag = line.strip()
                if flag and not flag.startswith("#"):
                    extra_flags.append(flag)

    cmd = ["clang++-16", "-std=c++17", "-I", prog_dir, "-o", binary_path] + extra_flags + all_sources
    result = _run_subprocess(cmd, timeout=60)
    return result.stderr if result.returncode != 0 else ""


def _compile_afl(source_path: str, afl_binary_path: str) -> str:
    """[T3-b] afl-clang++로 계측(instrumented) 바이너리 컴파일."""
    afl_compiler = shutil.which("afl-clang-fast++") or shutil.which("afl-clang++-16") or shutil.which("afl-clang++")
    if not afl_compiler:
        return "afl-clang-fast++ not found — skipping AFL instrumentation build."

    prog_dir = os.path.dirname(source_path)
    all_sources = [os.path.join(prog_dir, f) for f in os.listdir(prog_dir) if f.endswith((".cpp", ".cc", ".cxx"))]

    extra_flags = []
    # LibFuzzer 하네스 자동 감지
    for src in all_sources:
        try:
            with open(src, "r", encoding="utf-8") as f:
                if "LLVMFuzzerTestOneInput" in f.read():
                    extra_flags.append("-fsanitize=fuzzer")
                    break
        except Exception:
            pass

    # 커스텀 컴파일 플래그 파일 읽기
    flags_file = os.path.join(prog_dir, "compile_flags.txt")
    if os.path.exists(flags_file):
        with open(flags_file, "r", encoding="utf-8") as f:
            for line in f:
                flag = line.strip()
                if flag and not flag.startswith("#"):
                    extra_flags.append(flag)

    cmd = [afl_compiler, "-std=c++17", "-I", prog_dir, "-o", afl_binary_path] + extra_flags + all_sources
    result = _run_subprocess(cmd, timeout=60)
    return result.stderr if result.returncode != 0 else ""


def _run_afl_docker(program_id: int, afl_binary_path: str,
                    afl_out_dir: str, timeout_sec: int = 60) -> bool:
    """
    [T1, T4] AFL++ 퍼저 실행.
    afl_binary_path는 DB에서 직접 받은 절대경로를 사용 (숫자 ID 기반 재조합 없음).
    """
    afl_out_dir  = os.path.abspath(afl_out_dir)
    binary_path  = os.path.abspath(afl_binary_path)

    if not os.path.isfile(binary_path):
        print(f"[AFL++] Binary not found: {binary_path}")
        return False

    # 씨드 디렉토리: 출력 디렉토리 바깥에 위치 (AFL++ 요구사항)
    seed_dir = os.path.abspath(os.path.join(AFL_OUTPUT_BASE, f"seeds_{program_id}"))
    os.makedirs(seed_dir, exist_ok=True)
    os.makedirs(afl_out_dir, exist_ok=True)

    if not os.listdir(seed_dir):
        with open(os.path.join(seed_dir, "seed0"), "wb") as f:
            f.write(b"\x00" * 8)

    afl_env = {
        **os.environ,
        "AFL_NO_UI":                             "1",
        "AFL_SKIP_CPUFREQ":                      "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "AFL_AUTORESUME":                        "1",
        "AFL_FORKSRV_INIT_TMOUT":                "5000",
    }

    afl_bin = shutil.which("afl-fuzz")
    if not afl_bin:
        return False

    host_cmd = [
        "timeout", str(timeout_sec),
        "afl-fuzz", "-i", seed_dir, "-o", afl_out_dir, "--", binary_path
    ]

    result = subprocess.run(host_cmd, capture_output=True,
                            timeout=timeout_sec + 15, env=afl_env)

    if result.returncode not in (0, 124):  # 124 = timeout 정상 종료
        print(f"[AFL++] FAILED (code={result.returncode}):\n"
              f"STDOUT: {result.stdout.decode(errors='ignore')[-800:]}\n"
              f"STDERR: {result.stderr.decode(errors='ignore')[-800:]}")

    return True


# ─────────────────────────────────────────────────────────────────────────────
# API 엔드포인트
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/v1/target")
async def init_target(files: list[UploadFile] = File(...)):
    """[T2] 여러 소스/헤더 파일 업로드 → 전용 디렉토리 저장 → program_id 발급."""
    try:
        # 1. DB에 먼저 레코드 생성하여 ID 발급
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO TargetProgram (file_path, original_code) VALUES (?, ?)",
                ("pending", "multiple_files")
            )
            program_id = cursor.lastrowid
            conn.commit()

        # 2. ID별 전용 디렉토리 생성
        prog_dir = os.path.join(TEMP_TARGETS_DIR, str(program_id))
        os.makedirs(prog_dir, exist_ok=True)
        
        primary_file_path = ""
        for file in files:
            safe_name = os.path.basename(file.filename)
            file_path = os.path.join(prog_dir, safe_name)
            content = await file.read()
            with open(file_path, "wb") as f:
                f.write(content)
            # 첫 번째 .cpp 파일을 메인 타겟으로 설정
            if not primary_file_path and safe_name.endswith((".cpp", ".cc", ".cxx")):
                primary_file_path = file_path

        # 3. 대표 파일 경로 업데이트
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
    """[T2-Git] Github 저장소 클론 → CMake 분석 → compile_flags.txt 자동 생성."""
    try:
        # 1. DB 레코드 생성
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO TargetProgram (file_path, original_code) VALUES (?, ?)",
                ("pending", "github_import")
            )
            program_id = cursor.lastrowid
            conn.commit()

        # 프로젝트명_연월일시분 형식으로 디렉터리 이름 결정
        from datetime import datetime
        repo_name_raw = req.repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        date_str = datetime.now().strftime("%Y%m%d%H%M")
        project_dir_name = f"{repo_name_raw}_{date_str}"
        prog_dir = os.path.join(TEMP_TARGETS_DIR, project_dir_name)
        # 같은 날 여러번 클론 시 번호 suffix 추가
        suffix = 1
        base_prog_dir = prog_dir
        while os.path.exists(prog_dir):
            prog_dir = f"{base_prog_dir}_{suffix}"
            suffix += 1
        os.makedirs(prog_dir, exist_ok=True)
        repo_dir = os.path.join(prog_dir, "repo")

        # 2. Git Clone
        print(f"[Git] Cloning {req.repo_url}...")
        _run_subprocess(["git", "clone", "--depth", "1", req.repo_url, repo_dir], timeout=120)

        # 3. CMake 실행 및 compile_commands.json 생성
        build_dir = os.path.join(repo_dir, "build")
        os.makedirs(build_dir, exist_ok=True)
        print(f"[CMake] Configuring {req.repo_url}...")
        _run_subprocess(["cmake", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", ".."], timeout=120, env={"PWD": build_dir})

        # 4. JSON 파싱 및 플래그 추출
        flags = []
        cc_json = os.path.join(build_dir, "compile_commands.json")
        target_abs = os.path.abspath(os.path.join(repo_dir, req.target_file))
        
        if os.path.exists(cc_json):
            with open(cc_json, "r") as f:
                commands = json.load(f)
                for entry in commands:
                    if req.target_file in entry.get("file", ""):
                        # 명령어 분리 후 -I, -D 등 주요 플래그 추출
                        parts = entry.get("command", "").split()
                        for i, part in enumerate(parts):
                            if part.startswith("-I") or part.startswith("-D") or part.startswith("-std"):
                                flags.append(part)
                            # -I 뒤에 띄어쓰기로 경로가 오는 경우
                            elif part == "-I" and i + 1 < len(parts):
                                flags.append(f"-I{parts[i+1]}")
                        break
        
        # 휴리스틱: 저장소 이름으로 링커 옵션 추론 (예: quantlib -> -lQuantLib)
        repo_name = req.repo_url.split("/")[-1].replace(".git", "").lower()
        if "quantlib" in repo_name:
            flags.append("-lQuantLib")
        elif "openssl" in repo_name:
            flags.append("-lssl")
            flags.append("-lcrypto")

        # 5. compile_flags.txt 저장
        flags_file = os.path.join(prog_dir, "compile_flags.txt")
        with open(flags_file, "w") as f:
            for flag in set(flags): # 중복 제거
                f.write(f"{flag}\n")

        # 대상 파일을 prog_dir로 복사 (파이프라인 일관성 유지)
        safe_name = os.path.basename(target_abs)
        file_path = os.path.join(prog_dir, safe_name)
        if os.path.exists(target_abs):
            shutil.copy(target_abs, file_path)
        else:
            raise Exception(f"Target file {req.target_file} not found in repository.")

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            actual_code = f.read()

        with get_db_connection() as conn:
            conn.execute(
                "UPDATE TargetProgram SET file_path=?, original_code=? WHERE id=?",
                # source_file_path: 레포 내 원본 위치 (결함 주입 후 덮어쓰기에 사용)
                (file_path, actual_code, program_id)
            )
            # 레포 내 원본 절대경로를 별도 컬럼에 저장 (없으면 그냥 동일 경로 사용)
            try:
                conn.execute(
                    "ALTER TABLE TargetProgram ADD COLUMN source_file_path TEXT"
                )
            except Exception:
                pass  # 이미 컬럼이 있으면 무시
            conn.execute(
                "UPDATE TargetProgram SET source_file_path=? WHERE id=?",
                (target_abs, program_id)
            )
            conn.commit()

        return {"status": "success", "program_id": program_id, "flags_extracted": len(flags)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Github Import Failed: {str(e)}")

@app.post("/api/v1/target/{program_id}/compile")
async def compile_target(program_id: int):
    """[T3] Clang/LLVM으로 일반 바이너리 + AFL++ 계측 바이너리 동시 빌드."""
    program = db.get_program(program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found.")

    source_path = program["file_path"]
    prog_dir = os.path.dirname(source_path)
    base = source_path.rsplit(".", 1)[0]
    binary_path = base + "_bin"
    afl_binary_path = base + "_afl"

    # 해당 디렉토리의 모든 .cpp 파일을 컴파일 대상으로 포함
    all_sources = [os.path.join(prog_dir, f) for f in os.listdir(prog_dir) 
                   if f.endswith((".cpp", ".cc", ".cxx"))]
    source_cmd_part = " ".join(all_sources)

    errors = {}

    # [T3-a] 일반 컴파일
    err = _compile_regular(source_path, binary_path)
    if err:
        print(f"[ERROR] Regular Compilation Failed:\n{err}") # 에러 로그 추가
        errors["clang_error"] = err
        raise HTTPException(status_code=400, detail=errors)

    # [T3-b] AFL++ 계측 컴파일 (실패해도 경고만)
    afl_err = _compile_afl(source_path, afl_binary_path)
    if afl_err:
        errors["afl_warning"] = afl_err
        afl_binary_path = None  # 실패 시 None 저장

    # 바이너리 경로 DB 업데이트
    with get_db_connection() as conn:
        conn.execute(
            "UPDATE TargetProgram SET binary_path=?, afl_binary_path=? WHERE id=?",
            (binary_path, afl_binary_path, program_id)
        )
        conn.commit()

    return {
        "status": "success",
        "binary_path": binary_path,
        "afl_binary_path": afl_binary_path,
        "warnings": errors if errors else None
    }


@app.get("/api/v1/target/{program_id}/traces")
async def collect_traces(program_id: int, fuzz_seconds: int = 60):
    """
    [T4] AFL++ 퍼저를 Docker 컨테이너에서 실행하고,
    출력 트레이스를 파싱하여 DB에 적재한다.
    """
    program = db.get_program(program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found.")

    afl_binary_path = program.get("afl_binary_path")
    if not afl_binary_path or not os.path.exists(afl_binary_path):
        raise HTTPException(
            status_code=400,
            detail="AFL++ 계측 바이너리가 없습니다. 먼저 /compile 을 호출하세요."
        )

    afl_binary_name = os.path.basename(afl_binary_path)
    afl_out_dir = os.path.join(AFL_OUTPUT_BASE, str(program_id))

    # [T4] AFL++ 실행 (호스트 직접 실행, 절대경로 전달)
    success = _run_afl_docker(program_id, afl_binary_path, afl_out_dir, timeout_sec=fuzz_seconds)

    # [T6, T9] 출력 파싱 → DB 적재
    stats = parse_afl_output(afl_out_dir, program_id, db)
    afl_stats = read_afl_stats(afl_out_dir)

    return {
        "status": "success" if success else "partial",
        "message": f"Tracing {'completed' if success else 'attempted'} for program {program_id}.",
        "trace_stats": stats,
        "afl_stats": afl_stats,
    }


@app.get("/api/v1/target/{program_id}/corner-cases")
async def get_corner_cases(program_id: int):
    """[T9] 코너 케이스 노드 조회 (exec_frequency < 0.01)."""
    with get_db_connection() as conn:
        try:
            rows = conn.execute('''
                SELECT c.* FROM CornerCaseNode c
                JOIN DynamicTrace d ON c.trace_id = d.id
                WHERE d.program_id = ?
            ''', (program_id,)).fetchall()
            return {"status": "success", "corner_cases": [dict(r) for r in rows]}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"DB Error: {str(e)}")


@app.get("/api/v1/target/{program_id}/tree-map")
async def get_trace_tree(program_id: int):
    """
    [T13] 트리맵 시각화용 데이터 반환.
    hit_count에 따른 색상 구분 및 코너케이스 강조 데이터를 포함함.
    """
    try:
        tree_data = build_trace_tree(program_id, db)
        return {"status": "success", "tree_data": tree_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Tree generation failed: {str(e)}")


@app.post("/api/v1/smt/solve")
async def solve_smt(req: SMTSolveRequest):
    """SMT 제약식 역산 API (Z3 코어 엔진 호출)."""
    try:
        # TODO: subprocess로 MutationEngine의 Z3 모듈 호출
        trigger_input = f"node_type == AST_CALL && depth > 5 && node_id == {req.node_id}"
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO SMTConstraint (node_id, constraint_expr, is_solved, trigger_input) VALUES (?,?,?,?)",
                (req.node_id, "auto_generated", 1, trigger_input)
            )
            conn.commit()
        return {"status": "success", "trigger_input": trigger_input}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/mutations/inject")
async def inject_mutation(req: MutationInjectRequest):
    """
    [T10, T11] MutationEngine 바이너리를 subprocess로 호출하여
    결함을 주입하고, 변조 코드를 재컴파일한다.
    """
    if req.pattern_id != 0 and req.pattern_id not in PATTERN_REGISTRY:
        raise HTTPException(status_code=400, detail=f"pattern_id는 0(Auto Detect) 또는 1~6 사이여야 합니다.")

    # node_id → program_id 조회 (CornerCaseNode 경유)
    # actual_node_id: FK에 쓸 실제 CornerCaseNode.id (없으면 None)
    actual_node_id: Optional[int] = None
    row = None
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                """SELECT t.id as program_id, t.file_path, t.original_code,
                          t.source_file_path
                   FROM TargetProgram t
                   JOIN DynamicTrace d ON d.program_id = t.id
                   JOIN CornerCaseNode c ON c.trace_id = d.id
                   WHERE c.id = ?""",
                (req.node_id,)
            ).fetchone()
        if row:
            actual_node_id = req.node_id  # 실제 CornerCaseNode.id
    except Exception:
        row = None  # 테이블 미존재 등 스키마 불일치 시 fallback

    if not row:
        # fallback: node_id를 program_id로 간주, node_id는 None으로 처리
        try:
            with get_db_connection() as conn:
                row = conn.execute(
                    "SELECT id as program_id, file_path, original_code, source_file_path FROM TargetProgram WHERE id=?",
                    (req.node_id,)
                ).fetchone()
            # fallback이므로 actual_node_id = None (FK 위반 방지)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"DB 조회 오류: {str(e)}")

    if not row:
        raise HTTPException(status_code=404, detail="해당 node_id에 연결된 프로그램을 찾을 수 없습니다.")

    program_id   = row["program_id"]
    source_path  = row["file_path"]
    original_code = row["original_code"]
    # 레포 내 원본 절대경로 (없으면 복사본 경로로 대체)
    try:
        source_file_path = row["source_file_path"] or source_path
    except Exception:
        source_file_path = source_path

    # [T11-a] MutationEngine subprocess 호출
    if not os.path.exists(MUTATION_ENGINE_BIN):
        raise HTTPException(
            status_code=503,
            detail=f"MutationEngine 바이너리가 없습니다: {MUTATION_ENGINE_BIN}\ncore/를 먼저 빌드해주세요."
        )

    patterns_to_try = [req.pattern_id] if req.pattern_id != 0 else list(PATTERN_REGISTRY.keys())
    successful_pattern_id = None
    mutated_code = ""
    mutations = []

    for pid in patterns_to_try:
        try:
            engine_result = _run_subprocess(
                [MUTATION_ENGINE_BIN,
                 source_path,
                 f"--pattern-id={pid}",
                 "--"],
                timeout=30
            )
        except subprocess.TimeoutExpired:
            continue
        except FileNotFoundError:
            raise HTTPException(status_code=503, detail="MutationEngine 바이너리를 실행할 수 없습니다.")

        if engine_result.returncode != 0:
            continue

        try:
            output = json.loads(engine_result.stdout)
            m_code = output.get("mutated_code", "")
            m_list = output.get("mutations", [])
            
            if m_code and m_code.strip() != original_code.strip():
                successful_pattern_id = pid
                mutated_code = m_code
                mutations = m_list
                req.pattern_id = pid  # 성공한 패턴 ID로 갱신
                break
        except json.JSONDecodeError:
            continue

    if not successful_pattern_id:
        raise HTTPException(
            status_code=400,
            detail="AST 매칭 실패: 해당 타겟 코드에서 주입 가능한 어떠한 취약점 패턴도 발견하지 못했습니다."
        )

    # [T11-b] 결함 주입된 코드를 의미 있는 파일명으로 저장 + 재컴파일
    mutant_binary_path = ""
    orig_basename = os.path.splitext(os.path.basename(source_path))[0]
    mutant_src = os.path.join(os.path.dirname(source_path), f"{orig_basename}_mutant.cpp")

    with open(mutant_src, "w", encoding="utf-8") as f:
        f.write(mutated_code)
    tmp_src = mutant_src

    # ── 레포 내 원본 파일 위치에도 결함 코드 덮어쓰기 ────────────────────
    if source_file_path and os.path.exists(os.path.dirname(source_file_path)):
        with open(source_file_path, "w", encoding="utf-8") as f:
            f.write(mutated_code)
        print(f"[Inject] Mutated code written back to original location: {source_file_path}")

    try:
        mutant_bin = tmp_src.replace(".cpp", "")
        recompile_err = _compile_regular(tmp_src, mutant_bin)
        if not recompile_err:
            mutant_binary_path = mutant_bin
    except Exception:
        pass  # 재컴파일 실패는 경고만; 변조 코드 자체는 저장

    # DB 저장 (actual_node_id=None이면 FK 제약 없이 저장)
    try:
        mutant_id = db.insert_mutant(
            program_id=program_id,
            node_id=actual_node_id,
            pattern_id=req.pattern_id,
            original_code=original_code,
            mutated_code=mutated_code,
            mutant_binary_path=mutant_binary_path
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB 저장 오류: {str(e)}")

    return {
        "status": "success",
        "mutant_id": mutant_id,
        "pattern_name": PATTERN_REGISTRY[req.pattern_id],
        "mutations_applied": mutations,
        "mutant_binary_path": mutant_binary_path or "재컴파일 실패",
        "original_code": original_code,
        "mutated_code": mutated_code,
    }


def _validation_task(mutant_id: int):
    """
    [T12] 백그라운드 검증: 원본 vs 변조본 실행 결과 대조.
    AFL++ 생존율 측정 → 95% 이상이면 LLM(Gemini) 평가.
    """
    mutant = db.get_mutant(mutant_id)
    if not mutant:
        return

    program = db.get_program(mutant["program_id"])
    if not program:
        return

    original_binary = program.get("binary_path", "")
    mutant_binary = mutant.get("mutant_binary_path", "")

    # ── 원본 vs 변조본 실행 결과 비교 ────────────────────────────
    crash_count = 0
    total_runs = 0
    COMPARE_INPUTS = [b"\x00" * 8, b"\xff" * 8, b"test\n", b"0\n", b"-1\n"]

    for test_input in COMPARE_INPUTS:
        if not os.path.exists(original_binary) or not os.path.exists(mutant_binary):
            break

        with tempfile.NamedTemporaryFile(delete=False) as inp_file:
            inp_file.write(test_input)
            inp_path = inp_file.name

        try:
            orig_res = subprocess.run(
                [original_binary], stdin=open(inp_path, "rb"),
                capture_output=True, timeout=5
            )
            mut_res = subprocess.run(
                [mutant_binary], stdin=open(inp_path, "rb"),
                capture_output=True, timeout=5
            )
            total_runs += 1
            # 원본은 정상 종료, 변조본은 비정상 → 결함 생존 (크래시 유발)
            if orig_res.returncode == 0 and mut_res.returncode != 0:
                crash_count += 1
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        finally:
            os.unlink(inp_path)

    # 생존율: 변조본이 크래시를 유발하지 않은 비율
    if total_runs > 0:
        survival_rate = ((total_runs - crash_count) / total_runs) * 100.0
    else:
        # 바이너리가 없으면 AFL++ 통계 파일 기반으로 추정
        afl_out_dir = os.path.join(AFL_OUTPUT_BASE, str(mutant["program_id"]))
        if os.path.exists(afl_out_dir):
            survival_rate = 90.0   # AFL++ 결과 있음 → 보수적 추정
        else:
            survival_rate = 0.0   # 데이터 없음

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
    print(f"[Validation] mutant_id={mutant_id} survival_rate={survival_rate:.1f}%")


@app.post("/api/v1/mutations/{mutant_id}/validate")
async def validate_mutant(mutant_id: int, background_tasks: BackgroundTasks):
    """[T12] 검증 파이프라인 비동기 실행."""
    if not db.get_mutant(mutant_id):
        raise HTTPException(status_code=404, detail="Mutant not found.")
    background_tasks.add_task(_validation_task, mutant_id)
    return {"status": "success", "message": f"Validation pipeline started for mutant {mutant_id}."}


@app.get("/api/v1/mutations/{mutant_id}/report")
async def generate_report(mutant_id: int):
    """리포트 다운로드 API."""
    mutant = db.get_mutant(mutant_id)
    if not mutant:
        raise HTTPException(status_code=404, detail="Mutant not found.")
    try:
        # TODO: reportlab으로 PDF 생성
        pdf_content = b"%PDF-1.4 FindAndFixMe Report"
        return Response(content=pdf_content, media_type="application/pdf")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
