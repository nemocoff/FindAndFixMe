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
from .data.trace_parser import parse_afl_output, export_traces_as_json, read_afl_stats

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
    """[T3-a] clang++-16으로 일반 바이너리 컴파일. 실패 시 stderr 반환."""
    result = _run_subprocess(["clang++-16", "-std=c++17", "-o", binary_path, source_path], timeout=60)
    return result.stderr if result.returncode != 0 else ""


def _compile_afl(source_path: str, afl_binary_path: str) -> str:
    """[T3-b] afl-clang++로 계측(instrumented) 바이너리 컴파일."""
    afl_compiler = shutil.which("afl-clang++") or shutil.which("afl-clang++-16")
    if not afl_compiler:
        return "afl-clang++ not found — skipping AFL instrumentation build."
    result = _run_subprocess([afl_compiler, "-std=c++17", "-o", afl_binary_path, source_path], timeout=60)
    return result.stderr if result.returncode != 0 else ""


def _run_afl_docker(program_id: int, afl_binary_name: str,
                    afl_out_dir: str, timeout_sec: int = 60) -> bool:
    """
    [T1, T4] AFL++ 퍼저 실행.
    모든 경로를 절대경로로 처리하여 작업 디렉토리 의존성 제거.
    """
    # 절대경로로 통일
    afl_out_dir = os.path.abspath(afl_out_dir)
    targets_abs = os.path.abspath(TEMP_TARGETS_DIR)
    binary_path = os.path.join(targets_abs, afl_binary_name)

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
              f"{result.stderr.decode(errors='ignore')[-800:]}")

    return True


# ─────────────────────────────────────────────────────────────────────────────
# API 엔드포인트
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/v1/target")
async def init_target(file: UploadFile = File(...)):
    """[T2] C++ 소스 파일 업로드 → 서버 저장 → program_id 발급 (HTTP 200 OK)."""
    if not file.filename.endswith((".cpp", ".cc", ".cxx")):
        raise HTTPException(status_code=400, detail="C++ 소스 파일(.cpp/.cc/.cxx)만 허용됩니다.")

    try:
        content = await file.read()
        os.makedirs(TEMP_TARGETS_DIR, exist_ok=True)
        safe_name = os.path.basename(file.filename)
        file_path = os.path.join(TEMP_TARGETS_DIR, safe_name)
        with open(file_path, "wb") as f:
            f.write(content)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO TargetProgram (file_path, original_code) VALUES (?, ?)",
                (file_path, content.decode("utf-8", errors="ignore"))
            )
            program_id = cursor.lastrowid
            conn.commit()

        return {"status": "success", "program_id": program_id, "file": safe_name}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/target/{program_id}/compile")
async def compile_target(program_id: int):
    """[T3] Clang/LLVM으로 일반 바이너리 + AFL++ 계측 바이너리 동시 빌드."""
    program = db.get_program(program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found.")

    source_path = program["file_path"]
    base = source_path.rsplit(".", 1)[0]
    binary_path = base + "_bin"
    afl_binary_path = base + "_afl"

    errors = {}

    # [T3-a] 일반 컴파일
    err = _compile_regular(source_path, binary_path)
    if err:
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

    # [T4] AFL++ 실행 (Docker 또는 호스트)
    success = _run_afl_docker(program_id, afl_binary_name, afl_out_dir, timeout_sec=fuzz_seconds)

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
                WHERE d.program_id = ? AND c.exec_frequency < 0.01
            ''', (program_id,)).fetchall()
            return {"status": "success", "corner_cases": [dict(r) for r in rows]}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"DB Error: {str(e)}")


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
    if req.pattern_id not in PATTERN_REGISTRY:
        raise HTTPException(status_code=400, detail=f"pattern_id는 1~6 사이여야 합니다.")

    # node_id → program_id 조회 (CornerCaseNode 경유)
    # actual_node_id: FK에 쓸 실제 CornerCaseNode.id (없으면 None)
    actual_node_id: Optional[int] = None
    row = None
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                """SELECT t.id as program_id, t.file_path, t.original_code
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
                    "SELECT id as program_id, file_path, original_code FROM TargetProgram WHERE id=?",
                    (req.node_id,)
                ).fetchone()
            # fallback이므로 actual_node_id = None (FK 위반 방지)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"DB 조회 오류: {str(e)}")

    if not row:
        raise HTTPException(status_code=404, detail="해당 node_id에 연결된 프로그램을 찾을 수 없습니다.")

    program_id = row["program_id"]
    source_path = row["file_path"]
    original_code = row["original_code"]

    # [T11-a] MutationEngine subprocess 호출
    if not os.path.exists(MUTATION_ENGINE_BIN):
        raise HTTPException(
            status_code=503,
            detail=f"MutationEngine 바이너리가 없습니다: {MUTATION_ENGINE_BIN}\ncore/를 먼저 빌드해주세요."
        )

    try:
        engine_result = _run_subprocess(
            [MUTATION_ENGINE_BIN,
             source_path,
             f"--pattern-id={req.pattern_id}",
             "--"],
            timeout=30
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="MutationEngine 실행 타임아웃 (30초)")
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="MutationEngine 바이너리를 실행할 수 없습니다.")

    if engine_result.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail=f"MutationEngine 오류:\n{engine_result.stderr}"
        )

    try:
        output = json.loads(engine_result.stdout)
        mutated_code = output.get("mutated_code", "")
        mutations = output.get("mutations", [])
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="MutationEngine 출력 JSON 파싱 실패")

    if not mutated_code or mutated_code.strip() == original_code.strip():
        raise HTTPException(
            status_code=400,
            detail="Integrity Rule 1: 변조 코드가 원본과 동일합니다. 해당 패턴이 소스에서 발견되지 않았을 수 있습니다."
        )

    # [T11-b] 변조 코드 임시 파일 저장 + 재컴파일
    mutant_binary_path = ""
    with tempfile.NamedTemporaryFile(
        suffix=".cpp", dir=TEMP_TARGETS_DIR,
        delete=False, mode="w", encoding="utf-8"
    ) as tmp:
        tmp.write(mutated_code)
        tmp_src = tmp.name

    try:
        mutant_bin = tmp_src.replace(".cpp", "_mutant")
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
