from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
import subprocess
import json
import os
import sqlite3

app = FastAPI(title="FindAndFixMe API Orchestrator")
DB_PATH = "trace_data.sqlite"

class SMTSolveRequest(BaseModel):
    node_id: int

class MutationInjectRequest(BaseModel):
    node_id: int
    pattern_id: int

class ValidationRequest(BaseModel):
    # Depending on how the body is passed, maybe empty if mutant_id is in path, but requirement says POST /api/v1/mutations/{mutant_id}/validate.
    pass

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.post("/api/v1/target")
async def init_target(file: UploadFile = File(...)):
    """1. 프로젝트 초기화 API: 타겟 C++ 소스 파일 업로드 및 program_id 발급"""
    try:
        content = await file.read()
        # 안전한 임시 디렉토리 저장
        os.makedirs("temp_targets", exist_ok=True)
        file_path = os.path.join("temp_targets", file.filename)
        with open(file_path, "wb") as f:
            f.write(content)
            
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO TargetProgram (file_path, original_code) VALUES (?, ?)", 
                (file_path, content.decode("utf-8", errors="ignore"))
            )
            program_id = cursor.lastrowid
            conn.commit()
            return {"status": "success", "program_id": program_id, "message": "Target initialized."}
        except Exception as e:
            conn.rollback()
            raise HTTPException(status_code=500, detail=f"DB Error: {str(e)}")
        finally:
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/target/{program_id}/traces")
async def collect_traces(program_id: int):
    """2. 동적 트레이스 수집 API: AFL++ 실행 및 커버리지 파싱"""
    # TODO: AFL++ 다중 실행 트리거 로직 작성
    # subprocess.run(["afl-fuzz", "-i", "in", "-o", "out", "./target_binary"])
    return {"status": "success", "message": f"Background tracing triggered for program {program_id}."}

@app.get("/api/v1/target/{program_id}/corner-cases")
async def get_corner_cases(program_id: int):
    """3. 코너 케이스 노드 조회 API: 실행 빈도 1% 미만 조회"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # DynamicTrace를 거쳐서 CornerCaseNode를 조인해야 함
        cursor.execute('''
            SELECT c.* FROM CornerCaseNode c
            JOIN DynamicTrace d ON c.trace_id = d.id
            WHERE d.program_id = ? AND c.exec_frequency < 0.01
        ''', (program_id,))
        cases = [dict(row) for row in cursor.fetchall()]
        return {"status": "success", "corner_cases": cases}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB Error: {str(e)}")
    finally:
        conn.close()

@app.post("/api/v1/smt/solve")
async def solve_smt(req: SMTSolveRequest):
    """4. 제약식 역산 API: C++ Z3 코어 엔진 호출하여 트리거 입력 도출"""
    try:
        # TODO: subprocess.run() 으로 Z3 모듈 바이너리 호출
        mock_trigger_input = "node_type == AST_CALL && depth > 5"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO SMTConstraint (node_id, constraint_expr, is_solved, trigger_input) VALUES (?, ?, ?, ?)",
                (req.node_id, "mock_expr", 1, mock_trigger_input)
            )
            conn.commit()
            return {"status": "success", "trigger_input": mock_trigger_input}
        except Exception as e:
            conn.rollback()
            raise HTTPException(status_code=500, detail=f"DB Error: {str(e)}")
        finally:
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/mutations/inject")
async def inject_mutation(req: MutationInjectRequest):
    """5. 결함 주입 API: C++ Rewriter 호출 및 변조 무결성 검증 후 저장"""
    if not (1 <= req.pattern_id <= 6):
        raise HTTPException(status_code=400, detail="pattern_id must be between 1 and 6.")
        
    try:
        # TODO: subprocess로 C++ MutationEngine 실행하여 변조 코드 받아오기
        mock_mutated_code = "// Injected code for pattern " + str(req.pattern_id)
        mock_original_code = "// Original"
        
        if mock_mutated_code == mock_original_code:
            raise HTTPException(status_code=400, detail="Integrity Rule 1 Failed: Code identical after mutation.")
            
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Requires program_id, assuming we can fetch it via node_id -> trace_id -> program_id
            cursor.execute(
                "INSERT INTO MutantRecord (program_id, node_id, injected_pattern_id, mutated_code) VALUES (?, ?, ?, ?)",
                (1, req.node_id, req.pattern_id, mock_mutated_code) # Mock program_id = 1
            )
            mutant_id = cursor.lastrowid
            conn.commit()
            return {"status": "success", "mutant_id": mutant_id, "mutated_code": mock_mutated_code}
        except Exception as e:
            conn.rollback()
            raise HTTPException(status_code=500, detail=f"DB Error: {str(e)}")
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def async_validation_task(mutant_id: int):
    """
    백그라운드에서 실행되는 결함 검증 태스크
    - AFL++ 생존율(Survival Rate) 측정
    - 생존율 95% 이상 시 LLM 정성 평가 수행
    """
    try:
        # TODO: 1. AFL++를 돌려 원래 코드와 변조 코드의 커버리지/크래시 비율을 비교 (Mock 데이터 96.5%)
        mock_survival_rate = 96.5
        
        # 2. 결함 생존율 95% 체크 로직
        is_stealthy = mock_survival_rate >= 95.0
        
        naturalness_score = 0
        if is_stealthy:
            # TODO: 3. 생존율이 95% 이상인 경우에만 Gemini API를 호출하여 코드 자연스러움(0~100) 평가
            # response = requests.post("https://generativelanguage.googleapis.com/...", ...)
            naturalness_score = 85  # Mock LLM Score
            
        # 4. DB에 검증 결과 업데이트 (MutantRecord 등)
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # MutantRecord 테이블에 survival_rate와 llm_score 컬럼이 있다고 가정
            # cursor.execute("UPDATE MutantRecord SET survival_rate=?, llm_score=? WHERE id=?", 
            #                (mock_survival_rate, naturalness_score, mutant_id))
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"DB Update Error in Background Task: {e}")
        finally:
            conn.close()
            
    except Exception as e:
        print(f"Validation Task Failed: {e}")

@app.post("/api/v1/mutations/{mutant_id}/validate")
async def validate_mutant(mutant_id: int, background_tasks: BackgroundTasks):
    """6. 검증 파이프라인 구동 API: AFL++ 및 Gemini API 호출 (비동기)"""
    try:
        background_tasks.add_task(async_validation_task, mutant_id)
        return {"status": "success", "message": f"Validation pipeline started for mutant {mutant_id}."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/mutations/{mutant_id}/report")
async def generate_report(mutant_id: int):
    """7. 리포트 다운로드 API: PDF 동적 생성 및 스트림 전송"""
    try:
        # TODO: reportlab 등 라이브러리를 사용하여 PDF 동적 생성
        pdf_content = b"%PDF-1.4 Mock PDF Content"
        return Response(content=pdf_content, media_type="application/pdf")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
