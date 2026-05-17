import requests
import time

API_BASE_URL = "http://localhost:8000/api/v1"
# 네트워크 연결 타임아웃 및 읽기 타임아웃 기본값 (연결 10초, 읽기 30초)
DEFAULT_REQ_TIMEOUT = (10, 30) 

def _make_request(method, url, **kwargs):
    """모든 HTTP 요청을 처리하는 내부 헬퍼 (에러 메시지 파싱 포함)"""
    if "timeout" not in kwargs:
        kwargs["timeout"] = DEFAULT_REQ_TIMEOUT
        
    try:
        response = requests.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        # 백엔드에서 보내준 상세 에러 메시지(detail) 추출
        try:
            err_detail = e.response.json().get("detail", str(e))
        except ValueError:
            err_detail = e.response.text or str(e)
        raise Exception(f"API Error [{e.response.status_code}]: {err_detail}")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Network Error: {str(e)}")

def upload_targets(files_list):
    """files_list: List of (file_name, file_content) tuples"""
    files = [("files", (name, content)) for name, content in files_list]
    return _make_request("POST", f"{API_BASE_URL}/target", files=files)

def compile_target(program_id, wait=False):
    res_json = _make_request("POST", f"{API_BASE_URL}/target/{program_id}/compile")
    # 대형 프로젝트 컴파일을 위해 타임아웃을 300초로 넉넉히 줌
    if wait and res_json.get("task_id"):
        return wait_for_task(res_json["task_id"], timeout=300)
    return res_json

def collect_traces(program_id, fuzz_seconds=60, wait=False):
    res_json = _make_request("GET", f"{API_BASE_URL}/target/{program_id}/traces", params={"fuzz_seconds": fuzz_seconds})
    if wait and res_json.get("task_id"):
        return wait_for_task(res_json["task_id"], timeout=fuzz_seconds + 30)
    return res_json

def get_corner_cases(program_id):
    return _make_request("GET", f"{API_BASE_URL}/target/{program_id}/corner-cases")

def get_trace_tree(program_id):
    return _make_request("GET", f"{API_BASE_URL}/target/{program_id}/tree-map")

def get_task_status(task_id: str):
    return _make_request("GET", f"{API_BASE_URL}/task/{task_id}")

def wait_for_task(task_id: str, timeout: int = 120, interval: int = 2):
    """비동기 작업이 완료될 때까지 폴링합니다."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        status_res = get_task_status(task_id)
        if status_res.get("status") == "completed":
            return status_res.get("result", {}) # 성공 시 내장된 result 딕셔너리 반환
        elif status_res.get("status") == "failed":
            raise Exception(f"Task failed in background: {status_res.get('error')}")
        time.sleep(interval)
    raise Exception(f"Task {task_id} timed out after {timeout} seconds")

def inject_mutation(node_id, pattern_id, wait=False):
    payload = {"node_id": node_id, "pattern_id": pattern_id}
    res_json = _make_request("POST", f"{API_BASE_URL}/mutations/inject", json=payload)
    if wait and res_json.get("task_id"):
        return wait_for_task(res_json["task_id"], timeout=60)
    return res_json

def validate_mutant(mutant_id, wait=False):
    res_json = _make_request("POST", f"{API_BASE_URL}/mutations/{mutant_id}/validate")
    if wait and res_json.get("task_id"):
        return wait_for_task(res_json["task_id"], timeout=120)
    return res_json

def upload_github_target(repo_url, target_file):
    payload = {"repo_url": repo_url, "target_file": target_file}
    # Github 클론/CMake는 동기 라우트이므로 매우 길게(최대 300초) 대기
    return _make_request("POST", f"{API_BASE_URL}/target/github", json=payload, timeout=(10, 300))

def _run_pipeline_tail(prog_id):
    # 2. Compile
    print(f"[{prog_id}] Compiling...")
    compile_target(prog_id, wait=True)
    
    # 3. Traces (fuzzing)
    print(f"[{prog_id}] Collecting traces (fuzzing)...")
    collect_traces(prog_id, fuzz_seconds=5, wait=True)
    
    # 4. Get Corner Cases
    print(f"[{prog_id}] Fetching corner cases...")
    res_cc = get_corner_cases(prog_id)
    cc_list = res_cc.get("corner_cases", [])
    
    if not cc_list:
        print(f"[{prog_id}] No corner cases found.")
        return {"status": "success", "data": {"mutations": []}, "program_id": prog_id}
    
    # 5. Inject Mutation (CWE-190 테스트로 pattern 1 지정)
    target_node = cc_list[0]["id"]
    print(f"[{prog_id}] Injecting mutation at node {target_node}...")
    res_mut = inject_mutation(target_node, 1, wait=True)
    
    return {
        "status": "success",
        "program_id": prog_id,
        "data": {
            "mutations": [
                {
                    "pattern_name": res_mut.get("pattern_name"),
                    "original_code": res_mut.get("original_code"), 
                    "mutated_code": res_mut.get("mutated_code"),
                    "mutant_id": res_mut.get("mutant_id")
                }
            ],
            "corner_cases": cc_list
        }
    }

def run_full_pipeline(uploaded_files):
    files_list = [(f.name, f.getvalue()) for f in uploaded_files]
    res_upload = upload_targets(files_list)
    return _run_pipeline_tail(res_upload["program_id"])

def run_github_pipeline(repo_url, target_file):
    print(f"[Git] Importing {repo_url}...")
    res_upload = upload_github_target(repo_url, target_file)
    return _run_pipeline_tail(res_upload["program_id"])