import requests
import time

API_BASE_URL = "http://localhost:8000/api/v1"

def upload_targets(files_list):
    """
    files_list: List of (file_name, file_content) tuples
    """
    files = [("files", (name, content)) for name, content in files_list]
    response = requests.post(f"{API_BASE_URL}/target", files=files)
    response.raise_for_status()
    return response.json()

def compile_target(program_id):
    response = requests.post(f"{API_BASE_URL}/target/{program_id}/compile")
    response.raise_for_status()
    return response.json()

def collect_traces(program_id, fuzz_seconds=10):
    response = requests.get(f"{API_BASE_URL}/target/{program_id}/traces", params={"fuzz_seconds": fuzz_seconds})
    response.raise_for_status()
    return response.json()

def get_corner_cases(program_id):
    response = requests.get(f"{API_BASE_URL}/target/{program_id}/corner-cases")
    response.raise_for_status()
    return response.json()

def inject_mutation(node_id, pattern_id):
    payload = {"node_id": node_id, "pattern_id": pattern_id}
    response = requests.post(f"{API_BASE_URL}/mutations/inject", json=payload)
    response.raise_for_status()
    return response.json()

def validate_mutant(mutant_id):
    response = requests.post(f"{API_BASE_URL}/mutations/{mutant_id}/validate")
    response.raise_for_status()
    return response.json()

def upload_github_target(repo_url, target_file):
    payload = {"repo_url": repo_url, "target_file": target_file}
    response = requests.post(f"{API_BASE_URL}/target/github", json=payload)
    response.raise_for_status()
    return response.json()

def _run_pipeline_tail(prog_id):
    # 2. Compile
    compile_target(prog_id)
    
    # 3. Traces (fuzzing)
    collect_traces(prog_id, fuzz_seconds=5)
    
    # 4. Get Corner Cases
    res_cc = get_corner_cases(prog_id)
    cc_list = res_cc.get("corner_cases", [])
    
    if not cc_list:
        return {"status": "success", "data": {"mutations": []}, "program_id": prog_id}
    
    # 5. Inject Mutation (CWE-190)
    target_node = cc_list[0]["id"]
    res_mut = inject_mutation(target_node, 1)
    
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
    res_upload = upload_github_target(repo_url, target_file)
    return _run_pipeline_tail(res_upload["program_id"])