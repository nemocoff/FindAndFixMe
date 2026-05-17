import streamlit as st
import pandas as pd
import requests
from api_client import (
    upload_targets, compile_target, collect_traces, get_corner_cases, inject_mutation, 
    upload_github_target, validate_mutant, get_trace_tree
)
from components.trace_tree import render_trace_tree_and_table
from components.diff_viewer import render_diff_viewer

API_BASE_URL = "http://localhost:8000/api/v1"

def _run_pipeline_ui(prog_id: int, status_container, pattern_options, selected_pattern_id):
    """File Upload와 Github Import에서 공통으로 사용하는 파이프라인 UI 로직"""
    st.write("Compiling target and extracting AST (with auto-flags)...")
    compile_target(prog_id, wait=True)
    
    st.write("Running AFL++ Fuzzer to collect traces (60s)...")
    res_traces = collect_traces(prog_id, fuzz_seconds=60, wait=True)
    
    st.write("Identifying Corner Cases from execution traces...")
    res_cc = get_corner_cases(prog_id)
    cc_list = res_cc.get("corner_cases", [])
    
    st.write("Generating Dynamic Execution Tree...")
    res_tree = get_trace_tree(prog_id)
    tree_data = res_tree.get("tree_data")
    
    if not cc_list:
        status_container.update(label="Pipeline finished. No corner cases found.", state="complete", expanded=False)
        st.session_state["analysis_result"] = {"status": "success", "data": {"mutations": []}, "program_id": prog_id}
    else:
        st.write(f"Found {len(cc_list)} corner cases! Injecting {pattern_options[selected_pattern_id]} Mutation...")
        target_node = cc_list[0]["id"]
        res_mut = inject_mutation(target_node, selected_pattern_id, wait=True)
        
        st.session_state["analysis_result"] = {
            "status": "success",
            "program_id": prog_id,
            "data": {
                "mutations": [{
                    "pattern_name": res_mut.get("pattern_name"),
                    "original_code": res_mut.get("original_code"), 
                    "mutated_code": res_mut.get("mutated_code"),
                    "mutant_id": res_mut.get("mutant_id")
                }],
                "corner_cases": cc_list,
                "tree_data": tree_data,
                "total_traces": res_traces.get("trace_stats", {}).get("total", 0),
                "execs_done": res_traces.get("afl_stats", {}).get("execs_done", 0)
            }
        }
        status_container.update(label="Pipeline complete!", state="complete", expanded=False)

def main() -> None:
    """
    FindAndFixMe C++ Migration Dashboard
    """
    st.set_page_config(page_title="FindAndFixMe Dashboard", layout="wide")
    st.title("FindAndFixMe Dashboard (C++ Core Engine)")
    
    import_type = st.radio("Choose Input Method", ["File Upload", "Import from Github"])
    
    pattern_options = {
        0: "Auto Detect (Find any applicable pattern)",
        1: "CWE-190 Integer Overflow",
        2: "CWE-193 Boundary Condition Error",
        3: "CWE-476 NULL Pointer Dereference",
        4: "CWE-122 Heap Buffer Overflow",
        5: "CWE-416 Use After Free",
        6: "CWE-401 Memory Leak"
    }
    selected_pattern_id = 0
    
    # 상태 초기화
    if "analysis_result" not in st.session_state:
        st.session_state["analysis_result"] = None
    if "validation_results" not in st.session_state:
        st.session_state["validation_results"] = {} # mutant_id를 키로 가지는 검증 결과 딕셔너리
        
    if import_type == "File Upload":
        target_files = st.file_uploader("Upload Target Sources (`.cpp`, `.h`, `.hpp`, `compile_flags.txt`)", type=["cpp", "h", "hpp", "c", "txt"], accept_multiple_files=True)
        if target_files:
            st.info(f"{len(target_files)} file(s) uploaded.")
            if st.button("Run Full Pipeline", type="primary"):
                st.session_state["analysis_result"] = None # 이전 결과 초기화
                st.session_state["validation_results"] = {}
                try:
                    with st.status("Running FindAndFixMe Pipeline...", expanded=True) as status:
                        st.write("Uploading files to server...")
                        files_list = [(f.name, f.getvalue()) for f in target_files]
                        res_upload = upload_targets(files_list)
                        prog_id = res_upload["program_id"]
                        
                        _run_pipeline_ui(prog_id, status, pattern_options, selected_pattern_id)
                except requests.exceptions.HTTPError as e:
                    err_msg = e.response.json().get("detail", str(e)) if e.response else str(e)
                    status.update(label="Pipeline Failed", state="error", expanded=True)
                    st.error(f"Pipeline Error: {err_msg}")
                except Exception as e:
                    status.update(label="Pipeline Failed", state="error", expanded=True)
                    st.error(f"Pipeline Error: {e}")
                    
    else:
        repo_url = st.text_input("Github Repository URL", placeholder="https://github.com/quantlib/QuantLib.git")
        target_file = st.text_input("Target C++ File Path (Relative)", placeholder="fuzz-test-suite/quantlibtestsuite.cpp")
        
        if repo_url and target_file:
            if st.button("Import and Run Pipeline", type="primary"):
                st.session_state["analysis_result"] = None # 이전 결과 초기화
                st.session_state["validation_results"] = {}
                try:
                    with st.status("Running FindAndFixMe Github Pipeline...", expanded=True) as status:
                        st.write("Cloning repo and parsing CMake build system...")
                        res_upload = upload_github_target(repo_url, target_file)
                        prog_id = res_upload["program_id"]
                        
                        _run_pipeline_ui(prog_id, status, pattern_options, selected_pattern_id)
                except requests.exceptions.HTTPError as e:
                    err_msg = e.response.json().get("detail", str(e)) if e.response else str(e)
                    status.update(label="Github Pipeline Failed", state="error", expanded=True)
                    st.error(f"Github Pipeline Error: {err_msg}")
                except Exception as e:
                    status.update(label="Github Pipeline Failed", state="error", expanded=True)
                    st.error(f"Github Pipeline Error: {e}")

    # 결과 표시 영역
    if st.session_state["analysis_result"] and st.session_state["analysis_result"].get("status") == "success":
        st.markdown("---")
        
        cc_data = st.session_state["analysis_result"].get("data", {}).get("corner_cases", [])
        tree_data = st.session_state["analysis_result"].get("data", {}).get("tree_data")
        total_traces = st.session_state["analysis_result"].get("data", {}).get("total_traces", 0)
        execs_done = st.session_state["analysis_result"].get("data", {}).get("execs_done", 0)
        
        if tree_data:
            render_trace_tree_and_table(tree_data, cc_data, total_traces, execs_done)
        
        st.markdown("---")
        st.markdown("### 2. Mutation Analysis & Diff Viewer")
        
        mutations = st.session_state["analysis_result"].get("data", {}).get("mutations", [])
        
        if not mutations:
            st.warning("No mutations were applied.")
        else:
            for idx, mut in enumerate(mutations):
                st.markdown(f"#### Mutation {idx+1}: {mut.get('pattern_name', 'Unknown Pattern')}")
                render_diff_viewer(mut.get('original_code', ''), mut.get('mutated_code', ''))
                
                m_id = mut.get('mutant_id')
                
                # 검증 결과가 있으면 표시, 없으면 버튼 표시
                if m_id in st.session_state["validation_results"]:
                    val_res = st.session_state["validation_results"][m_id]
                    st.success(f"Validation Complete! Survival Rate: **{val_res.get('survival_rate', 0):.1f}%**")
                    if val_res.get("llm_score"):
                        st.write(f"LLM Score: {val_res.get('llm_score')}")
                else:
                    if st.button(f"Validate Mutant {m_id}", key=f"val_{idx}"):
                        with st.spinner("Running validation pipeline in Docker..."):
                            try:
                                val_res = validate_mutant(m_id, wait=True)
                                # 결과를 세션 상태에 저장하여 화면 리렌더링 시에도 유지
                                st.session_state["validation_results"][m_id] = val_res
                                st.rerun() # 화면 즉시 새로고침하여 결과 표시
                            except Exception as e:
                                st.error(f"Validation Error: {e}")
                
        st.markdown("---")
        st.markdown("### 3. Verification Tools")
        col_afl, col_gemini = st.columns(2)
        with col_afl:
            st.button("Trigger AFL++ Fuzzer (Manual)", help="Manual re-run of AFL++")
        with col_gemini:
            st.button("Trigger Gemini API Verification (Manual)", help="Run LLM analysis on mutants")

if __name__ == "__main__":
    main()