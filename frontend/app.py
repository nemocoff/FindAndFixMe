import streamlit as st
import requests
from fpdf import FPDF
import pandas as pd
from api_client import (
    upload_targets, compile_target, collect_traces, get_corner_cases, inject_mutation, 
    upload_github_target, validate_mutant, get_trace_tree, wait_for_github_import,
    solve_smt, get_history
)
from components.trace_tree import render_trace_tree_and_table
from components.diff_viewer import render_diff_viewer

API_BASE_URL = "http://localhost:8000/api/v1"

def _run_pipeline_ui(prog_id: int, status_container, pattern_options, selected_pattern_id):
    """File Upload와 Github Import에서 공통으로 사용하는 파이프라인 UI 로직"""
    st.write("Compiling target and extracting AST (with auto-flags)...")
    compile_target(prog_id, wait=True)
    
    st.write("Running AFL++ Fuzzer to collect traces...")
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

        st.write("Solving path constraints with Z3 SMT Solver...")
        try:
            res_smt = solve_smt(target_node)
            trigger_input = res_smt.get("trigger_input", "")
        except Exception as e:
            st.warning(f"SMT Solver failed: {e}")
            trigger_input = ""
        
        st.session_state["analysis_result"] = {
            "status": "success",
            "program_id": prog_id,
            "data": {
                "mutations": [{
                    "pattern_name": res_mut.get("pattern_name"),
                    "original_code": res_mut.get("original_code"), 
                    "mutated_code": res_mut.get("mutated_code"),
                    "mutant_id": res_mut.get("mutant_id"),
                    "trigger_input": trigger_input
                }],
                "corner_cases": cc_list,
                "tree_data": tree_data,
                "total_traces": res_traces.get("trace_stats", {}).get("total", 0),
                "execs_done": res_traces.get("afl_stats", {}).get("execs_done", 0)
            }
        }
        status_container.update(label="Pipeline complete!", state="complete", expanded=False)

def create_pdf_report(record):
    pdf = FPDF()
    pdf.add_page()
    
    # 폰트 로드 (경로 주의)
    pdf.add_font("D2CodingBold", "", "fonts/D2CodingBold.ttf")
    pdf.add_font("D2Coding", "", "fonts/D2Coding.ttf")
    # --- [헤더: 리포트 제목] ---
    pdf.set_font("D2CodingBold", size=18)
    pdf.cell(0, 15, "FindAndFixMe - 상세 분석 리포트", ln=True, align='C')
    pdf.ln(5)

    # --- [우측 상단 텍스트 로고 배지 (블랙 원형)] ---
    pdf.set_fill_color(0, 0, 0) # 시크한 블랙 배경 지정
    
    # x=180, y=10 위치에 너비 15, 높이 15의 원형(ellipse)을 그리고 채웁니다('F')
    pdf.ellipse(180, 10, 15, 15, 'F') 

    # 원형 박스 안에 들어갈 텍스트 설정
    pdf.set_font("D2CodingBold", size=12) # 원형 안에 쏙 들어가도록 폰트 크기 미세 조정
    pdf.set_text_color(255, 255, 255) # 글자색: 하얀색
    
    # 텍스트 셀의 크기와 위치를 원형과 정확히 일치시켜 정중앙에 글자가 오도록 합니다
    pdf.set_xy(180, 10)
    pdf.cell(15, 15, "F&F", align='C')

    # 로고 출력 후 본문 작성을 위해 색상 및 위치 초기화
    pdf.set_text_color(0, 0, 0) 
    pdf.set_xy(10, 30)
    
    # --- [섹션 1: 메타데이터 요약 (회색 배경 박스)] ---
    pdf.set_fill_color(245, 245, 245) # 연한 회색 지정
    pdf.set_font("D2Coding", size=11)
    
    # 높이 8짜리 셀들에 fill=True를 주어 배경색을 입힙니다.
    pdf.cell(0, 8, f" 주입 일시   : {record['timestamp']}", ln=True, fill=True)
    pdf.cell(0, 8, f" 타겟 파일   : {record['file']} ({record['location']})", ln=True, fill=True)
    pdf.cell(0, 8, f" 주입 패턴   : {record['pattern']} (재시도: {record['retry_count']}회)", ln=True, fill=True)
    pdf.cell(0, 8, f" 퍼저 생존율 : {record['survival_rate']}% (총 {record['total_execs']}회 실행)", ln=True, fill=True)
    pdf.ln(8)
    
    # --- [구분선] ---
    pdf.set_line_width(0.3)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    
    # --- [섹션 2: Gemini 정성 평가] ---
    pdf.set_font("D2Coding", size=13)
    pdf.cell(0, 10, f"🤖 AI 정성 평가 결과 (Score: {record['llm_score']})", ln=True)
    
    pdf.set_font("D2Coding", size=11)
    # multi_cell로 긴 평가 사유를 줄바꿈하여 출력합니다.
    pdf.multi_cell(0, 8, f"평가 사유: {record['llm_reasoning']}")
    pdf.ln(5)
    
    # --- [구분선] ---
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    # --- [섹션 3: 기술 상세 정보 (Z3 & Diff)] ---
    pdf.set_font("D2Coding", size=13)
    pdf.cell(0, 10, "🎯 Z3 SMT Solver Trigger Condition", ln=True)
    pdf.set_font("D2Coding", size=10)
    pdf.multi_cell(0, 6, record['z3_condition'])
    pdf.ln(5)
    
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    pdf.set_font("D2Coding", size=13)
    pdf.cell(0, 10, "💻 Code Diff", ln=True)
    pdf.set_font("D2Coding", size=10)
    pdf.multi_cell(0, 6, record['diff'])
    
    return pdf.output()

def main() -> None:
    """
    FindAndFixMe C++ Migration Dashboard
    """
    st.set_page_config(page_title="FindAndFixMe Dashboard", layout="wide")
    st.title("FindAndFixMe Dashboard")

    tab_pipeline, tab_history = st.tabs(["🚀 Run Pipeline", "📜 History Dashboard"])
    
    with tab_pipeline:
        st.markdown("### 🚀 Automated Mutation Pipeline")
        st.caption("타겟 소스코드를 업로드하거나 Github 레포지토리를 연동하여 퍼징(Fuzzing) 및 결함 주입을 실행합니다.")

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
                            st.write("Cloning repo and compiling dependencies in background...")
                            res_upload = upload_github_target(repo_url, target_file)
                            prog_id = res_upload["program_id"]
                            
                            # Wait for the background compilation to finish successfully
                            wait_for_github_import(prog_id)
                            
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

    with tab_history:
        st.markdown("### 📚 Injection History Dashboard")
        st.caption("데이터베이스에 저장된 이전 결함 주입 및 검증 이력을 확인합니다.")

        try:
            db_records = get_history()
        except Exception as e:
            st.error(f"Failed to fetch history from database: {e}")
            db_records = []

        if not db_records:
            st.info("데이터베이스에 결함 주입 이력이 없습니다. 파이프라인을 먼저 실행해 주세요.")
        else:
            df = pd.DataFrame(db_records)

            # 2. Master View (상단 요약 표)
            st.markdown("##### 📌 Execution Records")
            event = st.dataframe(
                df[["timestamp", "file", "pattern", "survival_rate", "llm_score", "retry_count"]],
                use_container_width=True,
                on_select="rerun",
                selection_mode="single-row",
                hide_index=True
            )

            # 3. Detail View (하단 상세 정보 렌더링)
            selected_rows = event.selection.rows
            if selected_rows:
                selected_idx = selected_rows[0]
                selected_record = db_records[selected_idx]

                st.markdown(f"#### 🔍 세부 분석 결과: `{selected_record['file']}`")

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.info(f"**Pattern:** {selected_record['pattern']}")
                with col2:
                    st.warning(f"**Survival Rate:** {selected_record['survival_rate']:.1f}%")
                with col3:
                    st.success(f"**Gemini AI Score:** {selected_record['llm_score']}")

                st.markdown("##### 🎯 Z3 SMT Solver Trigger Condition")
                st.code(selected_record['z3_condition'], language="lisp")

                st.markdown("##### 💻 Code Diff")
                st.code(selected_record['diff'], language="diff")
                
                pdf_bytes = create_pdf_report(selected_record)
            
                st.download_button(
                    label="📄 Export to PDF (다운로드)",
                    data=bytes(pdf_bytes),
                    file_name=f"FindAndFixMe_Report_{selected_record['id']}.pdf",
                    mime="application/pdf",
                    type="primary"
                )
                
            else:
                st.info("👆 위 표에서 행을 클릭하면 상세한 트리거 조건과 Code Diff를 확인할 수 있습니다.")

if __name__ == "__main__":
    main()