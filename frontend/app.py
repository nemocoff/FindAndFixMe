import streamlit as st
import requests
import re
from fpdf import FPDF
import pandas as pd
from api_client import (
    upload_targets, compile_target, collect_traces, get_corner_cases, inject_mutation, 
    upload_github_target, validate_mutant, get_trace_tree, wait_for_github_import,
    solve_smt, get_history, gemini_evaluate_mutant
)
from components.trace_tree import render_trace_tree_and_table
from components.diff_viewer import render_diff_viewer, render_rich_diff_viewer

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

        st.write("Solving path constraints with Z3 SMT Solver for all corner cases...")
        trigger_input = ""
        for cc_node in cc_list:
            try:
                res_smt = solve_smt(cc_node["id"])
                if cc_node["id"] == target_node:
                    trigger_input = res_smt.get("trigger_input", "")
            except Exception as e:
                if cc_node["id"] == target_node:
                    st.warning(f"SMT Solver failed for target node: {e}")
        
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

    ts = record.get('timestamp', '기록 없음')
    file_name = record.get('file', 'Unknown')
    loc = record.get('location', '위치 미상')
    pat = record.get('pattern', 'N/A')
    retry = record.get('retry_count', 0)
    surv = record.get('survival_rate', 0.0)
    execs = record.get('total_execs', 0)
    llm_score = record.get('llm_score', 'N/A')
    llm_reasoning = record.get('llm_reasoning', '평가 사유가 데이터베이스에 없습니다.')
    z3_cond = record.get('z3_condition', '조건 정보 없음')
    diff = record.get('diff', 'Diff 정보 없음')
    
    pat_list = [p.strip() for p in pat.split('+')] if isinstance(pat, str) else [str(pat)]
    
    # 높이 8짜리 셀들에 fill=True를 주어 배경색을 입힙니다.
    pdf.cell(0, 8, f" 주입 일시   : {ts}", ln=True, fill=True)
    pdf.cell(0, 8, f" 타겟 파일   : {file_name} ({loc})", ln=True, fill=True)
    pdf.cell(0, 8, f" 주입 패턴   : {pat_list[0]}", ln=True, fill=True)

    if len(pat_list) > 1:
            for p in pat_list[1:]:
                pdf.cell(0, 8, f"               {p}", ln=True, fill=True)

    pdf.cell(0, 8, f" 주입 재시도 : {retry}회", ln=True, fill=True)
    pdf.cell(0, 8, f" 퍼저 생존율 : {surv}% (총 {execs}회 실행)", ln=True, fill=True)
    pdf.ln(8)
    
    # --- [구분선] ---
    pdf.set_line_width(0.3)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    
    # --- [섹션 2: Gemini 정성 평가] ---
    pdf.set_font("D2Coding", size=13)
    pdf.cell(0, 10, f"🤖 AI 정성 평가 결과 (Score: {llm_score})", ln=True)
    
    pdf.set_font("D2Coding", size=11)
    # multi_cell로 긴 평가 사유를 줄바꿈하여 출력합니다.
    pdf.multi_cell(0, 8, f"평가 사유: {llm_reasoning}")
    pdf.ln(5)
    
    # --- [구분선] ---
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    # --- [섹션 3: 기술 상세 정보 (Z3 & Diff)] ---
    pdf.set_font("D2Coding", size=13)
    pdf.cell(0, 10, "🎯 Z3 SMT Solver Trigger Conditions & Inputs", ln=True)
    
    constraints_list = record.get('constraints', [])
    if constraints_list:
        for c_item in constraints_list:
            loc_str = c_item.get('code_location', 'Unknown')
            expr_str = c_item.get('constraint_expr', 'N/A')
            inp_str = c_item.get('trigger_input', 'N/A')
            
            pdf.set_font("D2CodingBold", size=10)
            pdf.cell(0, 6, f" Location: {loc_str}", ln=True)
            pdf.set_font("D2Coding", size=9)
            pdf.multi_cell(0, 5, f"Constraint: {expr_str}")
            pdf.ln(2)
            pdf.multi_cell(0, 5, f"Trigger Input: {inp_str}")
            pdf.ln(4)
    else:
        pdf.set_font("D2Coding", size=10)
        pdf.multi_cell(0, 6, f"Constraint: {z3_cond}")
        pdf.ln(2)
        pdf.multi_cell(0, 6, f"Trigger Input: {record.get('trigger_input', 'N/A')}")
        pdf.ln(4)
    
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    # --- [섹션 4: Code Diff (Hunk 배너 가공 버전)] ---
    pdf.set_font("D2Coding", size=13)
    pdf.set_x(10)
    pdf.cell(pdf.epw, 10, "💻 Code Diff (Unified)")
    pdf.ln(8)
    
    # 소스코드용 폰트 크기 설정
    pdf.set_font("D2Coding", size=8.5)
    
    hunk_patterns = {}
    current_hunk_line = None
    
    # 1. Gather code lines per hunk
    hunk_lines = {}
    for line in diff.splitlines():
        hunk_match = re.search(r'@@ -(\d+)', line)
        if hunk_match:
            current_hunk_line = hunk_match.group(1)
            hunk_lines[current_hunk_line] = []
        elif current_hunk_line:
            hunk_lines[current_hunk_line].append(line)
            
    # 2. Analyze hunk lines dynamically to resolve specific CWEs
    db_pattern = record.get('pattern', 'Unknown Pattern')
    cwe_candidates = re.findall(r'(CWE-\d+)', db_pattern)
    
    for h_line, lines in hunk_lines.items():
        hunk_patterns[h_line] = set()
        detected = set()
        
        added_lines = [l[1:] for l in lines if l.startswith('+')]
        deleted_lines = [l[1:] for l in lines if l.startswith('-')]
        added_text = "\n".join(added_lines)
        deleted_text = "\n".join(deleted_lines)
        
        # CWE-193 Boundary Condition Error
        if ('<' in deleted_text and '<=' in added_text) or ('<=' in deleted_text and '<' in added_text):
            detected.add('CWE-193')
            
        # CWE-190 Integer Overflow
        if any(('+ 1' in add_line or ' + 1' in add_line) for add_line in added_lines):
            detected.add('CWE-190')
            
        # CWE-476 NULL Pointer Dereference
        if 'nullptr' in added_text:
            detected.add('CWE-476')
            
        # CWE-390 Detection of Error Condition Without Action
        if any(add_line.strip() == '{}' for add_line in added_lines) or '{}' in added_text:
            if len(deleted_lines) > 0 and not any(del_line.strip() == '{}' for del_line in deleted_lines):
                detected.add('CWE-390')
                
        # CWE-401 Memory Leak
        if any(add_line.strip() == ';' for add_line in added_lines) or ';' in added_text:
            if any(('delete' in del_line or 'free' in del_line) for del_line in deleted_lines):
                detected.add('CWE-401')
                
        # CWE-682 Incorrect Calculation
        operators = ['&&', '||', '&', '|', '%', '/', '*']
        for op1 in operators:
            for op2 in operators:
                if op1 != op2:
                    if any(op1 in del_line for del_line in deleted_lines) and any(op2 in add_line for add_line in added_lines):
                        detected.add('CWE-682')
                        
        valid_detected = {c for c in detected if c in cwe_candidates}
        if valid_detected:
            hunk_patterns[h_line] = valid_detected
        else:
            if cwe_candidates:
                hunk_patterns[h_line].add(cwe_candidates[0])
            else:
                hunk_patterns[h_line].add(db_pattern)

    for line in diff.splitlines():
        clean_line = line.replace('\xa0', ' ').replace('\t', '    ')
        
        if clean_line.startswith('+'):
            pdf.set_text_color(40, 167, 69)     # 진한 초록색 (추가)
            display_line = f"  {clean_line}"
            pdf.set_x(10)
            pdf.multi_cell(pdf.epw, 4.5, display_line)
            
        elif clean_line.startswith('-'):
            pdf.set_text_color(220, 53, 69)    # 진한 빨간색 (삭제)
            display_line = f"  {clean_line}"
            pdf.set_x(10)
            pdf.multi_cell(pdf.epw, 4.5, display_line)
            
        elif clean_line.startswith('@@'):
            pdf.ln(3)                          
            
            match = re.search(r'@@ -(\d+)', clean_line)
            if match:
                line_num = match.group(1)
                hunk_banner = f"[ 코드 변경 구간 : Line {line_num} 부근 ]"
                pdf.set_x(10)
                pdf.set_fill_color(243, 235, 250)
                pdf.set_text_color(111, 66, 193)
                pdf.set_font("D2CodingBold", size=9)
                pdf.cell(pdf.epw, 6, hunk_banner, ln=True, fill=True, align='C')
                pdf.ln(3)
            else:
                hunk_banner = f"[ {clean_line} ]"
                pdf.set_x(10)
                pdf.set_fill_color(243, 235, 250)
                pdf.set_text_color(111, 66, 193)
                pdf.set_font("D2CodingBold", size=9)
                pdf.cell(pdf.epw, 6, hunk_banner, ln=True, fill=True, align='C')
                pdf.ln(3)
                
            pdf.set_font("D2Coding", size=8.5)
            
        elif clean_line.startswith('---') or clean_line.startswith('+++'):
            # original, mutated 파일 헤더 텍스트는 리포트 가독성을 위해 과감히 생략합니다.
            continue
            
        else:
            pdf.set_text_color(120, 120, 120)  # 회색 (변화 없는 본문)
            display_line = f"  {clean_line}"
            pdf.set_x(10)
            pdf.multi_cell(pdf.epw, 4.5, display_line)
            
    pdf.set_text_color(0, 0, 0)
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
            3: "CWE-390 Detection of Error Condition Without Action",
            4: "CWE-401 Memory Leak",
            5: "CWE-476 NULL Pointer Dereference",
            6: "CWE-682 Incorrect Calculation"
        }
        selected_pattern_id = st.selectbox(
            "Select Vulnerability Pattern to Inject",
            options=list(pattern_options.keys()),
            format_func=lambda x: pattern_options[x],
            index=0
        )
        
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
                            st.success(f"**Gemini AI Score:** {val_res.get('llm_score')}")
                            if val_res.get("llm_rationale") or val_res.get("llm_reasoning"):
                                rationale_text = val_res.get("llm_rationale") or val_res.get("llm_reasoning")
                                st.info(f"**AI Rationale:** {rationale_text}")
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
                if st.button("Trigger Gemini API Verification (Manual)", help="Run LLM analysis on mutants"):
                    if not mutations:
                        st.warning("평가할 뮤턴트가 없습니다. 파이프라인을 먼저 실행하십시오.")
                    else:
                        with st.spinner("Gemini 정성 평가 수행 중..."):
                            success_count = 0
                            for val_idx, mut_item in enumerate(mutations):
                                current_m_id = mut_item.get('mutant_id')
                                if current_m_id:
                                    try:
                                        res = gemini_evaluate_mutant(current_m_id)
                                        if current_m_id not in st.session_state["validation_results"]:
                                            st.session_state["validation_results"][current_m_id] = {}
                                        score = res.get("llm_score")
                                        rationale = res.get("llm_rationale")
                                        st.session_state["validation_results"][current_m_id]["llm_score"] = f"{int(score)}/10" if score is not None else "N/A"
                                        st.session_state["validation_results"][current_m_id]["llm_rationale"] = rationale
                                        success_count += 1
                                    except Exception as e:
                                        st.error(f"Mutant {current_m_id} Gemini 평가 중 오류 발생: {e}")
                            if success_count > 0:
                                st.success(f"{success_count}개 뮤턴트에 대한 Gemini 정성 평가를 완료했습니다!")
                                st.rerun()

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

            def format_pattern_list(x):
                if not isinstance(x, str):
                    return []
                
                # 원본 패턴 리스트
                p_list = [p.strip() for p in x.split('+')]
                
                # 🚨 패턴이 2개를 초과하면, 앞의 2개만 남기고 요약 배지를 추가합니다.
                if len(p_list) > 2:
                    return p_list[:2] + [f"... (+{len(p_list)-2} more)"]
                return p_list
        
            # 데이터프레임에 적용
            if "pattern" in df.columns:
                df["pattern_list"] = df["pattern"].apply(format_pattern_list)

            desired_columns = ["timestamp", "file", "pattern_list", "survival_rate", "llm_score", "retry_count"]
            display_columns = [col for col in desired_columns if col in df.columns]
            
            # 2. Master View (상단 요약 표)
            st.markdown("##### 📌 Execution Records")
            event = st.dataframe(
                df[display_columns],
                use_container_width=True,
                on_select="rerun",
                selection_mode="single-row",
                hide_index=True,
                key="history_master_table",
                column_config={
                    "pattern_list": st.column_config.ListColumn("Injected Patterns", width="large"),
                }
            )

            # 3. Detail View (하단 상세 정보 렌더링)
            selected_rows = event.selection.rows
            if selected_rows:
                selected_idx = selected_rows[0]
                selected_record = db_records[selected_idx]

                st.markdown(f"#### 🔍 세부 분석 결과: `{selected_record.get('file', 'Unknown')}`")

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.caption("🛡️ **Injected Patterns**")
                    raw_pattern = selected_record.get('pattern', 'N/A')
                    
                    if raw_pattern != 'N/A':
                        pattern_list = [p.strip() for p in raw_pattern.split('+')]
                        
                        # 💡 핵심: st.expander를 사용해 드롭다운 토글을 만듭니다.
                        # expanded=False 로 두면 기본적으로 접혀 있어서 세 단의 높이가 예쁘게 맞습니다.
                        with st.expander(f"{len(pattern_list)} Injected Patterns", expanded=False):
                            for p in pattern_list:
                                st.code(p, language="plaintext")
                    else:
                        st.info("N/A")
                with col2:
                    st.caption("📈 **Survival Rate**")
                    st.warning(f"**Survival Rate:** {selected_record.get('survival_rate', 0.0):.1f}%")
                with col3:
                    st.caption("🤖 **Gemini AI Score**")
                    llm_score_val = selected_record.get('llm_score', 'N/A')
                    st.success(f"**Gemini AI Score:** {llm_score_val}")
                    
                    if st.button("Trigger Gemini API", key=f"gemini_eval_hist_{selected_record.get('id')}"):
                        with st.spinner("Gemini 정성 평가 수행 중..."):
                            try:
                                res = gemini_evaluate_mutant(selected_record.get('id'))
                                st.success(f"평가 완료! 점수: {res.get('llm_score')}/10")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Gemini 평가 실패: {e}")

                llm_reasoning_val = selected_record.get('llm_reasoning', '평가 대기 중 또는 점수 없음')
                if llm_reasoning_val and llm_reasoning_val != '평가 대기 중 또는 점수 없음':
                    st.info(f"**🤖 Gemini AI Rationale:** {llm_reasoning_val}")

                st.markdown("##### 🎯 Z3 SMT Solver Trigger Conditions & Inputs")
                constraints = selected_record.get('constraints', [])
                if constraints:
                    for idx, c_item in enumerate(constraints):
                        with st.expander(f"📍 Location: `{c_item.get('code_location', 'Unknown')}`", expanded=True):
                            st.caption("**Z3 Path Condition**")
                            st.code(c_item.get('constraint_expr', 'N/A'), language="lisp")
                            st.caption("**Trigger Input (PoC)**")
                            st.code(c_item.get('trigger_input', 'N/A'), language="plaintext")
                else:
                    st.code(selected_record.get('z3_condition', '조건 정보 없음'), language="lisp")
                    st.code(selected_record.get('trigger_input', 'N/A'), language="plaintext")

                st.markdown("##### 💻 Code Diff (Side-by-Side)")
                
                raw_diff = selected_record.get('diff', '')
                if raw_diff:
                    render_rich_diff_viewer(raw_diff)
                else:
                    st.info("표시할 Diff 데이터가 없습니다.")
                
                pdf_bytes = create_pdf_report(selected_record)
            
                st.download_button(
                    label="📄 Export to PDF (다운로드)",
                    data=bytes(pdf_bytes),
                    file_name=f"FindAndFixMe_Report_{selected_record.get('id', 'Unknown')}.pdf",
                    mime="application/pdf",
                    type="primary"
                )
                
            else:
                st.info("👆 위 표에서 행을 클릭하면 상세한 트리거 조건과 Code Diff를 확인할 수 있습니다.")

if __name__ == "__main__":
    main()