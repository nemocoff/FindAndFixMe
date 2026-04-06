import streamlit as st
from streamlit_echarts import st_echarts
import sys
import os
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check_import_exists(target_filename: str, harness_code: str) -> bool:
    
    """
    하네스 코드가 타겟 파일을 정상적으로 import 하고 있는지 검사합니다.
    """
    # 확장자(.py)를 제거하여 모듈 이름만 추출 (예: target_source_code.py -> target_source_code)
    module_name = os.path.splitext(target_filename)[0]
    
    # 파이썬 import 기본 패턴 2가지
    import_pattern_1 = f"import {module_name}"
    import_pattern_2 = f"from {module_name} import"
    
    # 둘 중 하나라도 하네스 코드에 포함되어 있으면 True
    if import_pattern_1 in harness_code or import_pattern_2 in harness_code:
        return True
    return False
    

def detect_concurrency_risks(code_str: str) -> bool:
    """Mock AST Engine: 동시성/비동기 모듈 임포트 감지"""
    risks = ["import threading", "import multiprocessing", "import asyncio", "from threading", "from multiprocessing"]
    return any(risk in code_str for risk in risks)

def fetch_corner_cases() -> list:
    """Mock: 백엔드에서 1% 미만 도달률을 가진 코너 케이스 리스트를 가져옴"""
    return [
        {"id": "CC-01", "name": "visit_Call() Exception Handler", "hit_rate": "0.4%", "line": 142},
        {"id": "CC-02", "name": "parse_ast_nodes() Timeout Fallback", "hit_rate": "0.1%", "line": 305},
        {"id": "CC-03", "name": "validate_inputs() Edge Type Cast", "hit_rate": "0.8%", "line": 88}
    ]

def render_diff_viewer(old_code: str, new_code: str):
    """GitHub 스타일의 Side-by-Side Diff 뷰어 (st.columns 활용)"""
    st.markdown("##### 🔍 Code Diff Viewer")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Original Code (AS-IS)**")
        st.code(old_code, language="python")
    with col2:
        st.markdown("**Injected Code (TO-BE)**")
        st.code(new_code, language="python")



def run_real_analysis(file_content):
    """
    백엔드 파이프라인 + 프로그레스 바 UI 통합
    """
    with st.status("Initializing Context-Aware Injection Pipeline...", expanded=True) as status:
        
        # 1단계
        st.write("🔍 Parsing AST with `libcst` and mapping contexts...")
        time.sleep(1.5) # 실제 파싱 함수 실행 (예: backend.parse_ast(file_content))
        
        # 2단계 + 프로그레스 바
        st.write("🚀 Running dynamic tracing via `sys.settrace`...")
        progress_text = "Tracking execution paths. Please wait."
        my_bar = st.progress(0, text=progress_text)
        
        # 실제 환경에서는 백엔드 함수가 진행률을 반환(yield 또는 callback)하도록 구성하여 업데이트합니다.
        for percent_complete in range(100):
            time.sleep(0.03) 
            my_bar.progress(percent_complete + 1, text=f"{progress_text} ({percent_complete + 1}%)")
            
        # 3단계
        st.write("🛡️ Verifying path reachability & solving constraints with `CrossHair`...")
        time.sleep(2.0) # 실제 CrossHair 연동 함수 실행
        
        # 상태 업데이트 완료
        status.update(label="Analysis & Bug Injection Complete!", state="complete", expanded=False)
    
    # 최종 결과 JSON 반환
    real_trace_json = {
        "name": "main()",
        "children": [
            {
                "name": "init_context()",
                "value": 15
            },
            {
                "name": "run_target_function()",
                "children": [
                    {"name": "validate_inputs()", "value": 20},
                    {
                        "name": "parse_ast_nodes()",
                        "children": [
                            {"name": "visit_If()", "value": 10},
                            {
                                "name": "visit_Call() [INJECTED]",
                                "value": 50,
                                # Highlight the exact injection point for the researchers
                                "itemStyle": {"color": "#ff4b4b", "borderColor": "#c22a2a"},
                                "label": {"color": "#ffffff", "fontWeight": "bold"},
                                "children": [
                                    {"name": "CrossHair_solver()", "value": 100}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }
    return real_trace_json


def render_interactive_tree(trace_data: dict): # 분석한 트레이스 경로 데이터를 상호작용하는 트리로 렌더링하는 함수
    """
    Renders an interactive, collapsible tree using Apache ECharts.
    """
    options = {
        "tooltip": {
            "trigger": "item",
            "triggerOn": "mousemove"
        },
        "series": [
            {
                "type": "tree",
                "data": [trace_data],
                "top": "1%",
                "left": "7%",
                "bottom": "1%",
                "right": "20%",
                "symbolSize": 10,
                "label": {
                    "position": "left",
                    "verticalAlign": "middle",
                    "align": "right",
                    "fontSize": 14,
                    "fontFamily": "monospace" # Better readability for code paths
                },
                "leaves": {
                    "label": {
                        "position": "right",
                        "verticalAlign": "middle",
                        "align": "left"
                    }
                },
                "emphasis": {
                    "focus": "descendant"
                },
                "expandAndCollapse": True,
                "animationDuration": 550,
                "animationDurationUpdate": 750,
                "initialTreeDepth": 2 # Auto-collapse deep traces initially
            }
        ]
    }
    
    # Render the chart in Streamlit
    st_echarts(options, height="600px")

def main() -> None:
    """
    [Req 5.1/5.3] 대화형 트리 맵 구현 (축소/확대, 미니맵 제공)
    [Req 5.4] 프로그레스 바 UI 표시
    [Req 6.1/6.2] GitHub 스타일의 Side-by-Side Diff 뷰어 대시보드 내장 및 하이라이팅 표시
    [Req 6.3] SMT Solver '트리거 입력 조건'의 클립보드 복사 패널 제공
    [Req 6.4] DB 기록 History 탭 연결
    
    [전문가 툴 필수 요건] 라인 밀림 방지를 위한 체크박스 순차 실행 프로세스 및 동시성 의심 경고
    [통합 필수 요건] 단방향 타겟 파일이 아닌 샌드박시 실행용 외부 'Test Harness Wrapper' 동시 입력 체계 구축
    """
    st.set_page_config(page_title="FindAndFixMe Dashboard", layout="wide")
    st.title("🐞 FindAndFixMe Dashboard")
    # [Req 6.4] 탭을 통한 대시보드와 History 분리
    tab_dash, tab_hist = st.tabs(["🚀 Injection Dashboard", "📜 DB History"])

    with tab_dash:
        st.markdown("### 1. Upload Target & Test Harness")
        # [통합 필수 요건] 두 개의 파일 동시 업로드
        col_file1, col_file2 = st.columns(2)
        with col_file1:
            target_file = st.file_uploader("Upload Target Source (`target_source_code.py`)", type=["py"])
        with col_file2:
            harness_file = st.file_uploader("Upload Test Harness (`test_harness_wrapper.py`)", type=["py"])

        if target_file and harness_file:
            target_code = target_file.getvalue().decode("utf-8")
            harness_code = harness_file.getvalue().decode("utf-8")

            # ⭐️ 1. Import 검증 로직 실행
            is_import_valid = check_import_exists(target_file.name, harness_code)
        
            if not is_import_valid:
                # 경고 메시지를 띄우고 사용자의 수정을 유도
                st.error(f"🚨 오류: 테스트 하네스에서 `{target_file.name}` 모듈을 import 하는 구문을 찾을 수 없습니다. 하네스 코드를 확인해주세요.")
            else:
                st.success("✅ 테스트 하네스 정상 연결 확인됨")
            
                # [전문가 툴 필수 요건] 동시성 의심 경고
                if detect_concurrency_risks(target_code):
                    st.warning("⚠ 멀티스레딩/비동기 모듈이 감지되었습니다. 일부 트레이스가 유실될 수 있으니 단위 테스트용 순수 진입점을 타겟하세요.")

                # 2. 기존 분석 버튼 노출
                if st.button("Run Path Analysis & Inject Bugs", type="primary"):
                    with st.spinner("분석 중..."):
                        # 백엔드 분석 실행 및 세션 저장
                        result_json = run_real_analysis(target_code)
                        st.session_state['trace_data'] = result_json
                        st.session_state['corner_cases'] = fetch_corner_cases()
                        st.success("Path analysis complete!")
            
        # 트레이스 데이터가 있을 때 렌더링
        if 'trace_data' in st.session_state:
            st.markdown("---")
            st.markdown("### 2. Interactive Execution Trace")
            render_interactive_tree(st.session_state['trace_data'])
            
            st.markdown("---")
            st.markdown("### 3. Select Corner Cases for Injection")
            
            # 코너 케이스 다중 선택 (Checkboxes)
            selected_cases = []
            for case in st.session_state['corner_cases']:
                if st.checkbox(f"[{case['id']}] {case['name']} (Hit rate: {case['hit_rate']}, Line: {case['line']})"):
                    selected_cases.append(case)
            
            if selected_cases:
                if st.button("Inject Bug & Run Z3 (CrossHair)", type="primary"):
                    st.markdown("---")
                    st.markdown("### 4. Sequential Injection & Verification Results")
                    
                    # [전문가 툴 필수 요건] 선택된 코너 케이스를 순차적(Sequential)으로 처리
                    for idx, case in enumerate(selected_cases):
                        with st.status(f"Processing {case['id']}...", expanded=(idx==0)):
                            time.sleep(1) # 버그 주입 시뮬레이션
                            st.write("✅ Bug Injected. Running Z3 Solver...")
                            time.sleep(1) # CrossHair 시뮬레이션
                            
                            # [Req 6.1/6.2] Diff 뷰어 렌더링
                            mock_old = f"def {case['name'].split('(')[0]}():\n    if node is not None:\n        return True"
                            mock_new = f"def {case['name'].split('(')[0]}():\n    # Injected by FindAndFixMe\n    if node is None: # Logic Flipped\n        return True"
                            render_diff_viewer(mock_old, mock_new)
                            
                            # [Req 6.3] SMT Solver 트리거 조건 복사 패널
                            st.markdown("##### 🎯 Z3 Solver Trigger Conditions")
                            st.info("CrossHair successfully generated constraints to reach this bug.")
                            # st.code는 기본적으로 우측 상단에 클립보드 복사 아이콘을 제공합니다.
                            st.code(f"# Input required to trigger {case['id']}\ninput_args = {{'node_type': 'AST_CALL', 'depth': {case['line']}}}\nassert not validate(input_args)", language="python")
                            
                            st.success(f"Task for {case['id']} completed.")

    # [Req 6.4] History 탭
    with tab_hist:
        st.markdown("### Injection History")
        st.dataframe([
            {"Date": "2023-11-20", "Target": "requests/sessions.py", "Injected Bugs": 3, "Verified": True},
            {"Date": "2023-11-21", "Target": "flask/app.py", "Injected Bugs": 1, "Verified": False},
        ], use_container_width=True)
    
    raise NotImplementedError(
        "TODO: 1) [통합 필수 요건] Render file uploaders for TWO files: `target_source_code.py` AND `test_harness_wrapper.py`. "
        "2) Extract raw code from target path and run `ast_engine.detect_concurrency_risks(code)`. "
        "3) If True, render `st.warning('⚠ 멀티스레딩/비동기 모듈이 감지되었습니다. 일부 트레이스가 유실될 수 있으니 단위 테스트용 순수 진입점을 타겟하세요.')` "
        "4) Feed the harness to `data.tracer` and fetch List of CornerCases (< 1% hit count) from backend."
        "5) Render multi-select checkboxes for the researcher to pick target corner cases. "
        "6) Ask user to click 'Inject Bug & Run Z3'. "
        "7) CRUCIAL: Iterate through selected checkboxes in a strict SEQUENTIAL LOOP. "
        "8) Render UI diff, stepper progress, and optionally ask for Gemini API (LLM Cost) evaluation."
    )

if __name__ == "__main__":
    main()
