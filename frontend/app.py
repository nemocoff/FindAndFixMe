import streamlit as st
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
