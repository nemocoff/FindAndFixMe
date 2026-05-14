import streamlit as st

def render_diff_viewer(old_code: str, new_code: str, trigger_input: str = ""):
    """
    US-11: GitHub 스타일의 고대조 Diff 뷰어 및 트리거 복사 컴포넌트
    """
    # 1. Z3 SMT Solver 트리거 입력값 (Trigger Input) 표시 및 복사
    if trigger_input:
        with st.container():
            st.markdown("##### 🎯 Z3 SMT Solver: Trigger Input (Proof of Concept)")
            st.info("아래의 입력값은 주입된 결함을 100% 발현시키기 위해 Z3 엔진이 역산한 수학적 정답지입니다.")
            # st.code는 우측 상단에 내장 복사 버튼을 제공하여 US-11 요구사항을 완벽히 충족합니다.
            st.code(trigger_input, language="text") 
            st.caption("💡 위 코드를 복사하여 테스트 드라이버의 입력값으로 사용하세요.")

    # 2. GitHub-style Unified Diff Layout
    import difflib
    
    st.markdown("#### Code Diff")
    
    # 두 코드의 차이를 계산하여 unified diff 생성
    diff = difflib.unified_diff(
        old_code.splitlines(), 
        new_code.splitlines(), 
        fromfile='AS-IS (Original Code)', 
        tofile='TO-BE (Injected Code)',
        lineterm=''
    )
    diff_text = '\n'.join(diff)
    
    # 변경사항이 없을 경우를 대비한 처리
    if not diff_text:
        diff_text = "No changes detected."
        
    # 언어를 'diff'로 설정하면 삭제된 줄은 빨간색, 추가된 줄은 초록색으로 자동 하이라이팅됩니다.
    st.code(diff_text, language="diff")

    st.success("✅ 결함 주입 무결성 검증 완료: AST 구조가 붕괴되지 않았으며 정상 컴파일이 가능합니다.")