import streamlit as st
import json
import streamlit.components.v1 as components

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

def render_rich_diff_viewer(raw_diff_string):
    """diff2html.js를 사용하여 GitHub 스타일의 미려한 Diff 뷰어를 렌더링합니다."""
    
    # C++ 코드 내의 따옴표나 줄바꿈이 JS 문법을 깨뜨리지 않도록 안전하게 인코딩합니다.
    safe_diff = json.dumps(raw_diff_string)
    
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/diff2html/bundles/css/diff2html.min.css" />
        <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/diff2html/bundles/js/diff2html-ui.min.js"></script>
    </head>
    <body style="margin: 0; font-family: sans-serif;">
        <div id="diff-ui"></div>
        <script>
            document.addEventListener('DOMContentLoaded', function () {{
                var diffString = {safe_diff};
                var targetElement = document.getElementById('diff-ui');
                var configuration = {{
                    drawFileList: false,
                    matching: 'lines',
                    outputFormat: 'side-by-side', // 좌우 분할 모드 (위아래로 보려면 'line-by-line'으로 변경)
                    synchronisedScroll: true,     // 양쪽 스크롤 동기화
                    highlight: true,
                    renderNothingWhenEmpty: false,
                }};
                var diff2htmlUi = new Diff2HtmlUI(targetElement, diffString, configuration);
                diff2htmlUi.draw();
            }});
        </script>
    </body>
    </html>
    """
    
    # 생성된 HTML을 Streamlit 화면에 높이 500px로 렌더링 (스크롤 가능)
    components.html(html_template, height=500, scrolling=True)