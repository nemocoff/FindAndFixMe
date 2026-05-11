import streamlit as st
from api_client import fetch_mock_analysis_result, fetch_history
from components.trace_tree import render_trace_tree_and_table
from components.diff_viewer import render_diff_viewer

API_BASE_URL = "http://localhost:8000/api/v1"

def main() -> None:
    """
    FindAndFixMe C++ Migration Dashboard
    """
    st.set_page_config(page_title="FindAndFixMe Dashboard", layout="wide")
    st.title("🐞 FindAndFixMe Dashboard (C++ Core Engine)")
    
    tab_dash, tab_hist = st.tabs(["🚀 Injection Dashboard", "📜 DB History"])

    with tab_dash:
        st.markdown("### 1. Upload Target C++ Source Code")
        target_file = st.file_uploader("Upload Target Source (`.cpp`, `.h`)", type=["cpp", "h", "hpp", "c"])
        
        if "analysis_result" not in st.session_state:
            st.session_state["analysis_result"] = None
        
        if target_file:
            st.info(f"File uploaded: {target_file.name}")
            
            if st.button("Run C++ AST Analysis & Inject Bugs", type="primary"):
                with st.spinner("Calling Core C++ Engine via API..."):
                    try:
                        # 세션에 가짜 응답을 저장하여 UI 렌더링 트리거
                        st.session_state["analysis_result"] = fetch_mock_analysis_result()
                        st.success("AST Analysis & Injection complete! (Mock Mode 켜짐 🟢)")
                    except Exception as e:
                        st.error(f"Connection Error: Ensure FastAPI is running on {API_BASE_URL}. Exception: {e}")

        if st.session_state["analysis_result"] and st.session_state["analysis_result"].get("status") == "success":
            st.markdown("---")
            render_trace_tree_and_table()
            st.markdown("---")
            st.markdown("### 2. Analysis Results & Diff Viewer")
            
            # Example response structure from Core C++ Engine
            mutations = st.session_state["analysis_result"].get("data", {}).get("mutations", [])
            
            if not mutations:
                st.warning("No mutations could be applied by the C++ engine.")
                # Mock display for presentation purposes if empty
                st.info("Mocking diff viewer for demonstration purposes:")
                render_diff_viewer(
                    "int main() {\n    int a = 10;\n    return 0;\n}",
                    "int main() {\n    // CWE-190 Integer Overflow\n    int a = 2147483647 + 1;\n    return 0;\n}"
                )
            else:
                for idx, mut in enumerate(mutations):
                    st.markdown(f"#### Mutation {idx+1}: {mut.get('pattern_name', 'Unknown')}")
                    render_diff_viewer(mut.get('original_code', ''), mut.get('mutated_code', ''))
                    
            st.markdown("---")
            st.markdown("### 3. Verification Pipeline")
            col_afl, col_gemini = st.columns(2)
            with col_afl:
                if st.button("Trigger AFL++ Fuzzer"):
                    st.info("AFL++ Fuzzing initiated. Check backend logs.")
            with col_gemini:
                if st.button("Trigger Gemini API Verification"):
                    st.info("Gemini API Verification initiated.")

    with tab_hist:
        st.markdown("### Injection History")
        if st.button("Refresh History"):
            try:
                response = fetch_history()
                if response.status_code == 200:
                    st.json(response.json())
            except Exception as e:
                st.error("Could not fetch history from API.")

if __name__ == "__main__":
    main()

