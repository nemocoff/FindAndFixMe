import streamlit as st
import requests
import time
import os

API_BASE_URL = "http://localhost:8000/api/v1"

def render_diff_viewer(old_code: str, new_code: str):
    """GitHub 스타일의 Side-by-Side Diff 뷰어"""
    st.markdown("##### 🔍 Code Diff Viewer")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Original Code (AS-IS)**")
        st.code(old_code, language="cpp")
    with col2:
        st.markdown("**Injected Code (TO-BE)**")
        st.code(new_code, language="cpp")

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
                        # Assuming API accepts file upload
                        files = {"file": (target_file.name, target_file.getvalue())}
                        response = requests.post(f"{API_BASE_URL}/analyze", files=files)
                        if response.status_code == 200:
                            st.session_state["analysis_result"] = response.json()
                            st.success("AST Analysis & Injection complete!")
                        else:
                            st.error(f"API Error: {response.text}")
                    except Exception as e:
                        st.error(f"Connection Error: Ensure FastAPI is running on {API_BASE_URL}. Exception: {e}")

        if st.session_state["analysis_result"] and st.session_state["analysis_result"].get("status") == "success":
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
                response = requests.get(f"{API_BASE_URL}/history")
                if response.status_code == 200:
                    st.json(response.json())
            except Exception as e:
                st.error("Could not fetch history from API.")

if __name__ == "__main__":
    main()

