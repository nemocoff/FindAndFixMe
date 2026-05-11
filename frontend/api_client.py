import requests
import time

API_BASE_URL = "http://localhost:8000/api/v1"

def fetch_mock_analysis_result():
    # Assuming API accepts file upload
    # files = {"file": (target_file.name, target_file.getvalue())}
    # response = requests.post(f"{API_BASE_URL}/analyze", files=files)
    # if response.status_code == 200:
    #     st.session_state["analysis_result"] = response.json()
    #     st.success("AST Analysis & Injection complete!")
    # else:
    #     st.error(f"API Error: {response.text}")
    time.sleep(1.5)

    mock_response = {
        "status": "success",
        "data": {
            "mutations": [
                {
                    "pattern_name": "🚨 CWE-193 (경계값 오류 / Off-by-one)",
                    "original_code": "for (int i = 0; i < len; i++) {\n    buffer[i] = payload[i];\n}",
                    "mutated_code": "for (int i = 0; i <= len; i++) { // 😈 1% 확률로 버퍼 오버플로우 유발\n    buffer[i] = payload[i];\n}"
                },
                {
                    "pattern_name": "🚨 CWE-682 (비트 연산자 혼동)",
                    "original_code": "int secret_key = checksum ^ 0xDEADBEEF;",
                    "mutated_code": "int secret_key = checksum | 0xDEADBEEF; // 😈 정답지 조건 붕괴"
                }
            ]
        }
    }

    return mock_response
    
def fetch_history():
    return requests.get(f"{API_BASE_URL}/history")