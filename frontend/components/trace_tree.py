import streamlit as st
import pandas as pd
from streamlit_echarts import st_echarts

def render_trace_tree_and_table():
    """
    US-10: 고가독성 노드 트리 시각화 및 코너 케이스 상세 표
    """
    st.markdown("### 🌳 AST Execution Flow & Corner Cases")

    # 1. ECharts Tree 렌더링을 위한 계층형 데이터
    trace_data = {
        "name": "main()\n(Exec: 10000)",
        "children": [
            {"name": "parse_input()\n(Exec: 9500)"},
            {"name": "validate_data()\n(Exec: 8000)"},
            {
                "name": "process_core()\n(Exec: 7500)",
                "children": [
                    {
                        "name": "edge_case_logic()",
                        "itemStyle": {"color": "#ff4b4b", "borderColor": "#ff0000"}, # 붉은색 강조
                        "label": {"color": "#ff4b4b", "fontWeight": "bold"},
                        "children": [
                            {
                                "name": "deep_nested_if()",
                                "itemStyle": {"color": "#ff4b4b", "borderColor": "#ff0000"},
                                "label": {"color": "#ff4b4b", "fontWeight": "bold"}
                            }
                        ]
                    }
                ]
            }
        ]
    }

    # 회원님이 제안해주신 완벽한 Tree 옵션 적용
    options = {
        "tooltip": {
            "trigger": "item",
            "triggerOn": "mousemove",
            "formatter": "{b}" # 마우스 오버 시 노드 이름 출력
        },
        "series": [
            {
                "type": "tree",
                "data": [trace_data],
                "top": "5%",
                "left": "10%",
                "bottom": "5%",
                "right": "20%",
                "symbolSize": 12,
                "label": {
                    "position": "left",
                    "verticalAlign": "middle",
                    "align": "right",
                    "fontSize": 14,
                    "fontFamily": "monospace" # 코드 경로 가독성을 위한 폰트
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
                "initialTreeDepth": 3 # 초기 펼침 깊이 설정
            }
        ]
    }

    # Tree 그래프 렌더링
    st_echarts(options=options, height="450px")

    # 2. 직관적인 표(Table) 형태의 상세 데이터 제공
    st.markdown("#### 🚨 탐지된 코너 케이스 (1% 미만 도달 노드)")
    
    # 표 렌더링을 위한 Mock DataFrame
    df_corner_cases = pd.DataFrame([
        {"Node_ID": "edge_case_logic()", "Parent": "process_core()", "Executions": 50, "Frequency": "0.50%"},
        {"Node_ID": "deep_nested_if()", "Parent": "edge_case_logic()", "Executions": 2, "Frequency": "0.02%"}
    ])

    # 붉은색 경고 박스와 함께 표 렌더링
    st.error(f"최신 퍼저가 탐지하기 힘든 깊은 코너 케이스가 {len(df_corner_cases)}건 발견되었습니다.")
    st.dataframe(
        df_corner_cases,
        width='stretch',
        hide_index=True
    )