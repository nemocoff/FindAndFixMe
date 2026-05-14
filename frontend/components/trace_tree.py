import streamlit as st
import pandas as pd
from streamlit_echarts import st_echarts


def _build_tree_data(cc_data: list) -> dict:
    """
    실제 cc_data(CornerCaseNode 목록)를 ECharts Tree 형태로 변환.
    node_type에 따라 색상을 다르게 표시.
    """
    # 루트 노드
    root = {
        "name": "Target Program\n(Entry Point)",
        "itemStyle": {"color": "#4a9eff"},
        "children": []
    }

    # 소스 타입별 색상 맵
    color_map = {
        "afl_crash": "#ff4b4b",
        "afl_hang":  "#ff9800",
        "afl_queue": "#4caf50",
    }

    for cc in cc_data:
        node_type  = cc.get("node_type", "afl_queue")
        node_id    = cc.get("id", "?")
        freq       = cc.get("exec_frequency", 0)
        location   = cc.get("code_location", "unknown")
        color      = color_map.get(node_type, "#9c27b0")

        label = f"{location}\n[{node_type}] freq={freq:.4f}"

        node = {
            "name": label,
            "value": node_id,
            "itemStyle": {"color": color, "borderColor": color},
            "label": {"color": color, "fontWeight": "bold"},
        }
        root["children"].append(node)

    return root


def render_trace_tree_and_table(cc_data=None, total_traces=0, execs_done=0):
    """
    US-10: 실제 퍼징 결과 기반 노드 트리 시각화 및 코너 케이스 상세 표
    """
    execs_formatted = f"{int(execs_done):,}" if execs_done else "0"
    st.markdown(f"### AST Execution Flow & Corner Cases (총 {total_traces}개 경로 탐색)")

    # ── 1. 범례 ────────────────────────────────────────────────────────────────
    legend_html = """
    <div style="display:flex;gap:18px;margin-bottom:8px;font-size:13px;">
        <span><span style="color:#ff4b4b;font-size:18px;">●</span> Crash</span>
        <span><span style="color:#ff9800;font-size:18px;">●</span> Hang</span>
        <span><span style="color:#4caf50;font-size:18px;">●</span> Queue (희귀 경로)</span>
        <span><span style="color:#4a9eff;font-size:18px;">●</span> Entry</span>
    </div>
    """
    st.markdown(legend_html, unsafe_allow_html=True)

    # ── 2. ECharts Tree 렌더링 ─────────────────────────────────────────────────
    if cc_data:
        trace_data = _build_tree_data(cc_data)
    else:
        # 데이터가 없을 때 보여줄 안내 목업
        trace_data = {
            "name": "Target Program\n(Entry Point)",
            "itemStyle": {"color": "#4a9eff"},
            "children": [
                {"name": "No corner cases detected\n(Run pipeline first)", "itemStyle": {"color": "#aaaaaa"}}
            ]
        }

    options = {
        "tooltip": {
            "trigger": "item",
            "triggerOn": "mousemove",
            "formatter": "{b}"
        },
        "series": [
            {
                "type": "tree",
                "data": [trace_data],
                "top": "5%",
                "left": "15%",
                "bottom": "5%",
                "right": "25%",
                "symbolSize": 14,
                "label": {
                    "position": "left",
                    "verticalAlign": "middle",
                    "align": "right",
                    "fontSize": 12,
                    "fontFamily": "monospace"
                },
                "leaves": {
                    "label": {
                        "position": "right",
                        "verticalAlign": "middle",
                        "align": "left"
                    }
                },
                "emphasis": {"focus": "descendant"},
                "expandAndCollapse": True,
                "animationDuration": 550,
                "animationDurationUpdate": 750,
                "initialTreeDepth": 3
            }
        ]
    }

    st_echarts(options=options, height="450px")

    # ── 3. 상세 테이블 ─────────────────────────────────────────────────────────
    st.markdown("#### 탐지된 코너 케이스")

    if cc_data:
        df_rows = []
        for cc in cc_data:
            df_rows.append({
                "ID":        cc.get("id"),
                "Type":      cc.get("node_type", "-"),
                "Location":  cc.get("code_location", "-"),
                "Frequency": f"{cc.get('exec_frequency', 0):.4f}",
            })
        df_corner_cases = pd.DataFrame(df_rows)
        count = len(cc_data)
    else:
        df_corner_cases = pd.DataFrame([])
        count = 0

    st.error(
        f"60초 동안 퍼저가 코드를 **{execs_formatted}번** 실행하여 "
        f"총 **{total_traces}**개의 고유 경로를 탐색했으며, "
        f"그중 도달률이 가장 낮은 코너 케이스 **{count}**건을 찾아냈습니다!"
    )
    st.dataframe(df_corner_cases, width="stretch", hide_index=True)