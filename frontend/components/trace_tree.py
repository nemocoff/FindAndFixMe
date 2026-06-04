import streamlit as st
import pandas as pd
from streamlit_echarts import st_echarts


def _has_corner_case(node: dict) -> bool:
    """노드 또는 하위 노드 중 코너케이스가 있는지 여부 판별"""
    if node.get("is_corner_case", False):
        return True
    if node.get("name") in ("Crash Paths", "Timeout Paths"):
        return True
    for child in node.get("children", []):
        if _has_corner_case(child):
            return True
    return False


def _simplify_function_name(name: str, max_len: int = 24) -> str:
    """긴 C++ 함수명을 가독성 좋고 겹치지 않게 축소. 단, 툴팁에는 전체명이 보존됨."""
    if len(name) <= max_len:
        return name
        
    # 1. 괄호와 괄호 안의 매개변수 목록 제거
    # 예: my_func(int, float) -> my_func
    if "(" in name:
        name = name.split("(")[0].strip()
        
    # 2. C++ 템플릿 인자 <...> 제거
    clean_name = ""
    depth = 0
    for char in name:
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
        elif depth == 0:
            clean_name += char
            
    # 3. 네임스페이스가 너무 길면 마지막 2개 세그먼트만 추출
    if "::" in clean_name:
        parts = clean_name.split("::")
        if len(parts) > 2:
            clean_name = "::".join(parts[-2:])
            
    # 4. 그래도 너무 길면 글자수 잘라내고 ... 붙임
    if len(clean_name) > max_len:
        return clean_name[:max_len - 3] + "..."
    return clean_name


def _process_node(node: dict, max_hits: int) -> dict:
    """
    재귀적으로 노드를 처리하며 ECharts 스타일 및 자동 펼침/접힘 속성 적용.
    - 코너케이스: 빨간색
    - 일반노드: hit_count에 따른 파란색 농도 조절
    - 코너케이스 포함 경로: collapsed = False (기본 펼침)
    - 일반 경로: collapsed = True (기본 접힘)
    """
    is_cc = node.get("is_corner_case", False)
    hits = node.get("hit_count", 0)
    
    # 색상 결정 로직
    if is_cc:
        color = "#ff4b4b" # 빨간색
    else:
        # 방문 횟수에 따른 파란색 농도 (0.2 ~ 1.0)
        opacity = max(0.2, min(1.0, hits / max_hits)) if max_hits > 0 else 0.5
        color = f"rgba(74, 158, 255, {opacity})"
    
    # 툴팁 내용 구성 (코너케이스일 경우 코드 포함)
    name = node.get("name", "node")
    snippet = node.get("code_snippet", "")
    tooltip_text = f"<b>Location:</b> {name}<br/><b>Hits:</b> {hits}"
    if snippet:
        # HTML 엔티티 처리 및 줄바꿈 적용
        safe_snippet = snippet.replace("\n", "<br/>").replace(" ", "&nbsp;")
        tooltip_text += f"<br/><hr/><b>Code Trace:</b><br/><code style='font-family:monospace; font-size:11px; word-break:break-all; white-space:pre-wrap;'>{safe_snippet}</code>"

    # 코너케이스 관련 경로(본인 또는 후손이 코너케이스이거나 최상위 Main 노드)는 펼침
    has_cc = _has_corner_case(node) or name == "Main"

    # ECharts 그래프 노드 상의 라벨용으로 이름 축소 (겹침 원천 방지)
    display_name = _simplify_function_name(name)

    processed = {
        "name": display_name,
        "value": hits,
        "collapsed": not has_cc, # 코너케이스가 있으면 펼치고(collapsed=False), 없으면 접음(collapsed=True)
        "itemStyle": {"color": color, "borderColor": color},
        "label": {"show": True, "color": "#333"},
        "tooltip": {"formatter": tooltip_text},
        "children": [_process_node(c, max_hits) for c in node.get("children", [])]
    }
    return processed


def render_trace_tree_and_table(tree_data=None, cc_data=None, total_traces=0, execs_done=0):
    """
    [T13] 전체 실행 경로를 트리맵으로 시각화.
    - 자주 방문한 곳: 파란색 그라데이션
    - 코너 케이스: 빨간색 강조 및 코드 툴팁
    """
    execs_formatted = f"{int(execs_done):,}" if execs_done else "0"
    st.markdown(f"### Dynamic Execution Path Tree ({total_traces} Paths)")

    # ── 1. 범례 ────────────────────────────────────────────────────────────────
    legend_html = """
    <div style="display:flex;gap:18px;margin-bottom:12px;font-size:13px;align-items:center;">
        <div style="display:flex;align-items:center;"><span style="display:inline-block;width:12px;height:12px;background:#ff4b4b;margin-right:5px;border-radius:2px;"></span><b>Corner Case</b> (Red)</div>
        <div style="display:flex;align-items:center;"><span style="display:inline-block;width:12px;height:12px;background:#4a9eff;margin-right:5px;border-radius:2px;"></span><b>Frequent Path</b> (Deep Blue)</div>
        <div style="display:flex;align-items:center;"><span style="display:inline-block;width:12px;height:12px;background:rgba(74,158,255,0.3);margin-right:5px;border-radius:2px;"></span><b>Rare Path</b> (Light Blue)</div>
    </div>
    """
    st.markdown(legend_html, unsafe_allow_html=True)

    # ── 2. ECharts Tree 렌더링 ─────────────────────────────────────────────────
    if tree_data and tree_data.get("children"):
        max_hits = tree_data.get("hit_count", 1)
        formatted_data = _process_node(tree_data, max_hits)
    else:
        formatted_data = {
            "name": "No Execution Data",
            "itemStyle": {"color": "#ccc"},
            "children": []
        }

    options = {
        "tooltip": {
            "trigger": "item",
            "triggerOn": "mousemove",
            "enterable": True, # 툴팁 안의 텍스트 드래그 가능하게
            "backgroundColor": "rgba(255, 255, 255, 0.95)",
            "extraCssText": "box-shadow: 0 0 8px rgba(0,0,0,0.3); border-radius: 4px; padding: 10px; max-width: 550px; white-space: normal; word-break: break-all; overflow-wrap: break-word;"
        },
        "series": [
            {
                "type": "tree",
                "data": [formatted_data],
                "top": "5%",
                "left": "10%",
                "bottom": "5%",
                "right": "20%",
                "symbol": "circle",
                "symbolSize": 18,
                "orient": "LR", # Left to Right
                "label": {
                    "show": False,
                    "position": "left",
                    "align": "right",
                    "verticalAlign": "middle",
                    "fontSize": 11
                },
                "leaves": {
                    "label": {
                        "show": True,
                        "position": "right",
                        "align": "left"
                    }
                },
                "labelLayout": {
                    "hideOverlap": True
                },
                "expandAndCollapse": True,
                "initialTreeDepth": -1,
                "lineStyle": {"width": 2, "curveness": 0.5}
            }
        ]
    }

    st_echarts(options=options, height="500px")

    # ── 3. 상세 테이블 (기존 기능 유지) ─────────────────────────────────────────
    if cc_data:
        st.markdown("#### Detected Corner Cases")
        df_rows = []
        for cc in cc_data:
            df_rows.append({
                "ID":        str(cc.get("id")),
                "Type":      cc.get("node_type", "-"),
                "Location":  cc.get("code_location", "-"),
                "Frequency": f"{cc.get('exec_frequency', 0):.4f}",
            })
        df_corner_cases = pd.DataFrame(df_rows)
        st.dataframe(df_corner_cases, width="stretch", hide_index=True)

    st.info(
        f"분석 결과: 60초 동안 총 **{execs_formatted}번**의 실행을 통해 "
        f"**{total_traces}**개의 경로를 탐색했습니다."
    )