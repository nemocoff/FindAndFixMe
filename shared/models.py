from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class TraceNode:
    """
    [Req 1.3] 수집된 거대한 실행 경로 데이터를 부모-자식 노드(Node)를 가진 JSON 트리 구조로 정규화
    """
    node_id: str
    line_number: int
    code_snippet: str
    hit_count: int
    is_corner_case: bool  # [Req 2.1] 트레이스 상에서 실행 빈도 1% 미만이거나 미개척된 분기점을 코너 케이스 후보군으로 추출
    observed_types: Dict[str, str] = field(default_factory=dict) # [신뢰성 향상] 동적 타입 추론을 위한 변수별 런타임 타입 스냅샷 기록
    children: List['TraceNode'] = field(default_factory=list)

@dataclass
class InjectionResult:
    original_code: str
    mutated_code: str
    applied_pattern_name: str
    trigger_input: Dict[str, Any]  # [Req 2.4] 버그 발현의 명확한 정답지인 '트리거 입력 조건'을 JSON 형태로 산출
    is_syntax_valid: bool
    rollback_occurred: bool # [Req 3.3] 결함 주입 시 예기치 못한 AST 트리의 붕괴가 발생할 경우 원본 코드로 자동 롤백

@dataclass
class EvaluationReport:
    fuzzing_survival_rate: float   # [Req 7.1] 파이썬 퍼저(Atheris) 백그라운드 실행 결함 생존율 (0.0 - 100.0)
    llm_score: Optional[float]     # [Req 7.2] Gemini API 연동 (사용자 선택 시에만 할당됨)
    llm_rationale: Optional[str]   # Feedback text from Gemini (사용자 선택 시에만 할당됨)
    pdf_report_path: Optional[str] = None # [Req 7.3] 종합 PDF 리포트 자동 생성
