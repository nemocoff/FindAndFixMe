from typing import Tuple
from shared.models import EvaluationReport

class PerformanceEvaluator:
    """
    LLM and Fuzzer Evaluation Pipeline.
    """
    def __init__(self) -> None:
        pass

    def evaluate_stealthiness(self, mutated_code: str) -> float:
        """
        [Req 7.1] 파이썬 퍼저(Atheris)를 원클릭으로 백그라운드 실행하여 결함 생존율(은닉성)을 퍼센트로 자동 계산
        """
        raise NotImplementedError("TODO: Write fuzzer wrapper leveraging Atheris to test mutated_code and return survival rate percentage.")
        
    def evaluate_naturalness_with_gemini(self, code_diff: str) -> Tuple[float, str]:
        """
        [Req 7.2] Gemini API를 연동하여 코드의 자연스러움을 평가하는 모듈 파이프라인 통합
        """
        raise NotImplementedError("TODO: Make request to generativeai API. Prompt Diff text and extract score/rationale.")
        
    def run_evaluation_pipeline(self, target_file: str, mutated_code: str, code_diff: str) -> EvaluationReport:
        """
        [Req 7.3] 테스트 완료 후 '코너 케이스 위치 + 트리거 입력 정답 + 은닉성 점수'를 포함한 종합 PDF 리포트 자동 생성
        [Req 7.4] 은닉성(결함 생존율) 점수가 기준 미달일 경우, 자동으로 다른 결함 패턴을 2차 재주입하는 파이프라인 설계
        [Req 7.5] 누적된 LLM 피드백을 바탕으로 시스템이 향후 결함 패턴 라이브러리를 스스로 개선해 나갈 수 있는 구조 고안
        """
        raise NotImplementedError(
            "TODO: 1) Run stealthiness evaluation. "
            "2) If score < threshold, trigger reinjection loop (Req 7.4). "
            "3) Run Gemini evaluation. Save results for self-improvement (Req 7.5). "
            "4) Generate PDF report and return EvaluationReport."
        )
