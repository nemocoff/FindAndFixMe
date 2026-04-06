import libcst as cst
from libcst.metadata import PositionProvider
from typing import Any, List, Optional
from shared.models import InjectionResult
import sys
import os

# fault_patterns.py 로드를 위한 path 확보
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.fault_patterns import HumanErrorPatterns

class ConcurrencyScanner(cst.CSTVisitor):
    def __init__(self) -> None:
        self.found_risk = False
        self.risk_modules = {'threading', 'multiprocessing', 'asyncio'}

    def visit_Import(self, node: cst.Import) -> None:
        for alias in node.names:
            if alias.name.value in self.risk_modules:
                self.found_risk = True

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:
        if node.module and node.module.value in self.risk_modules:
            self.found_risk = True

class FaultInjectionEngine:
    """
    AST-based safe mutator (MVP).
    libcst를 활용하여 타겟 라인에 대해 패턴 A, B 변조를 구동하고, 
    compile() 검증을 통해 구문 오류 시 안전하게 자동 롤백하는 핵심 엔진입니다.
    """
    def __init__(self) -> None:
        pass

    def detect_concurrency_risks(self, code: str) -> bool:
        """
        타겟 코드 헤더를 스캔하여 병렬 모듈 존재 여부 검사.
        """
        try:
            tree = cst.parse_module(code)
            scanner = ConcurrencyScanner()
            tree.visit(scanner)
            return scanner.found_risk
        except Exception:
            return False

    def _ensure_module_dependencies(self, module: cst.Module, required_imports: List[str]) -> cst.Module:
        """
        [Sprint 2 연기] 종속성 자동 주입기 (Dependency Auto-Injector)
        패턴 C이상에서 구현될 내용이므로 임시로 원본 반환
        """
        return module

    def inject_with_safety(self, code: str, target_line_number: int, pattern: str) -> InjectionResult:
        """
        [Sprint 1 핵심 통합 요건]
        지정된 target_line_number에 매핑되는 AST 노드를 찾아 패턴을 주입하고,
        SyntaxError 발생 시 즉각 원본 코드를 반환하는 단일 패스 롤백 시스템.
        """
        try:
            # 1. 원본 파싱 및 PositionProvider 랩핑
            module = cst.parse_module(code)
            wrapper = cst.MetadataWrapper(module)

            # 2. 패턴 이름에 해당하는 Transformer 클래스 확보 (Pattern A or B)
            transformer_class = HumanErrorPatterns.get_pattern_transformer(pattern)
            if not transformer_class:
                raise ValueError(f"Pattern '{pattern}' is not implemented yet in Sprint 1.")

            # 3. 타겟 라인을 추적할 수 있도록 초기화된 Transformer 주입
            transformer = transformer_class(target_line_number=target_line_number)
            mutated_module = wrapper.visit(transformer)
            
            # Sprint 2 Dependency Auto-Injector (if needed)
            req_imports = HumanErrorPatterns.get_required_imports(pattern)
            if req_imports:
                mutated_module = self._ensure_module_dependencies(mutated_module, req_imports)

            # 4. 언파싱(Unparsing) 수행
            mutated_code = mutated_module.code

            # 5. 자동 롤백 검증 (구문 에러 방어망)
            try:
                compile(mutated_code, filename="<ast>", mode="exec")
                is_valid = True
                rollback = False
                final_code = mutated_code
            except SyntaxError:
                # 붕괴 발생 시 자동 롤백
                is_valid = False
                rollback = True
                final_code = code

            return InjectionResult(
                original_code=code,
                mutated_code=final_code,
                applied_pattern_name=pattern,
                trigger_input={},  # Sprint 2 (SMT Solver 몫)
                is_syntax_valid=is_valid,
                rollback_occurred=rollback
            )

        except Exception as e:
            # 파싱 단계에서나 알 수 없는 크래시 발생 시 최상단 방어 (원상 복구)
            return InjectionResult(
                original_code=code,
                mutated_code=code,
                applied_pattern_name=pattern,
                trigger_input={},
                is_syntax_valid=False,
                rollback_occurred=True
            )
