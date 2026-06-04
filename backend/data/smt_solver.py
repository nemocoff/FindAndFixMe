"""
backend/data/smt_solver.py

US-04: Z3 SMT Solver 기반 트리거 조건 역산
- 입력된 AST 제어 흐름 경로(조건식 리스트)를 Z3 조건식으로 변환하고 트리거 입력값 역산.
- 노드당 3초 타임아웃을 적용하기 위해 multiprocessing 패키지 활용 (Windows/Linux 호환성 제공).
- 예외 발생 시 '분석 불가' 처리.
"""

import ast
import logging
import multiprocessing
import queue
from typing import Dict, List, Any, Union, Optional
import z3

logger = logging.getLogger("FindAndFixMe.SMTSolver")

class ASTToZ3Translator:
    """
    Python AST 노드를 Z3 수식으로 변환하는 클래스.
    이동 경로 조건문(예: "x > 10")을 파싱하여 Z3 Assertions로 변환합니다.
    """
    def __init__(self):
        self.vars: Dict[str, Any] = {}

    def get_var(self, name: str) -> Any:
        """변수명을 기반으로 Z3 변수를 동적 생성 및 관리"""
        if name not in self.vars:
            # 기본적으로 정수(Int) 타입 변수로 정의
            self.vars[name] = z3.Int(name)
        return self.vars[name]

    def translate_expr(self, node: ast.AST) -> Any:
        """AST 노드를 Z3 연산식으로 변환"""
        if isinstance(node, ast.Expression):
            return self.translate_expr(node.body)
        
        elif isinstance(node, ast.BinOp):
            left = self.translate_expr(node.left)
            right = self.translate_expr(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            elif isinstance(node.op, ast.Sub):
                return left - right
            elif isinstance(node.op, ast.Mult):
                return left * right
            elif isinstance(node.op, ast.Div):
                return left / right
            elif isinstance(node.op, ast.Mod):
                return left % right
            else:
                raise NotImplementedError(f"지원하지 않는 이항 연산자: {type(node.op)}")

        elif isinstance(node, ast.Compare):
            left = self.translate_expr(node.left)
            # 단일 비교 연산 지원 (예: x > 5)
            op = node.ops[0]
            right = self.translate_expr(node.comparators[0])

            if isinstance(op, ast.Gt):
                return left > right
            elif isinstance(op, ast.GtE):
                return left >= right
            elif isinstance(op, ast.Lt):
                return left < right
            elif isinstance(op, ast.LtE):
                return left <= right
            elif isinstance(op, ast.Eq):
                return left == right
            elif isinstance(op, ast.NotEq):
                return left != right
            else:
                raise NotImplementedError(f"지원하지 않는 비교 연산자: {type(op)}")

        elif isinstance(node, ast.Name):
            return self.get_var(node.id)

        elif isinstance(node, ast.Constant):
            return node.value

        elif isinstance(node, ast.UnaryOp):
            operand = self.translate_expr(node.operand)
            if isinstance(node.op, ast.USub):
                return -operand
            elif isinstance(node.op, ast.Not):
                return z3.Not(operand)
            else:
                raise NotImplementedError(f"지원하지 않는 단항 연산자: {type(node.op)}")

        else:
            raise NotImplementedError(f"지원하지 않는 AST 노드 타입: {type(node)}")


def _solver_worker(conditions: List[str], result_queue: multiprocessing.Queue):
    """
    별도 프로세스에서 실행되어 Z3 Solver를 풀고 결과를 큐에 저장하는 워커 함수.
    """
    try:
        translator = ASTToZ3Translator()
        solver = z3.Solver()

        for cond_str in conditions:
            # 문자열 수식을 AST로 변환
            parsed = ast.parse(cond_str.strip(), mode='eval')
            z3_expr = translator.translate_expr(parsed)
            solver.add(z3_expr)

        check_res = solver.check()
        if check_res == z3.sat:
            model = solver.model()
            result_dict = {}
            for d in model.decls():
                name = d.name()
                val = model[d]
                # Z3 자료형을 Python 기본 타입으로 변환
                if z3.is_int_value(val):
                    result_dict[name] = val.as_long()
                elif z3.is_rational_value(val):
                    result_dict[name] = float(val.as_decimal(4))
                else:
                    result_dict[name] = str(val)
            result_queue.put(("SUCCESS", result_dict))
        elif check_res == z3.unsat:
            result_queue.put(("UNSAT", "분석 불가 (Unsatisfiable Constraints)"))
        else:
            result_queue.put(("UNKNOWN", "분석 불가 (Unknown SMT Result)"))
            
    except Exception as e:
        result_queue.put(("ERROR", f"분석 불가 (Error: {str(e)})"))


class SMTSolver:
    """
    Z3 SMT Solver 래퍼 클래스.
    3초 타임아웃을 강제하여 무한 루프나 연산 폭발을 차단합니다.
    """
    def __init__(self, timeout_sec: float = 3.0):
        self.timeout_sec = timeout_sec

    def solve_path_constraints(self, conditions: List[str]) -> Union[Dict[str, Any], str]:
        """
        제시된 제어 흐름 경로 상의 조건들을 만족하는 입력 변수 값을 역산합니다.
        
        Args:
            conditions (List[str]): ["x > 5", "x + y == 15", ...] 형태의 파이썬 스타일 조건식 리스트
            
        Returns:
            Union[Dict[str, Any], str]: 역산 성공 시 변수 매핑 딕셔너리, 실패/타임아웃 시 '분석 불가 ...' 문자열 반환
        """
        # 멀티프로세싱을 통한 3초 타임아웃 강제
        result_queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=_solver_worker, 
            args=(conditions, result_queue)
        )
        
        try:
            process.start()
            # 지정된 시간 동안 큐에서 대기
            status, val = result_queue.get(timeout=self.timeout_sec)
            process.join()
            
            if status == "SUCCESS":
                return val
            else:
                return val # 에러 메시지 반환
                
        except queue.Empty:
            logger.warning(f"SMT Solver timed out after {self.timeout_sec} seconds.")
            # 타임아웃 시 프로세스 즉각 종료
            process.terminate()
            process.join()
            return "분석 불가 (Timeout)"
        except Exception as e:
            logger.error(f"Unexpected error in SMT solver: {e}")
            if process.is_alive():
                process.terminate()
                process.join()
            return f"분석 불가 (Exception: {str(e)})"
