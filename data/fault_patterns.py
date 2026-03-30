import libcst as cst

class HumanErrorPatterns:
    """
    Pattern library for semantic bug injections via libcst transformers.
    """
    
    @staticmethod
    def apply_pattern_a(node: cst.CSTNode) -> cst.CSTNode:
        """
        [Req 4.1] [패턴 A] 방어적 프로그래밍 누락: Null Check(is None)나 try-except 블록 통째로 삭제
        """
        raise NotImplementedError("TODO: Implement CSTTransformer to find If nodes with 'is None' or Try nodes and remove them.")

    @staticmethod
    def apply_pattern_b(node: cst.CSTNode) -> cst.CSTNode:
        """
        [Req 4.2] [패턴 B] 경계값 오류(Off-by-one) 유발: <를 <=로, >를 >=로 미세 변조하여 오작동 유도
        """
        raise NotImplementedError("TODO: Implement CSTTransformer to find LessThan/GreaterThan comparison operators and swap to LessThanEqual/GreaterThanEqual.")

    @staticmethod
    def apply_pattern_c(node: cst.CSTNode) -> cst.CSTNode:
        """
        [Req 4.3] [패턴 C] 깊은 복사 오류: copy.deepcopy()를 단순 할당(=)으로 변조하여 참조 덮어쓰기 유발
        """
        raise NotImplementedError("TODO: Implement CSTTransformer to match Call node containing 'deepcopy' and replace with Assignment node.")

    @staticmethod
    def apply_pattern_d(node: cst.CSTNode) -> cst.CSTNode:
        """
        [Req 4.4] [패턴 D] 논리 연산자 문맥 혼동: 다중 조건문에서 주변 변수명을 분석해 and를 or로 교묘하게 스와핑
        """
        raise NotImplementedError("TODO: Implement CSTTransformer to randomly select BooleanOperation 'And' and swap with 'Or' based on context variables.")

    @staticmethod
    def apply_pattern_e(node: cst.CSTNode) -> cst.CSTNode:
        """
        [Req 4.5] [패턴 E] 반환값 무시: 함수의 반환값을 변수에 할당하지 않고 로직을 진행하는 실수 모사
        """
        raise NotImplementedError("TODO: Implement CSTTransformer to find Assign node holding a Call node and extract the Call, removing the variable target.")

    @staticmethod
    def apply_pattern_f(node: cst.CSTNode) -> cst.CSTNode:
        """
        [Req 4.6] [패턴 F] 섀도잉 혼동: 지역 변수와 전역 변수의 이름이 유사할 때 이를 헷갈려 잘못 할당하는 인지적 오류 모사
        """
        raise NotImplementedError("TODO: Implement CSTTransformer to rename a Name node locally if a similarly named global variable exists.")
