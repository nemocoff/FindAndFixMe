#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <future>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "llvm/Support/raw_ostream.h"
#include "z3++.h"

using namespace clang;
using namespace clang::tooling;
using namespace clang::ast_matchers;

static llvm::cl::OptionCategory FindAndFixMeCategory("FindAndFixMe Options");

// [T10] 주입할 패턴 ID (CLI --pattern-id 옵션으로 지정)
static llvm::cl::opt<int> PatternId(
    "pattern-id",
    llvm::cl::desc("결함 주입 패턴 ID (1=CWE-190, 2=CWE-193, 3=CWE-390, 4=CWE-401, 5=CWE-476, 6=CWE-682)"),
    llvm::cl::init(0),  // 0 = 모든 패턴 적용
    llvm::cl::cat(FindAndFixMeCategory)
);

// Target function for localized injection
static llvm::cl::opt<std::string> TargetFunc(
    "target-func",
    llvm::cl::desc("Target function for injection (empty = everywhere)"),
    llvm::cl::init(""),
    llvm::cl::cat(FindAndFixMeCategory)
);

// [T8] ClangTool 실행 타임아웃 (초)
static llvm::cl::opt<int> AstTimeout(
    "ast-timeout",
    llvm::cl::desc("AST 파싱 타임아웃 (초, 기본 30)"),
    llvm::cl::init(30),
    llvm::cl::cat(FindAndFixMeCategory)
);

// ─────────────────────────────────────────────────────────────────────────────
// [T10] 패턴 레지스트리: ID → 이름 매핑
// ─────────────────────────────────────────────────────────────────────────────
static const std::map<int, std::string> PATTERN_REGISTRY = {
    {1, "CWE-190 Integer Overflow"},
    {2, "CWE-193 Boundary Condition Error"},
    {3, "CWE-390 Detection of Error Condition Without Action"},
    {4, "CWE-401 Memory Leak"},
    {5, "CWE-476 NULL Pointer Dereference"},
    {6, "CWE-682 Incorrect Calculation"},
    {7, "CWE-416 Use After Free (UAF)"},
    {8, "CWE-125/787 Out-of-bounds Access"},
    {9, "CWE-457 Uninitialized Variable"},
    {10, "CWE-369 Divide By Zero"},
    {11, "CWE-835 Infinite Loop (Hang)"},
    {12, "CWE-131 Missing sizeof in memcpy"},
    {13, "CWE-134 Uncontrolled Format String"},
    {14, "CWE-415 Double Free (Copy-Paste Error)"},
};

// JSON 이스케이프 헬퍼
std::string escapeJSON(const std::string& input) {
    std::string output;
    for (char c : input) {
        if      (c == '"')  output += "\\\"";
        else if (c == '\\') output += "\\\\";
        else if (c == '\b') output += "\\b";
        else if (c == '\f') output += "\\f";
        else if (c == '\n') output += "\\n";
        else if (c == '\r') output += "\\r";
        else if (c == '\t') output += "\\t";
        else                output += c;
    }
    return output;
}

struct MutationResult {
    int    pattern_id;
    std::string pattern_name;
    std::string status;
};

class FaultInjectionCallback : public MatchFinder::MatchCallback {
public:
    FaultInjectionCallback(Rewriter& R, std::vector<MutationResult>& log, int targetPatternId)
        : Rewrite(R), mutations_log(log), targetPatternId(targetPatternId) {}

    void setContext(ASTContext* C) { Context = C; }

    std::string getExprString(const Expr* E) {
        if (!E || !Context) return "";
        SourceRange sr = E->getSourceRange();
        return Lexer::getSourceText(CharSourceRange::getTokenRange(sr), Context->getSourceManager(), Context->getLangOpts()).str();
    }

    void run(const MatchFinder::MatchResult& Result) override {
        // [New] Check TargetFunc filter
        if (!TargetFunc.empty()) {
            if (const FunctionDecl* FD = Result.Nodes.getNodeAs<FunctionDecl>("parent_func")) {
                if (FD->getNameAsString() != TargetFunc) {
                    return; // Skip if not inside the target function
                }
            } else {
                return; // Skip if no parent_func bound
            }
        }

        // ── [T10] CWE-190: 정수 오버플로우 (타입 캐스팅 축소) 주입 ──────────────────────
        if (targetPatternId == 0 || targetPatternId == 1) {
            // 위 Step 1에서 수정한 바인딩 이름("cwe190_mul")으로 노드를 가져옵니다.
            if (const BinaryOperator* BinOp =
                    Result.Nodes.getNodeAs<clang::BinaryOperator>("cwe190")) {
                
                // 연산자가 곱셈(BO_Mul)인지 확인
                if (BinOp->getOpcode() == BO_Mul) {
                    std::string lhs = getExprString(BinOp->getLHS());
                    std::string rhs = getExprString(BinOp->getRHS());
                    
                    if (!lhs.empty() && !rhs.empty()) {
                        // 기존의 "A * B" 연산 전체를 "(short)(A * B)" 형태로 강제 캐스팅
                        // 메모리 할당 크기 등을 계산할 때 값이 잘려나가 음수가 되거나 작아지게 만듦
                        std::string mutatedExpr = "(short)(" + lhs + " * " + rhs + ")";
                        
                        Rewrite.ReplaceText(
                            BinOp->getSourceRange(),
                            mutatedExpr
                        );
                        
                        mutations_log.push_back({1, "CWE-190 Integer Overflow (Truncation)", "injected"});
                    }
                }
            }
        }

        // ── [T10] CWE-193: 루프 언더-이터레이션 (마지막 원소 처리 누락) ─────────────
        // RHS만 '(RHS) - 1'로 교체하여 좌항 및 루프 구문 손상 방지
        if (targetPatternId == 0 || targetPatternId == 2) {
            if (const BinaryOperator* BinOp =
                    Result.Nodes.getNodeAs<clang::BinaryOperator>("cwe193")) {
                if (BinOp->getOpcode() == BO_LT || BinOp->getOpcode() == BO_LE) {
                    if (const Expr* RHS = BinOp->getRHS()) {
                        std::string rhs = getExprString(RHS);
                        if (!rhs.empty()) {
                            Rewrite.ReplaceText(RHS->getSourceRange(), "(" + rhs + ") - 1");
                            mutations_log.push_back({2, "CWE-193 Boundary Condition Error (Under-iteration)", "injected"});
                        }
                    }
                }
            }
        }

        // ── [교묘한 버전] CWE-390: 예외 처리 누락 (throw 무력화) ───────────
        if (targetPatternId == 0 || targetPatternId == 3) {
            if (const CXXThrowExpr* ThrowExpr = Result.Nodes.getNodeAs<CXXThrowExpr>("cwe390_throw")) {
                Rewrite.ReplaceText(ThrowExpr->getSourceRange(), "/* throw ignored for debugging */");
                mutations_log.push_back({3, "CWE-390 Detection of Error Condition Without Action (Throw Ignored)", "injected"});
            }
        }
        
        // ── CWE-401: 메모리 누수 ───────────────────────────
        if (targetPatternId == 0 || targetPatternId == 4) {
            if (const CXXDeleteExpr* DelExpr = Result.Nodes.getNodeAs<CXXDeleteExpr>("cwe401_delete")) {
                std::string ptrName = getExprString(DelExpr->getArgument());
                corrupted_pointers.insert(ptrName);
                Rewrite.ReplaceText(DelExpr->getSourceRange(), "/* CWE-401: delete skipped */");
                mutations_log.push_back({4, "CWE-401 Memory Leak", "injected"});
            }
            else if (const CallExpr* FreeCall = Result.Nodes.getNodeAs<CallExpr>("cwe401_free")) {
                std::string ptrName = getExprString(FreeCall->getArg(0));
                corrupted_pointers.insert(ptrName);
                Rewrite.ReplaceText(FreeCall->getSourceRange(), "/* CWE-401: free skipped */");
                mutations_log.push_back({4, "CWE-401 Memory Leak", "injected"});
            }
        }

        // ── [교묘한 버전] CWE-476: NULL 포인터 역참조 (방어 로직 반전) ───────────
        if (targetPatternId == 0 || targetPatternId == 5) {
            if (const BinaryOperator* BinOp = Result.Nodes.getNodeAs<BinaryOperator>("cwe476_cond")) {
                if (BinOp->getOpcode() == BO_EQ) {
                    Rewrite.ReplaceText(BinOp->getOperatorLoc(), 2, "!=");
                } else if (BinOp->getOpcode() == BO_NE) {
                    Rewrite.ReplaceText(BinOp->getOperatorLoc(), 2, "==");
                }
                mutations_log.push_back({5, "CWE-476 NULL Pointer Dereference (Inverted Logic)", "injected"});
            }
        }

        // ── CWE-682: 논리/비트 연산자 혼동 (크래시 없는 시맨틱 오류만) ──────────────
        if (targetPatternId == 0 || targetPatternId == 6) {
            if (const BinaryOperator* BinOp = Result.Nodes.getNodeAs<BinaryOperator>("cwe682")) {
                std::string rep = "";
                unsigned opLen = BinOp->getOpcodeStr().size();
                if      (BinOp->getOpcode() == BO_LAnd) { rep = "&";  }  // && → &
                else if (BinOp->getOpcode() == BO_LOr)  { rep = "|";  }  // || → |
                else if (BinOp->getOpcode() == BO_And)  { rep = "&&"; }  // & → &&
                else if (BinOp->getOpcode() == BO_Or)   { rep = "||"; }  // | → ||

                if (!rep.empty()) {
                    Rewrite.ReplaceText(BinOp->getOperatorLoc(), opLen, rep);
                    mutations_log.push_back({6, "CWE-682 Incorrect Calculation (Logic/Bitwise Swap)", "injected"});
                }
            }
        }

        // ── [자연스러운 버전] CWE-416: Use After Free (Dangling Pointer 유발) ──────────
        if (targetPatternId == 0 || targetPatternId == 7) {
            if (const BinaryOperator* NullAssign = Result.Nodes.getNodeAs<BinaryOperator>("cwe416_null_assign")) {
                std::string ptrName = getExprString(NullAssign->getLHS());
                if (corrupted_pointers.find(ptrName) != corrupted_pointers.end()) {
                    return; // 이미 오염된 포인터면 주입 생략
                }

                Rewrite.ReplaceText(NullAssign->getSourceRange(), "/* Forgot to nullify pointer */");
                mutations_log.push_back({7, "CWE-416 Use After Free (Missing Null Assignment)", "injected"});
            }
        }

        // ── [수정] CWE-125/787: OOB (할당 크기 축소) 주입 ───────────────────
        if (targetPatternId == 0 || targetPatternId == 8) {
            if (const CXXNewExpr* NewExpr = Result.Nodes.getNodeAs<CXXNewExpr>("cwe_oob_alloc")) {
                if (const Expr* ArraySizeExpr = NewExpr->getArraySize().value_or(nullptr)) {
                    std::string sizeStr = getExprString(ArraySizeExpr);
                    if (!sizeStr.empty()) {
                        std::string mutatedSize = "(" + sizeStr + ") - 1";
                        Rewrite.ReplaceText(ArraySizeExpr->getSourceRange(), mutatedSize);
                        mutations_log.push_back({8, "CWE-125/787 OOB (Buffer Under-allocation)", "injected"});
                    }
                }
            }
        }

        // ── [교묘한 버전] CWE-457: 초기화 누락 주입 (쓰레기값 시뮬레이션) ───
        if (targetPatternId == 0 || targetPatternId == 9) {
            if (const VarDecl* VD = Result.Nodes.getNodeAs<VarDecl>("cwe457_decl")) {
                if (const Expr* Init = VD->getInit()) {
                    // 초기화 표현식 '0'을 쓰레기값(Garbage value)으로 치환
                    Rewrite.ReplaceText(Init->getSourceRange(), "(int)0xCCCCCCCC");
                    mutations_log.push_back({9, "CWE-457 Uninitialized Variable (Garbage Value)", "injected"});
                }
            }
        }

        // ── [수정] CWE-369: 0으로 나누기 (방어 조건 확장) 주입 ──────────
        if (targetPatternId == 0 || targetPatternId == 10) {
            if (const BinaryOperator* CondOp = Result.Nodes.getNodeAs<BinaryOperator>("cwe369_cond")) {
                Rewrite.ReplaceText(CondOp->getOperatorLoc(), 2, ">=");
                mutations_log.push_back({10, "CWE-369 Divide By Zero (Guard Over-broadening)", "injected"});
            }
        }

        // ── [수정] CWE-835: 루프 스킵 주입 (증감식 2배속) ──────────
        if (targetPatternId == 0 || targetPatternId == 11) {
            if (const Expr* IncExpr = Result.Nodes.getNodeAs<Expr>("cwe835_inc")) {
                std::string incStr = getExprString(IncExpr);
                if (!incStr.empty()) {
                    std::string varName = incStr;
                    if (varName.size() >= 2 && varName.substr(varName.size()-2) == "++")
                        varName = varName.substr(0, varName.size()-2);
                    else if (varName.size() >= 2 && varName.substr(0, 2) == "++")
                        varName = varName.substr(2);
                    while (!varName.empty() && varName[0] == ' ') varName = varName.substr(1);
                    while (!varName.empty() && varName.back() == ' ') varName.pop_back();

                    std::string replacement = varName.empty() ? incStr + ", " + incStr : varName + " += 2";
                    Rewrite.ReplaceText(IncExpr->getSourceRange(), replacement);
                    mutations_log.push_back({11, "CWE-835 Loop Skip (Step-2 Increment)", "injected"});
                }
            }
        }

        // ── [검증 완료] CWE-131: 메모리 복사 크기 오류 주입 ───────────────────────
        if (targetPatternId == 0 || targetPatternId == 12) {
            if (const BinaryOperator* BinOp = Result.Nodes.getNodeAs<BinaryOperator>("cwe131_binop")) {
                std::string lhsStr = getExprString(BinOp->getLHS());
                std::string rhsStr = getExprString(BinOp->getRHS());
                if (rhsStr.find("sizeof") != std::string::npos) {
                    Rewrite.ReplaceText(BinOp->getSourceRange(), lhsStr);
                    mutations_log.push_back({12, "CWE-131 Missing sizeof in memcpy", "injected"});
                } else if (lhsStr.find("sizeof") != std::string::npos) {
                    Rewrite.ReplaceText(BinOp->getSourceRange(), rhsStr);
                    mutations_log.push_back({12, "CWE-131 Missing sizeof in memcpy", "injected"});
                }
            }
        }

        // ── [검증 완료] CWE-134: 통제되지 않은 포맷 스트링 주입 ──────────
        if (targetPatternId == 0 || targetPatternId == 13) {
            if (const CallExpr* Call = Result.Nodes.getNodeAs<CallExpr>("cwe134_call")) {
                std::string callStr = getExprString(Call);
                size_t pos = callStr.find("\"%s\", ");
                if (pos != std::string::npos) {
                    callStr.replace(pos, 6, ""); 
                    Rewrite.ReplaceText(Call->getSourceRange(), callStr);
                    mutations_log.push_back({13, "CWE-134 Uncontrolled Format String", "injected"});
                }
            }
        }

        // ── [수정] CWE-415: Null-After-Free 누락 주입 ──────────
        if (targetPatternId == 0 || targetPatternId == 14) {
            if (const CXXDeleteExpr* DelExpr = Result.Nodes.getNodeAs<CXXDeleteExpr>("cwe415_delete")) {
                std::string ptrName = getExprString(DelExpr->getArgument());
                if (corrupted_pointers.find(ptrName) == corrupted_pointers.end()) {
                    corrupted_pointers.insert(ptrName);
                    std::string delStr = getExprString(DelExpr);
                    if (!delStr.empty()) {
                        Rewrite.ReplaceText(DelExpr->getSourceRange(),
                                            delStr + " /* CWE-415: dangling */");
                        mutations_log.push_back({14, "CWE-415 Double Free (Missing nullptr Reset)", "injected"});
                    }
                }
            }
        }

        
    }

private:
    Rewriter& Rewrite;
    std::vector<MutationResult>& mutations_log;
    ASTContext* Context = nullptr;
    int targetPatternId;

    // 💡 마스킹 방지를 위한 블랙리스트 추가
    std::set<std::string> corrupted_pointers;
};

// ─────────────────────────────────────────────────────────────────────────────
// ASTConsumer — 매처 등록
// ─────────────────────────────────────────────────────────────────────────────
class MyASTConsumer : public ASTConsumer {
public:
    MyASTConsumer(Rewriter& R, std::vector<MutationResult>& log, int patternId)
        : Callback(R, log, patternId) {

        bool all = (patternId == 0);

        if (all || patternId == 1) {
            Finder.addMatcher(
                binaryOperator(isExpansionInMainFile(),
                               hasOperatorName("*"),
                               hasAncestor(declStmt()), // 💡 선언문 내부의 곱셈만 타겟팅 (추가)
                               hasAncestor(functionDecl().bind("parent_func"))).bind("cwe190"), // 바인딩 이름 수정 반영
                &Callback);
        }

        if (all || patternId == 2) {
            Finder.addMatcher(
                binaryOperator(isExpansionInMainFile(),
                               anyOf(hasOperatorName("<"), hasOperatorName("<=")),
                               hasAncestor(forStmt(hasAncestor(functionDecl().bind("parent_func"))))).bind("cwe193"),
                &Callback);
        }

        // ── [교묘한 버전] CWE-390: 예외 처리 누락 (throw 문 찾기) ───────────
        if (all || patternId == 3) {
            Finder.addMatcher(
                cxxThrowExpr(isExpansionInMainFile(),
                             hasAncestor(functionDecl().bind("parent_func"))).bind("cwe390_throw"),
                &Callback);
        }

        if (all || patternId == 4) {
            Finder.addMatcher(
                cxxDeleteExpr(isExpansionInMainFile(),
                              hasAncestor(functionDecl().bind("parent_func"))).bind("cwe401_delete"),
                &Callback);
            Finder.addMatcher(
                callExpr(isExpansionInMainFile(),
                         callee(functionDecl(hasName("free"))),
                         hasAncestor(functionDecl().bind("parent_func"))).bind("cwe401_free"),
                &Callback);
        }

        // ── [교묘한 버전] CWE-476: NULL 포인터 방어 로직 탐색 ───────────
        if (all || patternId == 5) {
            Finder.addMatcher(
                // if문 안에서 nullptr과 == 또는 != 로 비교하는 로직 찾기
                binaryOperator(isExpansionInMainFile(),
                               anyOf(hasOperatorName("=="), hasOperatorName("!=")),
                               hasEitherOperand(ignoringParenImpCasts(cxxNullPtrLiteralExpr())),
                               hasAncestor(ifStmt()),
                               hasAncestor(functionDecl().bind("parent_func"))).bind("cwe476_cond"),
                &Callback);
        }

        if (all || patternId == 6) {
            Finder.addMatcher(
                binaryOperator(isExpansionInMainFile(),
                               // 크래시 없는 논리↔비트 교체만 허용 (%, / 제거 — SIGFPE 위험)
                               anyOf(hasOperatorName("&&"), hasOperatorName("||"),
                                     hasOperatorName("&"),  hasOperatorName("|")),
                               hasAncestor(ifStmt()),
                               hasAncestor(functionDecl().bind("parent_func"))).bind("cwe682"),
                &Callback);
        }

        // ── [추가] CWE-416: Use After Free 탐색 (nullptr 할당문 찾기) ────────────────────────
        if (all || patternId == 7) {
            Finder.addMatcher(
                binaryOperator(isExpansionInMainFile(),
                               hasOperatorName("="),
                               hasRHS(cxxNullPtrLiteralExpr()), // 우항이 nullptr인 경우
                               hasAncestor(functionDecl().bind("parent_func"))).bind("cwe416_null_assign"),
                &Callback);
        }

        // ── [수정] CWE-125/787: OOB (할당 크기 축소) 탐색 ──────────────────
        if (all || patternId == 8) {
            // C++의 'new Type[size]' 형태의 배열 동적 할당 구문을 찾음
            Finder.addMatcher(
                cxxNewExpr(isExpansionInMainFile(),
                           isArray(), // 단일 객체가 아닌 배열 할당인지 확인
                           hasAncestor(functionDecl().bind("parent_func"))).bind("cwe_oob_alloc"),
                &Callback);
        }

        // ── [CWE-457 매처 핵심 수정] = 0 상수 초기화 변수만 타겟 ──────────
        // 문제: hasInitializer(expr())는 'int size = (val%7)+1' 같은 표현식도 매칭
        //   → 쓰레기 size → fill_array(쓰레기) → OOB → SIGSEGV → 생존률 ~6%
        // 수정: integerLiteral(equals(0)) → 'int result = 0;', 'int count = 0;' 등
        //       상수 0 초기화만 타겟. 'int size = expr;' 절대 불변
        if (all || patternId == 9) {
            Finder.addMatcher(
                varDecl(isExpansionInMainFile(),
                        hasType(isInteger()),
                        hasInitializer(ignoringImplicit(integerLiteral(equals(0)))),
                        unless(hasAncestor(forStmt())), // for 루프 변수(int i = 0)는 제외
                        hasAncestor(functionDecl().bind("parent_func"))).bind("cwe457_decl"),
                &Callback);
        }

        // ── [수정] CWE-369: 0으로 나누기 (방어문 == 오타 유발) 탐색 ──────────
        if (all || patternId == 10) {
            Finder.addMatcher(
                ifStmt(isExpansionInMainFile(),
                       hasCondition(
                           // 조건식 안에 '== 0' 또는 '0 ==' 이 있는지 탐색
                           binaryOperator(hasOperatorName("=="),
                                          hasEitherOperand(integerLiteral(equals(0)))).bind("cwe369_cond")
                       ),
                       hasAncestor(functionDecl().bind("parent_func"))).bind("cwe369_if"),
                &Callback);
        }

        // ── [추가] CWE-835: 무한 루프 탐색 (for문의 증감식 부분) ──────────
        if (all || patternId == 11) {
            Finder.addMatcher(
                forStmt(isExpansionInMainFile(),
                        hasIncrement(expr().bind("cwe835_inc")), // for(int i=0; i<10; i++) 에서 i++ 부분
                        hasAncestor(functionDecl().bind("parent_func"))).bind("cwe835_loop"),
                &Callback);
        }

        // ── [추가] CWE-131: memcpy/memset의 3번째 인자에서 곱셈 연산 찾기 ──────────
        if (all || patternId == 12) {
            Finder.addMatcher(
                callExpr(isExpansionInMainFile(),
                         callee(functionDecl(hasAnyName("memcpy", "memset", "memmove"))),
                         hasArgument(2, binaryOperator(hasOperatorName("*")).bind("cwe131_binop")),
                         hasAncestor(functionDecl().bind("parent_func"))).bind("cwe131_call"),
                &Callback);
        }

        // ── [추가] CWE-134: 포맷 스트링 출력 함수 찾기 ──────────
        if (all || patternId == 13) {
            Finder.addMatcher(
                callExpr(isExpansionInMainFile(),
                         callee(functionDecl(hasAnyName("printf", "fprintf", "sprintf"))),
                         hasAncestor(functionDecl().bind("parent_func"))).bind("cwe134_call"),
                &Callback);
        }

        // ── [추가] CWE-415: 이중 해제를 위한 정상적인 delete 구문 찾기 ──────────
        if (all || patternId == 14) {
            Finder.addMatcher(
                cxxDeleteExpr(isExpansionInMainFile(),
                              hasAncestor(functionDecl().bind("parent_func"))).bind("cwe415_delete"),
                &Callback);
        }
    
        
    }

    void HandleTranslationUnit(ASTContext& Context) override {
        Callback.setContext(&Context);
        Finder.matchAST(Context);
    }

private:
    MatchFinder Finder;
    FaultInjectionCallback Callback;
};

// ─────────────────────────────────────────────────────────────────────────────
// FrontendAction
// ─────────────────────────────────────────────────────────────────────────────
class RewriteAction : public ASTFrontendAction {
public:
    RewriteAction(std::vector<MutationResult>& log, std::string& outCode, int patternId)
        : mutations_log(log), mutated_code(outCode), patternId(patternId) {}

    void EndSourceFileAction() override {
        SourceManager& SM = TheRewriter.getSourceMgr();
        llvm::StringRef mainBuf = SM.getBufferData(SM.getMainFileID());
        const RewriteBuffer* RB = TheRewriter.getRewriteBufferFor(SM.getMainFileID());
        mutated_code = RB ? std::string(RB->begin(), RB->end()) : mainBuf.str();
    }

    std::unique_ptr<ASTConsumer>
    CreateASTConsumer(CompilerInstance& CI, StringRef) override {
        TheRewriter.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
        return std::make_unique<MyASTConsumer>(TheRewriter, mutations_log, patternId);
    }

private:
    Rewriter TheRewriter;
    std::vector<MutationResult>& mutations_log;
    std::string& mutated_code;
    int patternId;
};

class MyFactory : public FrontendActionFactory {
public:
    MyFactory(std::vector<MutationResult>& log, std::string& outCode, int patternId)
        : mutations_log(log), mutated_code(outCode), patternId(patternId) {}

    std::unique_ptr<FrontendAction> create() override {
        return std::make_unique<RewriteAction>(mutations_log, mutated_code, patternId);
    }

private:
    std::vector<MutationResult>& mutations_log;
    std::string& mutated_code;
    int patternId;
};

// ─────────────────────────────────────────────────────────────────────────────
// [T11] 변조 코드 재컴파일
// ─────────────────────────────────────────────────────────────────────────────
bool recompileMutant(const std::string& mutatedCode, std::string& outBinaryPath) {
    // 임시 소스 파일 생성
    char tmpSrc[] = "/tmp/faf_mutant_XXXXXX.cpp";
    int fd = mkstemps(tmpSrc, 4);
    if (fd < 0) return false;

    if (write(fd, mutatedCode.c_str(), mutatedCode.size()) < 0) {
        close(fd);
        return false;
    }
    close(fd);

    // 출력 바이너리 경로
    outBinaryPath = std::string(tmpSrc) + "_bin";

    // clang++ 재컴파일
    std::string cmd = "clang++-16 -std=c++17 -o " + outBinaryPath + " " + tmpSrc + " 2>/dev/null";
    int ret = std::system(cmd.c_str());
    return (ret == 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// [US-04] Z3 SMT 제약 풀이 (타임아웃 포함)
// ─────────────────────────────────────────────────────────────────────────────
void solveConstraintWithTimeout() {
    try {
        z3::context c;
        z3::solver  s(c);
        z3::params  p(c);
        p.set("timeout", 3000u);   // 3초 Z3 타임아웃
        s.set(p);
        // TODO: 실제 경로 도달 가능성 제약식 추가
        if (s.check() == z3::sat) { /* sat */ }
    } catch (z3::exception& ex) {
        std::cerr << "[Z3] Exception: " << ex.msg() << std::endl;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MutationEngine 메인 클래스
// ─────────────────────────────────────────────────────────────────────────────
class MutationEngine {
public:
    int runTool(int argc, const char** argv) {
        auto ExpectedParser = CommonOptionsParser::create(argc, argv, FindAndFixMeCategory);
        if (!ExpectedParser) {
            llvm::errs() << ExpectedParser.takeError();
            return 1;
        }
        CommonOptionsParser& OP = ExpectedParser.get();
        ClangTool Tool(OP.getCompilations(), OP.getSourcePathList());

        int patternId = PatternId.getValue();
        int timeoutSec = AstTimeout.getValue();

        // [T10] 패턴 ID 유효성 검사
        if (patternId != 0 && PATTERN_REGISTRY.find(patternId) == PATTERN_REGISTRY.end()) {
            outputError("Invalid pattern-id: " + std::to_string(patternId) +
                        ". Must be 0 (all) or 1~15.");
            return 1;
        }

        std::vector<MutationResult> mutations_log;
        std::string mutated_code;

        // [T8] std::future + std::async 으로 ClangTool 타임아웃 적용
        MyFactory Factory(mutations_log, mutated_code, patternId);

        auto future = std::async(std::launch::async, [&]() -> int {
            return Tool.run(&Factory);
        });

        auto status = future.wait_for(std::chrono::seconds(timeoutSec));
        if (status == std::future_status::timeout) {
            outputError("AST parsing timed out after " + std::to_string(timeoutSec) + "s.");
            return 1;
        }
        int toolResult = future.get();
        if (toolResult != 0) {
            outputError("ClangTool failed with code " + std::to_string(toolResult));
            return 1;
        }

        // Z3 제약 풀이
        solveConstraintWithTimeout();

        // [T11] 재컴파일
        std::string mutant_binary_path;
        bool recompiled = recompileMutant(mutated_code, mutant_binary_path);

        // JSON 출력
        std::cout << "{";
        std::cout << "\"status\": \"success\", ";
        std::cout << "\"pattern_id\": " << patternId << ", ";

        if (patternId != 0 && PATTERN_REGISTRY.count(patternId))
            std::cout << "\"pattern_name\": \"" << PATTERN_REGISTRY.at(patternId) << "\", ";

        std::cout << "\"recompiled\": " << (recompiled ? "true" : "false") << ", ";
        std::cout << "\"mutant_binary\": \"" << escapeJSON(mutant_binary_path) << "\", ";

        std::cout << "\"mutations\": [";
        for (size_t i = 0; i < mutations_log.size(); ++i) {
            std::cout << "{"
                      << "\"pattern_id\": " << mutations_log[i].pattern_id << ", "
                      << "\"pattern_name\": \"" << mutations_log[i].pattern_name << "\", "
                      << "\"status\": \"" << mutations_log[i].status << "\""
                      << "}";
            if (i + 1 < mutations_log.size()) std::cout << ", ";
        }
        std::cout << "], ";

        std::cout << "\"mutated_code\": \"" << escapeJSON(mutated_code) << "\"";
        std::cout << "}" << std::endl;

        return 0;
    }

private:
    void outputError(const std::string& msg) {
        std::cout << "{\"status\": \"error\", \"message\": \""
                  << escapeJSON(msg) << "\"}" << std::endl;
    }
};

int main(int argc, const char** argv) {
    MutationEngine engine;
    return engine.runTool(argc, argv);
}
