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

        // ── [T10] CWE-190: 정수 덧셈 오버플로우 주입 ──────────────────────
        if (targetPatternId == 0 || targetPatternId == 1) {
            if (const BinaryOperator* BinOp =
                    Result.Nodes.getNodeAs<clang::BinaryOperator>("cwe190")) {
                if (BinOp->getOpcode() == BO_Add) {
                    std::string lhs = getExprString(BinOp->getLHS());
                    std::string rhs = getExprString(BinOp->getRHS());
                    if (!lhs.empty() && !rhs.empty()) {
                        Rewrite.ReplaceText(
                            BinOp->getSourceRange(),
                            lhs + " + " + rhs + " + 1"
                        );
                    } else {
                        Rewrite.ReplaceText(
                            BinOp->getSourceRange(),
                            "1"
                        );
                    }
                    mutations_log.push_back({1, "CWE-190 Integer Overflow", "injected"});
                }
            }
        }

        // ── [T10] CWE-193: 루프 경계 조건 반전 ───────────────────────────
        if (targetPatternId == 0 || targetPatternId == 2) {
            if (const BinaryOperator* BinOp =
                    Result.Nodes.getNodeAs<clang::BinaryOperator>("cwe193")) {
                if (BinOp->getOpcode() == BO_LT) {
                    Rewrite.ReplaceText(BinOp->getOperatorLoc(), 1, "<=");
                    mutations_log.push_back({2, "CWE-193 Boundary Condition Error", "injected"});
                } else if (BinOp->getOpcode() == BO_LE) {
                    Rewrite.ReplaceText(BinOp->getOperatorLoc(), 2, "<");
                    mutations_log.push_back({2, "CWE-193 Boundary Condition Error", "injected"});
                }
            }
        }

        // ── CWE-390: 예외 처리 누락 ───────────────────────────
        if (targetPatternId == 0 || targetPatternId == 3) {
            if (const CXXCatchStmt* Catch = Result.Nodes.getNodeAs<CXXCatchStmt>("cwe390_catch")) {
                if (const Stmt* Block = Catch->getHandlerBlock()) {
                    Rewrite.ReplaceText(Block->getSourceRange(), "{}");
                    mutations_log.push_back({3, "CWE-390 Detection of Error Condition Without Action", "injected"});
                }
            }
            else if (const IfStmt* If = Result.Nodes.getNodeAs<IfStmt>("cwe390_if")) {
                if (const Stmt* Then = If->getThen()) {
                    Rewrite.ReplaceText(Then->getSourceRange(), "{}");
                    mutations_log.push_back({3, "CWE-390 Detection of Error Condition Without Action", "injected"});
                }
            }
        }

        // ── CWE-401: 메모리 누수 ───────────────────────────
        if (targetPatternId == 0 || targetPatternId == 4) {
            if (const CXXDeleteExpr* DelExpr = Result.Nodes.getNodeAs<CXXDeleteExpr>("cwe401_delete")) {
                Rewrite.ReplaceText(DelExpr->getSourceRange(), ";");
                mutations_log.push_back({4, "CWE-401 Memory Leak", "injected"});
            }
            else if (const CallExpr* FreeCall = Result.Nodes.getNodeAs<CallExpr>("cwe401_free")) {
                Rewrite.ReplaceText(FreeCall->getSourceRange(), ";");
                mutations_log.push_back({4, "CWE-401 Memory Leak", "injected"});
            }
        }

        // ── CWE-476: NULL 포인터 역참조 ───────────────────────────
        if (targetPatternId == 0 || targetPatternId == 5) {
            if (const VarDecl* VD = Result.Nodes.getNodeAs<VarDecl>("cwe476_decl")) {
                if (const Expr* Init = Result.Nodes.getNodeAs<Expr>("cwe476_init")) {
                    Rewrite.ReplaceText(Init->getSourceRange(), "nullptr");
                    mutations_log.push_back({5, "CWE-476 NULL Pointer Dereference", "injected"});
                }
            } else if (const DeclStmt* DS = Result.Nodes.getNodeAs<DeclStmt>("cwe476_stmt")) {
                SourceLocation insertLoc = DS->getEndLoc().getLocWithOffset(1);
                Rewrite.InsertTextAfter(
                    insertLoc,
                    "\n*((int*)nullptr) = 0;"
                );
                mutations_log.push_back({5, "CWE-476 NULL Pointer Dereference", "injected"});
            }
        }

        // ── CWE-682: 논리 연산자 및 비트 연산자 혼동 및 연산 오류 ──────────────
        if (targetPatternId == 0 || targetPatternId == 6) {
            if (const BinaryOperator* BinOp = Result.Nodes.getNodeAs<BinaryOperator>("cwe682")) {
                std::string rep = "";
                unsigned opLen = BinOp->getOpcodeStr().size();
                if (BinOp->getOpcode() == BO_LAnd) { rep = "&"; }
                else if (BinOp->getOpcode() == BO_LOr) { rep = "|"; }
                else if (BinOp->getOpcode() == BO_And) { rep = "&&"; }
                else if (BinOp->getOpcode() == BO_Or) { rep = "||"; }
                else if (BinOp->getOpcode() == BO_Rem) { rep = "/"; }
                else if (BinOp->getOpcode() == BO_Div) { rep = "%"; }
                else if (BinOp->getOpcode() == BO_Mul) { rep = "+"; }
                
                if (!rep.empty()) {
                    Rewrite.ReplaceText(BinOp->getOperatorLoc(), opLen, rep);
                    mutations_log.push_back({6, "CWE-682 Incorrect Calculation", "injected"});
                }
            }
        }
    }

private:
    Rewriter& Rewrite;
    std::vector<MutationResult>& mutations_log;
    ASTContext* Context = nullptr;
    int targetPatternId;
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
                               hasOperatorName("+"),
                               unless(hasLHS(binaryOperator(hasOperatorName("+")))),
                               unless(hasRHS(binaryOperator(hasOperatorName("+")))),
                               hasAncestor(functionDecl().bind("parent_func"))).bind("cwe190"),
                &Callback);
        }

        if (all || patternId == 2) {
            Finder.addMatcher(
                binaryOperator(isExpansionInMainFile(),
                               anyOf(hasOperatorName("<"), hasOperatorName("<=")),
                               hasAncestor(forStmt(hasAncestor(functionDecl().bind("parent_func"))))).bind("cwe193"),
                &Callback);
        }

        if (all || patternId == 3) {
            Finder.addMatcher(
                cxxCatchStmt(isExpansionInMainFile(),
                             hasAncestor(functionDecl().bind("parent_func"))).bind("cwe390_catch"),
                &Callback);
            Finder.addMatcher(
                ifStmt(isExpansionInMainFile(),
                       hasThen(stmt(anyOf(
                           returnStmt(),
                           callExpr(callee(functionDecl(hasAnyName("abort", "exit")))),
                           compoundStmt(hasAnySubstatement(anyOf(
                               returnStmt(),
                               callExpr(callee(functionDecl(hasAnyName("abort", "exit"))))
                           )))
                       ))),
                       hasAncestor(functionDecl().bind("parent_func"))).bind("cwe390_if"),
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

        if (all || patternId == 5) {
            Finder.addMatcher(
                varDecl(isExpansionInMainFile(),
                        hasType(pointerType()),
                        hasInitializer(expr().bind("cwe476_init")),
                        hasAncestor(functionDecl().bind("parent_func"))).bind("cwe476_decl"),
                &Callback);
            Finder.addMatcher(
                declStmt(isExpansionInMainFile(),
                         containsDeclaration(0, varDecl(hasType(pointerType()))),
                         hasAncestor(functionDecl().bind("parent_func"))).bind("cwe476_stmt"),
                &Callback);
        }

        if (all || patternId == 6) {
            Finder.addMatcher(
                binaryOperator(isExpansionInMainFile(),
                               anyOf(hasOperatorName("&&"), hasOperatorName("||"),
                                     hasOperatorName("&"), hasOperatorName("|"),
                                     hasOperatorName("%"), hasOperatorName("/"),
                                     hasOperatorName("*")),
                               hasAncestor(functionDecl().bind("parent_func"))).bind("cwe682"),
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
                        ". Must be 0 (all) or 1~6.");
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
