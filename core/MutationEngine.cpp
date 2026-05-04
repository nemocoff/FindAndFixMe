#include <iostream>
#include <string>
#include <vector>
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

// CWE-190 & CWE-193 MatchCallback
class FaultInjectionCallback : public MatchFinder::MatchCallback {
private:
    Rewriter &Rewrite;
    std::vector<std::string> &mutations_log;

public:
    FaultInjectionCallback(Rewriter &R, std::vector<std::string> &log) : Rewrite(R), mutations_log(log) {}

    virtual void run(const MatchFinder::MatchResult &Result) override {
        ASTContext *Context = Result.Context;
        const SourceManager &SM = Context->getSourceManager();

        // CWE-190: Integer Overflow (e.g. change + to result in INT_MAX + 1)
        if (const BinaryOperator *BinOp = Result.Nodes.getNodeAs<clang::BinaryOperator>("cwe190")) {
            if (BinOp->getOpcode() == BO_Add) {
                // Draft Mutation: Replace entire expression with a boundary violation
                SourceRange range = BinOp->getSourceRange();
                Rewrite.ReplaceText(range, "2147483647 + 1 /* Injected CWE-190 */");
                mutations_log.push_back("{\"pattern_id\": 1, \"pattern_name\": \"CWE-190 Integer Overflow\", \"status\": \"injected\"}");
            }
        }
        
        // CWE-193: Off-by-one / Boundary Condition (e.g. change < to <=)
        if (const BinaryOperator *BinOp = Result.Nodes.getNodeAs<clang::BinaryOperator>("cwe193")) {
            if (BinOp->getOpcode() == BO_LT) { // '<'
                SourceLocation opLoc = BinOp->getOperatorLoc();
                Rewrite.ReplaceText(opLoc, 1, "<=");
                mutations_log.push_back("{\"pattern_id\": 2, \"pattern_name\": \"CWE-193 Boundary Condition Error\", \"status\": \"injected\"}");
            } else if (BinOp->getOpcode() == BO_LE) { // '<='
                SourceLocation opLoc = BinOp->getOperatorLoc();
                Rewrite.ReplaceText(opLoc, 2, "<");
                mutations_log.push_back("{\"pattern_id\": 2, \"pattern_name\": \"CWE-193 Boundary Condition Error\", \"status\": \"injected\"}");
            }
        }
    }
};

class MutationEngine {
private:
    void solveConstraintWithTimeout() {
        try {
            z3::context c;
            z3::solver s(c);
            z3::params p(c);
            p.set("timeout", 3000u); // 3 seconds timeout
            s.set(p);
            
            // Example Z3 logic...
            if (s.check() == z3::sat) {
                // Solvable
            }
        } catch (z3::exception &ex) {
            std::cerr << "Z3 Exception: " << ex.msg() << std::endl;
        }
    }

public:
    int runTool(int argc, const char **argv) {
        auto ExpectedParser = CommonOptionsParser::create(argc, argv, FindAndFixMeCategory);
        if (!ExpectedParser) {
            llvm::errs() << ExpectedParser.takeError();
            return 1;
        }
        CommonOptionsParser &OptionsParser = ExpectedParser.get();
        ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

        std::vector<std::string> mutations_log;
        
        // Setup Matchers
        MatchFinder Finder;
        
        // CWE-190 Matcher: Integer Addition
        StatementMatcher CWE190Matcher = binaryOperator(hasOperatorName("+"), hasType(isInteger())).bind("cwe190");
        
        // CWE-193 Matcher: Loop conditions < or <=
        StatementMatcher CWE193Matcher = binaryOperator(anyOf(hasOperatorName("<"), hasOperatorName("<=")), hasParent(forStmt())).bind("cwe193");

        // Factory to run action and apply rewriting
        class RewriteAction : public ASTFrontendAction {
        private:
            MatchFinder &Finder;
            FaultInjectionCallback *Callback;
            Rewriter TheRewriter;
        public:
            RewriteAction(MatchFinder &F, FaultInjectionCallback *CB) : Finder(F), Callback(CB) {}
            
            void EndSourceFileAction() override {
                // Here we could output the rewritten code, but for now we just log
                // TheRewriter.getEditBuffer(TheRewriter.getSourceMgr().getMainFileID()).write(llvm::outs());
            }

            std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef file) override {
                TheRewriter.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
                // Link Rewriter to Callback
                *Callback = FaultInjectionCallback(TheRewriter, Callback->mutations_log);
                return Finder.newASTConsumer();
            }
        };

        // Dummy Rewriter just for initialization
        Rewriter dummy;
        FaultInjectionCallback Callback(dummy, mutations_log);
        Finder.addMatcher(CWE190Matcher, &Callback);
        Finder.addMatcher(CWE193Matcher, &Callback);

        // Run Tool
        Tool.run(newFrontendActionFactory(&Finder).get()); // Note: Usually requires custom factory for passing Rewriter, simplified here.

        // Z3 Solver call example
        solveConstraintWithTimeout();

        // Output JSON Result
        std::cout << "{\"status\": \"success\", \"mutations\": [";
        for (size_t i = 0; i < mutations_log.size(); ++i) {
            std::cout << mutations_log[i] << (i < mutations_log.size() - 1 ? ", " : "");
        }
        std::cout << "]}" << std::endl;

        return 0;
    }
};

int main(int argc, const char **argv) {
    MutationEngine engine;
    return engine.runTool(argc, argv);
}
