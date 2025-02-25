#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <string>
#include <experimental/filesystem> // For Clang 10/17 compatibility
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <mutex>

#include <clang/AST/AST.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/CommandLine.h>
#include <clang/Basic/SourceLocation.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Analysis/CFG.h>
#include <clang/Analysis/Analyses/Dominators.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Type.h>
#include <llvm/Support/raw_ostream.h>

using json = nlohmann::json;
using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
namespace fs = std::experimental::filesystem; // Change to std::filesystem if fully supported

static llvm::cl::OptionCategory ToolingSampleCategory("My Tooling Sample Options");

// Change this path to where you want the JSON outputs to be stored.
const std::string OUTPUT_FOLDER = "/mnt/linuxstorage/vlsi-open-source-tool/output";

// Global set to track visited types and avoid infinite recursion in getSafeTypeSize.
static std::unordered_set<const Type*> globalSeenTypes;
static thread_local unsigned RecursionDepth = 0;
static const unsigned MAX_RECURSION_DEPTH = 16;  // Reduced to 16 for stack safety

// Add mutex for globalSeenTypes
static std::mutex gTypeMutex;

unsigned long long getSafeTypeSize(ASTContext &context, QualType qt) {
    // Immediate depth check before any processing
    if (RecursionDepth > MAX_RECURSION_DEPTH) {
        llvm::errs() << "[CRITICAL] Aborting deep recursion at depth " 
                    << RecursionDepth << " for type: "
                    << qt.getAsString() << "\n";
        return context.getTargetInfo().getPointerWidth(LangAS::Default) / 8;
    }
    ++RecursionDepth;

    if (qt.isNull()) {
        --RecursionDepth;
        return 0;
    }

    QualType canonicalQT = qt.getCanonicalType();
    const Type *rawType = canonicalQT.getTypePtrOrNull();
    if (!rawType) {
        --RecursionDepth;
        return 0;
    }

    // Enhanced cycle detection with thread-safe access
    {
        std::lock_guard<std::mutex> lock(gTypeMutex);
        if (globalSeenTypes.count(rawType)) {
            llvm::errs() << "[WARNING] Cyclic type detected at depth "
                        << RecursionDepth << ": " 
                        << qt.getAsString() << "\n";
            --RecursionDepth;
            return context.getTargetInfo().getPointerWidth(LangAS::Default) / 8;
        }
        globalSeenTypes.insert(rawType);
    }

    unsigned size = 0;
    try {
        // Validate type before size calculation
        if (canonicalQT->isSizelessType()) {
            llvm::errs() << "[WARNING] Unsized type: " 
                        << qt.getAsString() << "\n";
            throw std::runtime_error("Unsized type");
        }
        
        size = context.getTypeSize(qt) / 8;
    } catch (const std::exception& e) {
        llvm::errs() << "[ERROR] Size calculation failed for "
                    << qt.getAsString() << ": " << e.what() << "\n";
    }

    // Cleanup type tracking
    {
        std::lock_guard<std::mutex> lock(gTypeMutex);
        globalSeenTypes.erase(rawType);
    }
    
    --RecursionDepth;
    return size;
}

class LocalVariableCounter : public RecursiveASTVisitor<LocalVariableCounter> {
public:
    std::unordered_map<std::string, int> typeCount;
    unsigned long long stackSize = 0;
    int totalLocalCount = 0;
    ASTContext *Context;  // Add context reference

    bool VisitVarDecl(const VarDecl *v) {
        if (v->isLocalVarDecl() && !v->hasGlobalStorage()) {
            QualType varType = v->getType().getCanonicalType();
            
            // Apply the same safety checks as parameters
            if (varType.isNull() ||
                varType->isSizelessType() ||
                varType->isDependentType() ||
                varType->isIncompleteType()) {
                llvm::errs() << "[SKIPPED] Unanalyzable local variable type: " 
                            << varType.getAsString() << "\n";
                return true;
            }

            try {
                std::string typeName = varType.getAsString();
                typeCount[typeName]++;
                unsigned typeSize = getSafeTypeSize(*Context, varType);
                stackSize += typeSize;
                totalLocalCount++;
            } catch (const std::exception& e) {
                llvm::errs() << "[ERROR] Local variable analysis failed: " 
                            << e.what() << "\n";
            }
        }
        return true;
    }
};

class FunctionAnalyzer : public MatchFinder::MatchCallback {
public:
    std::vector<json> functionData;

    void run(const MatchFinder::MatchResult &Result) override {
        if (const FunctionDecl *FD = Result.Nodes.getNodeAs<FunctionDecl>("functionDecl")) {
            if (!FD->getLocation().isInvalid() && Result.SourceManager->isInMainFile(FD->getLocation())) {
                ASTContext &Context = *Result.Context; // Get context from match result
                
                json functionJson;
                functionJson["function_name"] = FD->getNameAsString();
                functionJson["number_of_parameters"] = FD->getNumParams();

                unsigned long long paramStackSize = 0;
                for (const auto *param : FD->parameters()) {
                    if (!param) continue;
                    QualType paramType = param->getType().getCanonicalType();
                    
                    // Comprehensive pre-checks
                    if (paramType.isNull() ||
                        paramType->isSizelessType() ||  // Critical check
                        paramType->isDependentType() ||
                        paramType->isIncompleteType()) {
                        llvm::errs() << "[SKIPPED] Unanalyzable parameter type: "
                                    << paramType.getAsString() << "\n";

                        continue;
                    }

                    try {
                        paramStackSize += getSafeTypeSize(Context, paramType);
                    } catch (const std::exception& e) {
                        llvm::errs() << "[FATAL] Aborted type analysis: "
                                    << e.what() << "\n";
                        break;  // Prevent further processing
                    }
                }
                functionJson["total_parameter_stack_size_bytes"] = paramStackSize;

                LocalVariableCounter LVC;
                LVC.Context = &Context;  // Set the context before traversal
                LVC.TraverseDecl(const_cast<FunctionDecl*>(FD));
                functionJson["total_local_variable_stack_size_bytes"] = LVC.stackSize;
                functionJson["total_local_variables"] = LVC.totalLocalCount;

                int meaningfulBlocks = 0;
                if (FD->hasBody()) {
                    if (auto cfg = CFG::buildCFG(FD, FD->getBody(), &FD->getASTContext(), CFG::BuildOptions())) {
                        for (const auto *block : *cfg) {
                            if (!block->empty() && block != &cfg->getEntry() && block != &cfg->getExit())
                                meaningfulBlocks++;
                        }
                    } else {
                        llvm::errs() << "Warning: Failed to build CFG for function " 
                                     << FD->getNameAsString() << "\n";
                    }
                }
                functionJson["number_of_meaningful_basic_blocks"] = meaningfulBlocks;
                functionJson["vector"] = {FD->getNumParams(), paramStackSize, LVC.stackSize, LVC.totalLocalCount, meaningfulBlocks};

                functionData.push_back(functionJson);
            }
        }
    }

    void saveResults(const std::string &filename) {
        fs::create_directories(OUTPUT_FOLDER);
        std::string outputPath = OUTPUT_FOLDER + "/" + filename;
        std::ofstream jsonFile(outputPath);
        if (!jsonFile.is_open()) {
            std::cerr << "Failed to open JSON file: " << outputPath << std::endl;
            return;
        }
        jsonFile << json(functionData).dump(4);
        jsonFile.close();
    }
};

std::vector<std::string> getSourceFilesFromCompileCommands(const std::string &compileCommandsPath) {
    std::vector<std::string> sources;
    std::ifstream jsonFile(compileCommandsPath);
    if (!jsonFile.is_open()) {
        std::cerr << "Failed to open " << compileCommandsPath << std::endl;
        return sources;
    }
    json compileCommands;
    jsonFile >> compileCommands;
    for (const auto &entry : compileCommands) {
        sources.push_back(entry["file"]);
    }
    return sources;
}

int main(int argc, const char **argv) {
    std::cout << "START" << std::endl;
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <compile_commands.json>" << std::endl;
        return 1;
    }
    std::string compileCommandsPath = argv[1];
    std::string dbDirectory = fs::path(compileCommandsPath).parent_path().string();
    std::string ErrorMessage;
    auto Compilations = CompilationDatabase::loadFromDirectory(dbDirectory, ErrorMessage);
    if (!Compilations) {
        std::cerr << "Error loading compilation database: " << ErrorMessage << std::endl;
        return 1;
    }

    auto sourceFiles = getSourceFilesFromCompileCommands(compileCommandsPath);
    if (sourceFiles.empty()) {
        std::cerr << "No source files found in " << compileCommandsPath << std::endl;
        return 1;
    }

    for (const std::string &filePath : sourceFiles) {
        std::cout << "Analyzing: " << filePath << std::endl;
        std::vector<std::string> filesToAnalyze = { filePath };

        ClangTool Tool(*Compilations, filesToAnalyze);
        FunctionAnalyzer Analyzer;
        MatchFinder Finder;
        Finder.addMatcher(functionDecl().bind("functionDecl"), &Analyzer);

        int result = Tool.run(newFrontendActionFactory(&Finder).get());
        if (result != 0) {
            std::cerr << "Error analyzing file: " << filePath << std::endl;
        }

        std::string outputFileName = "output_" + fs::path(filePath).filename().string() + ".json";
        Analyzer.saveResults(outputFileName);
    }
    std::cout << "END" << std::endl;
    return 0;
}
