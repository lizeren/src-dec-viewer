#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <string>
#include <experimental/filesystem> // For Clang 10/17 compatibility
#include <nlohmann/json.hpp>
#include <unordered_set>

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
static const unsigned MAX_RECURSION_DEPTH = 64;

unsigned long long getSafeTypeSize(ASTContext &context, QualType qt) {
    if (qt.isNull())
        return 0;

    QualType canonicalQT = qt.getCanonicalType();
    const Type *rawType = canonicalQT.getTypePtrOrNull();
    if (!rawType)
        return 0;

    llvm::errs() << "[DEBUG] Analyzing type: " << qt.getAsString() << "\n";

    if (RecursionDepth > MAX_RECURSION_DEPTH - 5) {
        llvm::errs() << "[WARNING] Recursion depth approaching limit for type: " 
                     << qt.getAsString() << " (Depth: " << RecursionDepth << ")\n";
    }
    if (RecursionDepth > MAX_RECURSION_DEPTH) {
        llvm::errs() << "[ERROR] Skipping type due to excessive recursion: " 
                     << qt.getAsString() << "\n";
        return context.getTargetInfo().getPointerWidth(LangAS::Default) / 8;
    }
    if (globalSeenTypes.find(rawType) != globalSeenTypes.end()) {
        std::cout << "CYCLIC_TYPE_DETECTED: " << qt.getAsString() << std::endl;
        llvm::errs() << "[WARNING] Skipping cyclic type: " << qt.getAsString() << "\n";
        //return 0;  // Avoid infinite recursion
        // Return pointer size instead of 0 for cyclic types
        return context.getTargetInfo().getPointerWidth(LangAS::Default) / 8;
    }

    globalSeenTypes.insert(rawType);
    ++RecursionDepth;

    unsigned size = context.getTypeSize(qt) / 8;

    --RecursionDepth;
    globalSeenTypes.erase(rawType);

    return size;
}

class LocalVariableCounter : public RecursiveASTVisitor<LocalVariableCounter> {
public:
    std::unordered_map<std::string, int> typeCount;
    unsigned long long stackSize = 0;
    int totalLocalCount = 0;

    bool VisitVarDecl(const VarDecl *v) {
        if (v->isLocalVarDecl() && !v->hasGlobalStorage()) {
            std::string typeName = v->getType().getAsString();
            typeCount[typeName]++;
            unsigned typeSize = v->getASTContext().getTypeSize(v->getType()) / 8;
            stackSize += typeSize;
            totalLocalCount++;
        }
        return true;
    }
};

class FunctionAnalyzer : public MatchFinder::MatchCallback {
public:
    std::vector<json> functionData;

    void run(const MatchFinder::MatchResult &Result) override {
        if (const FunctionDecl *FD = Result.Nodes.getNodeAs<FunctionDecl>("functionDecl")) {
            // Only process functions from the main file.
            if (!FD->getLocation().isInvalid() && Result.SourceManager->isInMainFile(FD->getLocation())) {
                json functionJson;
                functionJson["function_name"] = FD->getNameAsString();
                functionJson["number_of_parameters"] = FD->getNumParams();

                unsigned long long paramStackSize = 0;
                for (const auto *param : FD->parameters()) {
                    if (!param)
                        continue;
                    QualType paramType = param->getType();
                    if (paramType.isNull())
                        continue;

                    // Compute and accumulate parameter sizes.
                    if (param->getASTContext().getTypeInfo(paramType).Width > 0) {
                        paramStackSize += getSafeTypeSize(param->getASTContext(), paramType);
                    }
                }
                functionJson["total_parameter_stack_size_bytes"] = paramStackSize;

                LocalVariableCounter LVC;
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
