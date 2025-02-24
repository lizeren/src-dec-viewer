cmake_minimum_required(VERSION 3.10)
project(MyStaticAnalyzer)

# Enable compile_commands.json generation
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force the use of Clang 17 (adjust if you prefer Clang 10)
set(CMAKE_C_COMPILER "/usr/bin/clang-17" CACHE STRING "C Compiler" FORCE)
set(CMAKE_CXX_COMPILER "/usr/bin/clang++-17" CACHE STRING "C++ Compiler" FORCE)

# Set LLVM and Clang directories (adjust if necessary)
set(LLVM_DIR "/usr/lib/llvm-17/lib/cmake/llvm/")
set(CLANG_DIR "/usr/lib/llvm-17/lib/cmake/clang/")

# Enable AddressSanitizer for debugging memory issues
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -g -O1")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")

# Find LLVM and Clang
find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "LLVM version: ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVM from: ${LLVM_DIR}")
message(STATUS "Using Clang from: ${CLANG_DIR}")

# Add include directories for LLVM, Clang, and nlohmann/json, and for readline if needed.
include_directories(${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS} /usr/include/nlohmann)
add_definitions(${LLVM_DEFINITIONS})

# Link directories for LLVM libraries
link_directories(${LLVM_LIBRARY_DIRS})

# Add the source file
add_executable(MyStaticAnalyzer feature_extraction.cpp)

# Link against Clang and LLVM libraries (and stdc++fs for filesystem support)
target_link_libraries(MyStaticAnalyzer
  PRIVATE
  clangTooling
  clangASTMatchers
  clangBasic
  clangAST
  clangFrontend
  clangSerialization
  LLVM
  stdc++fs
)

# Optionally, add a target for tests or additional libraries as needed.
