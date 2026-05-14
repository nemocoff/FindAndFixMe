cmake_minimum_required(VERSION 3.10)
project(FindAndFixMeCore)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find LLVM
find_package(LLVM 16.0 REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# Find Clang
find_package(Clang 16 REQUIRED CONFIG)

# Include directories
include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${CLANG_INCLUDE_DIRS})

# Add definitions
add_definitions(${LLVM_DEFINITIONS})

# Find Z3
find_package(Z3 REQUIRED)
include_directories(${Z3_INCLUDE_DIRS})

# Set up the executable
add_executable(MutationEngine MutationEngine.cpp)

# Link libraries (Using Dynamic Libraries to prevent duplicate CLI option registration)
target_link_libraries(MutationEngine
    PRIVATE
    clang-cpp
    LLVM
    ${Z3_LIBRARIES}
)
