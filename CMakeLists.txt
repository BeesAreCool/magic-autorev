cmake_minimum_required(VERSION "3.15")
project(AutoRev VERSION 0.0.1 LANGUAGES CXX)

# Register Zydis dependency.
# Disable build of tools and examples.
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")
add_subdirectory("deps/elf-parser")

# Ok our new executable
add_executable("MemStrings" "src/memstrings.cpp" "src/debugger.cpp" "src/debugger.h" "src/zydisHelper.h")

# Now link it in with Zydis!
target_link_libraries("MemStrings" PRIVATE "Zydis")
