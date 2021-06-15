cmake_minimum_required(VERSION "3.15")
project("MyProject")

# Register Zydis dependency.
# Disable build of tools and examples.
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

# Ok our new executable
add_executable("MemStrings" "src/memstrings.cpp")

# Now link it in with Zydis!
target_link_libraries("MemStrings" PRIVATE "Zydis")
