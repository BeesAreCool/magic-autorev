# magic-autorev

This is my personal project to create an "autosolver" for many common reverse engineering CTF challenges. It is focused primarily on x86_64 programs and makes heavy use of ptrace for automated dynamic analysis.

The gist of the project is a c++ project that will automatically identify "interesting" strings.

I'm currently testing out the Zydis disassembler. Much of the code is inspired by https://github.com/zyantific/zydis-submodule-example
