#pragma once

#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <Zydis/Zydis.h>
#include <string>
#include <sys/user.h>
#include <vector>

using namespace std;

class Debugger {

private:
    pid_t pid;
    ZydisDecoder decoder;
    ZydisFormatter formatter;
    void initialize_zydis(bool bit_64t);
    void complete_exec();
public:
    Debugger(char* processName, char** processArgs);
    int get_word(long location);
    int get_word_dangerous(long location);
    user_regs_struct get_registers();
    void single_step();
    ZydisDecodedInstruction load_instruction(long rip);
    void get_edited_memory(long*, int*);
    
};
