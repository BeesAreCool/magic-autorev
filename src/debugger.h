#pragma once

#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <Zydis/Zydis.h>
#include <string>
#include <sys/user.h>
#include <vector>

using namespace std;

typedef unsigned long p_word;
#define P_WORD_SIZE 8

class Debugger {

private:
    pid_t pid;
    ZydisDecoder decoder;
    ZydisFormatter formatter;
    void initialize_zydis(bool bit_64t);
    void complete_exec();
    void complete_syscall();
    void complete_entry();
public:
    long entry;
    bool exited;
    Debugger(char* processName, char** processArgs);
    p_word get_word(long location);
    p_word get_word_dangerous(long location);
    char get_byte(long location);
    void set_word(long location, p_word value);
    void set_byte(long location, char value);
    user_regs_struct get_registers();
    void set_registers(user_regs_struct);
    void single_step();
    ZydisDecodedInstruction load_instruction(long rip);
    void get_edited_memory(long*, int*);
    std::string get_disasm();
    
};
