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
    void complete_syscall();
    void complete_entry();
public:
    long entry;
    Debugger(char* processName, char** processArgs);
    int get_word(long location);
    int get_word_dangerous(long location);
    char get_byte(long location);
    void set_word(long location, int value);
    void set_byte(long location, char value);
    user_regs_struct get_registers();
    void single_step();
    ZydisDecodedInstruction load_instruction(long rip);
    void get_edited_memory(long*, int*);
    std::string get_disasm();
    
};
