#include "debugger.h"
#include "zydisHelper.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <iostream>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <string>
#include <tuple>
#include <set>
#include <stdio.h>
#include <inttypes.h>
#include <sys/personality.h>
#include <Zydis/Zydis.h>
#include <vector>

using namespace std;

void Debugger::initialize_zydis(bool bit_64){
    ZydisDecoderInit(&this->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    ZydisFormatterInit(&this->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

Debugger::Debugger(char* processName, char** processArgs){
    this->initialize_zydis(true);
    pid_t pid = fork();
    if (pid){
        int status;
        this->pid = pid;
        waitpid(this->pid, &status, 0);
        user_regs_struct last_state;
        if (errno != 0){
            perror("Error on startup in Debugger::Debugger");
        }
    } else {
        //If we are the forkee
        //We need to set ourselves up for the ptrace
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME);
        pid_t our_pid = getpid();
        kill(our_pid, SIGSTOP);
        exit(execvp(processName, processArgs));
    }
}

void Debugger::complete_exec(){
    int status;
    ptrace(PTRACE_SETOPTIONS, this->pid, 0, PTRACE_O_TRACEEXEC);
    ptrace(PTRACE_CONT, pid, 0, 0);
    if (errno != 0){
        perror("Error in Debugger::complete_exec");
        errno = 0;
    }
    waitpid(pid, &status, 0);
}

void Debugger::single_step(){
    int status;
    ptrace(PTRACE_SINGLESTEP, this->pid, 0, 0);
    if (errno != 0){
        perror("Error in Debugger::single_step");
        errno = 0;
    }
    waitpid(this->pid, &status, 0);
}

user_regs_struct Debugger::get_registers(){
    user_regs_struct registers;
    int status;
    for(int i=0; i<5; i++){
        ptrace(PTRACE_GETREGS, pid, 0, &registers);
        if (errno == 0){
            return registers;
        } else {
            errno = 0;
        }
    }
    if (errno != 0){
        perror("Error in Debugger::get_registers");
        errno = 0;
        //exit(0);
    }
    return registers;
    
}

int Debugger::get_word_dangerous(long location){
    int read_word = ptrace(PTRACE_PEEKDATA, this->pid, location, 0);
    return read_word;
}

int Debugger::get_word(long location){
    int read_word = ptrace(PTRACE_PEEKDATA, this->pid, location, 0);
    if (errno != 0){
        perror("Error in Debugger::get_word");
        errno = 0;
        return -1;
    }
    return read_word;
}

ZydisDecodedInstruction Debugger::load_instruction(long rip){
    char buffer[24];
    for(int i=0; i<24; i++){
        buffer[i] = 0;
    }
    ZydisDecodedInstruction instruction;
    for(int i=0; i<5; i++){
        *((int*) (buffer + i*4)) = this->get_word(rip+i*4);
        if(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&this->decoder, buffer, (i+1)*4,
        &instruction))){
            return instruction;
        }
    }
    throw "Should never happen, instruction too long or won't parse";
}

void Debugger::get_edited_memory(long* locations, int* location_count){
    user_regs_struct registers = this->get_registers();
    ZydisDecodedInstruction instruction = this->load_instruction(registers.rip);
    *location_count = 0;
    for(int i=0; i<instruction.operand_count; i++){
        ZydisDecodedOperand operand=instruction.operands[i];
        if ((operand.type & (ZYDIS_OPERAND_ACTION_WRITE | ZYDIS_OPERAND_ACTION_CONDWRITE)) != 0 && operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&  operand.mem.type == ZYDIS_MEMOP_TYPE_MEM) {
            long location = zydis_helper::get_register_value(operand.mem.base, registers);
            location += zydis_helper::get_register_value(operand.mem.index, registers) * operand.mem.scale;
            location += operand.mem.disp.has_displacement * operand.mem.disp.value;
            locations[*location_count] = location;
            *location_count += 1;
        }
    }
}
