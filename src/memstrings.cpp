/*
High level concept:
    We ptrace the program
    Single step through
    Dump any strings pointed at by registers

Our first test is to simply count the number of steps.

*/

// This is inspired by the following blog post: https://blog.nelhage.com/2010/08/write-yourself-an-strace-in-70-lines-of-code/

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
#include <Zydis/Zydis.h>
#include <sys/personality.h>

using namespace std;

//For even a trivial program, 10 seconds just to step through
//This involves around 1 million single steps

//We look for changes in rsi, rdi, and rax. Should any of these change, look for a string at that location
// CURRENTLY JUST RAX
//TODO: Split into functions
//TODO: Make it so that we find a string from a given location in memory, searching forward AND backward. Load this into a buffer

bool goHard = false;
string BAD_STRING = "";
char GOOD_CHARS[] = {48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93, 94, 95, 96, 123, 124, 125, 126, 32, 9, 10, 13, 11, 12};
int NUM_GOOD_CHARS = sizeof(GOOD_CHARS)/sizeof(char);

struct global_state_struct {
    set<string> all_strings;
    string last_string;
    string start_string;
    bool started;
    int min_length;
    ZydisDecoder decoder;
    ZydisFormatter formatter;
} global_state;

void initialize_state(){
    global_state.last_string="";
    global_state.start_string="";
    global_state.started=true;
    global_state.min_length=6;
    ZydisDecoderInit(&global_state.decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    ZydisFormatterInit(&global_state.formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

string loadBuffer(pid_t pid, long location){

    int read_word = ptrace(PTRACE_PEEKDATA, pid, location, 0);
    if (errno != 0){
        errno = 0;
    }
    //cout << pid << " " << location << " " << read_word << " " << errno << endl;
    if (errno != 0){
        return BAD_STRING;
    }
    //cout << "GOT ONE!" << endl;
    char buffer[256];
    const int BUFFER_SIZE = 256;
    const int BUFFER_MID = 128;
    int BUFFER_START = BUFFER_MID;
    int BUFFER_END = BUFFER_MID;
    //FOR RUNNING FORWARD
    bool bad_char = false;
    for (int i=0; i + 4 < BUFFER_SIZE - BUFFER_MID && !bad_char; i += 4){
        BUFFER_END += 4;
        read_word = ptrace(PTRACE_PEEKDATA, pid, location+i, 0);
        //printf("RUNNING FORWARD AT %i %08x\n", i, read_word);
        *((int*) (buffer + BUFFER_MID + i)) = read_word;
        for (int q =0; q < 4; q ++){
            bool matched = false;
            for(int z = 0; z < NUM_GOOD_CHARS; z++){
                if(buffer[BUFFER_MID+i+q] == GOOD_CHARS[z]){
                    matched = true;
                }
            }
            if (!matched){
                buffer[BUFFER_MID+i+q] = 0;
                bad_char = true;
                BUFFER_END = BUFFER_MID+i+q;
                break;
            }
        }
        if (errno != 0){
            errno = 0;
            break;
        }
    }
    bad_char = false;
    //FOR RUNNING BACKWARDS
    for (int i=-4; i - 4 > - BUFFER_MID && !bad_char; i-= 4){
        BUFFER_START -= 4;
        read_word = ptrace(PTRACE_PEEKDATA, pid, location+i, 0);
        //printf("RUNNING BACKWARD AT %i %08x\n", i, read_word);
        *((int*) (buffer + BUFFER_MID + i)) = read_word;
        for (int q = 0; q <= 4; q ++){
            bool matched = false;
            for(int z = 0; z < NUM_GOOD_CHARS; z++){
                if(buffer[BUFFER_MID+i+q] == GOOD_CHARS[z]){
                    matched = true;
                }
            }
            if (!matched){
                buffer[BUFFER_MID+i+q] = 0;
                bad_char = true;
                BUFFER_START = BUFFER_MID+i+q+1;
                //break;
            }
        }
        if (errno != 0){
            errno = 0;
            break;
        }
    }
    //BUFFER_START = BUFFER_MID;
    //cout << BUFFER_MID << " : " << BUFFER_END << " " << BUFFER_START << endl;
    //cout << "STR: " << (buffer + BUFFER_START) << endl;
    string result = (buffer + BUFFER_START);
    return result;
}

void handle_register(pid_t pid, long location, long instruction, long offset){
    string loaded = loadBuffer(pid, location + offset);
    if (goHard){
    //    cout << instruction << ": had string " << loaded << endl;
    }
    //cout <<registers.rax << ":"<< read_word << ":"<<errno << endl;
    if (loaded.size() >=  global_state.min_length){
        if (global_state.started){
            //cout << instruction << " " << loaded << " " << all_strings.count(loaded) << endl;
            if(global_state.all_strings.count(loaded) == 0 && global_state.last_string.find(loaded) == string::npos){
                cout << hex << instruction << dec << ": " << hex << location+offset << " " << loaded << " " << dec << global_state.all_strings.size() <<"!" << endl;
                global_state.all_strings.insert(loaded);
                global_state.last_string = loaded;
            }
        }
        if (loaded == global_state.start_string) {
            global_state.started = true;
        }
    } 
}

int get_word(pid_t pid, long location){
    int read_word = ptrace(PTRACE_PEEKDATA, pid, location, 0);
    if (errno != 0){
        //cout << "ERROR! " << errno << " at address " << hex << location << dec << endl;
        //cout << pid << endl;
        perror("oops in peek");
        errno = 0;
        return -1;
    }
    return read_word;
}

void print_byte_array(char * buffer, int size){
    for(int i=0; i<size; i++){
        printf("%02hhx", (int) (char) buffer[i]);
    }
    cout << ";" << endl;
}

user_regs_struct get_registers(pid_t pid, bool* success){
    user_regs_struct registers;
    ptrace(PTRACE_GETREGS, pid, 0, &registers);
    *success= true;
    if (errno != 0){
        *success= false;
        perror("oops in registers");
        errno = 0;
    }
    return registers;
    
}

ZydisDecodedInstruction load_instruction(pid_t pid, long ip){
    char buffer[24];
    for(int i=0; i<24; i++){
        buffer[i] = 0;
    }
    ZydisDecodedInstruction instruction;
    //int offset = (ip%4);
    for(int i=0; i<5; i++){
        //cout << i << endl;
        *((int*) (buffer + i*4)) = get_word(pid, ip+i*4);
        //print_byte_array(buffer, (i+1)*4);
        if(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&global_state.decoder, buffer, (i+1)*4,
        &instruction))){
            //cout << "Got at " << (i+1) * 4 << endl;
            return instruction;
        }
    }
    throw "Should never happen, instruction too long or won't parse";
}

void single_step(pid_t pid){
    int status;
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    if (errno != 0){
        perror("oops in step");
        errno = 0;
    }
    waitpid(pid, &status, 0);
}

void go_to_exec(pid_t pid){
    int status;
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC);
    ptrace(PTRACE_CONT, pid, 0, 0);
    if (errno != 0){
        perror("oops in exec");
        errno = 0;
    }
    waitpid(pid, &status, 0);
    cout << "Waited and got " << status << endl;
}

long get_register_by_num(int num, user_regs_struct registers){
    switch(num){
        case 0:
            //cout << "Getting RAX" << endl;
            return registers.rax;
        case 1:
            //cout << "Getting RCX" << endl;
            return registers.rcx;
        case 2:
            //cout << "Getting RDX" << endl;
            return registers.rdx;
        case 3:
            //cout << "Getting RBX" << endl;
            return registers.rbx;
        case 4:
            //cout << "Getting RSP" << endl;
            return registers.rsp;
        case 5:
            //cout << "Getting RBP" << endl;
            return registers.rbp;
        case 6:
            //cout << "Getting RSI" << endl;
            return registers.rsi;
        case 7:
            //cout << "Getting RDI" << endl;
            return registers.rdi;
        case 8:
            //cout << "Getting R8" << endl;
            return registers.r8;
        case 9:
            return registers.r9;
        case 10:
            return registers.r10;
        case 11:
            return registers.r11;
        case 12:
            return registers.r12;
        case 13:
            return registers.r13;
        case 14:
            return registers.r14;
        case 15:
            return registers.r15;
    }
    return 0;
}

long get_register_value(ZydisRegister value, user_regs_struct registers){
    //cout << "Looking up register " << value << endl;
    if (value == 0){
        return 0;
    }
    if (value <= 4){
        return get_register_by_num(value-1, registers) & 0xff;
    }
    if (value <= 8){
        return (get_register_by_num(value-5, registers) >> 8) & 0xff;
    }
    if (value <= 20){
        return get_register_by_num(value-9, registers) & 0xff;
    }
    if (value <= 36){
        return get_register_by_num(value-21, registers) & 0xffff;
    }
    if (value <= 52){
        return get_register_by_num(value-37, registers) & 0xffffffff;
    }
    if (value <= 68){
        return get_register_by_num(value-53, registers) ;
    }
    if (value >= 195 and value <= 197){
        if (value == 195){
            return registers.rip & 0xffff;
        }
        if (value == 196){
            return registers.rip & 0xffffffff;
        }
        if (value == 197){
            return registers.rip;
        }
    }
    return 0;
}

string register_to_string(ZydisRegister value){
    string register_names[] = {"none", "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7", "x87control", "x87status", "x87tag", "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm16", "xmm17", "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31", "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "ymm16", "ymm17", "ymm18", "ymm19", "ymm20", "ymm21", "ymm22", "ymm23", "ymm24", "ymm25", "ymm26", "ymm27", "ymm28", "ymm29", "ymm30", "ymm31", "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31", "tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7", "flags", "eflags", "rflags", "ip", "eip", "rip", "es", "cs", "ss", "ds", "fs", "gs", "gdtr", "ldtr", "idtr", "tr", "tr0", "tr1", "tr2", "tr3", "tr4", "tr5", "tr6", "tr7", "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7", "cr8", "cr9", "cr10", "cr11", "cr12", "cr13", "cr14", "cr15", "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7", "dr8", "dr9", "dr10", "dr11", "dr12", "dr13", "dr14", "dr15", "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7", "bnd0", "bnd1", "bnd2", "bnd3", "bndcfg", "bndstatus", "mxcsr", "pkru", "xcr0"};
    return register_names[value];
}

void get_edited_memory(ZydisDecodedInstruction instruction, user_regs_struct registers, pid_t pid, long instruction_index){
    for(int i=0; i<instruction.operand_count; i++){
        ZydisDecodedOperand operand=instruction.operands[i];
        //cout << i << " : " << operand.type << " : " << (operand.type & (ZYDIS_OPERAND_ACTION_WRITE | ZYDIS_OPERAND_ACTION_CONDWRITE)) << endl;
        if ((operand.type & (ZYDIS_OPERAND_ACTION_WRITE | ZYDIS_OPERAND_ACTION_CONDWRITE)) != 0 && operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&  operand.mem.type == ZYDIS_MEMOP_TYPE_MEM) {
            //cout << "HAVE A WRITE! "<< endl;
            //cout << "Segment register: " << register_to_string(operand.mem.segment) << endl;
            
            //cout << "Base register: " << register_to_string(operand.mem.base) << endl;
            long location = get_register_value(operand.mem.base, registers);
            //cout << hex << location  << dec << endl;
            //cout << "Index register: " << register_to_string(operand.mem.index) << endl;
            //cout << "Scale: " << (int) operand.mem.scale << endl;
            location += get_register_value(operand.mem.index, registers) * operand.mem.scale;
            //cout << hex << location  << dec << endl;
            //cout << "Displacement: " << (int) operand.mem.disp.has_displacement << " , " <<  (int) operand.mem.disp.value << endl;
            location += operand.mem.disp.has_displacement * operand.mem.disp.value;
            //cout << hex << location << dec << endl;
            handle_register(pid, location, instruction_index, 0);
        }
    }
}

//look around 600888
int main(int argc, char** argv){
    initialize_state();
    pid_t pid = fork();
    if (pid){
        //If we are the child
        cout << "Attaching to process with ptrace...." << endl;
        int status;
        unsigned long long start_printing = 0x555555554787;
        waitpid(pid, &status, 0);
        //ptrace(PTRACE_ATTACH, pid, 0, 0);
        //wait(NULL);
        user_regs_struct last_state;
        perror("Starting");
        //go_to_exec(pid);
        long instructions = 0;
        for(long i=0; i<100000000; i++){
            bool success = false;
            user_regs_struct registers = get_registers(pid, &success);
            if (!success){
                instructions = i;
                break;
            }
            /*if (registers.rip == start_printing){
                goHard = true;
                cout << "GOING HARD!" << endl;
            }*/
            ZydisDecodedInstruction instruction;
            //if(((registers.rip >> 32) & 0xff) == 0x55 ){
                instruction = load_instruction(pid, registers.rip);
            //}
            
            /*if(((registers.rip >> 32) & 0xff) == 0x55 && goHard){
                cout << i << " . "<< hex << registers.rip << dec << ": ";
                char buffer[256];
                ZydisFormatterFormatInstruction(&global_state.formatter, &instruction, buffer, sizeof(buffer),
                    registers.rip);
                puts(buffer);
            }
            */
            #define checkRegs(reg, offset) if(registers.reg != last_state.reg) { handle_register(pid, registers.reg, registers.rip, offset); handle_register(pid, last_state.reg, registers.rip, offset); };
            /*checkRegs(rax, 0);
            checkRegs(rbx, 0);
            checkRegs(rcx, 0);
            checkRegs(rdx, 0);
            checkRegs(rsi, 0);
            checkRegs(rdi, 0);
            checkRegs(rsp, 16);
            checkRegs(rbp, 16);
            checkRegs(rsp, -16);
            checkRegs(rbp, -16);
            checkRegs(rsp, 32);
            checkRegs(rbp, 32);
            checkRegs(rsp, -32);
            checkRegs(rbp, -32);
            checkRegs(rsp, 64);
            checkRegs(rbp, 64);
            checkRegs(rsp, -64);
            checkRegs(rbp, -64);*/
            last_state = registers;
            //get_edited_memory(instruction, registers, pid, registers.rip);
            single_step(pid);
            //if(((registers.rip >> 32) & 0xff) == 0x55){
            //if(((registers.rip >> 32) & 0xff) == 0x55 ){
                get_edited_memory(instruction, registers, pid, i);
            //}
            //}
        }
        cout << "Exited after " << instructions << endl;
        
    } else {
        //If we are the forkee
        //We need to set ourselves up for the ptrace
        cout << "Spinning up process to debug...." << endl;
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME);
        pid_t our_pid = getpid();
        kill(our_pid, SIGSTOP);
        cout << "Starting now!" << endl;
        return execvp(argv[1], argv+1);
    }
    return 0;
}
