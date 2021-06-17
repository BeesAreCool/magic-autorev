#pragma once

#include <Zydis/Zydis.h>

namespace zydis_helper{

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

}
