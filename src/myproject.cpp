#include <stdio.h>
#include <inttypes.h>
#include <Zydis/Zydis.h>
#include <iostream>

using namespace std;

string operand_encoding_to_string(ZydisOperandEncoding encoding){
    string encodings[] = {"ZYDIS_OPERAND_ENCODING_NONE","ZYDIS_OPERAND_ENCODING_MODRM_REG","ZYDIS_OPERAND_ENCODING_MODRM_RM",
"ZYDIS_OPERAND_ENCODING_OPCODE","ZYDIS_OPERAND_ENCODING_NDSNDD","ZYDIS_OPERAND_ENCODING_IS4",
"ZYDIS_OPERAND_ENCODING_MASK","ZYDIS_OPERAND_ENCODING_DISP8","ZYDIS_OPERAND_ENCODING_DISP16",
"ZYDIS_OPERAND_ENCODING_DISP32","ZYDIS_OPERAND_ENCODING_DISP64","ZYDIS_OPERAND_ENCODING_DISP16_32_64",
"ZYDIS_OPERAND_ENCODING_DISP32_32_64","ZYDIS_OPERAND_ENCODING_DISP16_32_32","ZYDIS_OPERAND_ENCODING_UIMM8",
"ZYDIS_OPERAND_ENCODING_UIMM16","ZYDIS_OPERAND_ENCODING_UIMM32","ZYDIS_OPERAND_ENCODING_UIMM64",
"ZYDIS_OPERAND_ENCODING_UIMM16_32_64","ZYDIS_OPERAND_ENCODING_UIMM32_32_64","ZYDIS_OPERAND_ENCODING_UIMM16_32_32",
"ZYDIS_OPERAND_ENCODING_SIMM8","ZYDIS_OPERAND_ENCODING_SIMM16","ZYDIS_OPERAND_ENCODING_SIMM32",
"ZYDIS_OPERAND_ENCODING_SIMM64","ZYDIS_OPERAND_ENCODING_SIMM16_32_64","ZYDIS_OPERAND_ENCODING_SIMM32_32_64",
"ZYDIS_OPERAND_ENCODING_SIMM16_32_32","ZYDIS_OPERAND_ENCODING_JIMM8","ZYDIS_OPERAND_ENCODING_JIMM16",
"ZYDIS_OPERAND_ENCODING_JIMM32","ZYDIS_OPERAND_ENCODING_JIMM64","ZYDIS_OPERAND_ENCODING_JIMM16_32_64",
"ZYDIS_OPERAND_ENCODING_JIMM32_32_64","ZYDIS_OPERAND_ENCODING_JIMM16_32_32"};
    if (encoding > ZYDIS_OPERAND_ENCODING_MAX_VALUE){
        return "ERROR";
    }
    return encodings[encoding];
}

string operand_actions_to_string(ZydisOperandActions action){
    string actions = "";
    int int_action = action;
    if (int_action == 0){
        return "No actions";
    }
    if ((int) (int_action & ZYDIS_OPERAND_ACTION_READ) != 0){
        actions += "READ, ";
    }
    if ((int) (int_action & ZYDIS_OPERAND_ACTION_WRITE) != 0){
        actions += "WRITE, ";
    }
    if ((int) (int_action & ZYDIS_OPERAND_ACTION_CONDREAD) != 0){
        actions += "CONDREAD, ";
    }
    if ((int) (int_action & ZYDIS_OPERAND_ACTION_CONDWRITE) != 0){
        actions += "CONDWRITE, ";
    }
    return actions;
}

string operand_element_type_to_string(ZydisElementType type){
    switch(type){
    case ZYDIS_ELEMENT_TYPE_INVALID:
        return "INVALID";
    case ZYDIS_ELEMENT_TYPE_STRUCT:
        return "STRUCT";
    case ZYDIS_ELEMENT_TYPE_UINT:
        return "UINT";
    case ZYDIS_ELEMENT_TYPE_INT:
        return "INT";
    case ZYDIS_ELEMENT_TYPE_FLOAT16:
        return "FLOAT16";
    case ZYDIS_ELEMENT_TYPE_FLOAT32:
        return "FLOAT32";
    case ZYDIS_ELEMENT_TYPE_FLOAT64:
        return "FLOAT64";
    case ZYDIS_ELEMENT_TYPE_FLOAT80:
        return "FLOAT80";
    case ZYDIS_ELEMENT_TYPE_LONGBCD:
        return "LONGBCD";
    case ZYDIS_ELEMENT_TYPE_CC:
        return "CC";
    default:
        return "ERROR";
    }
}

string operand_type_to_string(ZydisOperandType type){
    switch(type){
    case ZYDIS_OPERAND_TYPE_UNUSED:
        return "UNUSED";
    case ZYDIS_OPERAND_TYPE_REGISTER:
        return "REGISTER";
    case ZYDIS_OPERAND_TYPE_MEMORY:
        return "MEMORY";
    case ZYDIS_OPERAND_TYPE_POINTER:
        return "POINTER";
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        return "IMMEDIATE";
    default:
        return "ERROR";
    }
}

string operand_visibility_to_string(ZydisOperandVisibility visibility){
    switch(visibility){
    case ZYDIS_OPERAND_VISIBILITY_INVALID:
        return "INVALID";
    case ZYDIS_OPERAND_VISIBILITY_EXPLICIT:
        return "EXPLICIT";
    case ZYDIS_OPERAND_VISIBILITY_IMPLICIT:
        return "IMPLICIT";
    case ZYDIS_OPERAND_VISIBILITY_HIDDEN:
        return "HIDDEN";
    default:
        return "ERROR";
    }
}
string register_to_string(ZydisRegister value){
    string register_names[] = {"none", "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7", "x87control", "x87status", "x87tag", "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm16", "xmm17", "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31", "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "ymm16", "ymm17", "ymm18", "ymm19", "ymm20", "ymm21", "ymm22", "ymm23", "ymm24", "ymm25", "ymm26", "ymm27", "ymm28", "ymm29", "ymm30", "ymm31", "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31", "tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7", "flags", "eflags", "rflags", "ip", "eip", "rip", "es", "cs", "ss", "ds", "fs", "gs", "gdtr", "ldtr", "idtr", "tr", "tr0", "tr1", "tr2", "tr3", "tr4", "tr5", "tr6", "tr7", "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7", "cr8", "cr9", "cr10", "cr11", "cr12", "cr13", "cr14", "cr15", "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7", "dr8", "dr9", "dr10", "dr11", "dr12", "dr13", "dr14", "dr15", "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7", "bnd0", "bnd1", "bnd2", "bnd3", "bndcfg", "bndstatus", "mxcsr", "pkru", "xcr0"};
    return register_names[value];
}

void print_register(ZydisDecodedOperand* operand){
    cout << "Register name: " << register_to_string(operand->reg.value) << endl;
}

void print_immediate(ZydisDecodedOperand* operand){
    cout << "IMMEDIATE VALUE: " << hex << operand->imm.value.u << dec;
    cout << " signed: " <<  (int) operand->imm.is_signed << " relative " << (int) operand->imm.is_relative << endl;
}

void print_memory_details(ZydisDecodedOperand* operand){
    cout << "<><><><><><><>" << endl;
    cout << "Segment register: " << register_to_string(operand->mem.segment) << endl;
    cout << "Base register: " << register_to_string(operand->mem.base) << endl;
    cout << "Index register: " << register_to_string(operand->mem.index) << endl;
    cout << "Scale: " << (int) operand->mem.scale << endl;
    cout << "Displacement: " << (int) operand->mem.disp.has_displacement << " , " <<  (int) operand->mem.disp.value << endl;
}

void print_memory(ZydisDecodedOperand* operand){
    switch(operand->mem.type){
    case ZYDIS_MEMOP_TYPE_MEM:
        cout << "MEMORY: MEM, INVESTIGATE!" << endl;
        break;
    case ZYDIS_MEMOP_TYPE_AGEN:
        cout << "MEMORY: AGEN, NOT PREPARED!" << endl;
        break;
    case ZYDIS_MEMOP_TYPE_MIB:
        cout << "MEMORY: MIB, NOT PREPARED!" << endl;
        break;
    default:
        cout << "MEMORY: FAILED!" << endl;
    }
    print_memory_details(operand);
}

void print_operand(ZydisDecodedOperand* operand){
    cout << "------" << endl;
    //cout << "id: " << (unsigned int) operand->id << endl;
    cout << "type: " << operand_type_to_string(operand->type) << endl;
    cout << "visibility: " << operand_visibility_to_string(operand->visibility) << endl;
    cout << "actions: " << operand_actions_to_string(operand->actions) << endl;
    //cout << "encoding: " << operand_encoding_to_string(operand->encoding) << endl;
    //cout << "size: " << (unsigned int) operand->size << endl;
    //cout << "reg: " << (unsigned int) operand->reg.value << endl;
    //cout << "element_type: " << operand_element_type_to_string(operand->element_type) << endl;
    //cout << "element_size: " << (unsigned int) operand->element_size << endl;
    //cout << "element_count: " << (unsigned int) operand->element_count << endl;
    switch(operand->type){
    case ZYDIS_OPERAND_TYPE_REGISTER:
        //print_register(operand);
        break;
    case ZYDIS_OPERAND_TYPE_MEMORY:
        print_memory(operand);
        break;
    case ZYDIS_OPERAND_TYPE_POINTER:
        //return "POINTER";
        break;
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        //print_immediate(operand);
        break;
    }
}

void print_instruction(ZydisDecodedInstruction* instruction){
    cout << "=======" << endl;
    //cout << "Machine Mode: " << (unsigned int) instruction->machine_mode << endl;
    //cout << "Mnemonic: " << (unsigned int) instruction->mnemonic << endl;
    cout << "Length: " << (unsigned int) instruction->length << endl;
    cout << "Encoding: " << (unsigned int) instruction->encoding << endl;
    //cout << "Opcode: " << (unsigned int) instruction->opcode << endl;
    //cout << "Stack width: " << (unsigned int) instruction->stack_width << endl;
    cout << "Operand width: " << (unsigned int) instruction->operand_width << endl;
    cout << "Address width: " << (unsigned int) instruction->address_width << endl;
    cout << "Operand count: " << (unsigned int) instruction->operand_count << endl;
    cout << "PRINTING THE OPERANDS..." << endl;
    for(int i=0; i<instruction->operand_count; i++){
        print_operand(&instruction->operands[i]);
    }
}

int main()
{
    ZyanU8 data[] =
    {
        243, 15, 30, 250, 85, 72, 137, 229, 72, 131, 236, 16, 72, 137, 125, 248, 72, 139, 69, 248, 15, 183, 64, 4, 15, 183, 192, 72, 152, 72, 141, 20, 0, 72, 141, 5, 71, 39, 0, 0, 15, 183, 52, 2, 72, 139, 21, 44, 39, 0, 0, 72, 139, 69, 248, 15, 183, 64, 2, 15, 183, 192, 72, 152, 72, 141, 12, 0, 72, 141, 5, 36, 39, 0, 0, 15, 183, 4, 1, 72, 15, 191, 192, 72, 1, 208, 137, 242, 136, 16, 72, 139, 69, 248, 15, 183, 64, 4, 15, 183, 192, 72, 152, 72, 141, 20, 0, 72, 141, 5, 253, 38, 0, 0, 15, 183, 4, 2, 152, 137, 198, 72, 141, 61, 231, 5, 0, 0, 184, 0, 0, 0, 0, 232, 229, 246, 255, 255, 15, 183, 5, 238, 38, 0, 0, 131, 192, 7, 102, 137, 5, 228, 38, 0, 0, 144, 201, 195
    };

    // Initialize decoder context
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    // Initialize formatter. Only required when you actually plan to do instruction
    // formatting ("disassembling"), like we do here
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    // Loop over the instructions in our buffer.
    // The runtime-address (instruction pointer) is chosen arbitrary here in order to better
    // visualize relative addressing
    ZyanU64 runtime_address = 0x001019a1;
    ZyanUSize offset = 0;
    const ZyanUSize length = sizeof(data);
    ZydisDecodedInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, length - offset,
        &instruction)))
    {
        cout << ";;;;;;;;;;;" << endl;
        // Print current instruction pointer.
        printf("%016" PRIX64 "  ", runtime_address);

        // Format & print the binary instruction structure to human readable format
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer),
            runtime_address);
        puts(buffer);
        offset += instruction.length;
        runtime_address += instruction.length;
        print_instruction(&instruction);
    }
}
