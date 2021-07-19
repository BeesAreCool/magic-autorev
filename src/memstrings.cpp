/*
High level concept:
    We ptrace the program
    Single step through
    Dump any strings pointed at by registers

Our first test is to simply count the number of steps.

*/

// This is inspired by the following blog post: https://blog.nelhage.com/2010/08/write-yourself-an-strace-in-70-lines-of-code/

#include <string>
#include <vector>
#include <iostream>
#include <string.h>
#include <set>
#include "debugger.h"


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

void loadBuffer(Debugger* dbg, long location, char* result, int* length){

    p_word read_word = dbg->get_word_dangerous(location);
    if (errno != 0){
        length = 0;
        return;
    }
    //cout << "GOT ONE!" << endl;
    char buffer[256];
    const int BUFFER_SIZE = 256;
    const int BUFFER_MID = 128;
    int BUFFER_START = BUFFER_MID;
    int BUFFER_END = BUFFER_MID;
    //FOR RUNNING FORWARD
    bool bad_char = false;
    for (int i=0; i + P_WORD_SIZE < BUFFER_SIZE - BUFFER_MID && !bad_char; i += P_WORD_SIZE){
        BUFFER_END += P_WORD_SIZE;
        read_word = dbg->get_word_dangerous(location+i);
        //printf("RUNNING FORWARD AT %i %08x\n", i, read_word);
        *((p_word*) (buffer + BUFFER_MID + i)) = read_word;
        for (int q =0; q < P_WORD_SIZE; q ++){
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
    for (int i=-P_WORD_SIZE; i - P_WORD_SIZE > - BUFFER_MID && !bad_char; i-= P_WORD_SIZE){
        BUFFER_START -= P_WORD_SIZE;
        read_word = dbg->get_word_dangerous(location+i);
        //printf("RUNNING BACKWARD AT %i %08x\n", i, read_word);
        *((p_word*) (buffer + BUFFER_MID + i)) = read_word;
        for (int q = 0; q <= P_WORD_SIZE; q ++){
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
    *length = BUFFER_END-BUFFER_START;
    memcpy(result, (buffer + BUFFER_START), *length+1);
}

set<string> getMemStrings(char* processName, char ** args){
    Debugger dbg = Debugger(processName, args);
    long* locations = new long[32];
    char* current_string = new char[1024];
    int string_length;
    int location_count;
    set<string> seen;
    for(int i=0; i<1000000; i++){
        //cout << i << " " << dbg.get_disasm() << endl;
        dbg.get_edited_memory(locations, &location_count);
        dbg.single_step();
        if(dbg.exited){
            cout << "Program exited after executing " << i << " instructions!" << endl;
            return seen;
        }
        for(int q=0; q<location_count; q++){
            loadBuffer(&dbg, locations[q], current_string, &string_length);
            if (string_length > 6){
                string current = current_string;
                if (seen.find(current) == seen.end()){
                    seen.insert(current);
                    cout << "Memstring #" << seen.size() << ": " << current_string << endl;
                }
            }
        }
    }
    return seen;
}

int main(int argc, char** argv){
    getMemStrings(argv[1], argv+1);
}
