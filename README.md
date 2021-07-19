# magic-autorev (but currently just MemStrings).

This is my personal project to create an "autosolver" for many common reverse engineering CTF challenges. In its present state it simply solves problems where a "string" is loaded into memory and edited to contain a "flag". This is done by automating ptrace (low level gdb tool essentially). Whenever a bit of memory is edited the program looks there for a string, and if it finds a valid ascii string it is printed to the terminal.

This currently only works on PIE enabled x86_64 binaries on linux. Coincidentally, that is most reverse engineering challenges these days.


# How to run

To compile, I advise running the simple_build.sh script. After that is done you should have a "MemStrings" binary in your build folder. Simply run `MemStrings a.out program arguments`. It will print out strings as they are loaded into memory.

NOTE: It only outputs strings that get edited. If a string is never edited, you can find it with "strings" in the raw binary instead of using this tool.

# How it works

If you've ever done reverse engineering CTF challenges you'll have likely encountered binaries which generate strings and other values dynamically. For instance, by xoring two byte strings togethers. While you can manually decode what is happening by using a disassembler the challenges often want you to run GDB, set a breakpoint at the correct location, and then read the string from memory. The goal of this program is to automatically break at every location in the program and check for strings, if a string is found, display it to the user.

This is accomplished by making use of the linux tool known as ptrace. Ptrace allows us to trace the execution of a process at a very low level, seeing every register and every bit of memory. When MemStrings starts it simply forks and the parent fork attempts to "attach" to the child in order to watch it. Once the child knows it has been attached to, it executes the command line arguments passed to the program. We can now advance the instructions in the program one step at a time.

Now, ptrace on its own doesn't give us much information on what these instructions do. So, to understand that we make use of the Zydis disassembler. This disassembler lets us parse out the opcodes and operands for every instruction, including hidden and implicit operands. When the operands point towards a memory location and the operand includes writing to that location, we record the memory offset. Once it is recorded we check the values at that location both before and after the execution of the instruction. If either form an ascii string, we've found a potential flag and output it.

This generates a lot of false positives, especially in C++ code. The biggest source of false positives was previously the library loader routine, when a process is called it executes a lot of instructions before ever hitting the "entry" specified in the ELF. This is due to dynamically linked libraries being loaded into memory. In order to remove these specific false positives the program makes use of a primitive implementation of breakpoints to detect where the "entry" point is and jump over the library loader code without actually examining anything.

# Example programs tested.

```
bee@blackandyellow:~/hackinghobby/magic-autorev$ ./build/MemStrings samples/problem 
Memstring #1: Input password: 
Memstring #2: Good job dude !!!
Memstring #3: Wrong password
Memstring #4: _dl_find_dso_for_object
Memstring #5: posix_spawn
Memstring #6: _dl_make_stack_executable
Memstring #7: GLIBC_2.4
Memstring #8: GLIBC_2.30
Memstring #9: GLIBC_PRIVATE
Memstring #10: /lib/x86_64-linux-gnu/libc.so.6
Memstring #11: )qI+`^X
Memstring #12: Fj[GE>
                     
Memstring #13: al:$)~ 
Memstring #14: >?:,i@:,i
Memstring #15: &q+v~{ 
Memstring #16: $'!gi
                    PTK
Memstring #17: __tunable_get_val
Memstring #18: __resolv_context_get_preinit
Memstring #19: _dl_signal_exception
Memstring #20: Input p
Memstring #21: Input pa
Memstring #22: Input pas
Memstring #23: Input pass
Memstring #24: Input passw
Memstring #25: Input passwo
Memstring #26: Input passwor
Memstring #27: Input password
Memstring #28: Input password:
Input password: no idea!
Memstring #29: no idea!

Memstring #30: IdontKnowWhatsGoingOn
Memstring #31: AbCTF{r
Memstring #32: AbCTF{r3
Memstring #33: AbCTF{r3v
Memstring #34: AbCTF{r3ve
Memstring #35: AbCTF{r3ver
Memstring #36: AbCTF{r3vers
Memstring #37: AbCTF{r3vers1
Memstring #38: AbCTF{r3vers1n
Memstring #39: AbCTF{r3vers1ng
Memstring #40: AbCTF{r3vers1ng_
Memstring #41: AbCTF{r3vers1ng_d
Memstring #42: AbCTF{r3vers1ng_du
Memstring #43: AbCTF{r3vers1ng_dud
Memstring #44: AbCTF{r3vers1ng_dud3
Memstring #45: AbCTF{r3vers1ng_dud3}
Memstring #46: Wrong password: 
Memstring #47: Wrong password
 
Wrong password
Program exited after executing 80001 instructions!

```


# Credits
I'm currently testing out the Zydis disassembler. Much of the code is inspired by https://github.com/zyantific/zydis-submodule-example

It is a really great tool.
