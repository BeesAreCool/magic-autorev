# magic-autorev

This is my personal project to create an "autosolver" for many common reverse engineering CTF challenges. In its present state it simply solves problems where a "string" is loaded into memory and edited to contain a "flag". This is done by automating ptrace (low level gdb tool essentially). Whenever a bit of memory is edited the program looks there for a string, and if it finds a valid ascii string it is printed to the terminal.

This currently only works on PIE enabled x86_64 binaries on linux. Coincidentally, that is most reverse engineering challenges these days.


# How to run

To compile, I advise running the simple_build.sh script. After that is done you should have a "MemStrings" binary in your build folder. Simply run `MemStrings a.out program arguments`. It will print out strings as they are loaded into memory.

NOTE: It only outputs strings that get edited. If a string is never edited, you can find it with "strings" in the raw binary instead of using this tool.

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
