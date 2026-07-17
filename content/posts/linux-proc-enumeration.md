+++
title = 'Overcomplicated Linux Process Enumeration'
date = 2026-07-16T20:18:54+02:00
draft = false 
+++

The guide on how to overthink process enumeration in Linux.

I am coming from the Windows heavy internals background, however, Linux has been always super interesting to me. This is where I started, back in the day doing some heavy auditd stuff here and there. It is time that I have decided to get back to Linux and share something that might help or inspire others.

Why the f.. would you want to enumerate processes? Well, this would be the case of your typical recon phase once you got into the host. You can find some interesting stuff... From the maldev point of view, you usually want to enumerate processes to find some juicy targets for potential process injection (that's what you do in Windows world, so I assume that would be also valid in Linux land, lol, idk).

In Linux you can just simply utilize tools like `ps` or `pstree` in order to enumerate the process. That's soooo boring, this is freaking maldev isn't it? You build this sh\*t from ground up...

Better... Do it in assembly... ;) because why not? I like pain too.

The code will be just printing all process names with pids, not really that fancy for now, in the future we might try to look at some memory regions of the processes and write to them... for now we are going just to re-create `ps` with NASM.

## Couple of things you need to know

1. Trying to make it super simple: we do it in x64, so we need to comply with Linux Calling Convention.
```
First six arguments passed in RDI, RSI, RDX, RCX, R8, R9 (in this order).
Seventh and beyond on stack. (This is quite scary so let's limit ourselves to 6 arguments)
```
2. There is this pseudo/dynamic/crazy `/proc` directory that kernel builds dynamically that you can read to learn about all processes:

![Traversing /proc](/images/procfs.png)

3. For our usage it is important to know that the pattern is `/proc/<PID>/comm`. Reading this file gives us command name associated with the process. [man page](https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html). Super easy, we just need to traverse the directory and read all `comm` files.

4. We will utilize syscalls heavily. TBH, it is a matter of setting up arguments/parameters call appropriate syscall, work with the provided output, repeat. It is that simple.

```
You might recall also there is this SSN in Windows that could change across different builds/versions of Windows, thus you usually need to dynamically resolve it.
So you need to do a lot of work, parsing and stuff.
Fortunately for us, Linus is a beast and says that in Linux these numbers are not going to change.
```
[syscalls documentation](https://github.com/torvalds/linux/blob/master/Documentation/ABI/README)

```
[...]
Most interfaces (like syscalls) are expected to never change and always be available.
```

We can just hardcode these bad boys!

5. There is a lot of online docs you can find that will give you list of syscalls and their numbers, do exploring, but in case you lost: `ausyscall x86_64 --dump`

## The Code

```
; code to perform process enumeration, lists all processes and their PIDs
; uses only syscalls just for lolz
; I <3 asm
global _start

%define BUF_SIZE 1024

;macro to print
%macro print 2
    xor rax, rax
    inc rax
    xor rdi, rdi
    inc rdi
    mov rsi, %1
    mov rdx, %2
    syscall
%endmacro

section .data
    proc_dir    db "/proc", 0
    proc_prefix db "/proc/"        
    proc_prefix_len equ $-proc_prefix
    comm_suffix db "/comm", 0      
    comm_suffix_len equ $-comm_suffix
    separator   db " - "         
    newline     db 10             

section .bss
    buffer      resb 1024           ; getdents64 buffer
    path_buf    resb 256            
    comm_buf    resb 256            

section .text
_start:
    mov rax, 2          
    mov rdi, proc_dir   
    mov rsi, 0x10000    ; O_RDONLY | O_DIRECTORY
    xor rdx, rdx        
    syscall

    test rax, rax
    js .exit            
    mov r12, rax        

.read_dir:
    mov rax, 217        ; sys_getdents64
    mov rdi, r12        
    mov rsi, buffer     
    mov rdx, BUF_SIZE       
    syscall

    test rax, rax
    jle .close          
    mov r13, rax        
    mov r14, buffer     

.parse_entries:
    test r13, r13
    jle .read_dir       

    lea r15, [r14 + 19] 
    xor rbx, rbx        

.check_pid:
    mov al, byte [r15 + rbx]
    test al, al         
    je .good_pid ; found null terminator

    cmp al, '0'
    jl .next_entry      
    cmp al, '9'
    jg .next_entry      

    inc rbx             
    jmp .check_pid

.good_pid:
    test rbx, rbx
    je .next_entry
    
    ;print pid
    print r15, rbx

    ;print sep
    print separator, 3

   ; setting up print buf 
    lea rdi, [rel path_buf]
    
    
    lea rsi, [rel proc_prefix]
    mov rcx, proc_prefix_len 
    rep movsb           
    
    mov rsi, r15        
    mov rcx, rbx        
    rep movsb
    
    lea rsi, [rel comm_suffix]
    mov rcx, comm_suffix_len 
    rep movsb

    ;checking comm file 
    mov rax, 2          ; sys_open
    lea rdi, [rel path_buf] 
    xor rsi, rsi        ; O_RDONLY (0)
    xor rdx, rdx
    syscall

    test rax, rax
    js .fail ; if fails the proc has probably died 

    mov r8, rax         

    ; read comm file
    xor rax, rax        ; sys_read
    mov rdi, r8         
    lea rsi, [rel comm_buf]
    mov rdx, 255        
    syscall

    mov r9, rax         

    ; close comm file
    mov rax, 3          ; sys_close
    mov rdi, r8
    syscall

    test r9, r9
    jle .fail ; If read failed or empty, print newline

    ;print proc name 
    lea rsi, [rel comm_buf]
    print rsi, r9
    jmp .next_entry

.fail:
    ;edge case when current proc just dead 
    lea rsi, [rel newline]
    print rsi, 1
    syscall

.next_entry:
    movzx rcx, word [r14 + 16] 
    add r14, rcx               
    sub r13, rcx               
    jmp .parse_entries

.close:
    mov rax, 3          ; sys_close
    mov rdi, r12        
    syscall

.exit:
    mov rax, 60         ; sys_exit
    xor rdi, rdi        ; status 0
    syscall
```

### Build:

```
nasm -f elf64 proc.asm -o proc.o
ld proc.o -o proc
```

### Couple of notes:

You load "syscall number" into the rax prior the `syscall` instruction.
Utilized syscalls:
- `read` to read the contents of `/proc/<PID./comm`
- `write` to print outputs to stdout
- `open`  to open `/proc` and `/proc/<PID>/comm`
- `close` to close file descriptor (fd) for `comm` and `/proc`
- `exit` lol
- `getdents64` to read directory entries - `linux_dirent` structure [link](https://linux.die.net/man/2/getdents64)

Notice a magic number: `19` offset to `d_name`, `16` for `d_reclen`. Check above link for structure brekadown



