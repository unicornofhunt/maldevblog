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
### Output:

[!Proc listing](/images/proc_listing.png)

Awesome we can see all the processes with corresponding PIDs listed.

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


## Telemetry

This is malware development blog, it is called maldevblog lol, but I am a detection engineer at heart. I also believe that red team should serve blue team. I ALSO BELIEVE THAT THE BEST DETECTIONS ARE PRODUCED BY RUNNING ACTUAL TOOLS AND TTPs. Do NOT write without telemetry generated, please, DO NOT ASSUME, do the thing, look what's there and write the logic.


### Auditd

I am getting nostalgic, auditd is something I have been playing with years ago, before eBPF. I recall also MDE agent using auditd (now they upgraded to eBPF).

I know some people are still using it, so let's explore.

Let's think about the behavior for a second: what's actually happening - we are opening a lot of `/proc/<PID>/comm` files, thus I would expect to observe a spike of syscall (2) `open` against `/proc/` directory (technically subdirectories).

The easiest `auditd` rule you can add to see this activity: `sudo auditctl -w /proc/ -p r -k proc_read` (this is not persistent way of adding this, fyi)

After rerunning the program and inspecting the log file: `cat /var/log/audit/audit.log | grep proc_read | grep 'comm="proc"':

```
type=SYSCALL msg=audit(1784295498.869:1361): arch=c000003e syscall=2 success=yes exit=4 a0=402418 a1=0 a2=0 a3=0 items=1 ppid=10018 pid=10085 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="proc" exe="/home/pawel/proc" subj=unconfined key="proc_read"ARCH=x86_64 SYSCALL=open AUID="pawel" UID="pawel" GID="pawel" EUID="pawel" SUID="pawel" FSUID="pawel" EGID="pawel" SGID="pawel" FSGID="pawel"
```

Well, we have all the details that we need, users pids etc. In total I had over 350 of the same log like above. So in theory you could write a detection logic that would look for same pid generating many reads on `/proc/` directory. 

SYSCALL event type is not the only type of events that are getting generated from this activity, each SYSCALL event would also have corresponding event types that you can correlated on unique event id (in above event case it would be `1784295498.869:1361`):

```
pawel@ubuntu-box:~/kernel_exercise_6.2$ cat /var/log/audit/audit.log | grep "1784295498.869:1361"
type=SYSCALL msg=audit(1784295498.869:1361): arch=c000003e syscall=2 success=yes exit=4 a0=402418 a1=0 a2=0 a3=0 items=1 ppid=10018 pid=10085 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="proc" exe="/home/pawel/proc" subj=unconfined key="proc_read"ARCH=x86_64 SYSCALL=open AUID="pawel" UID="pawel" GID="pawel" EUID="pawel" SUID="pawel" FSUID="pawel" EGID="pawel" SGID="pawel" FSGID="pawel"
type=CWD msg=audit(1784295498.869:1361): cwd="/home/pawel"
type=PATH msg=audit(1784295498.869:1361): item=0 name="/proc/10085/comm" inode=66925 dev=00:18 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="pawel" OGID="pawel"
type=PROCTITLE msg=audit(1784295498.869:1361): proctitle="./proc"
```
From this the most interesting would the PATH event type as it records the details about what file was open.

This presents the pain point of auditd. Thing is split into multiple event types and you would need to perform more work in order to correlate these together so you can work with these in your SIEM of choice. SUCKS.

What's more, the rule I provided you is noisy as f. There are processes in Linux that are constantly opening `/proc` so you would need somehow to do some baselining and exclude these.

Below you can find a simple dump from ubuntu vm that's been running only for couple of mins:

```
pawel@ubuntu-box:~/kernel_exercise_6.2$ grep proc_read /var/log/audit/audit.log | grep -v 'comm="proc"' | grep -o 'comm="[^"]*"' | cut -d '"' -f 2 | sort | uniq -c | sort -nr
   2472 fuser
   1358 (fwupd)
    476 vmtoolsd
    382 (fwupdmgr)
    142 tar
    135 dpkg
    109 snap
     98 snap-confine
     85 gsd-housekeepin
     84 9
     82 sadc
     78 http
     68 (python3)
     63 gnome-shell
     51 apt-config
     40 gpgconf
     39 sudo
     36 apt
     35 firmware-notifi
     32 gpg-connect-age
     28 snap-update-ns
     28 (snap)
     27 node
     27 grep
     24 gpgv
     18 sed
     14 snap-seccomp
     14 snap-exec
     14 snapctl
     14 ln
     12 https
     11 npm
     10 (sa1)
     10 cron
     10 apt-check
and more...
```

I hope it is clear: `DO NOT USE IT IN PRODUCTION`. We explore, we check, we learn. Most likely it will be not worth to detect this kind of activity (wtf, you ask).

So why do you even bother? Because we learn and applying same methodology and deep understanding of what telemetry is generated (by coding stuff yourself, understanding how it is build) by performing the activities.
