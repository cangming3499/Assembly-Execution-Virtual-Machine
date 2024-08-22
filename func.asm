.DATA
EXTERN EFL:QWORD ; 声明外部变量
EXTERN target_func_addr:QWORD ; 声明外部变量
EXTERN vm_stacked_num:QWORD ;
EXTERN vm_stack_low:QWORD;

EXTERN  real_rax:QWORD;
EXTERN  real_rbx:QWORD;
EXTERN  real_rcx:QWORD;
EXTERN  real_rdx:QWORD;

EXTERN  real_r8:QWORD;
EXTERN  real_r9:QWORD;
EXTERN  real_r10:QWORD;
EXTERN  real_r11:QWORD;
EXTERN  real_r12:QWORD;
EXTERN  real_r13:QWORD;
EXTERN  real_r14:QWORD;
EXTERN  real_r15:QWORD;

EXTERN  real_rsi:QWORD;
EXTERN  real_rdi:QWORD;
EXTERN  real_rsp:QWORD;
EXTERN  real_rbp:QWORD;
     
EXTERN  vm_rax:QWORD ;
EXTERN  vm_rbx:QWORD ;
EXTERN  vm_rcx:QWORD ;
EXTERN  vm_rdx:QWORD ;

EXTERN  vm_r8:QWORD ;
EXTERN  vm_r9:QWORD ;
EXTERN  vm_r10:QWORD;
EXTERN  vm_r11:QWORD;
EXTERN  vm_r12:QWORD;
EXTERN  vm_r13:QWORD;
EXTERN  vm_r14:QWORD;
EXTERN  vm_r15:QWORD;

EXTERN  vm_rsi:QWORD;
EXTERN  vm_rdi:QWORD;
EXTERN  vm_rsp:QWORD;
EXTERN  vm_rbp:QWORD;

EXTERN gs_60:QWORD ; 


.CODE

exec_api_func PROC
    mov rcx, vm_stacked_num ; 设置循环计数器，循环 10 次
    mov rbx, 1               ; 初始化 RBX 为 1，作为标志位

loop_start:
    cmp rbx, 1             ; 检查 RBX 是否为 1（是否是第一次进入循环）
    jne skip_save_rsp      ; 如果 RBX 不为 1，则跳过保存 RSP

    mov real_rax,rax
    mov real_rbx,rbx
    mov real_rcx,rcx
    mov real_rdx,rdx
    mov real_rdi,rdi
    mov real_rsi,rsi

    mov real_r8,r8
    mov real_r9,r9
    mov real_r10,r10
    mov real_r11,r11
    mov real_r12,r12
    mov real_r13,r13
    mov real_r14,r14
    mov real_r15,r15

    mov real_rbp,rbp
    mov real_rsp, rsp     ; 保存当前的 RSP 值到 saved_rsp 变量中


    mov rbx, 0             ; 将 RBX 置为 0，标识已经保存过 RSP
    mov rax,vm_stack_low
    sub rax,8

skip_save_rsp:
    mov rdx, [rax]         ; 将 RAX 指向的内存中的 8 字节数据加载到 RDX
    push rdx               ; 将 RDX 中的 8 字节数据压入栈
    sub rax, 8             ; 将 RAX 中的地址减去 8
    dec rcx                ; 手动将循环计数器减 1
    jnz skip_save_rsp         ; 如果 RCX 不为 0，则跳回 loop_start



    ;3、将虚拟寄存器的值复制到真实寄存器  不包括rsp
     mov rax,vm_rax
     mov rbx,vm_rbx
     mov rcx,vm_rcx
     mov rdx,vm_rdx
     mov rsi,vm_rsi
     mov rdi,vm_rdi

     mov r8,vm_r8
     mov r9,vm_r9
     mov r10,vm_r10
     mov r11,vm_r11
     mov r12,vm_r12
     mov r13,vm_r13
     mov r14,vm_r14
     mov r15,vm_r15

     mov rbp,vm_rbp  


    ; 4、执行函数

    call target_func_addr;

    ;5、将 真实寄存器的值反回到虚拟寄存器  不包括rsp
    mov vm_rax,rax
    mov vm_rbx,rbx
    mov vm_rcx,rcx
    mov vm_rdx,rdx
    mov vm_rsi,rsi
    mov vm_rdi,rdi

    mov vm_r8,r8
    mov vm_r9,r9
    mov vm_r10,r10
    mov vm_r11,r11
    mov vm_r12,r12
    mov vm_r13,r13
    mov vm_r14,r14
    mov vm_r15,r15
    mov vm_rbp,rbp

    ;6、恢复真实寄存器 和 真实栈
    mov rax,real_rax
    mov rbx,real_rbx
    mov rcx,real_rcx
    mov rdx,real_rdx
    mov rsi,real_rsi
    mov rdi,real_rdi

    mov r8,real_r8
    mov r9,real_r9
    mov r10,real_r10
    mov r11,real_r11
    mov r12,real_r12
    mov r13,real_r13
    mov r14,real_r14
    mov r15,real_r15

    mov rsp,real_rsp  
    mov rbp,real_rbp  


    ret;

exec_api_func ENDP





get_efl PROC
    pushfq                  ; 将 EFLAGS 寄存器的值推入堆栈
    pop rax                 ; 将堆栈顶的值弹出到 RAX 寄存器
    mov EFL, rax            ; 将 RAX 寄存器的值存储到全局变量 eflags_value 中
    ret;
get_efl ENDP







END