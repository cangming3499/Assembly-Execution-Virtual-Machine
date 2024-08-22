#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <inttypes.h>


#include <windows.h>
#include <stdio.h>

#include <string.h>
extern "C" void copy_stack(ULONG64 RSP);
EXTERN_C ULONG64   EFL = 0;
EXTERN_C ULONG64 get_efl();
EXTERN_C ULONG64 exec_api_func();


//EXTERN_C ULONG64 get_gs_60();
EXTERN_C ULONG64 target_func_addr = 0;
EXTERN_C ULONG64 vm_stacked_num = 0;
EXTERN_C ULONG64 vm_stack_low = 0;


EXTERN_C ULONG64 real_rax = 0;
EXTERN_C ULONG64 real_rbx = 0;
EXTERN_C ULONG64 real_rcx = 0;
EXTERN_C ULONG64 real_rdx = 0;
EXTERN_C ULONG64 real_rsi = 0;
EXTERN_C ULONG64 real_rdi = 0;

EXTERN_C ULONG64 real_r8 = 0;
EXTERN_C ULONG64 real_r9 = 0;
EXTERN_C ULONG64 real_r10 = 0;
EXTERN_C ULONG64 real_r11 = 0;
EXTERN_C ULONG64 real_r12 = 0;
EXTERN_C ULONG64 real_r13 = 0;
EXTERN_C ULONG64 real_r14 = 0;
EXTERN_C ULONG64 real_r15 = 0;

EXTERN_C ULONG64 real_rsp = 0;
EXTERN_C ULONG64 real_rbp = 0;

EXTERN_C ULONG64 vm_rax = 0;
EXTERN_C ULONG64 vm_rbx = 0;
EXTERN_C ULONG64 vm_rcx = 0;
EXTERN_C ULONG64 vm_rdx = 0;
EXTERN_C ULONG64 vm_r8 = 0;
EXTERN_C ULONG64 vm_r9 = 0;
EXTERN_C ULONG64 vm_rsi = 0;
EXTERN_C ULONG64 vm_rdi = 0;
EXTERN_C ULONG64 vm_r10 = 0;
EXTERN_C ULONG64 vm_r11 = 0;
EXTERN_C ULONG64 vm_r12 = 0;
EXTERN_C ULONG64 vm_r13 = 0;
EXTERN_C ULONG64 vm_r14 = 0;
EXTERN_C ULONG64 vm_r15 = 0;
EXTERN_C ULONG64 vm_rsp = 0;
EXTERN_C ULONG64 vm_rbp = 0;

EXTERN_C ULONG64 gs_60 = 0;


#define NUM_REGISTERS 16
#define MEMORY_SIZE 4096
//
// 定义数据类型
typedef unsigned char BYTE_T;
typedef unsigned short WORD_T;
typedef unsigned int DWORD_T;
typedef unsigned long long QWORD_T;

//这行代码定义了一个枚举类型 Register，其中列出了多个枚举常量。
//在C语言中，枚举类型允许你定义一组命名的整数常量，这些常量被称为枚举成员。
//
//具体来说：
//
//typedef enum { ... } Register; 
//定义了一个枚举类型 Register，
//并且通过 typedef 将其定义为 Register 类型。
//在大括号{ ... } 中列出了枚举的成员，每个成员都是一个常量。
//例如，RAX 是第一个成员，它的值为0，依次类推。
//这些枚举成员默认情况下是按照顺序从0开始分配值的，除非显式指定了值。
//在你的例子中，Register 枚举类型定义了16个成员，
//分别对应于x86 - 64架构中的通用寄存器 RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, R8, R9, R10, R11, R12, R13, R14, R15。
//这些枚举成员可以在代码中作为变量类型或者函数参数类型使用，有助于代码的可读性和维护性。

// 定义寄存器枚举
typedef enum {
    RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, R8, R9, R10, R11, R12, R13, R14, R15
} Register;

// 定义数据大小
typedef enum {
    BYTE_SIZE, WORD_SIZE, DWORD_SIZE, QWORD_SIZE
} DataSize;

typedef union {
    UINT64 r64;  // 64位寄存器（例如：rax, rbx, ...）
    UINT32 r32;  // 32位寄存器（例如：eax, ebx, ...）
    UINT16 r16;  // 16位寄存器（例如：ax, bx, ...）
    UINT8  r8;   // 8位寄存器（例如：al, bl, ...）
} RegisterValue;

// 定义 EFLAGS 寄存器的结构体
typedef struct {
    bool CF;  // Carry Flag
    bool PF;  // Parity Flag
    bool AF;  // Auxiliary Carry Flag
    bool ZF;  // Zero Flag
    bool SF;  // Sign Flag
    bool TF;  // Trap Flag
    bool IF;  // Interrupt Enable Flag
    bool DF;  // Direction Flag
    bool OF;  // Overflow Flag
    // 其他标志位可根据需要添加 
} RFLAGS;


// 定义虚拟 cpu 结构体
typedef struct {
    RegisterValue registers[NUM_REGISTERS]; // 寄存器
    long long EIP;     // 要执行下一条的指令编号  EIP 功能
    char* stack_base;                       // 栈基址
    char* stack_pointer;                    // 栈指针

    int num;                   // 指令数量  判断是否执行完毕
    RFLAGS rflags;      //  定义实现 eflags 寄存器

    int execute_ret_addr[20];  // 可以连续存放20个call的返回地址
    int execute_ret_addr_num;  // 记录 压入 execute_ret_addr 的指令序号的个数


} VM_registers;





// 解析 RFLAGS 寄存器的值并赋值给结构体
void parse_Rflags(ULONG64 rflags_value, RFLAGS* flags) {
    flags->CF = (rflags_value >> 0) & 1;
    flags->PF = (rflags_value >> 2) & 1;
    flags->AF = (rflags_value >> 4) & 1;
    flags->ZF = (rflags_value >> 6) & 1;
    flags->SF = (rflags_value >> 7) & 1;
    flags->TF = (rflags_value >> 8) & 1;
    flags->IF = (rflags_value >> 9) & 1;
    flags->DF = (rflags_value >> 10) & 1;
    flags->OF = (rflags_value >> 11) & 1;
}


char* create_stack()
{

    char* addr = (char*)malloc(4 * 1024);
    return addr;

}

//初始化虚拟机的寄存器：
void init_vm(VM_registers* vm_registers) {
    for (int i = 0; i < NUM_REGISTERS; i++) {

        vm_registers->registers[i].r64 = 0;
    }
    //                 [                   3072                    ][       1024        ]
    //  create_stack()*=========================================== RSP=================RBP

    vm_registers->registers[RBP].r64 = 0;
    vm_registers->registers[RSP].r64 = (UINT64)(create_stack() + 4000);
    vm_stack_low = vm_registers->registers[RSP].r64;
    vm_registers->EIP = 0;  //  从第一条指令开始
    for (int i = 0; i < 20; i++) {
        vm_registers->execute_ret_addr[i] = 0;
    }
    vm_registers->execute_ret_addr_num = 0;

    get_efl();
    //  vm_registers->Eflag = EFL; // 获取到当前efl 寄存器的值并赋值给 Eflag

    parse_Rflags(EFL, &(vm_registers->rflags));  //  初始化 efl寄存器

}
//创建一个将寄存器名称映射到索引的函数：
Register get_register(const char* name) {
    if (strcmp(name, "rax") == 0) return RAX;
    if (strcmp(name, "rbx") == 0) return RBX;
    if (strcmp(name, "rcx") == 0) return RCX;
    if (strcmp(name, "rdx") == 0) return RDX;
    if (strcmp(name, "rsi") == 0) return RSI;
    if (strcmp(name, "rdi") == 0) return RDI;
    if (strcmp(name, "rsp") == 0) return RSP;
    if (strcmp(name, "rbp") == 0) return RBP;
    if (strcmp(name, "r8") == 0) return R8;
    if (strcmp(name, "r9") == 0) return R9;
    if (strcmp(name, "r10") == 0) return R10;
    if (strcmp(name, "r11") == 0) return R11;
    if (strcmp(name, "r12") == 0) return R12;
    if (strcmp(name, "r13") == 0) return R13;
    if (strcmp(name, "r14") == 0) return R14;
    if (strcmp(name, "r15") == 0) return R15;
    fprintf(stderr, "Unknown register: %s\n", name);
    exit(1);
}


// 每执行一次指令，指令号就+1，如果遇到跳转指令就将跳转指令号赋值给指令号

int execute_lodsd(VM_registers* vm_registers, const char* dst, const char* src)
{
    Register dst_reg;

    //  获取dst寄存器

    if (dst[0] == 'r')
    {
        dst_reg = get_register(dst);

    }
    else if (dst[0] == 'e')
    {
        if (dst[1] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst[1] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst[1] == 'c')
        {

            dst_reg = get_register("rcx");
        }

        else if (dst[1] == 's')
        {

            dst_reg = get_register("rsi");
        }
        else if (dst[1] == 'd' && dst[2] == 'i')
        {

            dst_reg = get_register("rdi");
        }
        else if (dst[1] == 'd')
        {

            dst_reg = get_register("rdx");
        }

    }
    else if (dst[0] == 'a')
    {
        dst_reg = get_register("rax");

    }
    else if (dst[0] == 'b')
    {
        dst_reg = get_register("rbx");
    }
    else if (dst[0] == 'c')
    {

        dst_reg = get_register("rcx");
    }
    else if (dst[0] == 'd')
    {

        dst_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }

    vm_registers->registers[dst_reg].r64 = 0;

    Register src_reg;

    if (src[0] == 'q' || src[0] == 'd' || src[0] == 'w' || src[0] == 'b')
    {   // 获取 【】 中的值
        char* size = strtok((char*)src, " ");          // qword 
        char* type = strtok(NULL, " ");                // ptr

        char* first_arg = strtok(NULL, " ");  // [rdi] 


        char* left = strtok(first_arg, "[");                // +

        char* src_arg = strtok(left, "]");  // rsp


        if (src_arg[0] == 'r')
        {
            src_reg = get_register(src_arg);

        }
        else if (src_arg[0] == 'e')
        {
            if (src_arg[1] == 'a')
            {
                src_reg = get_register("rax");

            }
            else if (src_arg[1] == 'b')
            {
                src_reg = get_register("rbx");
            }
            else if (src_arg[1] == 'c')
            {

                src_reg = get_register("rcx");
            }

            else if (src_arg[1] == 's')
            {

                src_reg = get_register("rsi");
            }
            else if (src_arg[1] == 'd' && src_arg[2] == 'i')
            {

                src_reg = get_register("rdi");
            }
            else if (src_arg[1] == 'd')
            {

                src_reg = get_register("rdx");
            }

        }
        else  if (src_arg[0] == 'a')
        {
            src_reg = get_register("rax");

        }
        else if (src_arg[0] == 'b')
        {
            src_reg = get_register("rbx");
        }
        else if (src_arg[0] == 'c')
        {

            src_reg = get_register("rcx");
        }
        else if (src_arg[0] == 'd')
        {

            src_reg = get_register("rdx");
        }
        else
        {

            printf("error");
        }

    }

    DataSize offset_type = (src[0] == 'b') ? BYTE_SIZE : (src[0] == 'w') ? WORD_SIZE : (src[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
    switch (offset_type) {
    case BYTE_SIZE:
        vm_registers->registers[dst_reg].r64 = *((UINT8*)(vm_registers->registers[src_reg].r64));
        if (vm_registers->rflags.DF == true)
        {
            vm_registers->registers[src_reg].r64 = vm_registers->registers[src_reg].r64 - 1;
        }
        else {
            vm_registers->registers[src_reg].r64 = vm_registers->registers[src_reg].r64 + 1;
        }
        break;
    case WORD_SIZE:
        vm_registers->registers[dst_reg].r64 = *((UINT16*)(vm_registers->registers[src_reg].r64));
        if (vm_registers->rflags.DF == true)
        {
            vm_registers->registers[src_reg].r64 = vm_registers->registers[src_reg].r64 - 2;
        }
        else
        {
            vm_registers->registers[src_reg].r64 = vm_registers->registers[src_reg].r64 + 2;
        }
        break;
    case DWORD_SIZE:
        vm_registers->registers[dst_reg].r64 = *((UINT32*)(vm_registers->registers[src_reg].r64));
        if (vm_registers->rflags.DF == true)
        {
            vm_registers->registers[src_reg].r64 = vm_registers->registers[src_reg].r64 - 4;
        }
        else
        {
            vm_registers->registers[src_reg].r64 = vm_registers->registers[src_reg].r64 + 4;
        }
        break;
    case QWORD_SIZE:
        vm_registers->registers[dst_reg].r64 = *((UINT64*)(vm_registers->registers[src_reg].r64));
        if (vm_registers->rflags.DF == true)
        {
            vm_registers->registers[src_reg].r64 = vm_registers->registers[src_reg].r64 - 8;
        }
        else
        {
            vm_registers->registers[src_reg].r64 = vm_registers->registers[src_reg].r64 + 8;
        } break;
    }
    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;
}
int execute_ror(VM_registers* vm_registers, const char* dst, const char* src)
{
    Register dst_reg;

    //  获取dst寄存器

    if (dst[0] == 'r')
    {
        dst_reg = get_register(dst);

    }
    else if (dst[0] == 'e')
    {
        if (dst[1] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst[1] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst[1] == 'c')
        {

            dst_reg = get_register("rcx");
        }

        else if (dst[1] == 's')
        {

            dst_reg = get_register("rsi");
        }
        else if (dst[1] == 'd' && dst[2] == 'i')
        {

            dst_reg = get_register("rdi");
        }
        else if (dst[1] == 'd')
        {

            dst_reg = get_register("rdx");
        }
    }
    else if (dst[0] == 'a')
    {
        dst_reg = get_register("rax");

    }
    else if (dst[0] == 'b')
    {
        dst_reg = get_register("rbx");
    }
    else if (dst[0] == 'c')
    {

        dst_reg = get_register("rcx");
    }
    else if (dst[0] == 'd')
    {

        dst_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }

    ULONG64 num = 0;
    sscanf(src, "%x", &num); // 8

    vm_registers->registers[dst_reg].r64 = (vm_registers->registers[dst_reg].r64 >> num) | (vm_registers->registers[dst_reg].r64 << (32 - num));


    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;

}
int execute_dec(VM_registers* vm_registers, const char* dst)
{
    Register dst_reg;

    //  获取dst寄存器

    if (dst[0] == 'r')
    {
        dst_reg = get_register(dst);
        vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 - 1;
    }
    else if (dst[0] == 'e')
    {
        if (dst[1] == 'a')
        {
            dst_reg = get_register("rax");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 - 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }
        else if (dst[1] == 'b')
        {
            dst_reg = get_register("rbx");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 - 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }
        else if (dst[1] == 'c')
        {

            dst_reg = get_register("rcx");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 - 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }

        else if (dst[1] == 's')
        {

            dst_reg = get_register("rsi");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 - 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }
        else if (dst[1] == 'd' && dst[2] == 'i')
        {

            dst_reg = get_register("rdi");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 - 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }
        else if (dst[1] == 'd')
        {

            dst_reg = get_register("rdx");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 - 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }

    }
    else if (dst[0] == 'a')
    {
        dst_reg = get_register("rax");
        vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 - 1;
        vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000ffff;
    }
    else if (dst[0] == 'b')
    {
        dst_reg = get_register("rbx");
        vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 - 1;
        vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000ffff;
    }
    else if (dst[0] == 'c')
    {

        dst_reg = get_register("rcx");
        vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 - 1;
        vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000ffff;
    }
    else if (dst[0] == 'd')
    {

        dst_reg = get_register("rdx");
        vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 - 1;
        vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 - 1;
        vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000ffff;
    }
    else
    {

        printf("error");
        return 1;
    }


    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;
}
int execute_inc(VM_registers* vm_registers, const char* dst)
{
    Register dst_reg;

    //  获取dst寄存器

    if (dst[0] == 'r')
    {
        dst_reg = get_register(dst);
        vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 + 1;

    }
    else if (dst[0] == 'e')
    {
        if (dst[1] == 'a')
        {
            dst_reg = get_register("rax");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 + 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }
        else if (dst[1] == 'b')
        {
            dst_reg = get_register("rbx");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 + 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }
        else if (dst[1] == 'c')
        {

            dst_reg = get_register("rcx");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 + 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }
        else if (dst[1] == 'd')
        {

            dst_reg = get_register("rdx");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 + 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }
        else if (dst[1] == 's')
        {

            dst_reg = get_register("rsi");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 + 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }
        else if (dst[1] == 'd' && dst[2] == 'i')
        {

            dst_reg = get_register("rdi");
            vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 + 1;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000ffffffff;
        }

    }
    else if (dst[0] == 'a')
    {
        dst_reg = get_register("rax");
        vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 + 1;
        vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000ffff;

    }
    else if (dst[0] == 'b')
    {
        dst_reg = get_register("rbx");
        vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 + 1;
        vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000ffff;
    }
    else if (dst[0] == 'c')
    {

        dst_reg = get_register("rcx");
        vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 + 1;
        vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000ffff;
    }
    else if (dst[0] == 'd')
    {

        dst_reg = get_register("rdx");
        vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 + 1;
        vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000ffff;
    }
    else
    {

        printf("error");
    }


    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;
}
int execute_shl(VM_registers* vm_registers, const char* dst, const char* src)
{
    Register dst_reg;

    //  获取dst寄存器

    if (dst[0] == 'r')
    {
        dst_reg = get_register(dst);

    }
    else if (dst[0] == 'e')
    {
        if (dst[1] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst[1] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst[1] == 'c')
        {

            dst_reg = get_register("rcx");
        }
        else if (dst[1] == 's')
        {

            dst_reg = get_register("rsi");
        }
        else if (dst[1] == 'd' && dst[2] == 'i')
        {

            dst_reg = get_register("rdi");
        }
        else if (dst[1] == 'd')
        {

            dst_reg = get_register("rdx");
        }

    }
    else if (dst[0] == 'a')
    {
        dst_reg = get_register("rax");

    }
    else if (dst[0] == 'b')
    {
        dst_reg = get_register("rbx");
    }
    else if (dst[0] == 'c')
    {

        dst_reg = get_register("rcx");
    }
    else if (dst[0] == 'd')
    {

        dst_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }

    ULONG64 num = 0;
    sscanf(src, "%x", &num); // 8


    vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 << num;
    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;

}
int execute_shr(VM_registers* vm_registers, const char* dst, const char* src)
{
    Register dst_reg;

    //  获取dst寄存器

    if (dst[0] == 'r')
    {
        dst_reg = get_register(dst);

    }
    else if (dst[0] == 'e')
    {
        if (dst[1] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst[1] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst[1] == 'c')
        {

            dst_reg = get_register("rcx");
        }
        else if (dst[1] == 's')
        {

            dst_reg = get_register("rsi");
        }
        else if (dst[1] == 'd' && dst[2] == 'i')
        {

            dst_reg = get_register("rdi");
        }
        else if (dst[1] == 'd')
        {

            dst_reg = get_register("rdx");
        }

    }
    else if (dst[0] == 'a')
    {
        dst_reg = get_register("rax");

    }
    else if (dst[0] == 'b')
    {
        dst_reg = get_register("rbx");
    }
    else if (dst[0] == 'c')
    {

        dst_reg = get_register("rcx");
    }
    else if (dst[0] == 'd')
    {

        dst_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }

    ULONG64 num = 0;
    sscanf(src, "%x", &num); // 8


    vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 >> num;
    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;

}
int execute_movabs(VM_registers* vm_registers, const char* dst, const char* src)
{

    Register dst_reg;

    //  获取dst寄存器

    if (dst[0] == 'r')
    {
        dst_reg = get_register(dst);

    }
    else if (dst[0] == 'e')
    {
        if (dst[1] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst[1] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst[1] == 'c')
        {

            dst_reg = get_register("rcx");
        }
        else if (dst[1] == 's')
        {

            dst_reg = get_register("rsi");
        }
        else if (dst[1] == 'd' && dst[2] == 'i')
        {

            dst_reg = get_register("rdi");
        }
        else if (dst[1] == 'd')
        {

            dst_reg = get_register("rdx");
        }

    }
    else if (dst[0] == 'a')
    {
        dst_reg = get_register("rax");

    }
    else if (dst[0] == 'b')
    {
        dst_reg = get_register("rbx");
    }
    else if (dst[0] == 'c')
    {

        dst_reg = get_register("rcx");
    }
    else if (dst[0] == 'd')
    {

        dst_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }

    ULONG64 num1 = 0;
    sscanf(src, "%llx", &num1); // 8
    printf("src的值：%llx\n", num1);

    vm_registers->registers[dst_reg].r64 = num1;
    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;



}
int execute_movsx(VM_registers* vm_registers, const char* dst, const char* src)
{
    printf("execute_movsx执行\n");

    if ((dst[0] == 'r' || dst[0] == 'e' || dst[0] == 'a' || dst[0] == 'b' || dst[0] == 'c' || dst[0] == 'd') && (dst[1] == 'a' || dst[1] == 'b' || dst[1] == 'c' || dst[1] == 'd' || dst[1] == 's' || dst[1] == '8' || dst[1] == '9' || dst[1] == '1' || dst[1] == 'x'))

    {
        int reg_type = 0;
        printf("第一个参数是寄存器\n");
        Register dst_reg;
        if (dst[0] == 'r')
        {
            reg_type = 64;
            dst_reg = get_register(dst);

        }
        else if (dst[0] == 'e')
        {
            if (dst[1] == 'a')
            {
                dst_reg = get_register("rax");
                reg_type = 64;
            }
            else if (dst[1] == 'b')
            {
                reg_type = 64;
                dst_reg = get_register("rbx");
            }
            else if (dst[1] == 'c')
            {
                reg_type = 64;
                dst_reg = get_register("rcx");
            }

            else if (dst[1] == 's')
            {
                reg_type = 64;
                dst_reg = get_register("rsi");
            }
            else if (dst[1] == 'd' && dst[2] == 'i')
            {
                reg_type = 64;
                dst_reg = get_register("rdi");
            }
            else if (dst[1] == 'd')
            {
                reg_type = 64;
                dst_reg = get_register("rdx");
            }

        }
        else  if (dst[0] == 'a')
        {
            dst_reg = get_register("rax");
            reg_type = 16;
        }
        else if (dst[0] == 'b')
        {
            reg_type = 16;
            dst_reg = get_register("rbx");
        }
        else if (dst[0] == 'c')
        {
            reg_type = 16;
            dst_reg = get_register("rcx");
        }
        else if (dst[0] == 'd')
        {
            reg_type = 16;
            dst_reg = get_register("rdx");
        }
        else
        {

            printf("error");
        }





        if (src[0] == 'q' || src[0] == 'd' || src[0] == 'w' || src[0] == 'b')
        {
            char src_temp[50];
            strcpy(src_temp, src); // 复制字符串到可修改的缓冲区

            //  定义 [] 中的 地址
            ULONG64 target_addr = 0;

            char* ji_lu_arg[10];
            int num = 0;
            CHAR* arg1 = strtok(src_temp, " "); // 获取空格为分隔符的第一个字符串  QWORD
            printf("截取的字符串：%s\n", arg1);
            arg1 = strtok(NULL, " ");  //ptr
            printf("截取的字符串：%s\n", arg1);
            arg1 = strtok(NULL, "["); // [rsp
            arg1 = strtok(arg1, "]"); // [rsp

            // 如果是 [rsp] 
            // 否则 可能的结果
            // 1、 [rbx + 0x3c]
            // 2、 [rbx + rcx]
            // 3、 [rbx + rcx*3]
            // 4、 [rbx + rcx + 0x88]
            // 
            // 所以要先获取到  【】 中的所有参数，再依次判断出每个参数是什么类型

            if (arg1 != NULL)
            {
                char* token = strtok(arg1, " ");
                while (token != NULL) {
                    printf("截取的字符串：%s\n", token);


                    ji_lu_arg[num] = (char*)malloc(strlen(token) + 1);
                    strcpy(ji_lu_arg[num], token);
                    num++;
                    token = strtok(NULL, " ");  // 继续解析下一个部分


                }
            }

            printf("num:%d\n", num);

            // 依次识别 每个参数的种类 判断参数个数1, 3, 5
            if (num == 1)
            {
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");

                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                    }
                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                }
                else
                {

                    printf("error");
                    return 0;
                }

                target_addr = target_addr + vm_registers->registers[reg1].r64;
            }
            else if (num == 3)// 如果 两个参数 一个 符号
            {
                // 确定第一个是什么寄存器
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);
                    target_addr = target_addr + vm_registers->registers[reg1].r64;
                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }

                // 判断第二个 是否有 * 符号
                int symbol_flag = 0;
                char symbol = NULL;

                for (int i = 0; i < strlen(ji_lu_arg[2]); i++)
                {
                    if (ji_lu_arg[2][i] == '*')
                    {
                        symbol_flag = 1;
                        symbol = '*';
                    }

                }
                //如果有*，进行分离，识别寄存器，符号，和立即数
                if (symbol_flag == 1)//rcx*0x3
                {
                    char* a1 = strtok(ji_lu_arg[2], "*");// rcx
                    char* a2 = strtok(NULL, "*");        // 0x3

                    int a2_num = 0;
                    sscanf(a2, "%x", &a2_num); // 3
                    // 判断 a1是什么寄存器
                    Register reg2;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (a1[0] == 'r')
                    {
                        reg2 = get_register(a1);
                        target_addr = target_addr + vm_registers->registers[reg2].r64 * a2_num;
                    }
                    else if (a1[0] == 'e')
                    {
                        if (a1[1] == 'a')
                        {
                            reg2 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'b')
                        {
                            reg2 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'c')
                        {

                            reg2 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }

                        else if (a1[1] == 's')
                        {

                            reg2 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'd' && a1[2] == 'i')
                        {

                            reg2 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'd')
                        {

                            reg2 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }

                    }
                    else if (a1[0] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }



                }
                // 如果没有 识别第二个参数是寄存器还是立即数
                else
                {
                    Register reg2;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (ji_lu_arg[2][0] == 'r')
                    {
                        reg2 = get_register(ji_lu_arg[2]);
                        target_addr = target_addr + vm_registers->registers[reg2].r64;
                    }
                    else if (ji_lu_arg[2][0] == 'e')
                    {
                        if (ji_lu_arg[2][1] == 'a')
                        {
                            reg2 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'b')
                        {
                            reg2 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'c')
                        {

                            reg2 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }

                        else if (ji_lu_arg[2][1] == 's')
                        {

                            reg2 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                        {

                            reg2 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'd')
                        {

                            reg2 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }

                    }
                    else if (ji_lu_arg[2][0] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else // 不是寄存器是立即数
                    {


                        sscanf(ji_lu_arg[2], "%x", &offset_num); // 8
                        target_addr = target_addr + offset_num;

                    }
                }


            }
            else if (num == 5) // 三个参数 一个 符号
            {
                // 确定第一个是什么寄存器
                // 确定第二个是什么寄存器

                // 判断第二个是不是 寄存器
                // 
                //       如果是确定是什么寄存器
                //           如果不是 判断是否有加减乘除符号
                //               如果有则提取并计算
                //               如果没有则可以确定为立即数

                // 确定第一个是什么寄存器
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);
                    target_addr = target_addr + vm_registers->registers[reg1].r64;

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;

                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }

                // 确定第二个是什么寄存器
                Register reg2;
                if (ji_lu_arg[2][0] == 'r')
                {
                    reg2 = get_register(ji_lu_arg[2]);
                    target_addr = target_addr + vm_registers->registers[reg2].r64;

                }
                else if (ji_lu_arg[2][0] == 'e')
                {
                    if (ji_lu_arg[2][1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;

                    }
                    else if (ji_lu_arg[2][1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                    else if (ji_lu_arg[2][1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                }
                else if (ji_lu_arg[2][0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;

                }
                else if (ji_lu_arg[2][0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }


                // 判断第三个参数中是否有加减乘除符号
                int symbol_flag = 0;
                char symbol = NULL;

                for (int i = 0; i < strlen(ji_lu_arg[4]); i++)
                {
                    if (ji_lu_arg[4][i] == '*')
                    {
                        symbol_flag = 1;
                        symbol = '*';
                    }

                }
                //如果有*，进行分离，识别寄存器，符号，和立即数
                if (symbol_flag == 1)
                {
                    char* a1 = strtok(ji_lu_arg[4], "*");
                    char* a2 = strtok(NULL, "*");

                    int a2_num = 0;
                    sscanf(a2, "%x", &a2_num); // 8
                    // 判断 a1是什么寄存器
                    Register reg3;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (a1[0] == 'r')
                    {
                        reg3 = get_register(a1);

                        target_addr = target_addr + vm_registers->registers[reg3].r64 * a2_num;
                    }
                    else if (a1[0] == 'e')
                    {
                        if (a1[1] == 'a')
                        {
                            reg3 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'b')
                        {
                            reg3 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'c')
                        {

                            reg3 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }

                        else if (a1[1] == 's')
                        {

                            reg3 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'd' && a1[2] == 'i')
                        {

                            reg3 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'd')
                        {

                            reg3 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }

                    }
                    else if (a1[0] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }




                }
                // 如果没有 识别第二个参数是寄存器还是立即数
                else
                {
                    Register reg3;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (ji_lu_arg[4][0] == 'r')
                    {
                        reg3 = get_register(ji_lu_arg[4]);
                        target_addr = target_addr + vm_registers->registers[reg3].r64;
                    }
                    else if (ji_lu_arg[4][0] == 'e')
                    {
                        if (ji_lu_arg[4][1] == 'a')
                        {
                            reg3 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'b')
                        {
                            reg3 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'c')
                        {

                            reg3 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }

                        else if (ji_lu_arg[4][1] == 's')
                        {

                            reg3 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'd' && ji_lu_arg[4][2] == 'i')
                        {

                            reg3 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'd')
                        {

                            reg3 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }

                    }
                    else if (ji_lu_arg[4][0] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else // 不是寄存器是立即数
                    {


                        sscanf(ji_lu_arg[4], "%x", &offset_num); // 8
                        target_addr = target_addr + offset_num;

                    }
                }

            }
            else
            {

                printf("error");
                return 0;
            }


            // 按照指定的大小开始赋值，x86-64 架构的一个特性，当对 32 位寄存器操作时，其对应的 64 位寄存器的高 32 位会被自动清零。
            vm_registers->registers[dst_reg].r64 = 0;
            printf("target_addr:%x\n", target_addr);

            if (reg_type == 64)
            {
                DataSize offset_type = (src[0] == 'b') ? BYTE_SIZE : (src[0] == 'w') ? WORD_SIZE : (src[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
                switch (offset_type) {
                case BYTE_SIZE: vm_registers->registers[dst_reg].r64 = *((INT8*)target_addr); break;
                case WORD_SIZE: vm_registers->registers[dst_reg].r64 = *((INT16*)target_addr); break;
                case DWORD_SIZE: vm_registers->registers[dst_reg].r64 = *((INT32*)target_addr); break;
                case QWORD_SIZE: vm_registers->registers[dst_reg].r64 = *((INT64*)target_addr); break;

                }
            }
            else if (reg_type == 32)
            {
                DataSize offset_type = (src[0] == 'b') ? BYTE_SIZE : (src[0] == 'w') ? WORD_SIZE : (src[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
                switch (offset_type) {
                case BYTE_SIZE: vm_registers->registers[dst_reg].r32 = *((INT8*)target_addr); break;
                case WORD_SIZE: vm_registers->registers[dst_reg].r32 = *((INT16*)target_addr); break;
                case DWORD_SIZE: vm_registers->registers[dst_reg].r32 = *((INT32*)target_addr); break;
                case QWORD_SIZE: vm_registers->registers[dst_reg].r32 = *((INT64*)target_addr); break;

                }
            }
            else if (reg_type == 16)
            {
                DataSize offset_type = (src[0] == 'b') ? BYTE_SIZE : (src[0] == 'w') ? WORD_SIZE : (src[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
                switch (offset_type) {
                case BYTE_SIZE: vm_registers->registers[dst_reg].r16 = *((INT8*)target_addr); break;
                case WORD_SIZE: vm_registers->registers[dst_reg].r16 = *((INT16*)target_addr); break;
                case DWORD_SIZE: vm_registers->registers[dst_reg].r16 = *((INT32*)target_addr); break;
                case QWORD_SIZE: vm_registers->registers[dst_reg].r16 = *((INT64*)target_addr); break;

                }
            }




        }

        else {   // 如果第二个参数是 立即数
            UINT64 num = 0;
            sscanf(src, "%llx", &num);

            // 立即数赋值
            vm_registers->registers[dst_reg].r64 = 0;
            vm_registers->registers[dst_reg].r64 = num;
        }
    }

    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;
}
// mov  寄存 , 寄存器
int execute_mov(VM_registers* vm_registers, const char* dst, const char* src)
{
    //开始判断 寄存器还是立即数

        // 如果 第一个参数是寄存器
    int reg_type = 0;

    if (strcmp(src, "qword ptr gs:[0x60]") == 0)
    {
        Register dst_reg;

        //  获取dst寄存器

        if (dst[0] == 'r')
        {
            dst_reg = get_register(dst);

        }
        else if (dst[0] == 'e')
        {
            if (dst[1] == 'a')
            {
                dst_reg = get_register("rax");

            }
            else if (dst[1] == 'b')
            {
                dst_reg = get_register("rbx");
            }
            else if (dst[1] == 'c')
            {

                dst_reg = get_register("rcx");
            }

            else if (dst[1] == 's')
            {

                dst_reg = get_register("rsi");
            }
            else if (dst[1] == 'd' && dst[2] == 'i')
            {

                dst_reg = get_register("rdi");
            }
            else if (dst[1] == 'd')
            {

                dst_reg = get_register("rdx");
            }
        }
        else if (dst[0] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst[0] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst[0] == 'c')
        {

            dst_reg = get_register("rcx");
        }
        else if (dst[0] == 'd')
        {

            dst_reg = get_register("rdx");
        }
        else
        {

            printf("error");
        }


        vm_registers->registers[dst_reg].r64 = (ULONG64)__readgsqword(0x60);


    }

    else if ((dst[0] == 'r' || dst[0] == 'e' || dst[0] == 'a' || dst[0] == 'b' || dst[0] == 'c' || dst[0] == 'd') && (dst[1] == 'a' || dst[1] == 'b' || dst[1] == 'c' || dst[1] == 'd' || dst[1] == 's' || dst[1] == '8' || dst[1] == '9' || dst[1] == '1' || dst[1] == 'x'))

    {

        printf("第一个参数是寄存器\n");
        Register dst_reg;
        if (dst[0] == 'r')
        {
            reg_type = 64;
            dst_reg = get_register(dst);

        }
        else if (dst[0] == 'e')
        {
            if (dst[1] == 'a')
            {
                dst_reg = get_register("rax");
                reg_type = 64;
            }
            else if (dst[1] == 'b')
            {
                reg_type = 64;
                dst_reg = get_register("rbx");
            }
            else if (dst[1] == 'c')
            {
                reg_type = 64;
                dst_reg = get_register("rcx");
            }

            else if (dst[1] == 's')
            {
                reg_type = 64;
                dst_reg = get_register("rsi");
            }
            else if (dst[1] == 'd' && dst[2] == 'i')
            {
                reg_type = 64;
                dst_reg = get_register("rdi");
            }
            else if (dst[1] == 'd')
            {
                reg_type = 64;
                dst_reg = get_register("rdx");
            }

        }
        else  if (dst[0] == 'a')
        {
            dst_reg = get_register("rax");
            reg_type = 16;
        }
        else if (dst[0] == 'b')
        {
            reg_type = 16;
            dst_reg = get_register("rbx");
        }
        else if (dst[0] == 'c')
        {
            reg_type = 16;
            dst_reg = get_register("rcx");
        }
        else if (dst[0] == 'd')
        {
            reg_type = 16;
            dst_reg = get_register("rdx");
        }
        else
        {

            printf("error");
        }



        if (reg_type == 64)
        {

        }
        else if (reg_type == 32)
        {
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000FFFFFFFF;

        }
        else if (reg_type == 16)
        {
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000FFFF;

        }

        //如果 第二个参数是 寄存器
        if ((src[0] == 'r' || src[0] == 'e' || src[0] == 'a' || src[0] == 'b' || src[0] == 'c' || src[0] == 'd') && (src[1] == 'a' || src[1] == 'b' || src[1] == 'c' || src[1] == 'd' || src[1] == 's' || src[1] == '8' || src[1] == '9' || src[1] == '1' || src[1] == 'x'))
        {

            Register src_reg;

            if (src[0] == 'r')
            {

                src_reg = get_register(src);

            }
            else if (src[0] == 'e')
            {
                if (src[1] == 'a')
                {

                    src_reg = get_register("rax");

                }
                else if (src[1] == 'b')
                {

                    src_reg = get_register("rbx");
                }
                else if (src[1] == 'c')
                {

                    src_reg = get_register("rcx");
                }

                else if (src[1] == 's')
                {

                    src_reg = get_register("rsi");
                }
                else if (src[1] == 'd' && src[2] == 'i')
                {

                    src_reg = get_register("rdi");
                }
                else if (src[1] == 'd')
                {

                    src_reg = get_register("rdx");
                }
            }
            else  if (src[0] == 'a')
            {

                src_reg = get_register("rax");

            }
            else if (src[0] == 'b')
            {

                src_reg = get_register("rbx");
            }
            else if (src[0] == 'c')
            {

                src_reg = get_register("rcx");
            }
            else if (src[0] == 'd')
            {

                src_reg = get_register("rdx");
            }
            else
            {

                printf("error");
                return 1;
            }


            //   寄存器到寄存器赋值
            vm_registers->registers[dst_reg].r64 = 0;
            if (reg_type == 64)
            {
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[src_reg].r64;
            }
            else if (reg_type == 32)
            {
                vm_registers->registers[dst_reg].r32 = vm_registers->registers[src_reg].r32;
            }
            else if (reg_type == 16)
            {
                vm_registers->registers[dst_reg].r16 = vm_registers->registers[src_reg].r16;
            }

        }

        //如果  第二个参数是 qword ptr [rsp + 0x8]
        else if (src[0] == 'q' || src[0] == 'd' || src[0] == 'w' || src[0] == 'b')
        {
            char src_temp[50];
            strcpy(src_temp, src); // 复制字符串到可修改的缓冲区

            //  定义 [] 中的 地址
            ULONG64 target_addr = 0;

            char* ji_lu_arg[10];
            int num = 0;
            CHAR* arg1 = strtok(src_temp, " "); // 获取空格为分隔符的第一个字符串  QWORD
            printf("截取的字符串：%s\n", arg1);
            arg1 = strtok(NULL, " ");  //ptr
            printf("截取的字符串：%s\n", arg1);
            arg1 = strtok(NULL, "["); // [rsp
            arg1 = strtok(arg1, "]"); // [rsp

            // 如果是 [rsp] 
            // 否则 可能的结果
            // 1、 [rbx + 0x3c]
            // 2、 [rbx + rcx]
            // 3、 [rbx + rcx*3]
            // 4、 [rbx + rcx + 0x88]
            // 
            // 所以要先获取到  【】 中的所有参数，再依次判断出每个参数是什么类型

            if (arg1 != NULL)
            {
                char* token = strtok(arg1, " ");
                while (token != NULL) {
                    printf("截取的字符串：%s\n", token);


                    ji_lu_arg[num] = (char*)malloc(strlen(token) + 1);
                    strcpy(ji_lu_arg[num], token);
                    num++;
                    token = strtok(NULL, " ");  // 继续解析下一个部分


                }
            }

            printf("num:%d\n", num);

            // 依次识别 每个参数的种类 判断参数个数1, 3, 5
            if (num == 1)
            {
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");

                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                    }
                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                }
                else
                {

                    printf("error");
                    return 0;
                }

                target_addr = target_addr + vm_registers->registers[reg1].r64;
            }
            else if (num == 3)// 如果 两个参数 一个 符号
            {
                // 确定第一个是什么寄存器
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);
                    target_addr = target_addr + vm_registers->registers[reg1].r64;
                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }

                // 判断第二个 是否有 * 符号
                int symbol_flag = 0;
                char symbol = NULL;

                for (int i = 0; i < strlen(ji_lu_arg[2]); i++)
                {
                    if (ji_lu_arg[2][i] == '*')
                    {
                        symbol_flag = 1;
                        symbol = '*';
                    }

                }
                //如果有*，进行分离，识别寄存器，符号，和立即数
                if (symbol_flag == 1)//rcx*0x3
                {
                    char* a1 = strtok(ji_lu_arg[2], "*");// rcx
                    char* a2 = strtok(NULL, "*");        // 0x3

                    int a2_num = 0;
                    sscanf(a2, "%x", &a2_num); // 3
                    // 判断 a1是什么寄存器
                    Register reg2;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (a1[0] == 'r')
                    {
                        reg2 = get_register(a1);
                        target_addr = target_addr + vm_registers->registers[reg2].r64 * a2_num;
                    }
                    else if (a1[0] == 'e')
                    {
                        if (a1[1] == 'a')
                        {
                            reg2 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'b')
                        {
                            reg2 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'c')
                        {

                            reg2 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }

                        else if (a1[1] == 's')
                        {

                            reg2 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'd' && a1[2] == 'i')
                        {

                            reg2 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'd')
                        {

                            reg2 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }

                    }
                    else if (a1[0] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }



                }
                // 如果没有 识别第二个参数是寄存器还是立即数
                else
                {
                    Register reg2;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (ji_lu_arg[2][0] == 'r')
                    {
                        reg2 = get_register(ji_lu_arg[2]);
                        target_addr = target_addr + vm_registers->registers[reg2].r64;
                    }
                    else if (ji_lu_arg[2][0] == 'e')
                    {
                        if (ji_lu_arg[2][1] == 'a')
                        {
                            reg2 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'b')
                        {
                            reg2 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'c')
                        {

                            reg2 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }

                        else if (ji_lu_arg[2][1] == 's')
                        {

                            reg2 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                        {

                            reg2 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'd')
                        {

                            reg2 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }

                    }
                    else if (ji_lu_arg[2][0] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else // 不是寄存器是立即数
                    {


                        sscanf(ji_lu_arg[2], "%x", &offset_num); // 8
                        target_addr = target_addr + offset_num;

                    }
                }


            }
            else if (num == 5) // 三个参数 一个 符号
            {
                // 确定第一个是什么寄存器
                // 确定第二个是什么寄存器

                // 判断第二个是不是 寄存器
                // 
                //       如果是确定是什么寄存器
                //           如果不是 判断是否有加减乘除符号
                //               如果有则提取并计算
                //               如果没有则可以确定为立即数

                // 确定第一个是什么寄存器
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);
                    target_addr = target_addr + vm_registers->registers[reg1].r64;

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;

                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }

                // 确定第二个是什么寄存器
                Register reg2;
                if (ji_lu_arg[2][0] == 'r')
                {
                    reg2 = get_register(ji_lu_arg[2]);
                    target_addr = target_addr + vm_registers->registers[reg2].r64;

                }
                else if (ji_lu_arg[2][0] == 'e')
                {
                    if (ji_lu_arg[2][1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;

                    }
                    else if (ji_lu_arg[2][1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                    else if (ji_lu_arg[2][1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                }
                else if (ji_lu_arg[2][0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;

                }
                else if (ji_lu_arg[2][0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }


                // 判断第三个参数中是否有加减乘除符号
                int symbol_flag = 0;
                char symbol = NULL;

                for (int i = 0; i < strlen(ji_lu_arg[4]); i++)
                {
                    if (ji_lu_arg[4][i] == '*')
                    {
                        symbol_flag = 1;
                        symbol = '*';
                    }

                }
                //如果有*，进行分离，识别寄存器，符号，和立即数
                if (symbol_flag == 1)
                {
                    char* a1 = strtok(ji_lu_arg[4], "*");
                    char* a2 = strtok(NULL, "*");

                    int a2_num = 0;
                    sscanf(a2, "%x", &a2_num); // 8
                    // 判断 a1是什么寄存器
                    Register reg3;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (a1[0] == 'r')
                    {
                        reg3 = get_register(a1);

                        target_addr = target_addr + vm_registers->registers[reg3].r64 * a2_num;
                    }
                    else if (a1[0] == 'e')
                    {
                        if (a1[1] == 'a')
                        {
                            reg3 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'b')
                        {
                            reg3 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'c')
                        {

                            reg3 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }

                        else if (a1[1] == 's')
                        {

                            reg3 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'd' && a1[2] == 'i')
                        {

                            reg3 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'd')
                        {

                            reg3 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }

                    }
                    else if (a1[0] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }




                }
                // 如果没有 识别第二个参数是寄存器还是立即数
                else
                {
                    Register reg3;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (ji_lu_arg[4][0] == 'r')
                    {
                        reg3 = get_register(ji_lu_arg[4]);
                        target_addr = target_addr + vm_registers->registers[reg3].r64;
                    }
                    else if (ji_lu_arg[4][0] == 'e')
                    {
                        if (ji_lu_arg[4][1] == 'a')
                        {
                            reg3 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'b')
                        {
                            reg3 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'c')
                        {

                            reg3 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }

                        else if (ji_lu_arg[4][1] == 's')
                        {

                            reg3 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'd' && ji_lu_arg[4][2] == 'i')
                        {

                            reg3 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'd')
                        {

                            reg3 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                    }
                    else if (ji_lu_arg[4][0] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else // 不是寄存器是立即数
                    {


                        sscanf(ji_lu_arg[4], "%x", &offset_num); // 8
                        target_addr = target_addr + offset_num;

                    }
                }

            }
            else
            {

                printf("error");
                return 0;
            }


            // 按照指定的大小开始赋值，x86-64 架构的一个特性，当对 32 位寄存器操作时，其对应的 64 位寄存器的高 32 位会被自动清零。
            vm_registers->registers[dst_reg].r64 = 0;
            printf("target_addr:%x\n", target_addr);
            DataSize offset_type = (src[0] == 'b') ? BYTE_SIZE : (src[0] == 'w') ? WORD_SIZE : (src[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
            switch (offset_type) {
            case BYTE_SIZE: vm_registers->registers[dst_reg].r8 = *((UINT8*)target_addr); break;
            case WORD_SIZE: vm_registers->registers[dst_reg].r16 = *((UINT16*)target_addr); break;
            case DWORD_SIZE: vm_registers->registers[dst_reg].r32 = *((UINT32*)target_addr); break;
            case QWORD_SIZE: vm_registers->registers[dst_reg].r64 = *((UINT64*)target_addr); break;

            }



        }

        else {   // 如果第二个参数是 立即数
            UINT64 num = 0;
            sscanf(src, "%llx", &num);

            // 立即数赋值
            vm_registers->registers[dst_reg].r64 = 0;
            vm_registers->registers[dst_reg].r64 = num;
        }
    }

    // 如果 第一个参数qword ptr [rsp + 0x8]
    else if (dst[0] == 'q' || dst[0] == 'd' || dst[0] == 'w' || dst[0] == 'b')   //   dst 是 内存   
    {
        char src_temp[50];
        strcpy(src_temp, dst); // 复制字符串到可修改的缓冲区

        //  定义 [] 中的 地址
        ULONG64 target_addr = 0;

        char* ji_lu_arg[10];
        int num = 0;
        CHAR* arg1 = strtok(src_temp, " "); // 获取空格为分隔符的第一个字符串  QWORD
        printf("截取的字符串：%s\n", arg1);
        arg1 = strtok(NULL, " ");  //ptr
        printf("截取的字符串：%s\n", arg1);
        arg1 = strtok(NULL, "["); // [rsp
        arg1 = strtok(arg1, "]"); // [rsp

        // 如果是 [rsp] 
        // 否则 可能的结果
        // 1、 [rbx + 0x3c]
        // 2、 [rbx + rcx]
        // 3、 [rbx + rcx*3]
        // 4、 [rbx + rcx + 0x88]
        // 
        // 所以要先获取到  【】 中的所有参数，再依次判断出每个参数是什么类型

        if (arg1 != NULL)
        {
            char* token = strtok(arg1, " ");
            while (token != NULL) {
                printf("截取的字符串：%s\n", token);


                ji_lu_arg[num] = (char*)malloc(strlen(token) + 1);
                strcpy(ji_lu_arg[num], token);
                num++;
                token = strtok(NULL, " ");  // 继续解析下一个部分


            }
        }

        printf("num:%d\n", num);

        // 依次识别 每个参数的种类 判断参数个数1, 3, 5
        if (num == 1)
        {
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);

            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");

                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");
                }

                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");
                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                }
            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
            }
            else
            {

                printf("error");
                return 0;
            }

            target_addr = target_addr + vm_registers->registers[reg1].r64;
        }
        else if (num == 3)// 如果 两个参数 一个 符号
        {
            // 确定第一个是什么寄存器
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);
                target_addr = target_addr + vm_registers->registers[reg1].r64;
            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg1].r16;

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else
            {

                printf("error");
                return 0;
            }

            // 判断第二个 是否有 * 符号
            int symbol_flag = 0;
            char symbol = NULL;

            for (int i = 0; i < strlen(ji_lu_arg[2]); i++)
            {
                if (ji_lu_arg[2][i] == '*')
                {
                    symbol_flag = 1;
                    symbol = '*';
                }

            }
            //如果有*，进行分离，识别寄存器，符号，和立即数
            if (symbol_flag == 1)//rcx*0x3
            {
                char* a1 = strtok(ji_lu_arg[2], "*");// rcx
                char* a2 = strtok(NULL, "*");        // 0x3

                int a2_num = 0;
                sscanf(a2, "%x", &a2_num); // 3
                // 判断 a1是什么寄存器
                Register reg2;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (a1[0] == 'r')
                {
                    reg2 = get_register(a1);
                    target_addr = target_addr + vm_registers->registers[reg2].r64 * a2_num;
                }
                else if (a1[0] == 'e')
                {
                    if (a1[1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }

                    else if (a1[1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'd' && a1[2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }

                }
                else if (a1[0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }



            }
            // 如果没有 识别第二个参数是寄存器还是立即数
            else
            {
                Register reg2;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (ji_lu_arg[2][0] == 'r')
                {
                    reg2 = get_register(ji_lu_arg[2]);
                    target_addr = target_addr + vm_registers->registers[reg2].r64;
                }
                else if (ji_lu_arg[2][0] == 'e')
                {
                    if (ji_lu_arg[2][1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                    else if (ji_lu_arg[2][1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                }
                else if (ji_lu_arg[2][0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else // 不是寄存器是立即数
                {


                    sscanf(ji_lu_arg[2], "%x", &offset_num); // 8
                    target_addr = target_addr + offset_num;

                }
            }


        }
        else if (num == 5) // 三个参数 一个 符号
        {
            // 确定第一个是什么寄存器
            // 确定第二个是什么寄存器

            // 判断第二个是不是 寄存器
            // 
            //       如果是确定是什么寄存器
            //           如果不是 判断是否有加减乘除符号
            //               如果有则提取并计算
            //               如果没有则可以确定为立即数

            // 确定第一个是什么寄存器
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);
                target_addr = target_addr + vm_registers->registers[reg1].r64;

            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;

                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg1].r16;

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else
            {

                printf("error");
                return 0;
            }

            // 确定第二个是什么寄存器
            Register reg2;
            if (ji_lu_arg[2][0] == 'r')
            {
                reg2 = get_register(ji_lu_arg[2]);
                target_addr = target_addr + vm_registers->registers[reg2].r64;

            }
            else if (ji_lu_arg[2][0] == 'e')
            {
                if (ji_lu_arg[2][1] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;

                }
                else if (ji_lu_arg[2][1] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }

                else if (ji_lu_arg[2][1] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 's')
                {

                    reg2 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                {

                    reg2 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }

            }
            else if (ji_lu_arg[2][0] == 'a')
            {
                reg2 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg2].r16;

            }
            else if (ji_lu_arg[2][0] == 'b')
            {
                reg2 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else if (ji_lu_arg[2][0] == 'c')
            {

                reg2 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else if (ji_lu_arg[2][0] == 'd')
            {

                reg2 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else
            {

                printf("error");
                return 0;
            }


            // 判断第三个参数中是否有加减乘除符号
            int symbol_flag = 0;
            char symbol = NULL;

            for (int i = 0; i < strlen(ji_lu_arg[4]); i++)
            {
                if (ji_lu_arg[4][i] == '*')
                {
                    symbol_flag = 1;
                    symbol = '*';
                }

            }
            //如果有*，进行分离，识别寄存器，符号，和立即数
            if (symbol_flag == 1)
            {
                char* a1 = strtok(ji_lu_arg[4], "*");
                char* a2 = strtok(NULL, "*");

                int a2_num = 0;
                sscanf(a2, "%x", &a2_num); // 8
                // 判断 a1是什么寄存器
                Register reg3;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (a1[0] == 'r')
                {
                    reg3 = get_register(a1);

                    target_addr = target_addr + vm_registers->registers[reg3].r64 * a2_num;
                }
                else if (a1[0] == 'e')
                {
                    if (a1[1] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }

                    else if (a1[1] == 's')
                    {

                        reg3 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'd' && a1[2] == 'i')
                    {

                        reg3 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }

                }
                else if (a1[0] == 'a')
                {
                    reg3 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'b')
                {
                    reg3 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'c')
                {

                    reg3 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'd')
                {

                    reg3 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }




            }
            // 如果没有 识别第二个参数是寄存器还是立即数
            else
            {
                Register reg3;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (ji_lu_arg[4][0] == 'r')
                {
                    reg3 = get_register(ji_lu_arg[4]);
                    target_addr = target_addr + vm_registers->registers[reg3].r64;
                }
                else if (ji_lu_arg[4][0] == 'e')
                {
                    if (ji_lu_arg[4][1] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }

                    else if (ji_lu_arg[4][1] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 's')
                    {

                        reg3 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'd' && ji_lu_arg[4][2] == 'i')
                    {

                        reg3 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }

                }
                else if (ji_lu_arg[4][0] == 'a')
                {
                    reg3 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'b')
                {
                    reg3 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'c')
                {

                    reg3 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'd')
                {

                    reg3 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else // 不是寄存器是立即数
                {


                    sscanf(ji_lu_arg[4], "%x", &offset_num); // 8
                    target_addr = target_addr + offset_num;

                }
            }

        }
        else
        {

            printf("error");
            return 0;
        }


        // 按照指定的大小开始赋值，x86-64 架构的一个特性，当对 32 位寄存器操作时，其对应的 64 位寄存器的高 32 位会被自动清零。
       // vm_registers->registers[dst_reg].r64 = 0;
        printf("target_addr:%x\n", target_addr);


        // 第二个参数是寄存器
        if ((src[0] == 'r' || src[0] == 'e' || src[0] == 'a' || src[0] == 'b' || src[0] == 'c' || src[0] == 'd') && (src[1] == 'a' || src[1] == 'b' || src[1] == 'c' || src[1] == 'd' || src[1] == 's' || src[1] == '8' || src[1] == '9' || src[1] == '1' || src[1] == 'x'))
        {
            Register src_reg;

            if (src[0] == 'r')
            {
                src_reg = get_register(src);

            }
            else if (src[0] == 'e')
            {
                if (src[1] == 'a')
                {
                    src_reg = get_register("rax");

                }
                else if (src[1] == 'b')
                {
                    src_reg = get_register("rbx");
                }
                else if (src[1] == 'c')
                {

                    src_reg = get_register("rcx");
                }

                else if (src[1] == 's')
                {

                    src_reg = get_register("rsi");
                }
                else if (src[1] == 'd' && src[2] == 'i')
                {

                    src_reg = get_register("rdi");
                }
                else if (src[1] == 'd')
                {

                    src_reg = get_register("rdx");
                }

            }
            else if (src[0] == 'a')
            {
                src_reg = get_register("rax");

            }
            else if (src[0] == 'b')
            {
                src_reg = get_register("rbx");
            }
            else if (src[0] == 'c')
            {

                src_reg = get_register("rcx");
            }
            else if (src[0] == 'd')
            {

                src_reg = get_register("rdx");
            }
            else
            {

                printf("error");
            }


            // 按照指定的大小开始赋值
            DataSize offset_type = (dst[0] == 'b') ? BYTE_SIZE : (dst[0] == 'w') ? WORD_SIZE : (dst[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
            switch (offset_type) {
            case BYTE_SIZE:  ((UINT8*)target_addr)[0] = vm_registers->registers[src_reg].r8; break;
            case WORD_SIZE:  ((UINT16*)target_addr)[0] = vm_registers->registers[src_reg].r16; break;
            case DWORD_SIZE: ((UINT32*)target_addr)[0] = vm_registers->registers[src_reg].r32; break;
            case QWORD_SIZE: ((UINT64*)target_addr)[0] = vm_registers->registers[src_reg].r64; break;
            }

        }

        else { // 第二个参数是 立即数

            ULONG64 src_num = 0;
            sscanf(src, "%llx", &src_num); // 8

            DataSize offset_type = (dst[0] == 'b') ? BYTE_SIZE : (dst[0] == 'w') ? WORD_SIZE : (dst[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
            switch (offset_type) {
            case BYTE_SIZE:  ((UINT8*)target_addr)[0] = src_num; break;
            case WORD_SIZE:  ((UINT16*)target_addr)[0] = src_num; break;
            case DWORD_SIZE: ((UINT32*)target_addr)[0] = src_num; break;
            case QWORD_SIZE: ((UINT64*)target_addr)[0] = src_num; break;
            }

        }


        //    long long address = calculate_effective_address(vm, dst);
        // /*   if (address < 0 || address >= MEMORY_SIZE) {
        //        fprintf(stderr, "Memory address out of bounds: %lld\n", address);
        //        exit(1);
        //        */
        //    }



    }
    else {
        fprintf(stderr, "Invalid destination operand: %s\n", dst);
        //  vm_registers->EIP = vm_registers->EIP + 1;
        return 1;
    }
    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;

}
int execute_push(VM_registers* vm_registers, const char* arg)
{

    if (arg[0] == 'r' || arg[0] == 'e' || arg[0] == 'a' || arg[0] == 'b' || arg[0] == 'c' || arg[0] == 'd')
    {
        Register reg; // 要压入栈的寄存器

        if (arg[0] == 'r')
        {
            reg = get_register(arg);

        }
        else if (arg[0] == 'e')
        {
            if (arg[1] == 'a')
            {
                reg = get_register("rax");

            }
            else if (arg[1] == 'b')
            {
                reg = get_register("rbx");
            }
            else if (arg[1] == 'c')
            {

                reg = get_register("rcx");
            }
            else if (arg[1] == 's')
            {

                reg = get_register("rsi");
            }
            else if (arg[1] == 'd' && arg[2] == 'i')
            {

                reg = get_register("rdi");
            }
            else if (arg[1] == 'd')
            {

                reg = get_register("rdx");
            }

        }
        else if (arg[0] == 'a')
        {
            reg = get_register("rax");

        }
        else if (arg[0] == 'b')
        {
            reg = get_register("rbx");
        }
        else if (arg[0] == 'c')
        {
            reg = get_register("rcx");
        }
        else if (arg[0] == 'd')
        {
            reg = get_register("rdx");
        }
        else
        {
            printf("error");
        }


        LONG64 stack_src = (LONG64)(vm_registers->registers[get_register("rsp")].r64);
        // 将参数压入 栈中，
        *((UINT64*)(stack_src - 8)) = vm_registers->registers[reg].r64;
        //将rsp 的值 -8 
        (vm_registers->registers[get_register("rsp")].r64) = stack_src - 8;

    }
    else   // 立即数
    {
        int num = 0;
        sscanf(arg, "%x", &num); // 8

        LONG64 stack_src = (LONG64)(vm_registers->registers[get_register("rsp")].r64);
        // 将参数压入 栈中，
        ((UINT64*)(stack_src - 8))[0] = num;
        //将rsp 的值 -8 
        (vm_registers->registers[get_register("rsp")].r64) = stack_src - 8;

    }
    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;
}
int execute_pop(VM_registers* vm_registers, const char* arg)
{

    if (arg[0] == 'r' || arg[0] == 'e' || arg[0] == 'a' || arg[0] == 'b' || arg[0] == 'c' || arg[0] == 'd')
    {
        Register reg = get_register(arg); // 要压入栈的寄存器
        if (arg[0] == 'r')
        {
            reg = get_register(arg);

        }
        else if (arg[0] == 'e')
        {
            if (arg[1] == 'a')
            {
                reg = get_register("rax");

            }
            else if (arg[1] == 'b')
            {
                reg = get_register("rbx");
            }
            else if (arg[1] == 'c')
            {

                reg = get_register("rcx");
            }
            else if (arg[1] == 's')
            {

                reg = get_register("rsi");
            }
            else if (arg[1] == 'd' && arg[1] == 'i')
            {

                reg = get_register("rdi");
            }
            else if (arg[1] == 'd')
            {

                reg = get_register("rdx");
            }

        }
        else if (arg[0] == 'a')
        {
            reg = get_register("rax");

        }
        else if (arg[0] == 'b')
        {
            reg = get_register("rbx");
        }
        else if (arg[0] == 'c')
        {
            reg = get_register("rcx");
        }
        else if (arg[0] == 'd')
        {
            reg = get_register("rdx");
        }
        else
        {
            printf("error");
        }


        LONG64 stack_src = (LONG64)(vm_registers->registers[get_register("rsp")].r64);
        // 将参数压入 栈中，
        vm_registers->registers[reg].r64 = *((UINT64*)stack_src);
        //将rsp 的值 -8 
        (vm_registers->registers[get_register("rsp")].r64) = stack_src + 8;
        printf("pop 目标寄存器： %s  POP 后的值为 %x \n", arg, vm_registers->registers[reg].r64);
    }


    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;

}
int execute_sub(VM_registers* vm_registers, const char* dst, const char* src)
{
    //开始判断 寄存器还是立即数

       // 如果 第一个参数是寄存器
    int reg_type = 0;

    if ((dst[0] == 'r' || dst[0] == 'e' || dst[0] == 'a' || dst[0] == 'b' || dst[0] == 'c' || dst[0] == 'd') && (dst[1] == 'a' || dst[1] == 'b' || dst[1] == 'c' || dst[1] == 'd' || dst[1] == 's' || dst[1] == '8' || dst[1] == '9' || dst[1] == '1' || dst[1] == 'x'))

    {
        printf("第一个参数是寄存器\n");
        Register dst_reg;
        if (dst[0] == 'r')
        {
            reg_type == 64;
            dst_reg = get_register(dst);

        }
        else if (dst[0] == 'e')
        {
            if (dst[1] == 'a')
            {
                dst_reg = get_register("rax");
                reg_type == 32;
            }
            else if (dst[1] == 'b')
            {
                reg_type == 32;
                dst_reg = get_register("rbx");
            }
            else if (dst[1] == 'c')
            {
                reg_type == 32;
                dst_reg = get_register("rcx");
            }

            else if (dst[1] == 's')
            {
                reg_type == 32;
                dst_reg = get_register("rsi");
            }
            else if (dst[1] == 'd' && dst[2] == 'i')
            {
                reg_type == 32;
                dst_reg = get_register("rdi");
            }
            else if (dst[1] == 'd')
            {
                reg_type == 32;
                dst_reg = get_register("rdx");
            }

        }
        else  if (dst[0] == 'a')
        {
            reg_type == 16;
            dst_reg = get_register("rax");

        }
        else if (dst[0] == 'b')
        {
            reg_type == 16;
            dst_reg = get_register("rbx");
        }
        else if (dst[0] == 'c')
        {
            reg_type == 16;
            dst_reg = get_register("rcx");
        }
        else if (dst[0] == 'd')
        {
            reg_type == 16;
            dst_reg = get_register("rdx");
        }
        else
        {

            printf("error");
        }

        //if (reg_type == 64)
        //{

        //}
        //else if (reg_type == 32)
        //{
        //    vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000FFFFFFFF;
        //}
        //else if (reg_type == 16)
        //{
        //    vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000FFFFFFFF;
        //}

        //如果 第二个参数是 寄存器
        if ((src[0] == 'r' || src[0] == 'e' || src[0] == 'a' || src[0] == 'b' || src[0] == 'c' || src[0] == 'd') && (src[1] == 'a' || src[1] == 'b' || src[1] == 'c' || src[1] == 'd' || src[1] == 's' || src[1] == '8' || src[1] == '9' || src[1] == '1' || src[1] == 'x'))
        {

            Register src_reg;

            if (src[0] == 'r')
            {
                reg_type = 64;
                src_reg = get_register(src);

            }
            else if (src[0] == 'e')
            {
                if (src[1] == 'a')
                {
                    reg_type = 32;
                    src_reg = get_register("rax");

                }
                else if (src[1] == 'b')
                {
                    reg_type = 32;
                    src_reg = get_register("rbx");
                }
                else if (src[1] == 'c')
                {
                    reg_type = 32;
                    src_reg = get_register("rcx");
                }

                else if (src[1] == 's')
                {
                    reg_type = 32;
                    src_reg = get_register("rsi");
                }
                else if (src[1] == 'd' && src[2] == 'i')
                {
                    reg_type = 32;
                    src_reg = get_register("rdi");
                }
                else if (src[1] == 'd')
                {
                    reg_type = 32;
                    src_reg = get_register("rdx");
                }

            }
            else  if (src[0] == 'a')
            {
                reg_type = 16;
                src_reg = get_register("rax");

            }
            else if (src[0] == 'b')
            {
                reg_type = 16;
                src_reg = get_register("rbx");
            }
            else if (src[0] == 'c')
            {
                reg_type = 16;
                src_reg = get_register("rcx");
            }
            else if (src[0] == 'd')
            {
                reg_type = 16;
                src_reg = get_register("rdx");
            }
            else
            {

                printf("error");
                return 1;
            }


            //   寄存器到寄存器赋值

            if (reg_type == 64)
            {
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 - vm_registers->registers[src_reg].r64;

            }
            else if (reg_type == 32)
            {

                vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 - vm_registers->registers[src_reg].r32;
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000FFFFFFFF;
            }
            else if (reg_type == 16)
            {

                vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 - vm_registers->registers[src_reg].r16;
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000FFFF;
            }

        }

        //如果  第二个参数是 qword ptr [rsp + 0x8]
        else if (src[0] == 'q' || src[0] == 'd' || src[0] == 'w' || src[0] == 'b')
        {
            char src_temp[50];
            strcpy(src_temp, src); // 复制字符串到可修改的缓冲区

            //  定义 [] 中的 地址
            ULONG64 target_addr = 0;

            char* ji_lu_arg[10];
            int num = 0;
            CHAR* arg1 = strtok(src_temp, " "); // 获取空格为分隔符的第一个字符串  QWORD
            printf("截取的字符串：%s\n", arg1);
            arg1 = strtok(NULL, " ");  //ptr
            printf("截取的字符串：%s\n", arg1);
            arg1 = strtok(NULL, "["); // [rsp
            arg1 = strtok(arg1, "]"); // [rsp

            // 如果是 [rsp] 
            // 否则 可能的结果
            // 1、 [rbx + 0x3c]
            // 2、 [rbx + rcx]
            // 3、 [rbx + rcx*3]
            // 4、 [rbx + rcx + 0x88]
            // 
            // 所以要先获取到  【】 中的所有参数，再依次判断出每个参数是什么类型

            if (arg1 != NULL)
            {
                char* token = strtok(arg1, " ");
                while (token != NULL) {
                    printf("截取的字符串：%s\n", token);


                    ji_lu_arg[num] = (char*)malloc(strlen(token) + 1);
                    strcpy(ji_lu_arg[num], token);
                    num++;
                    token = strtok(NULL, " ");  // 继续解析下一个部分


                }
            }

            printf("num:%d\n", num);

            // 依次识别 每个参数的种类 判断参数个数1, 3, 5
            if (num == 1)
            {
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");

                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                    }

                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                }
                else
                {

                    printf("error");
                    return 0;
                }

                target_addr = vm_registers->registers[reg1].r64;
            }
            else if (num == 3)// 如果 两个参数 一个 符号
            {
                // 确定第一个是什么寄存器
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);
                    target_addr = target_addr + vm_registers->registers[reg1].r64;

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {
                        reg1 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }

                // 判断第二个 是否有 * 符号
                int symbol_flag = 0;
                char symbol = NULL;

                for (int i = 0; i < strlen(ji_lu_arg[2]); i++)
                {
                    if (ji_lu_arg[2][i] == '*')
                    {
                        symbol_flag = 1;
                        symbol = '*';
                    }

                }
                //如果有*，进行分离，识别寄存器，符号，和立即数
                if (symbol_flag == 1)//rcx*0x3
                {
                    char* a1 = strtok(ji_lu_arg[2], "*");// rcx
                    char* a2 = strtok(NULL, "*");        // 0x3

                    int a2_num = 0;
                    sscanf(a2, "%x", &a2_num); // 3
                    // 判断 a1是什么寄存器
                    Register reg2;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (a1[0] == 'r')
                    {
                        reg2 = get_register(a1);
                        target_addr = target_addr + vm_registers->registers[reg2].r64 * a2_num;
                    }
                    else if (a1[0] == 'e')
                    {
                        if (a1[1] == 'a')
                        {
                            reg2 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'b')
                        {
                            reg2 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'c')
                        {

                            reg2 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }

                        else if (a1[1] == 's')
                        {

                            reg2 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'd' && a1[2] == 'i')
                        {

                            reg2 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'd')
                        {

                            reg2 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }

                    }
                    else if (a1[0] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }



                }
                // 如果没有 识别第二个参数是寄存器还是立即数
                else
                {
                    Register reg2;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (ji_lu_arg[2][0] == 'r')
                    {
                        reg2 = get_register(ji_lu_arg[2]);
                        target_addr = target_addr + vm_registers->registers[reg2].r64;
                    }
                    else if (ji_lu_arg[2][0] == 'e')
                    {
                        if (ji_lu_arg[2][1] == 'a')
                        {
                            reg2 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'b')
                        {
                            reg2 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'c')
                        {

                            reg2 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }

                        else if (ji_lu_arg[2][1] == 's')
                        {

                            reg2 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                        {

                            reg2 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'd')
                        {

                            reg2 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }

                    }
                    else if (ji_lu_arg[2][0] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else // 不是寄存器是立即数
                    {


                        sscanf(ji_lu_arg[2], "%x", &offset_num); // 8
                        target_addr = vm_registers->registers[reg1].r64 + offset_num;

                    }
                }


            }
            else if (num == 5) // 三个参数 一个 符号
            {
                // 确定第一个是什么寄存器
                // 确定第二个是什么寄存器

                // 判断第二个是不是 寄存器
                // 
                //       如果是确定是什么寄存器
                //           如果不是 判断是否有加减乘除符号
                //               如果有则提取并计算
                //               如果没有则可以确定为立即数

                // 确定第一个是什么寄存器
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);
                    target_addr = target_addr + vm_registers->registers[reg1].r64;

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }

                // 确定第二个是什么寄存器
                Register reg2;
                if (ji_lu_arg[2][0] == 'r')
                {
                    reg2 = get_register(ji_lu_arg[2]);
                    target_addr = target_addr + vm_registers->registers[reg2].r64;

                }
                else if (ji_lu_arg[2][0] == 'e')
                {
                    if (ji_lu_arg[2][1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;

                    }
                    else if (ji_lu_arg[2][1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                    else if (ji_lu_arg[2][1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                }
                else if (ji_lu_arg[2][0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;

                }
                else if (ji_lu_arg[2][0] == 'c')
                {
                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;

                }
                else if (ji_lu_arg[2][0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;

                }
                else
                {

                    printf("error");
                    return 0;
                }


                // 判断第三个参数中是否有加减乘除符号
                int symbol_flag = 0;
                char symbol = NULL;

                for (int i = 0; i < strlen(ji_lu_arg[4]); i++)
                {
                    if (ji_lu_arg[4][i] == '*')
                    {
                        symbol_flag = 1;
                        symbol = '*';
                    }

                }
                //如果有*，进行分离，识别寄存器，符号，和立即数
                if (symbol_flag == 1)
                {
                    char* a1 = strtok(ji_lu_arg[4], "*");
                    char* a2 = strtok(NULL, "*");

                    int a2_num = 0;
                    sscanf(a2, "%x", &a2_num); // 8
                    // 判断 a1是什么寄存器
                    Register reg3;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (a1[0] == 'r')
                    {
                        reg3 = get_register(a1);
                        target_addr = target_addr + vm_registers->registers[reg3].r64 * a2_num;
                    }
                    else if (a1[0] == 'e')
                    {
                        if (a1[1] == 'a')
                        {
                            reg3 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'b')
                        {
                            reg3 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'c')
                        {

                            reg3 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }

                        else if (a1[1] == 's')
                        {

                            reg3 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'd' && a1[2] == 'i')
                        {

                            reg3 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'd')
                        {

                            reg3 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }

                    }
                    else if (a1[0] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }




                }
                // 如果没有 识别第二个参数是寄存器还是立即数
                else
                {
                    Register reg3;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (ji_lu_arg[4][0] == 'r')
                    {
                        reg3 = get_register(ji_lu_arg[4]);
                        target_addr = target_addr + vm_registers->registers[reg3].r64;
                    }
                    else if (ji_lu_arg[4][0] == 'e')
                    {
                        if (ji_lu_arg[4][1] == 'a')
                        {
                            reg3 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'b')
                        {
                            reg3 = get_register("rbx");

                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'c')
                        {

                            reg3 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }

                        else if (ji_lu_arg[4][1] == 's')
                        {

                            reg3 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'd' && ji_lu_arg[4][2] == 'i')
                        {

                            reg3 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'd')
                        {

                            reg3 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }

                    }
                    else if (ji_lu_arg[4][0] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else // 不是寄存器是立即数
                    {


                        sscanf(ji_lu_arg[4], "%x", &offset_num); // 8
                        target_addr = target_addr + offset_num;

                    }
                }

            }
            else
            {

                printf("error");
                return 0;
            }


            // 按照指定的大小开始赋值，x86-64 架构的一个特性，当对 32 位寄存器操作时，其对应的 64 位寄存器的高 32 位会被自动清零。
           // vm_registers->registers[dst_reg].r64 = 0;
            printf("target_addr:%x\n", target_addr);
            DataSize offset_type = (src[0] == 'b') ? BYTE_SIZE : (src[0] == 'w') ? WORD_SIZE : (src[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
            switch (offset_type) {
            case BYTE_SIZE: vm_registers->registers[dst_reg].r8 = vm_registers->registers[dst_reg].r8 - *((UINT8*)target_addr);  break;
            case WORD_SIZE: vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 - *((UINT16*)target_addr); break;
            case DWORD_SIZE: vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 - *((UINT32*)target_addr); break;
            case QWORD_SIZE: vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 - *((UINT64*)target_addr); break;

            }
            if (reg_type == 64)
            {

            }
            else if (reg_type == 32)
            {
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000FFFFFFFF;
            }
            else if (reg_type == 16)
            {
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000FFFF;
            }


        }

        else {   // 如果第二个参数是 立即数
            UINT64 num = 0;
            sscanf(src, "%llx", &num);

            // 立即数赋值
         //   vm_registers->registers[dst_reg].r64 = 0;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 - num;
            if (reg_type == 64)
            {

            }
            else if (reg_type == 32)
            {
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000FFFFFFFF;
            }
            else if (reg_type == 16)
            {
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000FFFF;
            }

        }
    }

    // 如果 第一个参数qword ptr [rsp + 0x8]
    else if (dst[0] == 'q' || dst[0] == 'd' || dst[0] == 'w' || dst[0] == 'b')   //   dst 是 内存   
    {
        char src_temp[50];
        strcpy(src_temp, dst); // 复制字符串到可修改的缓冲区

        //  定义 [] 中的 地址
        ULONG64 target_addr = 0;

        char* ji_lu_arg[10];
        int num = 0;
        CHAR* arg1 = strtok(src_temp, " "); // 获取空格为分隔符的第一个字符串  QWORD
        printf("截取的字符串：%s\n", arg1);
        arg1 = strtok(NULL, " ");  //ptr
        printf("截取的字符串：%s\n", arg1);
        arg1 = strtok(NULL, "["); // [rsp
        arg1 = strtok(arg1, "]"); // [rsp

        // 如果是 [rsp] 
        // 否则 可能的结果
        // 1、 [rbx + 0x3c]
        // 2、 [rbx + rcx]
        // 3、 [rbx + rcx*3]
        // 4、 [rbx + rcx + 0x88]
        // 
        // 所以要先获取到  【】 中的所有参数，再依次判断出每个参数是什么类型

        if (arg1 != NULL)
        {
            char* token = strtok(arg1, " ");
            while (token != NULL) {
                printf("截取的字符串：%s\n", token);


                ji_lu_arg[num] = (char*)malloc(strlen(token) + 1);
                strcpy(ji_lu_arg[num], token);
                num++;
                token = strtok(NULL, " ");  // 继续解析下一个部分


            }
        }

        printf("num:%d\n", num);

        // 依次识别 每个参数的种类 判断参数个数1, 3, 5
        if (num == 1)
        {
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);

            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");

                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");

                }
                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");

                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                }
            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
            }
            else
            {

                printf("error");
                return 0;
            }

            target_addr = target_addr + vm_registers->registers[reg1].r64;
        }
        else if (num == 3)// 如果 两个参数 一个 符号
        {
            // 确定第一个是什么寄存器
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);
                target_addr = target_addr + vm_registers->registers[reg1].r64;
            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg1].r16;

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else
            {

                printf("error");
                return 0;
            }

            // 判断第二个 是否有 * 符号
            int symbol_flag = 0;
            char symbol = NULL;

            for (int i = 0; i < strlen(ji_lu_arg[2]); i++)
            {
                if (ji_lu_arg[2][i] == '*')
                {
                    symbol_flag = 1;
                    symbol = '*';
                }

            }
            //如果有*，进行分离，识别寄存器，符号，和立即数
            if (symbol_flag == 1)//rcx*0x3
            {
                char* a1 = strtok(ji_lu_arg[2], "*");// rcx
                char* a2 = strtok(NULL, "*");        // 0x3

                int a2_num = 0;
                sscanf(a2, "%x", &a2_num); // 3
                // 判断 a1是什么寄存器
                Register reg2;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (a1[0] == 'r')
                {
                    reg2 = get_register(a1);
                    target_addr = target_addr + vm_registers->registers[reg2].r64 * a2_num;
                }
                else if (a1[0] == 'e')
                {
                    if (a1[1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }

                    else if (a1[1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'd' && a1[2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }

                }
                else if (a1[0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }



            }
            // 如果没有 识别第二个参数是寄存器还是立即数
            else
            {
                Register reg2;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (ji_lu_arg[2][0] == 'r')
                {
                    reg2 = get_register(ji_lu_arg[2]);
                    target_addr = target_addr + vm_registers->registers[reg2].r64;
                }
                else if (ji_lu_arg[2][0] == 'e')
                {
                    if (ji_lu_arg[2][1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                    else if (ji_lu_arg[2][1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                }
                else if (ji_lu_arg[2][0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else // 不是寄存器是立即数
                {


                    sscanf(ji_lu_arg[2], "%x", &offset_num); // 8
                    target_addr = target_addr + offset_num;

                }
            }


        }
        else if (num == 5) // 三个参数 一个 符号
        {
            // 确定第一个是什么寄存器
            // 确定第二个是什么寄存器

            // 判断第二个是不是 寄存器
            // 
            //       如果是确定是什么寄存器
            //           如果不是 判断是否有加减乘除符号
            //               如果有则提取并计算
            //               如果没有则可以确定为立即数

            // 确定第一个是什么寄存器
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);
                target_addr = target_addr + vm_registers->registers[reg1].r64;

            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;

                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg1].r16;

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else
            {

                printf("error");
                return 0;
            }

            // 确定第二个是什么寄存器
            Register reg2;
            if (ji_lu_arg[2][0] == 'r')
            {
                reg2 = get_register(ji_lu_arg[2]);
                target_addr = target_addr + vm_registers->registers[reg2].r64;

            }
            else if (ji_lu_arg[2][0] == 'e')
            {
                if (ji_lu_arg[2][1] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;

                }
                else if (ji_lu_arg[2][1] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }

                else if (ji_lu_arg[2][1] == 's')
                {

                    reg2 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                {

                    reg2 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }

            }
            else if (ji_lu_arg[2][0] == 'a')
            {
                reg2 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg2].r16;

            }
            else if (ji_lu_arg[2][0] == 'b')
            {
                reg2 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else if (ji_lu_arg[2][0] == 'c')
            {

                reg2 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else if (ji_lu_arg[2][0] == 'd')
            {

                reg2 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else
            {

                printf("error");
                return 0;
            }


            // 判断第三个参数中是否有加减乘除符号
            int symbol_flag = 0;
            char symbol = NULL;

            for (int i = 0; i < strlen(ji_lu_arg[4]); i++)
            {
                if (ji_lu_arg[4][i] == '*')
                {
                    symbol_flag = 1;
                    symbol = '*';
                }

            }
            //如果有*，进行分离，识别寄存器，符号，和立即数
            if (symbol_flag == 1)
            {
                char* a1 = strtok(ji_lu_arg[4], "*");
                char* a2 = strtok(NULL, "*");

                int a2_num = 0;
                sscanf(a2, "%x", &a2_num); // 8
                // 判断 a1是什么寄存器
                Register reg3;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (a1[0] == 'r')
                {
                    reg3 = get_register(a1);

                    target_addr = target_addr + vm_registers->registers[reg3].r64 * a2_num;
                }
                else if (a1[0] == 'e')
                {
                    if (a1[1] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }

                    else if (a1[1] == 's')
                    {

                        reg3 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'd' && a1[2] == 'i')
                    {

                        reg3 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                }
                else if (a1[0] == 'a')
                {
                    reg3 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'b')
                {
                    reg3 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'c')
                {

                    reg3 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'd')
                {

                    reg3 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }




            }
            // 如果没有 识别第二个参数是寄存器还是立即数
            else
            {
                Register reg3;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (ji_lu_arg[4][0] == 'r')
                {
                    reg3 = get_register(ji_lu_arg[4]);
                    target_addr = target_addr + vm_registers->registers[reg3].r64;
                }
                else if (ji_lu_arg[4][0] == 'e')
                {
                    if (ji_lu_arg[4][1] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }

                    else if (ji_lu_arg[4][1] == 's')
                    {

                        reg3 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'd' && ji_lu_arg[4][2] == 'i')
                    {

                        reg3 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }

                }
                else if (ji_lu_arg[4][0] == 'a')
                {
                    reg3 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'b')
                {
                    reg3 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'c')
                {

                    reg3 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'd')
                {

                    reg3 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else // 不是寄存器是立即数
                {


                    sscanf(ji_lu_arg[4], "%x", &offset_num); // 8
                    target_addr = target_addr + offset_num;

                }
            }

        }
        else
        {

            printf("error");
            return 0;
        }

        // 按照指定的大小开始赋值，x86-64 架构的一个特性，当对 32 位寄存器操作时，其对应的 64 位寄存器的高 32 位会被自动清零。
       // vm_registers->registers[dst_reg].r64 = 0;
        printf("target_addr:%x\n", target_addr);


        // 第二个参数是寄存器
        if ((src[0] == 'r' || src[0] == 'e' || src[0] == 'a' || src[0] == 'b' || src[0] == 'c' || src[0] == 'd') && (src[1] == 'a' || src[1] == 'b' || src[1] == 'c' || src[1] == 'd' || src[1] == 's' || src[1] == '8' || src[1] == '9' || src[1] == '1' || src[1] == 'x'))
        {
            Register src_reg;

            if (src[0] == 'r')
            {
                src_reg = get_register(src);

            }
            else if (src[0] == 'e')
            {
                if (src[1] == 'a')
                {
                    src_reg = get_register("rax");

                }
                else if (src[1] == 'b')
                {
                    src_reg = get_register("rbx");
                }
                else if (src[1] == 'c')
                {

                    src_reg = get_register("rcx");
                }

                else if (src[1] == 's')
                {

                    src_reg = get_register("rsi");
                }
                else if (src[1] == 'd' && src[2] == 'i')
                {

                    src_reg = get_register("rdi");
                }
                else if (src[1] == 'd')
                {

                    src_reg = get_register("rdx");
                }

            }
            else  if (src[0] == 'a')
            {
                src_reg = get_register("rax");

            }
            else if (src[0] == 'b')
            {
                src_reg = get_register("rbx");
            }
            else if (src[0] == 'c')
            {

                src_reg = get_register("rcx");
            }
            else if (src[0] == 'd')
            {

                src_reg = get_register("rdx");
            }
            else
            {

                printf("error");
            }


            // 按照指定的大小开始赋值
            DataSize offset_type = (dst[0] == 'b') ? BYTE_SIZE : (dst[0] == 'w') ? WORD_SIZE : (dst[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
            switch (offset_type) {
            case BYTE_SIZE:  ((UINT8*)target_addr)[0] = ((UINT8*)target_addr)[0] - vm_registers->registers[src_reg].r8; break;
            case WORD_SIZE:  ((UINT16*)target_addr)[0] = ((UINT16*)target_addr)[0] - vm_registers->registers[src_reg].r16; break;
            case DWORD_SIZE: ((UINT32*)target_addr)[0] = ((UINT32*)target_addr)[0] - vm_registers->registers[src_reg].r32; break;
            case QWORD_SIZE: ((UINT64*)target_addr)[0] = ((UINT64*)target_addr)[0] - vm_registers->registers[src_reg].r64; break;
            }

        }

        else { // 第二个参数是 立即数

            ULONG64 src_num = 0;
            sscanf(src, "%llx", &src_num); // 8

            DataSize offset_type = (dst[0] == 'b') ? BYTE_SIZE : (dst[0] == 'w') ? WORD_SIZE : (dst[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
            switch (offset_type) {
            case BYTE_SIZE:  ((UINT8*)target_addr)[0] = ((UINT8*)target_addr)[0] - src_num; break;
            case WORD_SIZE:  ((UINT16*)target_addr)[0] = ((UINT16*)target_addr)[0] - src_num; break;
            case DWORD_SIZE: ((UINT32*)target_addr)[0] = ((UINT32*)target_addr)[0] - src_num; break;
            case QWORD_SIZE: ((UINT64*)target_addr)[0] = ((UINT64*)target_addr)[0] - src_num; break;
            }

        }


        //    long long address = calculate_effective_address(vm, dst);
        // /*   if (address < 0 || address >= MEMORY_SIZE) {
        //        fprintf(stderr, "Memory address out of bounds: %lld\n", address);
        //        exit(1);
        //        */
        //    }



    }
    else {
        fprintf(stderr, "Invalid destination operand: %s\n", dst);
        //  vm_registers->EIP = vm_registers->EIP + 1;
        return 1;
    }
    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;
}
int execute_add(VM_registers* vm_registers, const char* dst, const char* src)
{
    //开始判断 寄存器还是立即数

       // 如果 第一个参数是寄存器
    int reg_type = 0;

    if ((dst[0] == 'r' || dst[0] == 'e' || dst[0] == 'a' || dst[0] == 'b' || dst[0] == 'c' || dst[0] == 'd') && (dst[1] == 'a' || dst[1] == 'b' || dst[1] == 'c' || dst[1] == 'd' || dst[1] == 's' || dst[1] == '8' || dst[1] == '9' || dst[1] == '1' || dst[1] == 'x'))

    {
        printf("第一个参数是寄存器\n");
        Register dst_reg;
        if (dst[0] == 'r')
        {
            reg_type == 64;
            dst_reg = get_register(dst);

        }
        else if (dst[0] == 'e')
        {
            if (dst[1] == 'a')
            {
                dst_reg = get_register("rax");
                reg_type == 32;
            }
            else if (dst[1] == 'b')
            {
                reg_type == 32;
                dst_reg = get_register("rbx");
            }
            else if (dst[1] == 'c')
            {
                reg_type == 32;
                dst_reg = get_register("rcx");
            }

            else if (dst[1] == 's')
            {
                reg_type == 32;
                dst_reg = get_register("rsi");
            }
            else if (dst[1] == 'd' && dst[2] == 'i')
            {
                reg_type == 32;
                dst_reg = get_register("rdi");
            }
            else if (dst[1] == 'd')
            {
                reg_type == 32;
                dst_reg = get_register("rdx");
            }

        }
        else  if (dst[0] == 'a')
        {
            reg_type == 16;
            dst_reg = get_register("rax");

        }
        else if (dst[0] == 'b')
        {
            reg_type == 16;
            dst_reg = get_register("rbx");
        }
        else if (dst[0] == 'c')
        {
            reg_type == 16;
            dst_reg = get_register("rcx");
        }
        else if (dst[0] == 'd')
        {
            reg_type == 16;
            dst_reg = get_register("rdx");
        }
        else
        {

            printf("error");
        }

        //if (reg_type == 64)
        //{

        //}
        //else if (reg_type == 32)
        //{
        //    vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000FFFFFFFF;
        //}
        //else if (reg_type == 16)
        //{
        //    vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000FFFFFFFF;
        //}

        //如果 第二个参数是 寄存器
        if ((src[0] == 'r' || src[0] == 'e' || src[0] == 'a' || src[0] == 'b' || src[0] == 'c' || src[0] == 'd') && (src[1] == 'a' || src[1] == 'b' || src[1] == 'c' || src[1] == 'd' || src[1] == 's' || src[1] == '8' || src[1] == '9' || src[1] == '1' || src[1] == 'x'))
        {

            Register src_reg;

            if (src[0] == 'r')
            {
                reg_type = 64;
                src_reg = get_register(src);

            }
            else if (src[0] == 'e')
            {
                if (src[1] == 'a')
                {
                    reg_type = 32;
                    src_reg = get_register("rax");

                }
                else if (src[1] == 'b')
                {
                    reg_type = 32;
                    src_reg = get_register("rbx");
                }
                else if (src[1] == 'c')
                {
                    reg_type = 32;
                    src_reg = get_register("rcx");
                }

                else if (src[1] == 's')
                {
                    reg_type = 32;
                    src_reg = get_register("rsi");
                }
                else if (src[1] == 'd' && src[2] == 'i')
                {
                    reg_type = 32;
                    src_reg = get_register("rdi");
                }
                else if (src[1] == 'd')
                {
                    reg_type = 32;
                    src_reg = get_register("rdx");
                }

            }
            else  if (src[0] == 'a')
            {
                reg_type = 16;
                src_reg = get_register("rax");

            }
            else if (src[0] == 'b')
            {
                reg_type = 16;
                src_reg = get_register("rbx");
            }
            else if (src[0] == 'c')
            {
                reg_type = 16;
                src_reg = get_register("rcx");
            }
            else if (src[0] == 'd')
            {
                reg_type = 16;
                src_reg = get_register("rdx");
            }
            else
            {

                printf("error");
                return 1;
            }


            //   寄存器到寄存器赋值

            if (reg_type == 64)
            {
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 + vm_registers->registers[src_reg].r64;

            }
            else if (reg_type == 32)
            {

                vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 + vm_registers->registers[src_reg].r32;
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000FFFFFFFF;
            }
            else if (reg_type == 16)
            {

                vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 + vm_registers->registers[src_reg].r16;
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000FFFF;
            }

        }

        //如果  第二个参数是 qword ptr [rsp + 0x8]
        else if (src[0] == 'q' || src[0] == 'd' || src[0] == 'w' || src[0] == 'b')
        {
            char src_temp[50];
            strcpy(src_temp, src); // 复制字符串到可修改的缓冲区

            //  定义 [] 中的 地址
            ULONG64 target_addr = 0;

            char* ji_lu_arg[10];
            int num = 0;
            CHAR* arg1 = strtok(src_temp, " "); // 获取空格为分隔符的第一个字符串  QWORD
            printf("截取的字符串：%s\n", arg1);
            arg1 = strtok(NULL, " ");  //ptr
            printf("截取的字符串：%s\n", arg1);
            arg1 = strtok(NULL, "["); // [rsp
            arg1 = strtok(arg1, "]"); // [rsp

            // 如果是 [rsp] 
            // 否则 可能的结果
            // 1、 [rbx + 0x3c]
            // 2、 [rbx + rcx]
            // 3、 [rbx + rcx*3]
            // 4、 [rbx + rcx + 0x88]
            // 
            // 所以要先获取到  【】 中的所有参数，再依次判断出每个参数是什么类型

            if (arg1 != NULL)
            {
                char* token = strtok(arg1, " ");
                while (token != NULL) {
                    printf("截取的字符串：%s\n", token);


                    ji_lu_arg[num] = (char*)malloc(strlen(token) + 1);
                    strcpy(ji_lu_arg[num], token);
                    num++;
                    token = strtok(NULL, " ");  // 继续解析下一个部分


                }
            }

            printf("num:%d\n", num);

            // 依次识别 每个参数的种类 判断参数个数1, 3, 5
            if (num == 1)
            {
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");

                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                    }

                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                }
                else
                {

                    printf("error");
                    return 0;
                }

                target_addr = vm_registers->registers[reg1].r64;
            }
            else if (num == 3)// 如果 两个参数 一个 符号
            {
                // 确定第一个是什么寄存器
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);
                    target_addr = target_addr + vm_registers->registers[reg1].r64;

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {
                        reg1 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }

                // 判断第二个 是否有 * 符号
                int symbol_flag = 0;
                char symbol = NULL;

                for (int i = 0; i < strlen(ji_lu_arg[2]); i++)
                {
                    if (ji_lu_arg[2][i] == '*')
                    {
                        symbol_flag = 1;
                        symbol = '*';
                    }

                }
                //如果有*，进行分离，识别寄存器，符号，和立即数
                if (symbol_flag == 1)//rcx*0x3
                {
                    char* a1 = strtok(ji_lu_arg[2], "*");// rcx
                    char* a2 = strtok(NULL, "*");        // 0x3

                    int a2_num = 0;
                    sscanf(a2, "%x", &a2_num); // 3
                    // 判断 a1是什么寄存器
                    Register reg2;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (a1[0] == 'r')
                    {
                        reg2 = get_register(a1);
                        target_addr = target_addr + vm_registers->registers[reg2].r64 * a2_num;
                    }
                    else if (a1[0] == 'e')
                    {
                        if (a1[1] == 'a')
                        {
                            reg2 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'b')
                        {
                            reg2 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'c')
                        {

                            reg2 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }

                        else if (a1[1] == 's')
                        {

                            reg2 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'd' && a1[2] == 'i')
                        {

                            reg2 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'd')
                        {

                            reg2 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }

                    }
                    else if (a1[0] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }



                }
                // 如果没有 识别第二个参数是寄存器还是立即数
                else
                {
                    Register reg2;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (ji_lu_arg[2][0] == 'r')
                    {
                        reg2 = get_register(ji_lu_arg[2]);
                        target_addr = target_addr + vm_registers->registers[reg2].r64;
                    }
                    else if (ji_lu_arg[2][0] == 'e')
                    {
                        if (ji_lu_arg[2][1] == 'a')
                        {
                            reg2 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'b')
                        {
                            reg2 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'c')
                        {

                            reg2 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }

                        else if (ji_lu_arg[2][1] == 's')
                        {

                            reg2 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                        {

                            reg2 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'd')
                        {

                            reg2 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }

                    }
                    else if (ji_lu_arg[2][0] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else // 不是寄存器是立即数
                    {


                        sscanf(ji_lu_arg[2], "%x", &offset_num); // 8
                        target_addr = vm_registers->registers[reg1].r64 + offset_num;

                    }
                }


            }
            else if (num == 5) // 三个参数 一个 符号
            {
                // 确定第一个是什么寄存器
                // 确定第二个是什么寄存器

                // 判断第二个是不是 寄存器
                // 
                //       如果是确定是什么寄存器
                //           如果不是 判断是否有加减乘除符号
                //               如果有则提取并计算
                //               如果没有则可以确定为立即数

                // 确定第一个是什么寄存器
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);
                    target_addr = target_addr + vm_registers->registers[reg1].r64;

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }

                // 确定第二个是什么寄存器
                Register reg2;
                if (ji_lu_arg[2][0] == 'r')
                {
                    reg2 = get_register(ji_lu_arg[2]);
                    target_addr = target_addr + vm_registers->registers[reg2].r64;

                }
                else if (ji_lu_arg[2][0] == 'e')
                {
                    if (ji_lu_arg[2][1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;

                    }
                    else if (ji_lu_arg[2][1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                    else if (ji_lu_arg[2][1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                }
                else if (ji_lu_arg[2][0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;

                }
                else if (ji_lu_arg[2][0] == 'c')
                {
                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;

                }
                else if (ji_lu_arg[2][0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;

                }
                else
                {

                    printf("error");
                    return 0;
                }


                // 判断第三个参数中是否有加减乘除符号
                int symbol_flag = 0;
                char symbol = NULL;

                for (int i = 0; i < strlen(ji_lu_arg[4]); i++)
                {
                    if (ji_lu_arg[4][i] == '*')
                    {
                        symbol_flag = 1;
                        symbol = '*';
                    }

                }
                //如果有*，进行分离，识别寄存器，符号，和立即数
                if (symbol_flag == 1)
                {
                    char* a1 = strtok(ji_lu_arg[4], "*");
                    char* a2 = strtok(NULL, "*");

                    int a2_num = 0;
                    sscanf(a2, "%x", &a2_num); // 8
                    // 判断 a1是什么寄存器
                    Register reg3;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (a1[0] == 'r')
                    {
                        reg3 = get_register(a1);
                        target_addr = target_addr + vm_registers->registers[reg3].r64 * a2_num;
                    }
                    else if (a1[0] == 'e')
                    {
                        if (a1[1] == 'a')
                        {
                            reg3 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'b')
                        {
                            reg3 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'c')
                        {

                            reg3 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }

                        else if (a1[1] == 's')
                        {

                            reg3 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'd' && a1[2] == 'i')
                        {

                            reg3 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'd')
                        {

                            reg3 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }

                    }
                    else if (a1[0] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }




                }
                // 如果没有 识别第二个参数是寄存器还是立即数
                else
                {
                    Register reg3;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (ji_lu_arg[4][0] == 'r')
                    {
                        reg3 = get_register(ji_lu_arg[4]);
                        target_addr = target_addr + vm_registers->registers[reg3].r64;
                    }
                    else if (ji_lu_arg[4][0] == 'e')
                    {
                        if (ji_lu_arg[4][1] == 'a')
                        {
                            reg3 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'b')
                        {
                            reg3 = get_register("rbx");

                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'c')
                        {

                            reg3 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }

                        else if (ji_lu_arg[4][1] == 's')
                        {

                            reg3 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'd' && ji_lu_arg[4][2] == 'i')
                        {

                            reg3 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'd')
                        {

                            reg3 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }

                    }
                    else if (ji_lu_arg[4][0] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else // 不是寄存器是立即数
                    {


                        sscanf(ji_lu_arg[4], "%x", &offset_num); // 8
                        target_addr = target_addr + offset_num;

                    }
                }

            }
            else
            {

                printf("error");
                return 0;
            }


            // 按照指定的大小开始赋值，x86-64 架构的一个特性，当对 32 位寄存器操作时，其对应的 64 位寄存器的高 32 位会被自动清零。
           // vm_registers->registers[dst_reg].r64 = 0;
            printf("target_addr:%x\n", target_addr);
            DataSize offset_type = (src[0] == 'b') ? BYTE_SIZE : (src[0] == 'w') ? WORD_SIZE : (src[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
            switch (offset_type) {
            case BYTE_SIZE: vm_registers->registers[dst_reg].r8 = vm_registers->registers[dst_reg].r8 + *((UINT8*)target_addr);  break;
            case WORD_SIZE: vm_registers->registers[dst_reg].r16 = vm_registers->registers[dst_reg].r16 + *((UINT16*)target_addr); break;
            case DWORD_SIZE: vm_registers->registers[dst_reg].r32 = vm_registers->registers[dst_reg].r32 + *((UINT32*)target_addr); break;
            case QWORD_SIZE: vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 + *((UINT64*)target_addr); break;

            }
            if (reg_type == 64)
            {

            }
            else if (reg_type == 32)
            {
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000FFFFFFFF;
            }
            else if (reg_type == 16)
            {
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000FFFF;
            }


        }

        else {   // 如果第二个参数是 立即数
            UINT64 num = 0;
            sscanf(src, "%llx", &num);

            // 立即数赋值
         //   vm_registers->registers[dst_reg].r64 = 0;
            vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 + num;
            if (reg_type == 64)
            {

            }
            else if (reg_type == 32)
            {
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x00000000FFFFFFFF;
            }
            else if (reg_type == 16)
            {
                vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & 0x000000000000FFFF;
            }

        }
    }

    // 如果 第一个参数qword ptr [rsp + 0x8]
    else if (dst[0] == 'q' || dst[0] == 'd' || dst[0] == 'w' || dst[0] == 'b')   //   dst 是 内存   
    {
        char src_temp[50];
        strcpy(src_temp, dst); // 复制字符串到可修改的缓冲区

        //  定义 [] 中的 地址
        ULONG64 target_addr = 0;

        char* ji_lu_arg[10];
        int num = 0;
        CHAR* arg1 = strtok(src_temp, " "); // 获取空格为分隔符的第一个字符串  QWORD
        printf("截取的字符串：%s\n", arg1);
        arg1 = strtok(NULL, " ");  //ptr
        printf("截取的字符串：%s\n", arg1);
        arg1 = strtok(NULL, "["); // [rsp
        arg1 = strtok(arg1, "]"); // [rsp

        // 如果是 [rsp] 
        // 否则 可能的结果
        // 1、 [rbx + 0x3c]
        // 2、 [rbx + rcx]
        // 3、 [rbx + rcx*3]
        // 4、 [rbx + rcx + 0x88]
        // 
        // 所以要先获取到  【】 中的所有参数，再依次判断出每个参数是什么类型

        if (arg1 != NULL)
        {
            char* token = strtok(arg1, " ");
            while (token != NULL) {
                printf("截取的字符串：%s\n", token);


                ji_lu_arg[num] = (char*)malloc(strlen(token) + 1);
                strcpy(ji_lu_arg[num], token);
                num++;
                token = strtok(NULL, " ");  // 继续解析下一个部分


            }
        }

        printf("num:%d\n", num);

        // 依次识别 每个参数的种类 判断参数个数1, 3, 5
        if (num == 1)
        {
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);

            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");

                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");
                }

                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");
                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                }
            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
            }
            else
            {

                printf("error");
                return 0;
            }

            target_addr = target_addr + vm_registers->registers[reg1].r64;
        }
        else if (num == 3)// 如果 两个参数 一个 符号
        {
            // 确定第一个是什么寄存器
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);
                target_addr = target_addr + vm_registers->registers[reg1].r64;
            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg1].r16;

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else
            {

                printf("error");
                return 0;
            }

            // 判断第二个 是否有 * 符号
            int symbol_flag = 0;
            char symbol = NULL;

            for (int i = 0; i < strlen(ji_lu_arg[2]); i++)
            {
                if (ji_lu_arg[2][i] == '*')
                {
                    symbol_flag = 1;
                    symbol = '*';
                }

            }
            //如果有*，进行分离，识别寄存器，符号，和立即数
            if (symbol_flag == 1)//rcx*0x3
            {
                char* a1 = strtok(ji_lu_arg[2], "*");// rcx
                char* a2 = strtok(NULL, "*");        // 0x3

                int a2_num = 0;
                sscanf(a2, "%x", &a2_num); // 3
                // 判断 a1是什么寄存器
                Register reg2;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (a1[0] == 'r')
                {
                    reg2 = get_register(a1);
                    target_addr = target_addr + vm_registers->registers[reg2].r64 * a2_num;
                }
                else if (a1[0] == 'e')
                {
                    if (a1[1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }

                    else if (a1[1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'd' && a1[2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }

                }
                else if (a1[0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }



            }
            // 如果没有 识别第二个参数是寄存器还是立即数
            else
            {
                Register reg2;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (ji_lu_arg[2][0] == 'r')
                {
                    reg2 = get_register(ji_lu_arg[2]);
                    target_addr = target_addr + vm_registers->registers[reg2].r64;
                }
                else if (ji_lu_arg[2][0] == 'e')
                {
                    if (ji_lu_arg[2][1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                    else if (ji_lu_arg[2][1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                }
                else if (ji_lu_arg[2][0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else // 不是寄存器是立即数
                {


                    sscanf(ji_lu_arg[2], "%x", &offset_num); // 8
                    target_addr = target_addr + offset_num;

                }
            }


        }
        else if (num == 5) // 三个参数 一个 符号
        {
            // 确定第一个是什么寄存器
            // 确定第二个是什么寄存器

            // 判断第二个是不是 寄存器
            // 
            //       如果是确定是什么寄存器
            //           如果不是 判断是否有加减乘除符号
            //               如果有则提取并计算
            //               如果没有则可以确定为立即数

            // 确定第一个是什么寄存器
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);
                target_addr = target_addr + vm_registers->registers[reg1].r64;

            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;

                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg1].r16;

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else
            {

                printf("error");
                return 0;
            }

            // 确定第二个是什么寄存器
            Register reg2;
            if (ji_lu_arg[2][0] == 'r')
            {
                reg2 = get_register(ji_lu_arg[2]);
                target_addr = target_addr + vm_registers->registers[reg2].r64;

            }
            else if (ji_lu_arg[2][0] == 'e')
            {
                if (ji_lu_arg[2][1] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;

                }
                else if (ji_lu_arg[2][1] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }

                else if (ji_lu_arg[2][1] == 's')
                {

                    reg2 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                {

                    reg2 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }

            }
            else if (ji_lu_arg[2][0] == 'a')
            {
                reg2 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg2].r16;

            }
            else if (ji_lu_arg[2][0] == 'b')
            {
                reg2 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else if (ji_lu_arg[2][0] == 'c')
            {

                reg2 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else if (ji_lu_arg[2][0] == 'd')
            {

                reg2 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else
            {

                printf("error");
                return 0;
            }


            // 判断第三个参数中是否有加减乘除符号
            int symbol_flag = 0;
            char symbol = NULL;

            for (int i = 0; i < strlen(ji_lu_arg[4]); i++)
            {
                if (ji_lu_arg[4][i] == '*')
                {
                    symbol_flag = 1;
                    symbol = '*';
                }

            }
            //如果有*，进行分离，识别寄存器，符号，和立即数
            if (symbol_flag == 1)
            {
                char* a1 = strtok(ji_lu_arg[4], "*");
                char* a2 = strtok(NULL, "*");

                int a2_num = 0;
                sscanf(a2, "%x", &a2_num); // 8
                // 判断 a1是什么寄存器
                Register reg3;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (a1[0] == 'r')
                {
                    reg3 = get_register(a1);

                    target_addr = target_addr + vm_registers->registers[reg3].r64 * a2_num;
                }
                else if (a1[0] == 'e')
                {
                    if (a1[1] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }

                    else if (a1[1] == 's')
                    {

                        reg3 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'd' && a1[2] == 'i')
                    {

                        reg3 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }

                }
                else if (a1[0] == 'a')
                {
                    reg3 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'b')
                {
                    reg3 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'c')
                {

                    reg3 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'd')
                {

                    reg3 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }




            }
            // 如果没有 识别第二个参数是寄存器还是立即数
            else
            {
                Register reg3;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (ji_lu_arg[4][0] == 'r')
                {
                    reg3 = get_register(ji_lu_arg[4]);
                    target_addr = target_addr + vm_registers->registers[reg3].r64;
                }
                else if (ji_lu_arg[4][0] == 'e')
                {
                    if (ji_lu_arg[4][1] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }

                    else if (ji_lu_arg[4][1] == 's')
                    {

                        reg3 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'd' && ji_lu_arg[4][2] == 'i')
                    {

                        reg3 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }

                }
                else if (ji_lu_arg[4][0] == 'a')
                {
                    reg3 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'b')
                {
                    reg3 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'c')
                {

                    reg3 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'd')
                {

                    reg3 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else // 不是寄存器是立即数
                {


                    sscanf(ji_lu_arg[4], "%x", &offset_num); // 8
                    target_addr = target_addr + offset_num;

                }
            }

        }
        else
        {

            printf("error");
            return 0;
        }

        // 按照指定的大小开始赋值，x86-64 架构的一个特性，当对 32 位寄存器操作时，其对应的 64 位寄存器的高 32 位会被自动清零。
       // vm_registers->registers[dst_reg].r64 = 0;
        printf("target_addr:%x\n", target_addr);


        // 第二个参数是寄存器
        if ((src[0] == 'r' || src[0] == 'e' || src[0] == 'a' || src[0] == 'b' || src[0] == 'c' || src[0] == 'd') && (src[1] == 'a' || src[1] == 'b' || src[1] == 'c' || src[1] == 'd' || src[1] == 's' || src[1] == '8' || src[1] == '9' || src[1] == '1' || src[1] == 'x'))
        {
            Register src_reg;

            if (src[0] == 'r')
            {
                src_reg = get_register(src);

            }
            else if (src[0] == 'e')
            {
                if (src[1] == 'a')
                {
                    src_reg = get_register("rax");

                }
                else if (src[1] == 'b')
                {
                    src_reg = get_register("rbx");
                }
                else if (src[1] == 'c')
                {

                    src_reg = get_register("rcx");
                }

                else if (src[1] == 's')
                {

                    src_reg = get_register("rsi");
                }
                else if (src[1] == 'd' && src[2] == 'i')
                {

                    src_reg = get_register("rdi");
                }
                else if (src[1] == 'd')
                {

                    src_reg = get_register("rdx");
                }

            }
            else  if (src[0] == 'a')
            {
                src_reg = get_register("rax");

            }
            else if (src[0] == 'b')
            {
                src_reg = get_register("rbx");
            }
            else if (src[0] == 'c')
            {

                src_reg = get_register("rcx");
            }
            else if (src[0] == 'd')
            {

                src_reg = get_register("rdx");
            }
            else
            {

                printf("error");
            }


            // 按照指定的大小开始赋值
            DataSize offset_type = (dst[0] == 'b') ? BYTE_SIZE : (dst[0] == 'w') ? WORD_SIZE : (dst[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
            switch (offset_type) {
            case BYTE_SIZE:  ((UINT8*)target_addr)[0] = ((UINT8*)target_addr)[0] + vm_registers->registers[src_reg].r8; break;
            case WORD_SIZE:  ((UINT16*)target_addr)[0] = ((UINT16*)target_addr)[0] + vm_registers->registers[src_reg].r16; break;
            case DWORD_SIZE: ((UINT32*)target_addr)[0] = ((UINT32*)target_addr)[0] + vm_registers->registers[src_reg].r32; break;
            case QWORD_SIZE: ((UINT64*)target_addr)[0] = ((UINT64*)target_addr)[0] + vm_registers->registers[src_reg].r64; break;
            }

        }

        else { // 第二个参数是 立即数

            ULONG64 src_num = 0;
            sscanf(src, "%llx", &src_num); // 8

            DataSize offset_type = (dst[0] == 'b') ? BYTE_SIZE : (dst[0] == 'w') ? WORD_SIZE : (dst[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
            switch (offset_type) {
            case BYTE_SIZE:  ((UINT8*)target_addr)[0] = ((UINT8*)target_addr)[0] + src_num; break;
            case WORD_SIZE:  ((UINT16*)target_addr)[0] = ((UINT16*)target_addr)[0] + src_num; break;
            case DWORD_SIZE: ((UINT32*)target_addr)[0] = ((UINT32*)target_addr)[0] + src_num; break;
            case QWORD_SIZE: ((UINT64*)target_addr)[0] = ((UINT64*)target_addr)[0] + src_num; break;
            }

        }


        //    long long address = calculate_effective_address(vm, dst);
        // /*   if (address < 0 || address >= MEMORY_SIZE) {
        //        fprintf(stderr, "Memory address out of bounds: %lld\n", address);
        //        exit(1);
        //        */
        //    }



    }
    else {
        fprintf(stderr, "Invalid destination operand: %s\n", dst);
        //  vm_registers->EIP = vm_registers->EIP + 1;
        return 1;
    }
    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;
}
int execute_xor(VM_registers* vm_registers, const char* dst, const char* src)
{
    Register dst_reg;

    if (dst[0] == 'r')
    {
        dst_reg = get_register(dst);

    }
    else if (dst[0] == 'e')
    {
        if (dst[1] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst[1] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst[1] == 'c')
        {

            dst_reg = get_register("rcx");
        }
        else if (dst[1] == 's')
        {

            dst_reg = get_register("rsi");
        }
        else if (dst[1] == 'd' && dst[2] == 'i')
        {

            dst_reg = get_register("rdi");
        }
        else if (dst[1] == 'd')
        {

            dst_reg = get_register("rdx");
        }

    }
    else  if (dst[0] == 'a')
    {
        dst_reg = get_register("rax");

    }
    else if (dst[0] == 'b')
    {
        dst_reg = get_register("rbx");
    }
    else if (dst[0] == 'c')
    {

        dst_reg = get_register("rcx");
    }
    else if (dst[0] == 'd')
    {

        dst_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }



    Register src_reg;

    if (src[0] == 'r')
    {
        src_reg = get_register(src);

    }
    else if (src[0] == 'e')
    {
        if (src[1] == 'a')
        {
            src_reg = get_register("rax");

        }
        else if (src[1] == 'b')
        {
            src_reg = get_register("rbx");
        }
        else if (src[1] == 'c')
        {

            src_reg = get_register("rcx");
        }
        else if (src[1] == 's')
        {

            src_reg = get_register("rsi");
        }
        else if (src[1] == 'd' && src[2] == 'i')
        {

            src_reg = get_register("rdi");
        }
        else if (src[1] == 'd')
        {

            src_reg = get_register("rdx");
        }

    }
    else  if (src[0] == 'a')
    {
        src_reg = get_register("rax");

    }
    else if (src[0] == 'b')
    {
        src_reg = get_register("rbx");
    }
    else if (src[0] == 'c')
    {

        src_reg = get_register("rcx");
    }
    else if (src[0] == 'd')
    {

        src_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }


    vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 ^ vm_registers->registers[src_reg].r64;
    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;
};
int execute_lea(VM_registers* vm_registers, const char* dst, const char* src)
{
    // 判断第一个参数是寄存器
      // lea rdi, [rsp + 0x40]   
      // lea rax, [rip]
    Register dst_reg;
    if (dst[0] == 'r')
    {
        dst_reg = get_register(dst);

    }
    else if (dst[0] == 'e')
    {
        if (dst[1] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst[1] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst[1] == 'c')
        {

            dst_reg = get_register("rcx");
        }
        else if (dst[1] == 's')
        {

            dst_reg = get_register("rsi");
        }
        else if (dst[1] == 'd' && dst[2] == 'i')
        {

            dst_reg = get_register("rdi");
        }
        else if (dst[1] == 'd')
        {

            dst_reg = get_register("rdx");
        }

    }
    else  if (dst[0] == 'a')
    {
        dst_reg = get_register("rax");

    }
    else if (dst[0] == 'b')
    {
        dst_reg = get_register("rbx");
    }
    else if (dst[0] == 'c')
    {

        dst_reg = get_register("rcx");
    }
    else if (dst[0] == 'd')
    {

        dst_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }


    // 判断第二个 【】 中的第一个参数是哪个寄存器   [rsp + 0x3e8]
      // 获取 【】 中的值
    ULONG64 target = 0;
    char* first_arg = strtok((char*)src, " ");          // [rsp 


    // 首先判断格式    [rsp + 0x3e8]   
    if (first_arg != src) // 说明不是 [rsp] 
    {
        char* symbool = strtok(NULL, " ");                // +

        char* second_arg = strtok(NULL, "]");  // 0x3e8

        first_arg = strtok(first_arg, "[");  // rsp 

        // 判断【】第一个是什么寄存器
        Register first_arg_reg;
        if (first_arg[0] == 'r')
        {
            first_arg_reg = get_register(first_arg);

        }
        else if (first_arg[0] == 'e')
        {
            if (first_arg[1] == 'a')
            {
                first_arg_reg = get_register("rax");

            }
            else if (first_arg[1] == 'b')
            {
                first_arg_reg = get_register("rbx");
            }
            else if (first_arg[1] == 'c')
            {

                first_arg_reg = get_register("rcx");
            }
            else if (first_arg[1] == 's')
            {

                first_arg_reg = get_register("rsi");
            }
            else if (first_arg[1] == 'd' && first_arg[2] == 'i')
            {

                first_arg_reg = get_register("rdi");
            }
            else if (first_arg[1] == 'd')
            {

                first_arg_reg = get_register("rdx");
            }

        }
        else  if (first_arg[0] == 'a')
        {
            first_arg_reg = get_register("rax");

        }
        else if (first_arg[0] == 'b')
        {
            first_arg_reg = get_register("rbx");
        }
        else if (first_arg[0] == 'c')
        {

            first_arg_reg = get_register("rcx");
        }
        else if (first_arg[0] == 'd')
        {

            first_arg_reg = get_register("rdx");
        }
        else
        {

            printf("error");
        }

        int flag = 0;
        Register second_arg_reg;
        if (second_arg[0] == 'r')
        {
            second_arg_reg = get_register(second_arg);
            flag = 1;// 表示第二个是寄存器

        }
        else if (second_arg[0] == 'e')
        {
            if (second_arg[1] == 'a')
            {
                second_arg_reg = get_register("rax");
                flag = 1;// 表示第二个是寄存器

            }
            else if (second_arg[1] == 'b')
            {
                second_arg_reg = get_register("rbx");
                flag = 1;// 表示第二个是寄存器
            }
            else if (second_arg[1] == 'c')
            {

                second_arg_reg = get_register("rcx");
                flag = 1;// 表示第二个是寄存器
            }
            else if (second_arg[1] == 's')
            {

                second_arg_reg = get_register("rsi");
                flag = 1;// 表示第二个是寄存器
            }
            else if (second_arg[1] == 'd' && second_arg[2] == 'i')
            {

                second_arg_reg = get_register("rdi");
                flag = 1;// 表示第二个是寄存器
            }
            else if (second_arg[1] == 'd')
            {

                second_arg_reg = get_register("rdx");
                flag = 1;// 表示第二个是寄存器
            }

        }
        else  if (second_arg[0] == 'a')
        {
            second_arg_reg = get_register("rax");
            flag = 1;// 表示第二个是寄存器

        }
        else if (second_arg[0] == 'b')
        {
            second_arg_reg = get_register("rbx");
            flag = 1;// 表示第二个是寄存器
        }
        else if (second_arg[0] == 'c')
        {

            second_arg_reg = get_register("rcx");
            flag = 1;// 表示第二个是寄存器
        }
        else if (second_arg[0] == 'd')
        {

            second_arg_reg = get_register("rdx");
            flag = 1;// 表示第二个是寄存器
        }
        else
        {

            printf("error");
        }


        // 判断第二个是什么寄存器，如果不是就是立即数
        if (flag == 1)
        {
            target = vm_registers->registers[first_arg_reg].r64 + vm_registers->registers[second_arg_reg].r64;

        }
        else
        {
            ULONG64 num = 0;
            sscanf(second_arg, "%x", &num); // 8

            target = vm_registers->registers[first_arg_reg].r64 + num;
        }

        vm_registers->registers[dst_reg].r64 = target;
    }
    else  // 只有一个寄存器，没有立即数   [rsp]
    {
        char* left = strtok(first_arg, "[");                // +

        char* src_arg = strtok(left, "]");  // rsp

        Register src_reg;
        if (src_arg[0] == 'r')
        {
            src_reg = get_register(src_arg);

        }
        else if (src_arg[0] == 'e')
        {
            if (src_arg[1] == 'a')
            {
                src_reg = get_register("rax");

            }
            else if (src_arg[1] == 'b')
            {
                src_reg = get_register("rbx");
            }
            else if (src_arg[1] == 'c')
            {

                src_reg = get_register("rcx");
            }
            else if (src_arg[1] == 's')
            {

                src_reg = get_register("rsi");
            }
            else if (src_arg[1] == 'd' && src_arg[2] == 'i')
            {

                src_reg = get_register("rdi");
            }
            else if (src_arg[1] == 'd')
            {

                src_reg = get_register("rdx");
            }

        }
        else  if (src_arg[0] == 'a')
        {
            src_reg = get_register("rax");

        }
        else if (src_arg[0] == 'b')
        {
            src_reg = get_register("rbx");
        }
        else if (src_arg[0] == 'c')
        {

            src_reg = get_register("rcx");
        }
        else if (src_arg[0] == 'd')
        {

            src_reg = get_register("rdx");
        }
        else
        {

            printf("error");
        }

        vm_registers->registers[dst_reg].r64 = vm_registers->registers[src_reg].r64;




    }

    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;

};
int execute_rep(VM_registers* vm_registers, const char* dst, const char* src)
{
    // dword ptr[rdi], eax
    // byte ptr [rdi], al
    //将src寄存器的值 赋值到dst所指向的内存，然后dst的地址值增加对应的长度，赋值次数由rcx指定，每次rcx减一

    Register dst_reg;
    Register src_reg;

    if (dst[0] == 'q' || dst[0] == 'd' || dst[0] == 'w' || dst[0] == 'b')
    {   // 获取 【】 中的值
        char* size = strtok((char*)dst, " ");          // qword 
        char* type = strtok(NULL, " ");                // ptr

        char* first_arg = strtok(NULL, " ");  // [rdi] 


        char* left = strtok(first_arg, "[");                // +

        char* dst_arg = strtok(left, "]");  // rsp


        if (dst_arg[0] == 'r')
        {
            dst_reg = get_register(dst_arg);

        }
        else if (dst_arg[0] == 'e')
        {
            if (dst_arg[1] == 'a')
            {
                dst_reg = get_register("rax");

            }
            else if (dst_arg[1] == 'b')
            {
                dst_reg = get_register("rbx");
            }
            else if (dst_arg[1] == 'c')
            {

                dst_reg = get_register("rcx");
            }
            else if (dst_arg[1] == 'd')
            {

                dst_reg = get_register("rdx");
            }

        }
        else  if (dst_arg[0] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst_arg[0] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst_arg[0] == 'c')
        {

            dst_reg = get_register("rcx");
        }
        else if (dst_arg[0] == 'd')
        {

            dst_reg = get_register("rdx");
        }
        else
        {

            printf("error");
        }

    }


    //  获取第二个寄存器
    if (src[0] == 'r')
    {
        src_reg = get_register(src);

    }
    else if (src[0] == 'e')
    {
        if (src[1] == 'a')
        {
            src_reg = get_register("rax");

        }
        else if (src[1] == 'b')
        {
            src_reg = get_register("rbx");
        }
        else if (src[1] == 'c')
        {

            src_reg = get_register("rcx");
        }
        else if (src[1] == 'd')
        {

            src_reg = get_register("rdx");
        }

    }
    else if (src[0] == 'a')
    {
        src_reg = get_register("rax");

    }
    else if (src[0] == 'b')
    {
        src_reg = get_register("rbx");
    }
    else if (src[0] == 'c')
    {

        src_reg = get_register("rcx");
    }
    else if (src[0] == 'd')
    {

        src_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }


    // 开始按照 rcx的值进行填充

    //获取RCX的值
    Register rcx_reg = get_register("rcx");
    ULONG64 rcx = vm_registers->registers[rcx_reg].r64;




    int i = 0;
    while (rcx != 0)
    {

        DataSize offset_type = (dst[0] == 'b') ? BYTE_SIZE : (dst[0] == 'w') ? WORD_SIZE : (dst[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
        switch (offset_type) {
        case BYTE_SIZE:  ((UINT8*)(vm_registers->registers[dst_reg].r64 + i * 1))[0] = vm_registers->registers[src_reg].r8; break;
        case WORD_SIZE:  ((UINT16*)(vm_registers->registers[dst_reg].r64 + i * 2))[0] = vm_registers->registers[src_reg].r16; break;
        case DWORD_SIZE: ((UINT32*)(vm_registers->registers[dst_reg].r64 + i * 4))[0] = vm_registers->registers[src_reg].r32; break;
        case QWORD_SIZE: ((UINT64*)(vm_registers->registers[dst_reg].r64 + i * 8))[0] = vm_registers->registers[src_reg].r64; break;
        }

        rcx = rcx - 1;
    }

    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;

}
int execute_imul(VM_registers* vm_registers, const char* dst, const char* src1, const char* src2)
{
    //  imul rax, rax, 0
        //imul rax, rax, 1
        //imul rax, rax, 2
        //imul rax, rax, 3
        //imul rax, rax, 4
        //    imul rax, rax, 0xb
    Register dst_reg;
    Register src1_reg;
    //  获取dst寄存器

    if (dst[0] == 'r')
    {
        dst_reg = get_register(dst);

    }
    else if (dst[0] == 'e')
    {
        if (dst[1] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst[1] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst[1] == 'c')
        {

            dst_reg = get_register("rcx");
        }
        else if (dst[1] == 'd')
        {

            dst_reg = get_register("rdx");
        }

    }
    else if (dst[0] == 'a')
    {
        dst_reg = get_register("rax");

    }
    else if (dst[0] == 'b')
    {
        dst_reg = get_register("rbx");
    }
    else if (dst[0] == 'c')
    {

        dst_reg = get_register("rcx");
    }
    else if (dst[0] == 'd')
    {

        dst_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }
    //  获取 src1 寄存器


    if (src1[0] == 'r')
    {
        src1_reg = get_register(src1);

    }
    else if (src1[0] == 'e')
    {
        if (src1[1] == 'a')
        {
            src1_reg = get_register("rax");

        }
        else if (src1[1] == 'b')
        {
            src1_reg = get_register("rbx");
        }
        else if (src1[1] == 'c')
        {

            src1_reg = get_register("rcx");
        }
        else if (src1[1] == 'd')
        {

            src1_reg = get_register("rdx");
        }

    }
    else if (src1[0] == 'a')
    {
        src1_reg = get_register("rax");

    }
    else if (src1[0] == 'b')
    {
        src1_reg = get_register("rbx");
    }
    else if (src1[0] == 'c')
    {

        src1_reg = get_register("rcx");
    }
    else if (src1[0] == 'd')
    {

        src1_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }





    // 将src2转换成立即数，
    ULONG64 num = 0;
    sscanf(src2, "%x", &num); // 8


    vm_registers->registers[dst_reg].r64 = vm_registers->registers[src1_reg].r64 * num;

    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;
}
int execute_test(VM_registers* vm_registers, const char* dst, const char* src)
{
    Register dst_reg;
    Register src_reg;
    //  获取dst寄存器

    if (dst[0] == 'r')
    {
        dst_reg = get_register(dst);

    }
    else if (dst[0] == 'e')
    {
        if (dst[1] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst[1] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst[1] == 'c')
        {

            dst_reg = get_register("rcx");
        }
        else if (dst[1] == 'd')
        {

            dst_reg = get_register("rdx");
        }

    }
    else if (dst[0] == 'a')
    {
        dst_reg = get_register("rax");

    }
    else if (dst[0] == 'b')
    {
        dst_reg = get_register("rbx");
    }
    else if (dst[0] == 'c')
    {

        dst_reg = get_register("rcx");
    }
    else if (dst[0] == 'd')
    {

        dst_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }
    //  获取 src 寄存器


    if (src[0] == 'r')
    {
        src_reg = get_register(src);

    }
    else if (src[0] == 'e')
    {
        if (src[1] == 'a')
        {
            src_reg = get_register("rax");

        }
        else if (src[1] == 'b')
        {
            src_reg = get_register("rbx");
        }
        else if (src[1] == 'c')
        {

            src_reg = get_register("rcx");
        }
        else if (src[1] == 'd')
        {

            src_reg = get_register("rdx");
        }

    }
    else if (src[0] == 'a')
    {
        src_reg = get_register("rax");

    }
    else if (src[0] == 'b')
    {
        src_reg = get_register("rbx");
    }
    else if (src[0] == 'c')
    {

        src_reg = get_register("rcx");
    }
    else if (src[0] == 'd')
    {

        src_reg = get_register("rdx");
    }
    else
    {

        printf("error");
    }

    vm_registers->registers[dst_reg].r64 = vm_registers->registers[dst_reg].r64 & vm_registers->registers[src_reg].r64;

    LONG64 result = vm_registers->registers[dst_reg].r64 & vm_registers->registers[src_reg].r64;

    // 更新 ZF (Zero Flag)
    vm_registers->rflags.ZF = (result == 0);

    // 更新 SF (Sign Flag)
    vm_registers->rflags.SF = (result < 0);

    // 更新 PF (Parity Flag)
    // 计算结果最低字节中的1的个数
    // 设置 PF 标志
    char low_byte = result & 0xFF;
    int one_bits = 0;
    for (int i = 0; i < 8; i++) {
        if (low_byte & (1 << i)) {
            one_bits++;
        }
    }
    vm_registers->rflags.PF = (one_bits % 2 == 0);

    // CF 和 OF 被清除
    vm_registers->rflags.CF = 0;
    vm_registers->rflags.OF = 0;




    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;
}
int execute_cmp(VM_registers* vm_registers, const char* dst, const char* src)
{
    //cmp dword ptr[rsp + 0x4d4], 0
    //cmp qword ptr[rbp + 0xf8], -1     说明所有的立即数都要变成有符号数
    //cmp dword ptr[rsp + 0x4d4], rax

    //cmp rax，dword ptr[rsp + 0x4d4]
    //cmp rax，rbx
    //cmp rax，0
    ULONG64 dst_num = 0;
    ULONG64 src_num = 0;
    int reg_type = 0;
    if ((dst[0] == 'r' || dst[0] == 'e' || dst[0] == 'a' || dst[0] == 'b' || dst[0] == 'c' || dst[0] == 'd') && (dst[1] == 'a' || dst[1] == 'b' || dst[1] == 'c' || dst[1] == 'd' || dst[1] == 's' || dst[1] == '8' || dst[1] == '9' || dst[1] == '1' || dst[1] == 'x'))

    {

        printf("第一个参数是寄存器\n");
        Register dst_reg;
        if (dst[0] == 'r')
        {
            reg_type = 64;
            dst_reg = get_register(dst);

        }
        else if (dst[0] == 'e')
        {
            if (dst[1] == 'a')
            {
                dst_reg = get_register("rax");
                reg_type = 64;
            }
            else if (dst[1] == 'b')
            {
                reg_type = 64;
                dst_reg = get_register("rbx");
            }
            else if (dst[1] == 'c')
            {
                reg_type = 64;
                dst_reg = get_register("rcx");
            }

            else if (dst[1] == 's')
            {
                reg_type = 64;
                dst_reg = get_register("rsi");
            }
            else if (dst[1] == 'd' && dst[2] == 'i')
            {
                reg_type = 64;
                dst_reg = get_register("rdi");
            }
            else if (dst[1] == 'd')
            {
                reg_type = 64;
                dst_reg = get_register("rdx");
            }

        }
        else  if (dst[0] == 'a')
        {
            dst_reg = get_register("rax");
            reg_type = 16;
        }
        else if (dst[0] == 'b')
        {
            reg_type = 16;
            dst_reg = get_register("rbx");
        }
        else if (dst[0] == 'c')
        {
            reg_type = 16;
            dst_reg = get_register("rcx");
        }
        else if (dst[0] == 'd')
        {
            reg_type = 16;
            dst_reg = get_register("rdx");
        }
        else
        {

            printf("error");
            return 1;
        }



        if (reg_type == 64)
        {
            dst_num = vm_registers->registers[dst_reg].r64;
        }
        else if (reg_type == 32)
        {
            dst_num = vm_registers->registers[dst_reg].r32;

        }
        else if (reg_type == 16)
        {
            dst_num = vm_registers->registers[dst_reg].r16;

        }

        //如果 第二个参数是 寄存器
        if ((src[0] == 'r' || src[0] == 'e' || src[0] == 'a' || src[0] == 'b' || src[0] == 'c' || src[0] == 'd') && (src[1] == 'a' || src[1] == 'b' || src[1] == 'c' || src[1] == 'd' || src[1] == 's' || src[1] == '8' || src[1] == '9' || src[1] == '1' || src[1] == 'x'))
        {

            Register src_reg;

            if (src[0] == 'r')
            {
                reg_type = 64;
                src_reg = get_register(src);

            }
            else if (src[0] == 'e')
            {
                if (src[1] == 'a')
                {
                    reg_type = 32;
                    src_reg = get_register("rax");

                }
                else if (src[1] == 'b')
                {
                    reg_type = 32;
                    src_reg = get_register("rbx");
                }
                else if (src[1] == 'c')
                {
                    reg_type = 32;
                    src_reg = get_register("rcx");
                }

                else if (src[1] == 's')
                {
                    reg_type = 32;
                    src_reg = get_register("rsi");
                }
                else if (src[1] == 'd' && src[2] == 'i')
                {
                    reg_type = 32;
                    src_reg = get_register("rdi");
                }
                else if (src[1] == 'd')
                {
                    reg_type = 32;
                    src_reg = get_register("rdx");
                }

            }
            else if (src[0] == 'a')
            {
                reg_type = 16;
                src_reg = get_register("rax");

            }
            else if (src[0] == 'b')
            {
                reg_type = 16;
                src_reg = get_register("rbx");
            }
            else if (src[0] == 'c')
            {
                reg_type = 16;
                src_reg = get_register("rcx");
            }
            else if (src[0] == 'd')
            {
                reg_type = 16;
                src_reg = get_register("rdx");
            }
            else
            {

                printf("error");
                return 1;
            }


            //   寄存器到寄存器赋值

            if (reg_type == 64)
            {
                src_num = vm_registers->registers[src_reg].r64;
            }
            else if (reg_type == 32)
            {
                src_num = vm_registers->registers[src_reg].r32;
            }
            else if (reg_type == 16)
            {
                src_num = vm_registers->registers[src_reg].r16;
            }

        }

        //如果  第二个参数是 qword ptr [rsp + 0x8]
        else if (src[0] == 'q' || src[0] == 'd' || src[0] == 'w' || src[0] == 'b')
        {
            char src_temp[50];
            strcpy(src_temp, src); // 复制字符串到可修改的缓冲区

            //  定义 [] 中的 地址
            ULONG64 target_addr = 0;

            char* ji_lu_arg[10];
            int num = 0;
            CHAR* arg1 = strtok(src_temp, " "); // 获取空格为分隔符的第一个字符串  QWORD
            printf("截取的字符串：%s\n", arg1);
            arg1 = strtok(NULL, " ");  //ptr
            printf("截取的字符串：%s\n", arg1);
            arg1 = strtok(NULL, "["); // [rsp
            arg1 = strtok(arg1, "]"); // [rsp

            // 如果是 [rsp] 
            // 否则 可能的结果
            // 1、 [rbx + 0x3c]
            // 2、 [rbx + rcx]
            // 3、 [rbx + rcx*3]
            // 4、 [rbx + rcx + 0x88]
            // 
            // 所以要先获取到  【】 中的所有参数，再依次判断出每个参数是什么类型

            if (arg1 != NULL)
            {
                char* token = strtok(arg1, " ");
                while (token != NULL) {
                    printf("截取的字符串：%s\n", token);


                    ji_lu_arg[num] = (char*)malloc(strlen(token) + 1);
                    strcpy(ji_lu_arg[num], token);
                    num++;
                    token = strtok(NULL, " ");  // 继续解析下一个部分


                }
            }

            printf("num:%d\n", num);

            // 依次识别 每个参数的种类 判断参数个数1, 3, 5
            if (num == 1)
            {
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");

                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                    }
                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                    }
                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                }
                else
                {

                    printf("error");
                    return 0;
                }

                target_addr = target_addr + vm_registers->registers[reg1].r64;
            }
            else if (num == 3)// 如果 两个参数 一个 符号
            {
                // 确定第一个是什么寄存器
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);
                    target_addr = target_addr + vm_registers->registers[reg1].r64;
                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }

                // 判断第二个 是否有 * 符号
                int symbol_flag = 0;
                char symbol = NULL;

                for (int i = 0; i < strlen(ji_lu_arg[2]); i++)
                {
                    if (ji_lu_arg[2][i] == '*')
                    {
                        symbol_flag = 1;
                        symbol = '*';
                    }

                }
                //如果有*，进行分离，识别寄存器，符号，和立即数
                if (symbol_flag == 1)//rcx*0x3
                {
                    char* a1 = strtok(ji_lu_arg[2], "*");// rcx
                    char* a2 = strtok(NULL, "*");        // 0x3

                    int a2_num = 0;
                    sscanf(a2, "%x", &a2_num); // 3
                    // 判断 a1是什么寄存器
                    Register reg2;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (a1[0] == 'r')
                    {
                        reg2 = get_register(a1);
                        target_addr = target_addr + vm_registers->registers[reg2].r64 * a2_num;
                    }
                    else if (a1[0] == 'e')
                    {
                        if (a1[1] == 'a')
                        {
                            reg2 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'b')
                        {
                            reg2 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'c')
                        {

                            reg2 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'd')
                        {

                            reg2 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 's')
                        {

                            reg2 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }
                        else if (a1[1] == 'd' && a1[2] == 'i')
                        {

                            reg2 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                        }

                    }
                    else if (a1[0] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }
                    else if (a1[0] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                    }



                }
                // 如果没有 识别第二个参数是寄存器还是立即数
                else
                {
                    Register reg2;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (ji_lu_arg[2][0] == 'r')
                    {
                        reg2 = get_register(ji_lu_arg[2]);
                        target_addr = target_addr + vm_registers->registers[reg2].r64;
                    }
                    else if (ji_lu_arg[2][0] == 'e')
                    {
                        if (ji_lu_arg[2][1] == 'a')
                        {
                            reg2 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'b')
                        {
                            reg2 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'c')
                        {

                            reg2 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'd')
                        {

                            reg2 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 's')
                        {

                            reg2 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }
                        else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                        {

                            reg2 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg2].r32;
                        }

                    }
                    else if (ji_lu_arg[2][0] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else if (ji_lu_arg[2][0] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r16;
                    }
                    else // 不是寄存器是立即数
                    {


                        sscanf(ji_lu_arg[2], "%x", &offset_num); // 8
                        target_addr = target_addr + offset_num;

                    }
                }


            }
            else if (num == 5) // 三个参数 一个 符号
            {
                // 确定第一个是什么寄存器
                // 确定第二个是什么寄存器

                // 判断第二个是不是 寄存器
                // 
                //       如果是确定是什么寄存器
                //           如果不是 判断是否有加减乘除符号
                //               如果有则提取并计算
                //               如果没有则可以确定为立即数

                // 确定第一个是什么寄存器
                Register reg1;
                if (ji_lu_arg[0][0] == 'r')
                {
                    reg1 = get_register(ji_lu_arg[0]);
                    target_addr = target_addr + vm_registers->registers[reg1].r64;

                }
                else if (ji_lu_arg[0][0] == 'e')
                {
                    if (ji_lu_arg[0][1] == 'a')
                    {
                        reg1 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;

                    }
                    else if (ji_lu_arg[0][1] == 'b')
                    {
                        reg1 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'c')
                    {

                        reg1 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd')
                    {

                        reg1 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 's')
                    {

                        reg1 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }
                    else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                    {

                        reg1 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg1].r32;
                    }

                }
                else if (ji_lu_arg[0][0] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;

                }
                else if (ji_lu_arg[0][0] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else if (ji_lu_arg[0][0] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }

                // 确定第二个是什么寄存器
                Register reg2;
                if (ji_lu_arg[2][0] == 'r')
                {
                    reg2 = get_register(ji_lu_arg[2]);
                    target_addr = target_addr + vm_registers->registers[reg2].r64;

                }
                else if (ji_lu_arg[2][0] == 'e')
                {
                    if (ji_lu_arg[2][1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;

                    }
                    else if (ji_lu_arg[2][1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                }
                else if (ji_lu_arg[2][0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;

                }
                else if (ji_lu_arg[2][0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else
                {

                    printf("error");
                    return 0;
                }


                // 判断第三个参数中是否有加减乘除符号
                int symbol_flag = 0;
                char symbol = NULL;

                for (int i = 0; i < strlen(ji_lu_arg[4]); i++)
                {
                    if (ji_lu_arg[4][i] == '*')
                    {
                        symbol_flag = 1;
                        symbol = '*';
                    }

                }
                //如果有*，进行分离，识别寄存器，符号，和立即数
                if (symbol_flag == 1)
                {
                    char* a1 = strtok(ji_lu_arg[4], "*");
                    char* a2 = strtok(NULL, "*");

                    int a2_num = 0;
                    sscanf(a2, "%x", &a2_num); // 8
                    // 判断 a1是什么寄存器
                    Register reg3;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (a1[0] == 'r')
                    {
                        reg3 = get_register(a1);

                        target_addr = target_addr + vm_registers->registers[reg3].r64 * a2_num;
                    }
                    else if (a1[0] == 'e')
                    {
                        if (a1[1] == 'a')
                        {
                            reg3 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'b')
                        {
                            reg3 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'c')
                        {

                            reg3 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'd')
                        {

                            reg3 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 's')
                        {

                            reg3 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }
                        else if (a1[1] == 'd' && a1[2] == 'i')
                        {

                            reg3 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                        }

                    }
                    else if (a1[0] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }
                    else if (a1[0] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                    }




                }
                // 如果没有 识别第二个参数是寄存器还是立即数
                else
                {
                    Register reg3;
                    ULONG64 offset_num = 0;
                    //  如果是确定是什么寄存器
                    if (ji_lu_arg[4][0] == 'r')
                    {
                        reg3 = get_register(ji_lu_arg[4]);
                        target_addr = target_addr + vm_registers->registers[reg3].r64;
                    }
                    else if (ji_lu_arg[4][0] == 'e')
                    {
                        if (ji_lu_arg[4][1] == 'a')
                        {
                            reg3 = get_register("rax");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'b')
                        {
                            reg3 = get_register("rbx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'c')
                        {

                            reg3 = get_register("rcx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'd')
                        {

                            reg3 = get_register("rdx");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 's')
                        {

                            reg3 = get_register("rsi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }
                        else if (ji_lu_arg[4][1] == 'd' && ji_lu_arg[4][2] == 'i')
                        {

                            reg3 = get_register("rdi");
                            target_addr = target_addr + vm_registers->registers[reg3].r32;
                        }

                    }
                    else if (ji_lu_arg[4][0] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else if (ji_lu_arg[4][0] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r16;
                    }
                    else // 不是寄存器是立即数
                    {


                        sscanf(ji_lu_arg[4], "%x", &offset_num); // 8
                        target_addr = target_addr + offset_num;

                    }
                }

            }
            else
            {

                printf("error");
                return 0;
            }


            // 按照指定的大小开始赋值，x86-64 架构的一个特性，当对 32 位寄存器操作时，其对应的 64 位寄存器的高 32 位会被自动清零。

            printf("target_addr:%x\n", target_addr);
            DataSize offset_type = (src[0] == 'b') ? BYTE_SIZE : (src[0] == 'w') ? WORD_SIZE : (src[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
            switch (offset_type) {
            case BYTE_SIZE: src_num = *((UINT8*)target_addr); break;
            case WORD_SIZE: src_num = *((UINT16*)target_addr); break;
            case DWORD_SIZE:src_num = *((UINT32*)target_addr); break;
            case QWORD_SIZE: src_num = *((UINT64*)target_addr); break;

            }



        }

        else {   // 如果第二个参数是 立即数
            UINT64 num1 = 0;
            sscanf(src, "%x", &num1);

            // 立即数赋值

            src_num = num1;
        }
    }

    // 如果 第一个参数qword ptr [rsp + 0x8]
    else if (dst[0] == 'q' || dst[0] == 'd' || dst[0] == 'w' || dst[0] == 'b')   //   dst 是 内存   
    {
        char src_temp[50];
        strcpy(src_temp, dst); // 复制字符串到可修改的缓冲区

        //  定义 [] 中的 地址
        ULONG64 target_addr = 0;

        char* ji_lu_arg[10];
        int num = 0;
        CHAR* arg1 = strtok(src_temp, " "); // 获取空格为分隔符的第一个字符串  QWORD
        printf("截取的字符串：%s\n", arg1);
        arg1 = strtok(NULL, " ");  //ptr
        printf("截取的字符串：%s\n", arg1);
        arg1 = strtok(NULL, "["); // [rsp
        arg1 = strtok(arg1, "]"); // [rsp

        // 如果是 [rsp] 
        // 否则 可能的结果
        // 1、 [rbx + 0x3c]
        // 2、 [rbx + rcx]
        // 3、 [rbx + rcx*3]
        // 4、 [rbx + rcx + 0x88]
        // 
        // 所以要先获取到  【】 中的所有参数，再依次判断出每个参数是什么类型

        if (arg1 != NULL)
        {
            char* token = strtok(arg1, " ");
            while (token != NULL) {
                printf("截取的字符串：%s\n", token);


                ji_lu_arg[num] = (char*)malloc(strlen(token) + 1);
                strcpy(ji_lu_arg[num], token);
                num++;
                token = strtok(NULL, " ");  // 继续解析下一个部分


            }
        }

        printf("num:%d\n", num);

        // 依次识别 每个参数的种类 判断参数个数1, 3, 5
        if (num == 1)
        {
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);

            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");

                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");
                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                }
                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");
                }
            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
            }
            else
            {

                printf("error");
                return 0;
            }

            target_addr = target_addr + vm_registers->registers[reg1].r64;
        }
        else if (num == 3)// 如果 两个参数 一个 符号
        {
            // 确定第一个是什么寄存器
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);
                target_addr = target_addr + vm_registers->registers[reg1].r64;
            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg1].r16;

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else
            {

                printf("error");
                return 0;
            }

            // 判断第二个 是否有 * 符号
            int symbol_flag = 0;
            char symbol = NULL;

            for (int i = 0; i < strlen(ji_lu_arg[2]); i++)
            {
                if (ji_lu_arg[2][i] == '*')
                {
                    symbol_flag = 1;
                    symbol = '*';
                }

            }
            //如果有*，进行分离，识别寄存器，符号，和立即数
            if (symbol_flag == 1)//rcx*0x3
            {
                char* a1 = strtok(ji_lu_arg[2], "*");// rcx
                char* a2 = strtok(NULL, "*");        // 0x3

                int a2_num = 0;
                sscanf(a2, "%x", &a2_num); // 3
                // 判断 a1是什么寄存器
                Register reg2;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (a1[0] == 'r')
                {
                    reg2 = get_register(a1);
                    target_addr = target_addr + vm_registers->registers[reg2].r64 * a2_num;
                }
                else if (a1[0] == 'e')
                {
                    if (a1[1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }
                    else if (a1[1] == 'd' && a1[2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32 * a2_num;
                    }

                }
                else if (a1[0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }
                else if (a1[0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16 * a2_num;
                }



            }
            // 如果没有 识别第二个参数是寄存器还是立即数
            else
            {
                Register reg2;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (ji_lu_arg[2][0] == 'r')
                {
                    reg2 = get_register(ji_lu_arg[2]);
                    target_addr = target_addr + vm_registers->registers[reg2].r64;
                }
                else if (ji_lu_arg[2][0] == 'e')
                {
                    if (ji_lu_arg[2][1] == 'a')
                    {
                        reg2 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'b')
                    {
                        reg2 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'c')
                    {

                        reg2 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd')
                    {

                        reg2 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 's')
                    {

                        reg2 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }
                    else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                    {

                        reg2 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg2].r32;
                    }

                }
                else if (ji_lu_arg[2][0] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else if (ji_lu_arg[2][0] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r16;
                }
                else // 不是寄存器是立即数
                {


                    sscanf(ji_lu_arg[2], "%x", &offset_num); // 8
                    target_addr = target_addr + offset_num;

                }
            }


        }
        else if (num == 5) // 三个参数 一个 符号
        {
            // 确定第一个是什么寄存器
            // 确定第二个是什么寄存器

            // 判断第二个是不是 寄存器
            // 
            //       如果是确定是什么寄存器
            //           如果不是 判断是否有加减乘除符号
            //               如果有则提取并计算
            //               如果没有则可以确定为立即数

            // 确定第一个是什么寄存器
            Register reg1;
            if (ji_lu_arg[0][0] == 'r')
            {
                reg1 = get_register(ji_lu_arg[0]);
                target_addr = target_addr + vm_registers->registers[reg1].r64;

            }
            else if (ji_lu_arg[0][0] == 'e')
            {
                if (ji_lu_arg[0][1] == 'a')
                {
                    reg1 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;

                }
                else if (ji_lu_arg[0][1] == 'b')
                {
                    reg1 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'c')
                {

                    reg1 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd')
                {

                    reg1 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 's')
                {

                    reg1 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }
                else if (ji_lu_arg[0][1] == 'd' && ji_lu_arg[0][2] == 'i')
                {

                    reg1 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg1].r32;
                }

            }
            else if (ji_lu_arg[0][0] == 'a')
            {
                reg1 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg1].r16;

            }
            else if (ji_lu_arg[0][0] == 'b')
            {
                reg1 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'c')
            {

                reg1 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else if (ji_lu_arg[0][0] == 'd')
            {

                reg1 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg1].r16;
            }
            else
            {

                printf("error");
                return 0;
            }

            // 确定第二个是什么寄存器
            Register reg2;
            if (ji_lu_arg[2][0] == 'r')
            {
                reg2 = get_register(ji_lu_arg[2]);
                target_addr = target_addr + vm_registers->registers[reg2].r64;

            }
            else if (ji_lu_arg[2][0] == 'e')
            {
                if (ji_lu_arg[2][1] == 'a')
                {
                    reg2 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;

                }
                else if (ji_lu_arg[2][1] == 'b')
                {
                    reg2 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 'c')
                {

                    reg2 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 'd')
                {

                    reg2 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 's')
                {

                    reg2 = get_register("rsi");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }
                else if (ji_lu_arg[2][1] == 'd' && ji_lu_arg[2][2] == 'i')
                {

                    reg2 = get_register("rdi");
                    target_addr = target_addr + vm_registers->registers[reg2].r32;
                }

            }
            else if (ji_lu_arg[2][0] == 'a')
            {
                reg2 = get_register("rax");
                target_addr = target_addr + vm_registers->registers[reg2].r16;

            }
            else if (ji_lu_arg[2][0] == 'b')
            {
                reg2 = get_register("rbx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else if (ji_lu_arg[2][0] == 'c')
            {

                reg2 = get_register("rcx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else if (ji_lu_arg[2][0] == 'd')
            {

                reg2 = get_register("rdx");
                target_addr = target_addr + vm_registers->registers[reg2].r16;
            }
            else
            {

                printf("error");
                return 0;
            }


            // 判断第三个参数中是否有加减乘除符号
            int symbol_flag = 0;
            char symbol = NULL;

            for (int i = 0; i < strlen(ji_lu_arg[4]); i++)
            {
                if (ji_lu_arg[4][i] == '*')
                {
                    symbol_flag = 1;
                    symbol = '*';
                }

            }
            //如果有*，进行分离，识别寄存器，符号，和立即数
            if (symbol_flag == 1)
            {
                char* a1 = strtok(ji_lu_arg[4], "*");
                char* a2 = strtok(NULL, "*");

                int a2_num = 0;
                sscanf(a2, "%x", &a2_num); // 8
                // 判断 a1是什么寄存器
                Register reg3;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (a1[0] == 'r')
                {
                    reg3 = get_register(a1);

                    target_addr = target_addr + vm_registers->registers[reg3].r64 * a2_num;
                }
                else if (a1[0] == 'e')
                {
                    if (a1[1] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 's')
                    {

                        reg3 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }
                    else if (a1[1] == 'd' && a1[2] == 'i')
                    {

                        reg3 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32 * a2_num;
                    }

                }
                else if (a1[0] == 'a')
                {
                    reg3 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'b')
                {
                    reg3 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'c')
                {

                    reg3 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }
                else if (a1[0] == 'd')
                {

                    reg3 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16 * a2_num;
                }




            }
            // 如果没有 识别第二个参数是寄存器还是立即数
            else
            {
                Register reg3;
                ULONG64 offset_num = 0;
                //  如果是确定是什么寄存器
                if (ji_lu_arg[4][0] == 'r')
                {
                    reg3 = get_register(ji_lu_arg[4]);
                    target_addr = target_addr + vm_registers->registers[reg3].r64;
                }
                else if (ji_lu_arg[4][0] == 'e')
                {
                    if (ji_lu_arg[4][1] == 'a')
                    {
                        reg3 = get_register("rax");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'b')
                    {
                        reg3 = get_register("rbx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'c')
                    {

                        reg3 = get_register("rcx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'd')
                    {

                        reg3 = get_register("rdx");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 's')
                    {

                        reg3 = get_register("rsi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }
                    else if (ji_lu_arg[4][1] == 'd' && ji_lu_arg[4][2] == 'i')
                    {

                        reg3 = get_register("rdi");
                        target_addr = target_addr + vm_registers->registers[reg3].r32;
                    }

                }
                else if (ji_lu_arg[4][0] == 'a')
                {
                    reg3 = get_register("rax");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'b')
                {
                    reg3 = get_register("rbx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'c')
                {

                    reg3 = get_register("rcx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else if (ji_lu_arg[4][0] == 'd')
                {

                    reg3 = get_register("rdx");
                    target_addr = target_addr + vm_registers->registers[reg3].r16;
                }
                else // 不是寄存器是立即数
                {


                    sscanf(ji_lu_arg[4], "%x", &offset_num); // 8
                    target_addr = target_addr + offset_num;

                }
            }

        }
        else
        {

            printf("error");
            return 0;
        }


        // 按照指定的大小开始赋值，x86-64 架构的一个特性，当对 32 位寄存器操作时，其对应的 64 位寄存器的高 32 位会被自动清零。
       // vm_registers->registers[dst_reg].r64 = 0;
        printf("target_addr:%x\n", target_addr);
        DataSize offset_type = (dst[0] == 'b') ? BYTE_SIZE : (dst[0] == 'w') ? WORD_SIZE : (dst[0] == 'd') ? DWORD_SIZE : QWORD_SIZE;
        switch (offset_type) {
        case BYTE_SIZE:  dst_num = *((UINT8*)target_addr); break;
        case WORD_SIZE:  dst_num = *((UINT16*)target_addr); break;
        case DWORD_SIZE: dst_num = *((UINT32*)target_addr); break;
        case QWORD_SIZE: dst_num = *((UINT64*)target_addr); break;
        }

        // 第二个参数是寄存器
        if ((src[0] == 'r' || src[0] == 'e' || src[0] == 'a' || src[0] == 'b' || src[0] == 'c' || src[0] == 'd') && (src[1] == 'a' || src[1] == 'b' || src[1] == 'c' || src[1] == 'd' || src[1] == 's' || src[1] == '8' || src[1] == '9' || src[1] == '1' || src[1] == 'x'))
        {
            Register src_reg;

            if (src[0] == 'r')
            {
                reg_type = 64;
                src_reg = get_register(src);

            }
            else if (src[0] == 'e')
            {
                if (src[1] == 'a')
                {
                    reg_type = 32;
                    src_reg = get_register("rax");

                }
                else if (src[1] == 'b')
                {
                    reg_type = 32;
                    src_reg = get_register("rbx");
                }
                else if (src[1] == 'c')
                {
                    reg_type = 32;
                    src_reg = get_register("rcx");
                }
                else if (src[1] == 'd')
                {
                    reg_type = 32;
                    src_reg = get_register("rdx");
                }
                else if (src[1] == 's')
                {
                    reg_type = 32;
                    src_reg = get_register("rsi");
                }
                else if (src[1] == 'd' && src[2] == 'i')
                {
                    reg_type = 32;
                    src_reg = get_register("rdi");
                }

            }
            else  if (src[0] == 'a')
            {
                reg_type = 16;
                src_reg = get_register("rax");

            }
            else if (src[0] == 'b')
            {
                reg_type = 16;
                src_reg = get_register("rbx");
            }
            else if (src[0] == 'c')
            {
                reg_type = 16;
                src_reg = get_register("rcx");
            }
            else if (src[0] == 'd')
            {
                reg_type = 16;
                src_reg = get_register("rdx");
            }
            else
            {

                printf("error");
            }
            if (reg_type = 64)
            {
                src_num = vm_registers->registers[src_reg].r64;
            }
            else if (reg_type = 32)
            {
                src_num = vm_registers->registers[src_reg].r32;
            }
            else if (reg_type = 16)
            {
                src_num = vm_registers->registers[src_reg].r16;
            }



        }

        else { // 第二个参数是 立即数

            ULONG64 num1 = 0;
            sscanf(src, "%x", &num1); // 8

            src_num = num1;

        }


        //    long long address = calculate_effective_address(vm, dst);
        // /*   if (address < 0 || address >= MEMORY_SIZE) {
        //        fprintf(stderr, "Memory address out of bounds: %lld\n", address);
        //        exit(1);
        //        */
        //    }



    }
    else {
        fprintf(stderr, "Invalid destination operand: %s\n", dst);
        //  vm_registers->EIP = vm_registers->EIP + 1;
        return 1;
    }
    printf("dst_num : %x \n", dst_num);
    printf("src_num : %x \n", src_num);
    LONG64 result = dst_num - src_num;

    // 设置 CF 标志
    vm_registers->rflags.CF = (dst_num < src_num);

    // 设置 ZF 标志
    vm_registers->rflags.ZF = (result == 0);

    // 设置 SF 标志
    vm_registers->rflags.SF = (result < 0);

    // 设置 OF 标志
    vm_registers->rflags.OF = ((dst_num < 0 && src_num > 0 && result > 0) || (dst_num > 0 && src_num < 0 && result < 0));

    // 设置 PF 标志
    // 简单的方法：计算结果的低8位中1的个数，偶数个则PF为1，奇数个则PF为0
    char low_byte = result & 0xFF;
    int one_bits = 0;
    for (int i = 0; i < 8; i++) {
        if (low_byte & (1 << i)) {
            one_bits++;
        }
    }
    vm_registers->rflags.PF = (one_bits % 2 == 0);

    vm_registers->EIP = vm_registers->EIP + 1;
    return 0;

}
int execute_jo(VM_registers* vm_registers, const char* dst)
{
    // 1: 判断ELF 寄存器中的标志位，然后决定 EIP 的指令编号的变化

    // 2、将 dst 转换为int类型// 将src2转换成立即数，
    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8
    if (vm_registers->rflags.OF == true) {
        vm_registers->EIP = num;
    }
    else {
        printf("Overflow Flag not set. No jump.\n");
        vm_registers->EIP = vm_registers->EIP + 1;
    }

    return 0;
}
int execute_jn0(VM_registers* vm_registers, const char* dst)
{
    //jno 函数检查 OF 标志位，如果 OF 未设置（即溢出标志位为 0），则跳转，否则输出“不跳转”的信息。
    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8
    if (!vm_registers->rflags.OF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
        printf("Overflow Flag is set. No jump.\n");
    }



}
int execute_jb_jnae_jc(VM_registers* vm_registers, const char* dst)
{
    //这三条指令实际上是等效的，它们都在检测条件标志寄存器（RFLAGS）中的进位标志（CF）。如果 CF 被设置（CF = 1），则执行跳转。
    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (vm_registers->rflags.CF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }


}
int execute_jnb_jae_jnc(VM_registers* vm_registers, const char* dst)
{

    //这三条指令实际上是等效的，它们都在检测条件标志寄存器（RFLAGS）中的进位标志（CF）。如果 CF 未设置（CF = 0），则执行跳转。
    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (!vm_registers->rflags.CF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }

}
int execute_jn_je(VM_registers* vm_registers, const char* dst)
{
    // JE (Jump if Equal) 和 JZ (Jump if Zero) 是等效的，它们都在检测条件标志寄存器（RFLAGS）中的零标志（ZF）。如果 ZF 被设置（ZF = 1），则执行跳转。

    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8
    if (vm_registers->rflags.ZF == true) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }



}
int execute_jnz_jne(VM_registers* vm_registers, const char* dst)
{
    //  JNE 或 JNZ (Jump if Not Equal or Jump if Not Zero)，它们也是等效的，如果 ZF 未设置（ZF = 0），则执行跳转。
    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (!vm_registers->rflags.ZF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }
}
int execute_jbe_jna(VM_registers* vm_registers, const char* dst)
{
    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    //JBE(Jump if Below or Equal) 和 JNA(Jump if Not Above) 是等效的，它们都在检测条件标志寄存器（RFLAGS）中的进位标志（CF）和零标志（ZF）。如果 CF 被设置或 ZF 被设置（即 CF = 1 或 ZF = 1），则执行跳转。
    if (vm_registers->rflags.CF || vm_registers->rflags.ZF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }

}
int execute_jnbe_ja(VM_registers* vm_registers, const char* dst)
{

    //JNBE(Jump if Not Below or Equal) 和 JA(Jump if Above) 是等效的，它们都在检测条件标志寄存器（RFLAGS）中的进位标志（CF）和零标志（ZF）。如果 CF 未设置且 ZF 未设置（即 CF = 0 且 ZF = 0），则执行跳转。

    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (!vm_registers->rflags.CF || !vm_registers->rflags.ZF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }

}
int execute_js(VM_registers* vm_registers, const char* dst)
{
    //JS(Jump if Sign) 指令会在条件标志寄存器（RFLAGS）中的符号标志（SF）被设置时执行跳转。如果 SF 被设置（SF = 1），则执行跳转。

    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (vm_registers->rflags.SF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }

}
int execute_jns(VM_registers* vm_registers, const char* dst)
{
    //JNS(Jump if Not Sign) 指令会在条件标志寄存器（RFLAGS）中的符号标志（SF）未被设置时执行跳转。如果 SF 未被设置（SF = 0），则执行跳转。
    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (!vm_registers->rflags.SF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }
}
int execute_jp_jpe(VM_registers* vm_registers, const char* dst)
{
    //JP(Jump if Parity) 和 JPE(Jump if Parity Even) 是等效的，它们都在检测条件标志寄存器（RFLAGS）中的奇偶标志（PF）。如果 PF 被设置（PF = 1），则执行跳转。
    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (vm_registers->rflags.PF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }
}
int execute_jnp_jpo(VM_registers* vm_registers, const char* dst)
{
    //JNP（Jump if Not Parity）和 JPO（Jump if Parity Odd）这两个指令是相同的，它们在汇编中都用于根据奇偶标志位（PF）决定是否跳转。具体来说，JNP 和 JPO 指令在 PF 为 0 时执行跳转。
    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (!vm_registers->rflags.PF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }
}
int execute_jl_jnge(VM_registers* vm_registers, const char* dst)
{
    //JL（Jump if Less）和 JNGE（Jump if Not Greater or Equal）这两个指令是等效的。在汇编语言中，它们都是根据标志寄存器中的条件来决定是否跳转。具体来说，这两个指令在标志寄存器的 SF（Sign Flag）和 OF（Overflow Flag）不相等时执行跳转。

    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (vm_registers->rflags.SF != vm_registers->rflags.OF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }
}
int execute_jnl_jge(VM_registers* vm_registers, const char* dst)
{
    //JNL（Jump if Not Less）和 JGE（Jump if Greater or Equal）这两个指令是等效的。它们都在 SF（Sign Flag）和 OF（Overflow Flag）相等时执行跳转。

    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (vm_registers->rflags.SF == vm_registers->rflags.OF) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }
}
int execute_jle_jng(VM_registers* vm_registers, const char* dst)
{
    //JLE（Jump if Less or Equal）和 JNG（Jump if Not Greater）这两个指令是等效的。在汇编语言中，它们都是根据标志寄存器中的条件来决定是否跳转。具体来说，这两个指令在 ZF（Zero Flag）为1或 SF（Sign Flag）不等于 OF（Overflow Flag）时执行跳转。


    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (vm_registers->rflags.ZF || (vm_registers->rflags.SF != vm_registers->rflags.OF)) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }
}
int execute_jnle_jg(VM_registers* vm_registers, const char* dst)
{
    //JNLE（Jump if Not Less or Equal）和 JG（Jump if Greater）这两个指令是等效的。在汇编语言中，它们都是根据标志寄存器中的条件来决定是否跳转。具体来说，这两个指令在 ZF（Zero Flag）为 0 且 SF（Sign Flag）等于 OF（Overflow Flag）时执行跳转。

    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    if (!vm_registers->rflags.ZF && (vm_registers->rflags.SF == vm_registers->rflags.OF)) {
        vm_registers->EIP = num;
        return 0;
    }
    else {
        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;
    }
}
int execute_call(VM_registers* vm_registers, const char* dst)
{
    // 识别出 到底是普通跳转，还是外部API调用

    // 外部跳转   
    // 
    // 获取要跳转到的函数地址，将 RSP 和 EBP 的值进行保存，然后将虚拟栈RSP 和RBP 赋值给真正的寄存器
    // 将虚拟通用寄存器复制给真正的寄存器，
    // ！ 因为在汇编函数中所以不需要使用ret函数，API 执行后会返回到汇编函数，然后在汇编函数修复通用寄存器就可以
    //    且虚拟栈没有改变所以不用修复，然后汇编函数执行完毕之后就会返回到execute_call函数，执行收尾工作，最后将
    //    虚拟EIP + 1，结束函数

    // call qword ptr[rsp + 0x58]
    // call rdx

    // 内部跳转 模拟 jmp
    // call    0xfb  ------>  call    20
       // 如果 第一个参数是寄存器


    if ((dst[0] == 'r' || dst[0] == 'e' || dst[0] == 'a' || dst[0] == 'b' || dst[0] == 'c' || dst[0] == 'd') && (dst[1] == 'a' || dst[1] == 'b' || dst[1] == 'c' || dst[1] == 'd' || dst[1] == 's' || dst[1] == '8' || dst[1] == '9' || dst[1] == '1' || dst[1] == 'x'))

    {

        printf("第一个参数是寄存器\n");
        Register dst_reg;
        if (dst[0] == 'r')
        {
            dst_reg = get_register(dst);

        }
        else if (dst[0] == 'e')
        {
            if (dst[1] == 'a')
            {
                dst_reg = get_register("rax");

            }
            else if (dst[1] == 'b')
            {
                dst_reg = get_register("rbx");
            }
            else if (dst[1] == 'c')
            {

                dst_reg = get_register("rcx");
            }
            else if (dst[1] == 'd')
            {

                dst_reg = get_register("rdx");
            }

        }
        else if (dst[0] == 'a')
        {
            dst_reg = get_register("rax");

        }
        else if (dst[0] == 'b')
        {
            dst_reg = get_register("rbx");
        }
        else if (dst[0] == 'c')
        {

            dst_reg = get_register("rcx");
        }
        else if (dst[0] == 'd')
        {

            dst_reg = get_register("rdx");
        }
        else
        {

            printf("error");
        }

        //else {   // 如果第二个参数是 立即数
        //    UINT64 num = 0;
        //    sscanf(src, "%x", &num);

        //    // 立即数赋值

        //    vm_registers->registers[dst_reg].r64 = num;
        //}
        target_func_addr = vm_registers->registers[dst_reg].r64;
        vm_stacked_num = (vm_stack_low - vm_registers->registers[RSP].r64) / 8;
        printf("target_func_addr:%llx\n", target_func_addr);



        vm_rax = vm_registers->registers[RAX].r64;
        vm_rbx = vm_registers->registers[RBX].r64;
        vm_rcx = vm_registers->registers[RCX].r64;
        vm_rdx = vm_registers->registers[RDX].r64;

        vm_r8 = vm_registers->registers[R8].r64;
        vm_r9 = vm_registers->registers[R9].r64;
        vm_r10 = vm_registers->registers[R10].r64;
        vm_r11 = vm_registers->registers[R11].r64;
        vm_r12 = vm_registers->registers[R12].r64;
        vm_r13 = vm_registers->registers[R13].r64;
        vm_r14 = vm_registers->registers[R14].r64;
        vm_r15 = vm_registers->registers[R15].r64;

        vm_rsi = vm_registers->registers[RSI].r64;
        vm_rdi = vm_registers->registers[RDI].r64;

        vm_rbp = vm_registers->registers[RBP].r64;
        exec_api_func();

        vm_registers->registers[RAX].r64 = vm_rax;
        vm_registers->registers[RBX].r64 = vm_rbx;
        vm_registers->registers[RCX].r64 = vm_rcx;
        vm_registers->registers[RDX].r64 = vm_rdx;
        vm_registers->registers[RSI].r64 = vm_rsi;
        vm_registers->registers[RDI].r64 = vm_rdi;

        vm_registers->registers[R8].r64 = vm_r8;
        vm_registers->registers[R9].r64 = vm_r9;
        vm_registers->registers[R10].r64 = vm_r10;
        vm_registers->registers[R11].r64 = vm_r11;
        vm_registers->registers[R12].r64 = vm_r12;
        vm_registers->registers[R13].r64 = vm_r13;
        vm_registers->registers[R14].r64 = vm_r14;
        vm_registers->registers[R15].r64 = vm_r15;


        vm_registers->registers[RBP].r64 = vm_rbp;

        vm_registers->EIP = vm_registers->EIP + 1;
    }

    // 如果 第一个参数qword ptr [rsp + 0x8]
    else if (dst[0] == 'q' || dst[0] == 'd' || dst[0] == 'w' || dst[0] == 'b')   //   dst 是 内存   
    {

        // 获取 【】 中的值
        char* size = strtok((char*)dst, " ");          // qword 
        char* type = strtok(NULL, " ");                // ptr

        char* lin_shi_base_offset = strtok(NULL, " "); // [rsp
        char* symbol = strtok(NULL, " ");              // +
        char* offset = strtok(NULL, "]");   //  8]



        char* base_offset = strtok(lin_shi_base_offset, "[");  // rsp 
        // char* offset = strtok(lin_shi_offset, "]"); // 8  


        printf("size:%s\n", size);
        printf("type:%s\n", type);
        printf("base_offset:%s\n", base_offset);

        //  定义 [] 中的 地址
        ULONG64 target_addr = 0;

        // 判断 [rax + * ]
        if (offset == NULL)   // 说明没有第二个参数，则可以判定第一个参数就是寄存器
        {
            base_offset = strtok(base_offset, "]");  // rsp 
            printf("[ ] 只有一个参数是寄存器\n");
            Register base_offset_reg;
            if (base_offset[0] == 'r')
            {
                base_offset_reg = get_register(base_offset);

            }
            else if (base_offset[0] == 'e')
            {
                if (base_offset[1] == 'a')
                {
                    base_offset_reg = get_register("rax");

                }
                else if (base_offset[1] == 'b')
                {
                    base_offset_reg = get_register("rbx");
                }
                else if (base_offset[1] == 'c')
                {

                    base_offset_reg = get_register("rcx");
                }
                else if (base_offset[1] == 'd')
                {

                    base_offset_reg = get_register("rdx");
                }

            }
            else if (base_offset[0] == 'a')
            {
                base_offset_reg = get_register("rax");

            }
            else if (base_offset[0] == 'b')
            {
                base_offset_reg = get_register("rbx");
            }
            else if (base_offset[0] == 'c')
            {

                base_offset_reg = get_register("rcx");
            }
            else if (base_offset[0] == 'd')
            {

                base_offset_reg = get_register("rdx");
            }
            else
            {

                printf("error");
                return 0;
            }

            target_addr = vm_registers->registers[base_offset_reg].r64;
        }

        //  说明有第二个参数， 判断 []  中的第一个参数是什么寄存器
        else if ((base_offset[0] == 'r' || base_offset[0] == 'e' || base_offset[0] == 'a' || base_offset[0] == 'b' || base_offset[0] == 'c' || base_offset[0] == 'd') && (base_offset[1] == 'a' || base_offset[1] == 'b' || base_offset[1] == 'c' || base_offset[1] == 'd' || base_offset[1] == 's' || base_offset[1] == '8' || base_offset[1] == '9' || base_offset[1] == '1' || base_offset[1] == 'x'))
        {

            printf("第一个参数是寄存器\n");
            Register base_offset_reg;
            if (base_offset[0] == 'r')
            {
                base_offset_reg = get_register(base_offset);

            }
            else if (base_offset[0] == 'e')
            {
                if (base_offset[1] == 'a')
                {
                    base_offset_reg = get_register("rax");

                }
                else if (base_offset[1] == 'b')
                {
                    base_offset_reg = get_register("rbx");
                }
                else if (base_offset[1] == 'c')
                {

                    base_offset_reg = get_register("rcx");
                }
                else if (base_offset[1] == 'd')
                {

                    base_offset_reg = get_register("rdx");
                }

            }
            else if (base_offset[0] == 'a')
            {
                base_offset_reg = get_register("rax");

            }
            else if (base_offset[0] == 'b')
            {
                base_offset_reg = get_register("rbx");
            }
            else if (base_offset[0] == 'c')
            {

                base_offset_reg = get_register("rcx");
            }
            else if (base_offset[0] == 'd')
            {

                base_offset_reg = get_register("rdx");
            }
            else
            {

                printf("error");
            }

            //------------- [rax + rcx ]
            if ((offset[0] == 'r' || offset[0] == 'e' || offset[0] == 'a' || offset[0] == 'b' || offset[0] == 'c' || offset[0] == 'd') && (offset[1] == 'a' || offset[1] == 'b' || offset[1] == 'c' || offset[1] == 'd' || offset[1] == 's' || offset[1] == '8' || offset[1] == '9' || offset[1] == '1' || offset[1] == 'x'))
            {

                Register offset_reg;

                if (offset[0] == 'r')
                {
                    offset_reg = get_register(offset);

                }
                else if (offset[0] == 'e')
                {
                    if (offset[1] == 'a')
                    {
                        offset_reg = get_register("rax");

                    }
                    else if (offset[1] == 'b')
                    {
                        offset_reg = get_register("rbx");
                    }
                    else if (offset[1] == 'c')
                    {

                        offset_reg = get_register("rcx");
                    }
                    else if (offset[1] == 'd')
                    {
                        offset_reg = get_register("rdx");
                    }

                }
                else if (offset[0] == 'a')
                {
                    offset_reg = get_register("rax");

                }
                else if (offset[0] == 'b')
                {
                    offset_reg = get_register("rbx");
                }
                else if (offset[0] == 'c')
                {
                    offset_reg = get_register("rcx");
                }
                else if (offset[0] == 'd')
                {

                    offset_reg = get_register("rdx");
                }
                else
                {
                    printf("error");
                    return 1;
                }


                //  获取偏移值
                if (strcmp(symbol, "+") == 0)
                {
                    target_addr = vm_registers->registers[base_offset_reg].r64 + vm_registers->registers[offset_reg].r64;
                }
                else if (strcmp(symbol, "-") == 0)
                {
                    target_addr = vm_registers->registers[base_offset_reg].r64 - vm_registers->registers[offset_reg].r64;
                }
                else
                {
                    printf("symbool error\n");
                }

            }
            else //[rax + 0x6]
            {
                ULONG64 offset_num = 0;
                sscanf(offset, "%x", &offset_num); // 8

                if (strcmp(symbol, "+") == 0)
                {
                    target_addr = vm_registers->registers[base_offset_reg].r64 + offset_num;
                }
                else if (strcmp(symbol, "-") == 0)
                {
                    target_addr = vm_registers->registers[base_offset_reg].r64 - offset_num;
                }
                else
                {
                    printf("symbool error\n");
                    return 1;
                }



            }

        }
        else// [0x1 + rax]
        {
            ULONG64 base_offset_num = 0;
            sscanf(base_offset, "%x", &base_offset_num); // 8

            Register offset_reg;

            if (offset[0] == 'r')
            {
                offset_reg = get_register(offset);
            }
            else if (offset[0] == 'e')
            {
                if (offset[1] == 'a')
                {
                    offset_reg = get_register("rax");

                }
                else if (offset[1] == 'b')
                {
                    offset_reg = get_register("rbx");
                }
                else if (offset[1] == 'c')
                {

                    offset_reg = get_register("rcx");
                }
                else if (offset[1] == 'd')
                {
                    offset_reg = get_register("rdx");
                }

            }
            else if (offset[0] == 'a')
            {
                offset_reg = get_register("rax");

            }
            else if (offset[0] == 'b')
            {
                offset_reg = get_register("rbx");
            }
            else if (offset[0] == 'c')
            {
                offset_reg = get_register("rcx");
            }
            else if (offset[0] == 'd')
            {
                offset_reg = get_register("rdx");
            }
            else
            {
                printf("error");
                return 1;
            }



            if (strcmp(symbol, "+") == 0)
            {
                target_addr = vm_registers->registers[offset_reg].r64 + base_offset_num;
            }
            else if (strcmp(symbol, "-") == 0)
            {
                target_addr = vm_registers->registers[offset_reg].r64 + base_offset_num;
            }
            else
            {
                printf("symbool error\n");
                return 1;
            }


        }


        target_func_addr = ((UINT64*)target_addr)[0];  // 获取到  API 函数地址

        vm_rsp = vm_registers->registers[RSP].r64;
        vm_rbp = vm_registers->registers[RBP].r64;

        vm_rcx = vm_registers->registers[RCX].r64;
        vm_rdx = vm_registers->registers[RDX].r64;
        vm_r8 = vm_registers->registers[R8].r64;
        vm_r9 = vm_registers->registers[R9].r64;

        exec_api_func();

        vm_registers->EIP = vm_registers->EIP + 1;
        return 0;


    }
    else {  // 立即数跳转
        printf("普通跳转\n");
        UINT64 num1 = 0;
        sscanf(dst, "%d", &num1);


        if (vm_registers->execute_ret_addr[vm_registers->execute_ret_addr_num] == 0)
        {
            vm_registers->execute_ret_addr[vm_registers->execute_ret_addr_num] = vm_registers->EIP + 1;
            vm_registers->execute_ret_addr_num = vm_registers->execute_ret_addr_num + 1;
        }

        vm_registers->EIP = num1;


    }
    return 0;
}
int execute_jmp(VM_registers* vm_registers, const char* dst)
{

    // jmp    0x13c  ------>   jmp   40
    ULONG64 num = 0;
    sscanf(dst, "%d", &num); // 8

    vm_registers->EIP = num;
    return 0;
}
int execute_ret(VM_registers* vm_registers)
{
    // 1、 判断 eip 和 指令总数是否相等
    if (vm_registers->execute_ret_addr_num != 0)
    {
        vm_registers->EIP = vm_registers->execute_ret_addr[vm_registers->execute_ret_addr_num - 1];
        vm_registers->execute_ret_addr[vm_registers->execute_ret_addr_num - 1] = 0;
        vm_registers->execute_ret_addr_num = vm_registers->execute_ret_addr_num - 1;
        return 0;
    }
    else if (vm_registers->execute_ret_addr_num == 0)
    {
        return 1;

    }

    // 2、如果不相等  且vm_registers->execute_ret_addr_num 不为0，直接修改EIP 

}



int interpret(VM_registers* vm, const char* instruction) {

    char target[50];
    strcpy(target, instruction); // 复制字符串到可修改的缓冲区


    if (strcmp(target, "ret") == 0)
    {
        if (execute_ret(vm))
        {
            return 1;
        }
        else
        {
            return 0;
        }

    }
    else {

        // 使用 strtok 分割字符串

        // 识别操作数
        int num = 0;
        num = strchr(target, ' ') - target; // 得到的数字是 空格之前到首字符一共的字符数
        printf("num: %d\n", num);  //3

        printf("\n");
        char* op = (char*)malloc(num + 1);
        memset(op, 0, num + 1);
        // op[num+1] = '\0';
        strncpy(op, target, num);
        printf("op:%s\n", op);
        char* args = (char*)malloc(strlen(target) - num); // 算上空格长度正好写入 '\0',但是真实长度要-1
        memset(args, 0, strlen(target) - num);
        //args[strlen(target) - num] = '\0';
        strncpy(args, target + num + 1, strlen(target) - num - 1);
        printf("args:%s\n\n", args);





        //开始识别指令
        if (strcmp(op, "mov") == 0) {
            // 安装 逗号获取 参数1，参数2
              // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_mov(vm, arg1, arg2))
            {
                return 1;
            }


        }
        else if (strcmp(op, "movsx") == 0) {   // 安装 逗号获取 参数1，参数2
            // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_movsx(vm, arg1, arg2))
            {
                return 1;
            }
        }
        else if (strcmp(op, "lodsd") == 0) {
            // 安装 逗号获取 参数1，参数2
              // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_lodsd(vm, arg1, arg2))
            {
                return 1;
            }


        }
        else if (strcmp(op, "ror") == 0) {
            // 安装 逗号获取 参数1，参数2
              // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_ror(vm, arg1, arg2))
            {
                return 1;
            }


        }
        else if (strcmp(op, "shl") == 0) {
            // 安装 逗号获取 参数1，参数2
              // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_shl(vm, arg1, arg2))
            {
                return 1;
            }


        }
        else if (strcmp(op, "shr") == 0) {
            // 安装 逗号获取 参数1，参数2
              // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_shr(vm, arg1, arg2))
            {
                return 1;
            }


        }
        else if (strcmp(op, "movabs") == 0) {
            // 安装 逗号获取 参数1，参数2
              // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_movabs(vm, arg1, arg2))
            {
                return 1;
            }


        }
        else if (strcmp(op, "push") == 0)
        {

            if (execute_push(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "pop") == 0)
        {
            if (execute_pop(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "sub") == 0)
        {
            // 安装 逗号获取 参数1，参数2
      // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_sub(vm, arg1, arg2))
            {
                return 1;
            }
        }
        else if (strcmp(op, "add") == 0)
        {
            // 安装 逗号获取 参数1，参数2
            // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_add(vm, arg1, arg2))
            {
                return 1;
            }
        }
        else if (strcmp(op, "xor") == 0)
        {
            // 安装 逗号获取 参数1，参数2
        // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_xor(vm, arg1, arg2))
            {
                return 1;
            }
        }
        else if (strcmp(op, "lea") == 0)
        {
            // 安装 逗号获取 参数1，参数2
            // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_lea(vm, arg1, arg2))
            {
                return 1;
            }
        }
        else if (strcmp(op, "rep") == 0)
        {
            // 安装 逗号获取 参数1，参数2
            // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_rep(vm, arg1, arg2))
            {
                return 1;
            }

        }
        else if (strcmp(op, "imul") == 0)
        {
            // 安装 逗号获取 参数1，参数2
        // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;
            char* arg3;
            //|rax, rax, 0


            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别    第一个参数的长度
            // arg_num  就是 逗号前面有几个字符
            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);     //rax

            char* arg2_temp = args + arg_num + 2; // rax, |rax, 0
            arg_num = strchr(arg2_temp, ',') - arg2_temp;  // 获取到第二个参数的长度

            arg2 = (char*)malloc(arg_num + 1);
            memset(arg2, 0, arg_num + 1);
            strncpy(arg2, arg2_temp, arg_num);

            arg3 = (char*)malloc(strlen(arg2_temp) - arg_num - 1);
            memset(arg3, 0, strlen(arg2_temp) - arg_num - 1);
            strncpy(arg3, arg2_temp + arg_num + 2, strlen(arg2_temp) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);
            printf("arg2:%s\n", arg3);
            if (execute_imul(vm, arg1, arg2, arg3))
            {
                return 1;
            }
        }
        else if (strcmp(op, "test") == 0)
        {
            // 安装 逗号获取 参数1，参数2
        // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_test(vm, arg1, arg2))
            {
                return 1;
            }
        }
        else if (strcmp(op, "cmp") == 0)
        {
            // 安装 逗号获取 参数1，参数2
        // 识别参数1，参数2    逗号 + 空格作为分隔符
            char* arg1;
            char* arg2;

            int arg_num = 0;
            arg_num = strchr(args, ',') - args; // 只能识别到一个字符，两个字符是分开识别不是连起识别

            arg1 = (char*)malloc(arg_num + 1);
            memset(arg1, 0, arg_num + 1);
            strncpy(arg1, args, arg_num);


            arg2 = (char*)malloc(strlen(args) - arg_num - 1);
            memset(arg2, 0, strlen(args) - arg_num - 1);
            strncpy(arg2, args + arg_num + 2, strlen(args) - arg_num - 1);

            printf("arg1:%s\n", arg1);
            printf("arg2:%s\n", arg2);

            if (execute_cmp(vm, arg1, arg2))
            {
                return 1;
            }
        }
        else if (strcmp(op, "call") == 0)
        {
            if (execute_call(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jmp") == 0)
        {
            if (execute_jmp(vm, args))
            {
                return 1;
            }
        }

        else if (strcmp(op, "dec") == 0)
        {
            if (execute_dec(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "inc") == 0)
        {
            if (execute_inc(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jo") == 0)
        {
            if (execute_jo(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jn0") == 0)
        {
            if (execute_jn0(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jb") == 0 || strcmp(op, "jnae") == 0 || strcmp(op, "jc") == 0)
        {
            if (execute_jb_jnae_jc(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jnb") == 0 || strcmp(op, "jae") == 0 || strcmp(op, "jnc") == 0)
        {
            if (execute_jnb_jae_jnc(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jn") == 0 || strcmp(op, "je") == 0)
        {
            if (execute_jn_je(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jnz") == 0 || strcmp(op, "jne") == 0)
        {
            if (execute_jnz_jne(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jbe") == 0 || strcmp(op, "jna") == 0)
        {
            if (execute_jbe_jna(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jnbe") == 0 || strcmp(op, "ja") == 0)
        {
            if (execute_jnbe_ja(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "js") == 0)
        {
            if (execute_js(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jns") == 0)
        {
            if (execute_jns(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jp") == 0 || strcmp(op, "jpe") == 0)
        {
            if (execute_jp_jpe(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jnp") == 0 || strcmp(op, "jpo") == 0)
        {
            if (execute_jnp_jpo(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jl") == 0 || strcmp(op, "jnge") == 0)
        {
            if (execute_jl_jnge(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jnl") == 0 || strcmp(op, "jge") == 0)
        {
            if (execute_jnl_jge(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jle") == 0 || strcmp(op, "jng") == 0)
        {
            if (execute_jle_jng(vm, args))
            {
                return 1;
            }
        }
        else if (strcmp(op, "jnle") == 0 || strcmp(op, "jg") == 0)
        {
            if (execute_jnle_jg(vm, args))
            {
                return 1;
            }
        }
        else {
            fprintf(stderr, "Unknown instruction: %s\n");
            exit(1);
        }


        return 0;


    }
}


int start_vm_cpu()
{

    // 初始化   虚拟机
    VM_registers vm_registers;
    init_vm(&vm_registers);

    // 获取指令字符串
    char str[] = "sub rsp, 0x100&&mov rax, qword ptr gs:[0x60]&&mov rax, qword ptr [rax + 0x18]&&mov rax, qword ptr [rax + 0x30]&&mov rsi, qword ptr [rax + 0x10]&&mov rbx, qword ptr [rax + 0x40]&&mov rax, qword ptr [rax]&&cmp dword ptr [rbx + 0xc], 0x320033&&jne 4&&mov rcx, rsi&&mov rdx, 0xc917432&&call 60&&mov r14, rax&&mov rbx, 0x6c6c&&push rbx&&movabs rbx, 0x642e323372657375&&push rbx&&mov rcx, rsp&&sub rsp, 0x18&&call r14&&mov rbx, rax&&mov rcx, rbx&&mov rdx, 0x1e380a6a&&call 60&&mov r14, rax&&xor r9, r9&&xor r8, r8&&xor rdx, rdx&&xor rcx, rcx&&call r14&&mov rcx, rsi&&mov rdx, 0x1a22f51&&call 60&&mov r14, rax&&xor rax, rax&&push rax&&movabs rax, 0x6578652e636c6163&&push rax&&mov rcx, rsp&&sub rsp, 0x20&&mov rdx, 1&&call r14&&mov rcx, rsi&&movabs rdx, 0xbbafdf85&&call 60&&mov r14, rax&&mov rax, 0x6461&&push rax&&movabs rax, 0x6572685474697845&&push rax&&mov rcx, rsi&&mov rdx, rsp&&sub rsp, 0x20&&call r14&&mov r14, rax&&add rsp, 0x188&&sub rsp, 0x18&&xor rcx, rcx&&call r14&&ret &&sub rsp, 0x40&&push rsi&&mov rdi, rdx&&mov rbx, rcx&&mov rsi, qword ptr [rbx + 0x3c]&&mov rax, rsi&&shl rax, 0x36&&shr rax, 0x36&&mov rsi, qword ptr [rbx + rax + 0x88]&&shl rsi, 0x20&&shr rsi, 0x20&&add rsi, rbx&&push rsi&&mov esi, dword ptr [rsi + 0x20]&&add rsi, rbx&&xor rcx, rcx&&dec ecx&&inc ecx&&lodsd eax, dword ptr [rsi]&&add rax, rbx&&xor edx, edx&&cmp byte ptr [rax], 0&&je 90&&ror edx, 7&&push rcx&&movsx ecx, byte ptr [rax]&&add edx, ecx&&pop rcx&&inc rax&&jmp 81&&cmp edx, edi&&jne 77&&pop rsi&&mov edx, dword ptr [rsi + 0x24]&&add rdx, rbx&&movsx ecx, word ptr [rdx + rcx*2]&&mov edx, dword ptr [rsi + 0x1c]&&add rdx, rbx&&mov eax, dword ptr [rdx + rcx*4]&&add rax, rbx&&pop rsi&&add rsp, 0x40&&ret";

    const char delimiter[] = "&&";
    char* token;
    int count = 0;
    char* substrings[1024]; // 假设最多有1024个子字符串

    // Use strtok to split the string by delimiter
    token = strtok(str, delimiter);
    while (token != NULL) {
        // Allocate memory for each substring and save it
        substrings[count] = (char*)malloc(strlen(token) + 1);
        if (substrings[count] == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            return 1;
        }
        strcpy(substrings[count], token);
        //printf("Substring %d: %s\n", count + 1, substrings[count]);
        count++;
        token = strtok(NULL, delimiter);
    }

    printf("Total number of substrings: %d\n", count);
    vm_registers.num = count;

    // 后续操作可以使用substrings数组中的字符串
    // 例如，打印所有保存的子字符串
    printf("Saved substrings:\n");

    // 创建文件
    FILE* file = _wfopen(L"output.txt", L"w, ccs=UTF-8");


    // 检查文件是否成功打开
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    printf("1");
    wchar_t  buffer[100] = { 0 };  // 创建缓冲区
    printf("1");

    //  循环执行指令  
    int success = 0;
    int ci = 0;
    do
    {

        // 设置本地环境以支持多字节字符
        size_t requiredSize = mbstowcs(NULL, substrings[vm_registers.EIP], 0) + 1;
        wchar_t* wideString = new wchar_t[requiredSize];

        // 将 char* 转换为 wchar_t*
        mbstowcs(wideString, substrings[vm_registers.EIP], requiredSize);

        ULONG64  old_eip = vm_registers.EIP;
        _snwprintf(buffer, sizeof(buffer), L"要执行的EIP：%d     指令内容：%s \n", vm_registers.EIP, wideString);

        delete[] wideString;
        fputws(buffer, file);
        memset(buffer, 0, 100);


        success = interpret(&vm_registers, substrings[vm_registers.EIP]);  //  开始执行指令


        if (!success)  // 成功为 0 
        {

            _snwprintf(buffer, sizeof(buffer), L"指令执行成功        \n");
            fputws(buffer, file);
            memset(buffer, 0, 100);
            //   vm_registers.EIP++;   因为 跳转指令的存在，所以需要在指令函数中 改变 EIP 

        }
        else   // 失败为 1
        {
            _snwprintf(buffer, sizeof(buffer), L"指令：%s 执行失败\n", substrings[vm_registers.EIP]);
            // return 0;
            break;
        }
        //, , , , , , , , , , , , , , , 
     /*   printf("寄存器：RAX  值:  %016llx\n", vm_registers.registers[RAX]);
        printf("寄存器：RBX  值:  %016llx\n", vm_registers.registers[RBX]);
        printf("寄存器：RCX  值:  %016llx\n", vm_registers.registers[RCX]);
        printf("寄存器：RDX  值:  %016llx\n", vm_registers.registers[RDX]);
        printf("寄存器：RSI  值:  %016llx\n", vm_registers.registers[RSI]);
        printf("寄存器：RDI  值:  %016llx\n", vm_registers.registers[RDI]);
        printf("寄存器：RSP  值:  %016llx\n", vm_registers.registers[RSP]);
        printf("寄存器：RBP  值:  %016llx\n", vm_registers.registers[RBP]);
        printf("寄存器：R8   值:  %016llx\n", vm_registers.registers[R8]);
        printf("寄存器：R9   值:  %016llx\n", vm_registers.registers[R9]);
        printf("寄存器：R10  值:  %016llx\n", vm_registers.registers[R10]);
        printf("寄存器：R11  值:  %016llx\n", vm_registers.registers[R11]);
        printf("寄存器：R12  值:  %016llx\n", vm_registers.registers[R12]);
        printf("寄存器：R13  值:  %016llx\n", vm_registers.registers[R13]);
        printf("寄存器：R14  值:  %016llx\n", vm_registers.registers[R14]);
        printf("寄存器：R15  值:  %016llx\n", vm_registers.registers[R15]);


        // 此处是写入日志文件
        _snwprintf(buffer, sizeof(buffer), L"寄存器：RAX  值:  %016llx\n", vm_registers.registers[RAX]);
        fputws( buffer,file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：RBX  值:  %016llx\n", vm_registers.registers[RBX]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：RCX  值:  %016llx\n", vm_registers.registers[RCX]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：RDX  值:  %016llx\n", vm_registers.registers[RDX]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：RSI  值:  %016llx\n", vm_registers.registers[RSI]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：RDI  值:  %016llx\n", vm_registers.registers[RDI]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：RSP  值:  %016llx\n", vm_registers.registers[RSP]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：RBP  值:  %016llx\n", vm_registers.registers[RBP]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：R8   值:  %016llx\n", vm_registers.registers[R8]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：R9   值:  %016llx\n", vm_registers.registers[R9]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：R10  值:  %016llx\n", vm_registers.registers[R10]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：R11  值:  %016llx\n", vm_registers.registers[R11]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：R12  值:  %016llx\n", vm_registers.registers[R12]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：R13  值:  %016llx\n", vm_registers.registers[R13]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：R14  值:  %016llx\n", vm_registers.registers[R14]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"寄存器：R15  值:  %016llx\n", vm_registers.registers[R15]);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"EFL：CF  值:  %d\n", vm_registers.rflags.CF);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"EFL：PF  值:  %d\n", vm_registers.rflags.PF);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"EFL：AF  值:  %d\n", vm_registers.rflags.AF);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"EFL：ZF  值:  %d\n", vm_registers.rflags.ZF);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"EFL：SF  值:  %d\n", vm_registers.rflags.SF);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"EFL：TF  值:  %d\n", vm_registers.rflags.TF);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"EFL：IF  值:  %d\n", vm_registers.rflags.IF);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"EFL：DF  值:  %d\n", vm_registers.rflags.DF);
        fputws(buffer, file);
        memset(buffer, 0, 100);

        _snwprintf(buffer, sizeof(buffer), L"EFL：OF  值:  %d\n", vm_registers.rflags.OF);
        fputws(buffer, file);
        memset(buffer, 0, 100);*/


    } while (1); // 如果要执行的EIP不等于指令总数，说明没有执行完毕

    fclose(file);
    printf(" __readgsqword(0x60): %016llx\n", __readgsqword(0x60));

    printf("vm_registers.EIP : %d\n", vm_registers.EIP);
    printf("vm_registers.num : %d\n", vm_registers.num);


    // 释放分配的内存
    for (int i = 0; i < count; i++) {
        free(substrings[i]);
    }

    return 0;
}



int main(void)
{
    start_vm_cpu();

    return 0;
}
