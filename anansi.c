#include<sys/syscall.h>
#include<unistd.h>
#include<sys/stat.h>
#include<sys/mman.h>

extern unsigned long real_start;

int anansi_exit(int status);
long anansi_write(int fd, const void *buf, size_t count);
long anansi_read(int fd, void *buf, size_t count);
void *anansi_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
long anansi_stat(char *path, struct stat *statbuf);
long anansi_munmap(void *addr, size_t len);

int _start() {
	__asm__ volatile (
			".globl real_start\n"
			"real_start:\n"
			"push %rsp\n" //preserve rsp first since push will alter the value.
			"push %rbp\n"
			"push %rax\n"
			"push %rbx\n"
			"push %rcx\n"
			"push %rdx\n"
			"push %rsi\n"
			"push %rdi\n"
			"push %r8\n"
			"push %r9\n"
			"push %r10\n"
			"push %r11\n"
			"push %r12\n"
			"push %r13\n"
			"push %r14\n"
			"push %r15\n"
			"call vx_main\n"
			"pop %r15\n"
			"pop %r14\n"
			"pop %r13\n"
			"pop %r12\n"
			"pop %r11\n"
			"pop %r10\n"
			"pop %r9\n"
			"pop %r8\n"
			"pop %rdi\n"
			"pop %rsi\n"
			"pop %rdx\n"
			"pop %rcx\n"
			"pop %rbx\n"
			"pop %rax\n"
			"pop %rbp\n"
			"pop %rsp\n"
			);
}

void vx_main()
{
	int exit_code;
	anansi_read(0, &exit_code, sizeof(int));
	anansi_write(1, &exit_code, sizeof(int));
	anansi_exit(exit_code);
}

#define __load_syscall_ret(var) __asm__ __volatile__ ("mov %%rax, %0" : "=r" (var));
#define __write_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
	type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
		type ret; \
		__asm__ __volatile__ (\
				"movq $1, %%rax\n" \
				"movq %0, %%rdi\n" \
				"movq %1, %%rsi\n" \
				"movq %2, %%rdx\n" \
				"syscall" \
           			      : \
				      : "g" (arg1), "g" (arg2), "g" (arg3) \
				      : "%rax", "%rdi", "%rsi", "%rdx" \
		); \
		__load_syscall_ret(ret); \
		return ret; \
	}

#define __exit_syscall(type, name, arg1, arg1_type) \
	type name(arg1_type arg1) { \
		type  ret; \
		__asm__ __volatile__ ( \
				"movq $60, %%rax\n" \
				"syscall\n" \
			       	: "=r" (ret) \
				: "D" (arg1) \
				: "%rax" \
		); \
		return ret; \
	}

#define __read_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
	type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
		type ret; \
		__asm__ __volatile__ (\
				"movq $0, %%rax\n" \
				"movq %0, %%rdi\n" \
				"movq %1, %%rsi\n" \
				"movq %2, %%rdx\n" \
				"syscall" \
					: \
					: "g" (arg1), "g" (arg2), "g" (arg3) \
					: "%rax", "%rdi", "%rsi", "%rdx" \
		); \
		__load_syscall_ret(ret); \
		return ret; \
	}

#define __mmap_syscall(type, name, arg1, arg1_type, arg2,  arg2_type, arg3, arg3_type, arg4, arg4_type, arg5, arg5_type, arg6, arg6_type) \
        type name(arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, arg5_type arg5, arg6_type arg6) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $9, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "movq %2, %%rdx\n" \
                                "movq %3, %%r10\n" \
                                "movq %4, %%r8\n" \
                                "movq %5, %%r9\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2), "g" (arg3), "g" (arg4), "g" (arg5), "g" (arg6) \
                                        : "%rax", "%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }
#define __stat_syscall(type, name, arg1, arg1_type, arg2, arg2_type) \
        type name(arg1_type arg1, arg2_type arg2) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $4, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2) \
                                        : "%rax", "%rdi", "%rsi" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

#define __munmap_syscall(type, name, arg1, arg1_type, arg2, arg2_type) \
        type name(arg1_type arg1, arg2_type arg2) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $11, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2) \
                                        : "%rax", "%rdi", "%rsi" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

__exit_syscall(int, anansi_exit, status, int);
__write_syscall(long, anansi_write, fd, int, buf, const void *, count, size_t);
__read_syscall(long, anansi_read, fd, int, buf, void *, count, size_t);
__mmap_syscall(void *, anansi_mmap, addr, void *, length, size_t, prot, int, flags, int, fd, int, offset, off_t);
__stat_syscall(long, anansi_stat, path, char *, statbuf, struct stat *);
__munmap_syscall(long, anansi_munmap, addr, void *, len, size_t);